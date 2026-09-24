import { createHash } from 'node:crypto'
import { type Json } from './jcs.js'
import { type Proof, coreBytes, coreHash, keyId, publicKeyFromSpki, verifyEs256 } from './core.js'
import { canonicalBytes, mediaHash } from './canonical.js'
import { Flag, parseTrailer } from './trailer.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type ContainerReading, ContainerMalformed, readContainer } from './container.js'
import { RANK, leafSpki, normalSerial, validateChain } from './attestation.js'
import { type TrustBundle } from './trust.js'
import { type IntegrityAttachment, type KeyStatusStatement, type RegistryAttachment, verifyIntegrity, verifyKeyStatus, verifyRegistry } from './registry.js'
import { type AnchorAttachment, type ChainRead, verifyAnchor } from './anchor.js'
import { verifyTimestampToken } from './rfc3161.js'
import { LOCATION_LEVELS, LOCATION_RANK, verifyLocationCorroboration } from './location.js'
import { jcs } from './jcs.js'
import { ProofSyntaxError, parseProofJson } from './json.js'

/**
 * Reference verifier for the whole format: trailer, canonical bytes, core
 * signature, the segment chain and its binding to the GOPs of the received
 * container (§5), version policy, every §6.2 attachment and its labels, the
 * proof level and its ceiling (§7) and the position level (§7.1). What it
 * takes as inputs rather than fetching — the online key status, the chain
 * read, the verifier's clock — is what a caller supplies.
 *
 * Its job in this repository is to prove that the committed vectors are
 * consistent with the spec. It is written from the spec; when it disagrees with
 * an expected verdict, one of the two is wrong and the review decides which.
 */
export type Outcome =
  | 'no_proof_found' | 'corrupted_proof' | 'nested_proof' | 'unsupported_format_version'
  | 'tampered' | 'frames_not_compared' | 'verified_clip' | 'authentic'

export interface Verdict {
  outcome: Outcome
  // §8 labels the verifier must show, sorted.
  labels: string[]
  // Unknown top-level keys (§9), sorted.
  not_evaluated: string[]
  core_hash?: string
  segments?: { verified: number[] }
  // §7: claimed by the device, proven by the evidence, and the ceiling the two
  // allow. Present whenever a core was read.
  level?: { claimed: string, proven: string, ceiling: 'green' | 'amber' | 'red' }
  // §7: the instant every certificate path was validated at, and what proved
  // it. A verifier must be able to say this, because the same file reads
  // differently when the capture time is a device's claim.
  validated_at?: { instant: string, source: 'timestamp' | 'anchor' | 'device_clock' | 'verifier_clock' }
  // §7.1: the position level the core claims and the one the evidence
  // reaches. Orthogonal to the outcome — present on every non-red verdict.
  location?: { claimed: string, level: string }
  reason?: string
}

const ABSENT_LABELS: [string, string][] = [

  ['attestation', 'origin not hardware-attested'],
  ['watermark', 'no watermark']
]

const KNOWN_KEYS = new Set([
  'v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy',
  'sig', 'segments', 'attestation', 'attestation_status', 'registry', 'timestamp', 'anchor', 'integrity',
  'location_corroboration'
])

/**
 * The v1.0 values of `device.platform` and `device.secure_hw`. A value outside
 * these sets is **not** a reason to refuse the proof: §7 says a v1.0 verifier
 * meeting an unknown `secure_hw` treats it as `none`, and §9 says to verify
 * every field you know and never fail. Rejecting instead would make a capture
 * from a newer minor unreadable by this verifier — the exact outcome §9 exists
 * to prevent — and would do it while the signature over the core is perfectly
 * valid.
 *
 * Treating the claim as `none` costs the capture nothing it was entitled to:
 * the claim is what a verifier must not believe anyway, and the level that
 * counts comes from the `attestation` attachment (§7).
 */
const PLATFORMS = new Set(['android', 'ios', 'web'])
const SECURE_HW = new Set(['strongbox', 'tee', 'secureEnclave', 'none'])

/** The claimed level, with anything this version does not know read as `none`. */
export const claimedLevel = (device: { platform: string, secure_hw: string }): string =>
  PLATFORMS.has(device.platform) && SECURE_HW.has(device.secure_hw) ? device.secure_hw : 'none'

const fail = (outcome: Outcome, reason: string, labels: string[] = []): Verdict =>
  ({ outcome, labels: labels.sort(), not_evaluated: [], reason })

const isObject = (v: unknown): v is { [key: string]: Json } => typeof v === 'object' && v !== null && !Array.isArray(v)

// §6.1: integers only, anywhere in the core.
const hasNonInteger = (v: Json): boolean => {
  if (typeof v === 'number') return !Number.isInteger(v)
  if (Array.isArray(v)) return v.some(hasNonInteger)
  if (isObject(v)) return Object.values(v).some(hasNonInteger)
  return false
}

const b64urlLen = (s: unknown, bytes: number): s is string =>
  typeof s === 'string' && /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, 'base64url').length === bytes

// The shape checks the verifier needs before it can trust the types it reads;
// `schema/` formalizes the rest.
const shapeProblem = (proof: Proof): string | null => {
  if (!b64urlLen(proof.capture_id, 16)) return 'capture_id missing or not 16 bytes'
  if (!isObject(proof.media) || typeof proof.media.hash !== 'string' || typeof proof.media.mime !== 'string') return 'media.hash or media.mime missing'
  // §8: the pixel dimensions are required. They are not evidence — nothing is
  // proven by them — but every writer holds them at capture, and a reader that
  // cannot say how large the frame is cannot place a watermark payload or a
  // segment in it. Missing is malformed, the same as an absent capture_id.
  if (!Number.isInteger(proof.media.w) || !Number.isInteger(proof.media.h) || (proof.media.w as number) < 1 || (proof.media.h as number) < 1) return 'media.w or media.h missing'
  if (!isObject(proof.device) || typeof proof.device.platform !== 'string' || typeof proof.device.secure_hw !== 'string' || typeof proof.device.key_id !== 'string') return 'device incomplete'
  if (!isObject(proof.sig) || typeof proof.sig.value !== 'string' || typeof proof.sig.pub !== 'string' || typeof proof.sig.alg !== 'string') return 'sig incomplete'
  if ('segments' in proof) {
    if (!Array.isArray(proof.segments)) return 'segments not an array'
    if (!Number.isInteger(proof.media.segment_count)) return 'media.segment_count missing'
  }
  // §8: media.mime alone decides that a proof is a video proof, and a video
  // proof needs its segments — the container and duration_ms decide nothing.
  if ((proof.media.mime as string).startsWith('video/') && !('segments' in proof && Number.isInteger(proof.media.segment_count))) return 'video proof without segments'
  if (hasNonInteger(coreObject(proof))) return 'floating-point number in the core'
  return null
}

const coreObject = (proof: Proof): Json => {
  const core: Proof = {}
  for (const key of ['v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy']) if (key in proof) core[key] = proof[key] as Json
  return core
}

export interface FileInput {
  file: Buffer
  sidecar?: Buffer
  /**
   * Recompute every present segment's `content_hash` from the container (§5)
   * instead of taking the proof's word for it.
   *
   * Optional because a verifier without a demuxer is still a verifier — the
   * signature layer stands on its own — but a verifier that has the file and
   * skips this checks only that *somebody signed some hashes*, not that the
   * frames in front of the reader are those frames.
   */
  recomputeSegments?: boolean
  /**
   * The anchors a verifier trusts: attestation roots and log keys, loaded from
   * the corpus's `_trust/` bundle or from wherever a real verifier keeps them.
   * Without them a chain is *not evaluated*, never *rejected* — the difference
   * between "this verifier cannot say" and "the proof is bad".
   */
  trust?: TrustBundle
  /** The verifier's own clock. Injectable so a vector's verdict is a constant. */
  clock?: Date
  /**
   * §6.2's online key status, as the caller fetched it. An **input**, like the
   * clock: this layer contacts nothing, and a vector that needs green has to
   * declare the statement a verifier is assumed to have obtained. Absent is
   * *revocation not checked*.
   */
  keyStatus?: KeyStatusStatement
  /**
   * §6.2's chain read for the `anchor` attachment, as the caller performed it.
   * An input for the same reason: this layer contacts nothing, and a contract
   * is somewhere else. Absent is *anchoring not verified*.
   */
  chainRead?: ChainRead
}

export const verifyFile = ({ file, sidecar, recomputeSegments, trust, clock = new Date(), keyStatus, chainRead }: FileInput): Verdict => {
  // 1. Trailer, sidecar, nesting (§3).
  const trailer = parseTrailer(file)
  if (trailer.kind === 'corrupted') return fail('corrupted_proof', 'footer valid, CRC mismatch')
  if (trailer.kind === 'unsupported') return fail('unsupported_format_version', `footer major ${trailer.major}`)

  const labels: string[] = []
  let payload: Buffer
  let media: Buffer
  let flags: number | null = null
  if (trailer.kind === 'ok') {
    payload = trailer.payload
    media = file.subarray(0, trailer.mediaEnd)
    flags = trailer.flags
    if (parseTrailer(media).kind !== 'none') return fail('nested_proof', 'the canonical bytes end in another trailer')
    if (sidecar && !sidecar.equals(payload)) labels.push('sidecar differs')
  } else if (sidecar) {
    payload = sidecar
    media = file
  } else {
    return fail('no_proof_found', 'no trailer and no sidecar')
  }

  // 2. JSON and version (§9).
  let proof: Proof
  try {
    const parsed: unknown = parseProofJson(payload)
    if (!isObject(parsed)) throw new ProofSyntaxError('not an object')
    proof = parsed
  } catch (e) {
    if (!(e instanceof ProofSyntaxError)) throw e
    return fail('no_proof_found', `payload is not a well-formed proof: ${e.message}`)
  }
  const version = typeof proof.v === 'string' ? /^vcap\/(\d+)\.(\d+)$/.exec(proof.v) : null
  if (!version) return fail('no_proof_found', 'v missing or malformed')
  if (version[1] !== '1') return fail('unsupported_format_version', `major ${version[1]}`)
  const notEvaluated = Object.keys(proof).filter((k) => !KNOWN_KEYS.has(k)).sort()

  // 3. Shape (§6.1, §8 required).
  const problem = shapeProblem(proof)
  if (problem) return fail('no_proof_found', problem)

  // 4. Core signature (§4.2) and key binding (§6.1).
  const sig = proof.sig as { alg: string, value: string, pub: string }
  const bytes = coreBytes(proof)
  const hash = coreHash(proof).toString('hex')
  // A red verdict carries its reason and nothing else: absence labels are for
  // verdicts where the absence still matters (§8).
  const tampered = (reason: string): Verdict => ({ outcome: 'tampered', labels: [], not_evaluated: notEvaluated, core_hash: hash, reason })

  if (sig.alg !== 'ES256') return tampered('sig.alg is not ES256')
  const spki = Buffer.from(sig.pub, 'base64url')
  const publicKey = publicKeyFromSpki(spki)
  if (!publicKey) return tampered('sig.pub is not an EC P-256 SubjectPublicKeyInfo')
  const signature = Buffer.from(sig.value, 'base64url')
  if (signature.length !== 64) return tampered('sig.value is not a 64-byte P1363 signature')
  if (!verifyEs256(bytes, signature, publicKey)) return tampered('core signature invalid')
  if ((proof.device as Proof).key_id !== keyId(spki)) return tampered('device.key_id is not SHA-256 of sig.pub')
  // §6.2: the attestation leaf's key MUST be the signing key. A chain about
  // another key attached to this proof is a signature swap, not weak evidence.
  if (Array.isArray(proof.attestation) && proof.attestation.length > 0) {
    const leaf = leafSpki(proof.attestation[0])
    if (leaf !== null && !leaf.equals(spki)) return tampered('attestation leaf key differs from sig.pub')
  }

  // 5. Media (§4.1) and, for video, the chain (§5).
  const mediaObj = proof.media as { hash: string, segment_count?: number }
  // §4.1: media the container rule cannot walk has no canonical bytes, and a
  // proof about bytes nobody can canonicalize is not a proof of anything —
  // never a crash, which is what a malformed JPEG used to produce.
  let mediaMatches: boolean
  try {
    mediaMatches = mediaHash(media) === mediaObj.hash
  } catch {
    return fail('no_proof_found', 'the media cannot be read as its container')
  }
  for (const [key, label] of ABSENT_LABELS) if (!(key in proof)) labels.push(label)
  // §6.2 `registry`, evaluated here and not inside `level` because a clip
  // returns before the level is computed and still has to say whether the key
  // was in the log — the label is about the key, not about the verdict.
  // §6.2 `anchor`. Its offline half — does the path reach the anchored root —
  // is checkable here; the chain read is an input, and its `block_time` is the
  // only instant in this layer that the device does not assert.
  const anchor = anchorOutcome(proof, Buffer.from(hash, 'hex'), chainRead, labels)
  // §6.2 `timestamp`: the only instant in a file that a device does not
  // assert about itself, and the one a verifier needs no network for.
  let timestamp = timestampOutcome(proof, Buffer.from(hash, 'hex'), trust, labels)
  // §6.2: a token and a verified anchor over the same core must agree. The
  // token is validated at its own genTime, which a leaked TSA key can choose;
  // the block time is one nobody can choose, so the token must predate it and
  // its signer must still have been valid then. A token that fails either is
  // evidence that does not hold up, and the anchor dates the capture instead.
  if (timestamp.ok && anchor.ok && anchor.blockTime !== null) {
    const block = anchor.blockTime
    if (timestamp.genTime.getTime() > block || block < timestamp.signerValid.from.getTime() || block > timestamp.signerValid.to.getTime()) {
      labels.push('no trusted time', 'timestamp evidence invalid')
      timestamp = { ok: false }
    }
  }
  // §6.1: a capture time the device did not declare is never read as "early
  // enough" — it is shown, and nothing that needs it can be established.
  const deviceClock = deviceClockOf(proof)
  if (deviceClock === null) labels.push('capture time not declared')
  // §6.2 `registry`, evaluated here and not inside `level` because a clip
  // returns before the level is computed and still has to say whether the key
  // was in the log — the label is about the key, not about the verdict.
  const registry = registryOutcome(proof, spki, trust, labels, deviceClock, timestamp.ok ? timestamp.genTime.getTime() : null)
  // §6.2 `integrity`. It corroborates and never carries, so it produces a
  // label and no level: see `integrityOutcome`.
  integrityOutcome(proof, Buffer.from(hash, 'hex'), trust, labels)
  // §7.1 the position level. Computed here, before the video branch, because
  // it is orthogonal to the outcome: a clip's coordinates are worth exactly
  // what an original's are.
  const location = locationOutcome(proof, Buffer.from(hash, 'hex'), trust, labels)
  // A declared watermark is the writer saying a mark was embedded, not a
  // promise a reader finds it. This verifier ships no detector, so the only
  // honest §7 outcome is *watermark not evaluated* — never silence, which a
  // reader would take for a match.
  if ('watermark' in proof) labels.push('watermark not evaluated')
  if (flags !== null) {
    // Bits 1 and 2 are derivable from the JSON and checked; bit 0 (a sidecar
    // exists) depends on the filesystem at verification time and is a hint only.
    const expectedFlags = (('segments' in proof) ? Flag.SEGMENTS : 0) | ((isObject(proof.policy) && proof.policy.pseudonymous === true) ? Flag.PSEUDONYMOUS : 0)
    if ((flags & (Flag.SEGMENTS | Flag.PSEUDONYMOUS)) !== expectedFlags) labels.push('flags disagree')
  }

  let segments: Verdict['segments']
  if ('segments' in proof) {
    const entries = proof.segments as unknown as SegmentEntry[]
    const captureId = Buffer.from(proof.capture_id as string, 'base64url')

    // The signature layer first: every present segment's signature and the
    // chain wherever two consecutive segments are present (§5).
    const chain = verifyChain(captureId, mediaObj.segment_count as number, entries, publicKey)

    // §5, *Locating segments*: a signature proves that somebody signed a
    // hash; only a GOP located in this file and recomputed proves that the
    // frames in front of the reader are those frames. A verifier that did not
    // recompute says so, and gives no segment credit.
    if (!recomputeSegments) labels.push('segment content not recomputed')
    let binding: Binding = { located: false, reason: 'segment content not recomputed' }
    if (recomputeSegments) {
      try {
        binding = bindSegments(readContainer(media), captureId, entries)
      } catch (e) {
        if (!(e instanceof ContainerMalformed)) throw e
        return { ...tampered(`the container is malformed: ${e.message}`), segments: { verified: [] } }
      }
    }
    // A segment whose signature fails is not verified, whatever its bytes.
    segments = { verified: binding.located ? binding.verified.filter((index) => chain.verified.includes(index)) : [] }
    if (chain.status === 'tampered') return { ...tampered(chain.reason ?? 'segment chain'), segments }
    if (binding.located && binding.problems.length > 0) return { ...tampered(binding.problems.join('; ')), segments }

    if (!mediaMatches) {
      // A file that is not the original, and in which no GOP of this capture
      // could be found: the signatures hold, and nothing ties them to these
      // frames. Never a clip — a clip is frames that were compared.
      if (!binding.located) {
        return { outcome: 'frames_not_compared', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash, segments, location, reason: `media.hash does not match and ${binding.reason}` }
      }
      return { outcome: 'verified_clip', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash, segments, location, reason: 'media.hash does not match the received file' }
    }
    // media.hash matches: these are the bytes the device sealed. A chain with
    // segments missing from the proof is still a clip of the proof, and says
    // so even over the original file.
    if (chain.status === 'clip') {
      return { outcome: 'verified_clip', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash, segments, location, reason: 'segments missing' }
    }
  } else if (!mediaMatches) {
    return tampered('media.hash does not match the canonical bytes')
  }

  return {
    outcome: 'authentic', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash,
    ...(segments ? { segments } : {}),
    ...level(proof, spki, Buffer.from(hash, 'hex'), labels, trust, clock, registry, keyStatus, anchor, timestamp),
    location
  }
}

/**
 * §7, the proof level. Three questions in order: at what instant is this proof
 * validated, what does the evidence prove at that instant, and what ceiling do
 * the two allow. The labels array is appended to in place, because a level is
 * not a separate verdict — it is part of this one.
 */
const level = (
  proof: Proof, spki: Buffer, coreHash: Buffer, labels: string[], trust: TrustBundle | undefined, clock: Date,
  registry: RegistryVerdict, keyStatus: KeyStatusStatement | undefined, anchor: AnchorVerdict,
  timestamp: TimestampVerdict
): Pick<Verdict, 'level' | 'validated_at'> => {
  // The instant (§7), in its order of trust: a valid timestamp token's
  // genTime, then a verified anchor's block, then the device's own clock —
  // which is a claim, and caps the verdict at amber — and, when the device
  // declared none, this verifier's clock, which proves nothing about the
  // capture and caps it the same way.
  const deviceClock = deviceClockOf(proof)
  const anchored = anchor.ok && anchor.blockTime !== null ? anchor.blockTime : null
  const stamped = timestamp.ok ? timestamp.genTime.getTime() : null
  const instant = stamped !== null
    ? new Date(stamped)
    : anchored !== null ? new Date(anchored) : deviceClock !== null ? new Date(deviceClock) : clock
  const source = stamped !== null
    ? 'timestamp' as const
    : anchored !== null ? 'anchor' as const : deviceClock !== null ? 'device_clock' as const : 'verifier_clock' as const

  // §6.2 online revocation. The statement is an *input* — this layer contacts
  // nothing — and its absence is the reason an offline verifier cannot reach
  // green: *revocation not checked*, by design, because green must never mean
  // less than it says.
  if (registry.ok) {
    const checked = keyStatus === undefined
      ? null
      : verifyKeyStatus(keyStatus, Buffer.from((proof.device as Proof).key_id as string, 'base64url'), instant, trust?.logs ?? [])
    if (checked?.ok === true && checked.status === 2) labels.push('key revoked')
    else if (checked?.ok !== true || checked.status === 0) labels.push('revocation not checked')
  }

  const claimed = claimedLevel(proof.device as { platform: string, secure_hw: string })
  let proven = 'none'
  const chain = Array.isArray(proof.attestation) && (proof.device as Proof).platform === 'android'
    ? validateChain(proof.attestation as string[], spki, trust?.attestationRoots ?? [], instant, clock)
    : null
  if (chain) {
    if ((trust?.attestationRoots.length ?? 0) === 0) labels.push('attestation not evaluated')
    else {
      proven = chain.proven
      // §8: a present attachment that does not hold up carries the absent
      // label and its own invalid one.
      if (chain.proven === 'none') labels.push(...(chain.evidenceInvalid ? ['origin not hardware-attested', 'attestation evidence invalid'] : ['origin not hardware-attested']))
      // §7: a chain valid at the proven instant and expired since is not an
      // error — the verifier is late, not the capture forged. It is worth
      // saying only when nothing independent places the capture inside the
      // chain's validity, which is the case for a device clock.
      // §7's table says the label only when the capture time is *only*
      // `time.device_clock`. A timestamp token or a verified anchor places the
      // capture inside the chain's validity independently, which is the whole
      // reason to carry one, so the caveat goes away rather than being shown
      // next to the evidence that answers it.
      if (chain.expiredSince && source === 'device_clock') {
        labels.push('attestation chain expired, capture time not proven')
      }
    }
  }

  // §7, *The Secure Enclave level*: iOS carries no chain, and this version
  // defines no offline binding to App Attest. The level is reachable only
  // through a verified registry leaf that records it, and it is the
  // registry's word — labelled so, never presented as checkable without it.
  if (!chain && (proof.device as Proof).platform === 'ios' && registry.ok && registry.secureHw === 'secureEnclave') {
    proven = 'secureEnclave'
    labels.push('level from registry records')
    const at = labels.indexOf('origin not hardware-attested')
    if (at !== -1) labels.splice(at, 1)
  }

  // §6.2: the chain's revocation status, frozen while the chain was current.
  // A `revoked` certificate is red unless an instant nobody can move — a
  // token's genTime or a verified anchor's block — places the capture before
  // the revocation date the source itself gives, and the reason is not one
  // that reaches back. The device clock can be set by whoever holds the key,
  // which is exactly who a revocation is about, so it never places anything.
  const trustedInstant = source === 'timestamp' || source === 'anchor' ? instant.getTime() : null
  if (chain && proven !== 'none') {
    const frozen = isObject(proof.attestation_status)
      ? frozenRevocation(proof.attestation_status, coreHash, trust, chain.serials ?? [])
      : { checked: false as const }
    if (frozen.checked && frozen.revoked.length > 0) {
      const after = trustedInstant !== null && frozen.revoked.every((r) => !r.retroactive && r.revokedAt !== null && trustedInstant < r.revokedAt)
      if (after) labels.push('attestation key revoked after the capture')
      else { proven = 'none'; labels.push('attestation key revoked') }
    } else if (!frozen.checked || frozen.incomplete) {
      labels.push('chain revocation not checked')
    }
  }

  if (chain && proven !== 'none' && (RANK[claimed] ?? 0) > (RANK[proven] ?? 0)) labels.push('inconsistent claim')

  // A leaf's `secure_hw` is the level the log saw proven at registration. §6.2
  // forbids it from exceeding what `attestation` proves, and the honest label
  // is the one the format already has for a claim above its evidence.
  if (registry.ok && (RANK[registry.secureHw] ?? 0) > (RANK[proven] ?? 0) && !labels.includes('inconsistent claim')) {
    labels.push('inconsistent claim')
  }

  // §7: the app that created the key. The leaf's attestationApplicationId is
  // compared with the signing digests the log declares for the apps it admits
  // keys from. It needs both halves, so it is evaluated only for a registered
  // key: without the declaration there is nothing to compare with, and that is
  // *not checked*, amber — never red, the hardware claim still stands.
  if (chain && proven !== 'none' && registry.ok) {
    const declared = registry.appSigningDigests
    const carried = chain.appSigningDigests ?? null
    if (declared === null || declared.length === 0 || carried === null) labels.push('attestation app not checked')
    else if (!carried.some((digest) => declared.includes(digest))) labels.push('attestation app not admitted')
  }

  // Green needs a proven level, the key in the log before the capture, and an
  // instant nobody can move. Red is for a chain, or a key, already revoked at
  // the capture.
  // Every amber cause has to be checked, not just the two nearest: §7's table
  // caps the verdict on an unchecked chain revocation, on a capture time only
  // the device vouches for, and on a failed integrity verdict, and a green that
  // ignored any of them would be a stronger claim than the evidence.
  const amberCauses = ['inconsistent claim', 'chain revocation not checked', 'revocation not checked',
                       'attestation chain expired, capture time not proven', 'registry evidence invalid',
                       'attestation app not checked', 'attestation app not admitted', 'integrity failed']
  const green = proven !== 'none' && registry.ok && registry.beforeCapture &&
    (source === 'timestamp' || source === 'anchor') &&
    !amberCauses.some((cause) => labels.includes(cause))
  const ceiling: NonNullable<Verdict['level']>['ceiling'] =
    labels.includes('attestation key revoked') || labels.includes('key revoked') ? 'red'
      : green ? 'green' : 'amber'
  labels.sort()
  return { level: { claimed, proven, ceiling }, validated_at: { instant: instant.toISOString(), source } }
}

/**
 * §6.2 `registry`, reduced to what §7 needs from it: is the key in a log this
 * verifier trusts, and was it there before the capture was claimed to happen.
 *
 * Three failures, and they are deliberately not one label. **Absent** and
 * **a log nobody trusts** are the same fact — nobody can check the
 * registration — so both read as *key not in transparency log*, which is §8's
 * rule that absent evidence is a weaker verdict and not an error. **Evidence
 * that does not hold up** is a different fact and gets *registry evidence
 * invalid* on top: conflating a key nobody registered with a forged inclusion
 * proof throws away the only part a reader can act on.
 */
type RegistryVerdict = { ok: false } | { ok: true, secureHw: string, beforeCapture: boolean, appSigningDigests: string[] | null }

type AnchorVerdict = { ok: false } | { ok: true, blockTime: number | null }

type TimestampVerdict = { ok: false } | { ok: true, genTime: Date, signerValid: { from: Date, to: Date } }

/**
 * §6.2 `integrity`, and §7's row for it: a valid `failed` verdict caps the
 * ceiling at amber and is shown prominently; every other verdict, and the
 * absence of one, is shown and caps nothing.
 *
 * Why only `failed`, and why it is not load-bearing the other way: deleting
 * the attachment gives *integrity unevaluated*, so no verdict here can be a
 * condition for green without letting whoever strips it decide. What a
 * present `failed` can do is refuse green on the strength of Google's or
 * Apple's word, which is the one direction a relabelling cannot fake — the
 * verdict is inside the signed message.
 */
const integrityOutcome = (proof: Proof, coreHash: Buffer, trust: TrustBundle | undefined, labels: string[]): void => {
  if (!isObject(proof.integrity)) {
    labels.push('integrity unevaluated')
    return
  }
  const outcome = verifyIntegrity(proof.integrity as unknown as IntegrityAttachment, coreHash, trust?.logs ?? [])
  if (!outcome.ok) {
    labels.push('integrity unevaluated')
    // The same distinction the registry draws: evidence that does not hold up
    // is a fact a reader can act on, while evidence this verifier cannot read
    // — a signer it does not follow, a source from a later minor — is absence.
    if (outcome.trusted && outcome.evaluated) labels.push('integrity evidence invalid')
    return
  }
  labels.push(`integrity ${outcome.verdict}`)
}

/**
 * §6.2 `timestamp`, and the §8 label rule again: absent is *no trusted time*,
 * a token that does not hold up adds *timestamp evidence invalid*, and no
 * pinned TSA root is *trusted time not evaluated* — evidence this verifier
 * cannot read rather than evidence that failed.
 */
const timestampOutcome = (
  proof: Proof, coreHash: Buffer, trust: TrustBundle | undefined, labels: string[]
): TimestampVerdict => {
  const attachment = isObject(proof.timestamp) ? proof.timestamp : null
  const tsr = attachment !== null && typeof attachment.tsr === 'string' ? attachment.tsr : null
  if (tsr === null) {
    labels.push('no trusted time')
    return { ok: false }
  }
  if ((trust?.tsaRoots.length ?? 0) === 0) {
    labels.push('trusted time not evaluated')
    return { ok: false }
  }
  let token: Buffer
  try {
    token = Buffer.from(tsr, 'base64url')
  } catch {
    labels.push('no trusted time', 'timestamp evidence invalid')
    return { ok: false }
  }
  const outcome = verifyTimestampToken(token, coreHash, trust?.tsaRoots ?? [])
  if (!outcome.ok) {
    labels.push('no trusted time', 'timestamp evidence invalid')
    return { ok: false }
  }
  return { ok: true, genTime: outcome.genTime, signerValid: outcome.signerValid }
}

/**
 * §6.2 `anchor`, reduced to what §7 needs: does the path reach the anchored
 * root, did the chain agree, and what instant does the block give.
 *
 * The label rule is the one §8 states once for every attachment: a present
 * attachment whose evidence does not hold up carries **the absent label and
 * its own invalid label**. *not anchored* is what a reader is shown; *anchor
 * evidence invalid* is what an operator can act on.
 */
const anchorOutcome = (
  proof: Proof, coreHash: Buffer, read: ChainRead | undefined, labels: string[]
): AnchorVerdict => {
  if (!isObject(proof.anchor)) {
    labels.push('not anchored')
    return { ok: false }
  }
  const outcome = verifyAnchor(proof.anchor as unknown as AnchorAttachment, coreHash, read)
  if (!outcome.ok) {
    labels.push('not anchored', 'anchor evidence invalid')
    return { ok: false }
  }
  // The offline half held. Without a chain read the root is still only the
  // proof's word about itself, so nothing is anchored yet.
  if (!outcome.onChain) labels.push('anchoring not verified')
  return { ok: true, blockTime: outcome.blockTime }
}

/**
 * §7.1 the position level, and the §8 labels around it.
 *
 * The claim in the core never raises the level: `location.level` is what the
 * device says it reached, and the verifier computes what the evidence reaches
 * — `declared` for signed coordinates, `corroborated` for a
 * `location_corroboration` a trusted registry key signed over this core with
 * `result: match`. `authenticated` needs an evidence kind this version does
 * not implement, so no proof reaches it here and a claim of it is shown as
 * claimed above evidence, with the evidence it carries listed as not
 * evaluated. Nothing here touches the ceiling.
 */
const locationOutcome = (
  proof: Proof, coreHash: Buffer, trust: TrustBundle | undefined, labels: string[]
): NonNullable<Verdict['location']> => {
  const claim = isObject(proof.location) ? proof.location : null
  const attachment = isObject(proof.location_corroboration) ? proof.location_corroboration : null
  // A position is two coordinates. A `location` without both declares
  // nothing, whatever its `level` says, and an attachment about it has
  // nothing to corroborate.
  const declared = claim !== null && Number.isInteger(claim.lat_udeg) && Number.isInteger(claim.lon_udeg)
  if (!declared) {
    if (attachment !== null) labels.push('location corroboration not evaluated')
    return { claimed: 'none', level: 'none' }
  }
  // `level` is not extensible (§9): a value this version does not know is
  // read as `declared`, the level any signed position reaches on its own.
  const claimed = typeof claim.level === 'string' && LOCATION_LEVELS.has(claim.level) ? claim.level : 'declared'
  let level = 'declared'
  if (attachment !== null) {
    const outcome = verifyLocationCorroboration(attachment, coreHash, trust?.logs ?? [])
    if (!outcome.ok) {
      labels.push(!outcome.evaluated
        ? 'location corroboration not evaluated'
        : outcome.trusted ? 'location corroboration evidence invalid' : 'location corroboration not verified')
    } else if (outcome.result === 'match') {
      level = 'corroborated'
    } else if (outcome.result === 'no-match') {
      // The operator's check disagreed with the declared position. Shown, and
      // the level stays what the device alone can reach; never a ceiling.
      labels.push('location contradicted')
    }
  }
  // Device-side evidence kinds arrive with a later minor (§7.1). None is
  // implemented here, so whatever the array carries is listed, not weighed.
  if (Array.isArray(claim.evidence) && claim.evidence.length > 0) labels.push('location evidence not evaluated')
  labels.push(level === 'corroborated' ? 'location corroborated' : 'location declared only')
  if ((LOCATION_RANK[claimed] ?? 0) > (LOCATION_RANK[level] ?? 0)) labels.push('location claimed above evidence')
  return { claimed, level }
}

/** `time.device_clock`, or null when the proof declares none. */
const deviceClockOf = (proof: Proof): number | null =>
  isObject(proof.time) && typeof proof.time.device_clock === 'number' ? proof.time.device_clock : null

const registryOutcome = (
  proof: Proof, spki: Buffer, trust: TrustBundle | undefined, labels: string[], deviceClock: number | null, genTime: number | null
): RegistryVerdict => {
  if (!isObject(proof.registry)) {
    labels.push('key not in transparency log')
    return { ok: false }
  }
  const keyId = ((proof.device as Proof).key_id ?? '') as string
  const outcome = verifyRegistry(proof.registry as unknown as RegistryAttachment, { keyId, sigPub: spki }, trust?.logs ?? [])
  if (!outcome.ok) {
    // A log nobody pinned is its own fact, and the shipping verifier already
    // says so: *log not trusted* rather than the absent-evidence label, which
    // would tell a reader nobody registered the key when somebody may well
    // have, in a log this verifier does not follow.
    if (!outcome.trusted) labels.push('log not trusted')
    else labels.push('key not in transparency log', 'registry evidence invalid')
    return { ok: false }
  }
  // The tree head is when the log signed a tree containing the key. §6.2: it
  // MUST NOT exceed the declared capture time, nor a valid token's genTime.
  // Later than either means the key was logged after the fact, which is shown
  // and caps the verdict rather than invalidating anything. With no declared
  // time there is nothing to be early against, and the answer is "not shown",
  // never "before" — an absent field is a weaker verdict, not a stronger one.
  const head = outcome.treeHeadTimestamp
  if (deviceClock !== null && head > deviceClock) labels.push('registered after the declared capture')
  if (genTime !== null && head > genTime) labels.push('registered after the trusted time')
  const beforeCapture = deviceClock !== null && head <= deviceClock && (genTime === null || head <= genTime)
  const log = (trust?.logs ?? []).find((candidate) => candidate.log_id === (proof.registry as Proof).log_id)
  return { ok: true, secureHw: outcome.secureHw, beforeCapture, appSigningDigests: log?.app_signing_digests ?? null }
}

/**
 * The `attestation_status` countersignature (§6.2), read into what §7 needs.
 *
 * `checked: false` means the evidence could not be used — no trusted log key,
 * an unknown source, a signature that does not verify — which is *not
 * checked*, never *revoked*. A usable snapshot answers per certificate, and
 * the answer is only as complete as its coverage: a certificate of the chain
 * with no entry, or with `unknown`, leaves the chain's revocation unchecked.
 *
 * `fetched_at` is when the registry read the list. It is **not** when anything
 * was revoked, and it is never used as a revocation date: a keybox leaked in
 * 2025 and listed in 2026 would otherwise read "revoked after" every capture
 * the thief signed in between. The only date that can place a revocation after
 * the capture is `revoked_at`, the date the source itself gives.
 */
type FrozenStatus =
  | { checked: false }
  | { checked: true, revoked: { revokedAt: number | null, retroactive: boolean }[], incomplete: boolean }

// Reasons that make a revocation reach back to the key's first use: a
// compromised key vouches for nothing it ever signed (§6.2).
const RETROACTIVE = new Set(['KEY_COMPROMISE', 'CA_COMPROMISE'])

const frozenRevocation = (
  attachment: { [key: string]: Json }, coreHash: Buffer, trust: TrustBundle | undefined, serials: string[]
): FrozenStatus => {
  const entries = attachment.entries
  const fetchedAt = attachment.fetched_at
  if (attachment.source !== 'googleStatusList' || !Array.isArray(entries) || typeof fetchedAt !== 'number' || !Number.isSafeInteger(fetchedAt) || fetchedAt < 0) return { checked: false }
  const at = Buffer.alloc(8)
  at.writeBigUInt64BE(BigInt(fetchedAt))
  const message = Buffer.concat([coreHash, jcs(entries), at])
  let signature: Buffer
  try { signature = Buffer.from(attachment.sig as string, 'base64url') } catch { return { checked: false } }
  // §6.2: the key is the one that signs that log's tree heads. With no
  // registry attachment naming it, every trusted log key is tried and the
  // signature identifies the one that made it.
  const signed = (trust?.logs ?? []).some((log) => {
    const key = publicKeyFromSpki(Buffer.from(log.spki, 'base64'))
    return key !== null && verifyEs256(message, signature, key)
  })
  if (!signed) return { checked: false }
  const bySerial = new Map<string, { [key: string]: Json }>()
  for (const entry of entries) if (isObject(entry) && typeof entry.serial === 'string') bySerial.set(normalSerial(entry.serial), entry)
  const revoked: { revokedAt: number | null, retroactive: boolean }[] = []
  let incomplete = false
  for (const serial of serials) {
    const entry = bySerial.get(serial)
    if (!entry || entry.status === 'unknown' || (entry.status !== 'valid' && entry.status !== 'revoked')) { incomplete = true; continue }
    if (entry.status === 'revoked') {
      revoked.push({
        revokedAt: typeof entry.revoked_at === 'number' && Number.isSafeInteger(entry.revoked_at) ? entry.revoked_at : null,
        retroactive: typeof entry.reason === 'string' && RETROACTIVE.has(entry.reason)
      })
    }
  }
  return { checked: true, revoked, incomplete }
}

/**
 * §5, *Locating segments*: which signed segments this file really contains.
 *
 * `located: false` means no GOP of this capture could be found — the file is
 * not ISO-BMFF, has no video track, or no GOP carries a vcap SEI naming this
 * `capture_id`. Then nothing is compared and nothing is credited.
 *
 * Once one GOP is located the file claims to be (part of) this capture, and
 * every GOP in it has to be accounted for, in decode order: exactly one vcap
 * SEI naming this capture and a segment the proof signs, indices strictly
 * increasing, each index at most once. Anything else is a GOP no signature
 * covers — inserted, duplicated, moved or relabelled — and the verdict is
 * *tampered*. Before this rule a GOP without an SEI, or with an index nobody
 * signed, was skipped, and a stolen proof read *verified clip* over a file it
 * had never seen.
 */
type Binding =
  | { located: false, reason: string }
  | { located: true, verified: number[], problems: string[] }

const bindSegments = (reading: ContainerReading, captureId: Buffer, entries: SegmentEntry[]): Binding => {
  if (reading.kind === 'unreadable') return { located: false, reason: `no GOP can be located: ${reading.reason}` }
  const ours = (gop: { captureId: Buffer | null }): boolean => gop.captureId !== null && gop.captureId.equals(captureId)
  if (!reading.gops.some(ours)) return { located: false, reason: 'no GOP carries a vcap SEI naming this capture' }

  const signed = new Map(entries.map((entry) => [entry.gop, entry.hash]))
  const problems: string[] = []
  const seen = new Map<number, number>()
  const matched = new Set<number>()
  let previous = -1
  reading.gops.forEach((gop, position) => {
    const where = `GOP ${position} of the file`
    if (gop.problem !== null) { problems.push(`${where}: ${gop.problem}`); return }
    if (gop.index === null) { problems.push(`${where} carries no vcap SEI`); return }
    if (!ours(gop)) { problems.push(`${where} names another capture`); return }
    if (gop.seiCount > 1) problems.push(`${where} carries ${gop.seiCount} vcap SEIs`)
    if (!signed.has(gop.index)) { problems.push(`${where} names segment ${gop.index}, which the proof does not sign`); return }
    if (gop.index <= previous) problems.push(`${where} names segment ${gop.index} after segment ${previous}: indices not strictly increasing`)
    previous = Math.max(previous, gop.index)
    seen.set(gop.index, (seen.get(gop.index) ?? 0) + 1)
    if (gop.contentHash.toString('base64url') === signed.get(gop.index)) matched.add(gop.index)
    else problems.push(`segment ${gop.index}: content recomputed from the container does not match the signed content_hash`)
  })
  for (const [index, count] of seen) if (count > 1) problems.push(`segment ${index} appears ${count} times`)
  // A segment counts once it is located exactly once and its bytes match.
  const verified = [...matched].filter((index) => seen.get(index) === 1).sort((a, b) => a - b)
  return { located: true, verified, problems }
}

/** Message-layer vectors: a chain given as content hashes, no container. */
export interface SegmentsInput {
  capture_id: string
  pub: string
  segment_count: number
  segments: SegmentEntry[]
}

export const verifySegments = (input: SegmentsInput): Verdict => {
  const publicKey = publicKeyFromSpki(Buffer.from(input.pub, 'base64url'))
  if (!publicKey) return fail('tampered', 'pub is not EC P-256')
  const chain = verifyChain(Buffer.from(input.capture_id, 'base64url'), input.segment_count, input.segments, publicKey)
  const outcome: Outcome = chain.status === 'complete' ? 'authentic' : chain.status === 'clip' ? 'verified_clip' : 'tampered'
  return { outcome, labels: [], not_evaluated: [], segments: { verified: chain.verified }, ...(chain.reason ? { reason: chain.reason } : {}) }
}

export const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex')
export { canonicalBytes }
