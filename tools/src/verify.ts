import { createHash } from 'node:crypto'
import { type Json } from './jcs.js'
import { type Proof, coreBytes, coreHash, keyId, publicKeyFromSpki, verifyEs256 } from './core.js'
import { canonicalBytes, mediaHash } from './canonical.js'
import { Flag, parseTrailer } from './trailer.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type Segment, containerSegments } from './container.js'
import { RANK, validateChain } from './attestation.js'
import { type TrustBundle } from './trust.js'
import { type KeyStatusStatement, type RegistryAttachment, verifyKeyStatus, verifyRegistry } from './registry.js'
import { type AnchorAttachment, type ChainRead, verifyAnchor } from './anchor.js'
import { verifyTimestampToken } from './rfc3161.js'
import { jcs } from './jcs.js'

/**
 * Reference verifier for the signature layer of the format: trailer, canonical
 * bytes, core signature, segment chain, version policy, labels for absent
 * attachments, and — when asked — the §5 content hashes recomputed from an
 * ISO-BMFF container. It does NOT evaluate the proof level (§7: attestation,
 * registry, revocation): that is a separate layer with its own vectors.
 *
 * Its job in this repository is to prove that the committed vectors are
 * consistent with the spec. It is written from the spec; when it disagrees with
 * an expected verdict, one of the two is wrong and the review decides which.
 */
export type Outcome =
  | 'no_proof_found' | 'corrupted_proof' | 'nested_proof' | 'unsupported_format_version'
  | 'tampered' | 'verified_clip' | 'authentic'

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
  reason?: string
}

const ABSENT_LABELS: [string, string][] = [

  ['attestation', 'origin not hardware-attested'],
  ['integrity', 'integrity unevaluated'],
  ['watermark', 'no watermark']
]

const KNOWN_KEYS = new Set([
  'v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy',
  'sig', 'segments', 'attestation', 'attestation_status', 'registry', 'timestamp', 'anchor', 'integrity'
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

// Shape checks a schema will formalize in step 6; here, what the verifier
// needs before it can trust the types it reads.
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
    const parsed: unknown = JSON.parse(payload.toString('utf8'))
    if (!isObject(parsed)) throw new Error('not an object')
    proof = parsed
  } catch {
    return fail('no_proof_found', 'payload is not a JSON object')
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

  // 5. Media (§4.1) and, for video, the chain (§5).
  const mediaObj = proof.media as { hash: string, segment_count?: number }
  const mediaMatches = mediaHash(media) === mediaObj.hash
  for (const [key, label] of ABSENT_LABELS) if (!(key in proof)) labels.push(label)
  // §6.2 `registry`, evaluated here and not inside `level` because a clip
  // returns before the level is computed and still has to say whether the key
  // was in the log — the label is about the key, not about the verdict.
  const registry = registryOutcome(proof, spki, trust, labels, deviceClockOf(proof))
  // §6.2 `anchor`. Its offline half — does the path reach the anchored root —
  // is checkable here; the chain read is an input, and its `block_time` is the
  // only instant in this layer that the device does not assert.
  const anchor = anchorOutcome(proof, Buffer.from(hash, 'hex'), chainRead, labels)
  // §6.2 `timestamp`: the only instant in a file that a device does not
  // assert about itself, and the one a verifier needs no network for.
  const timestamp = timestampOutcome(proof, Buffer.from(hash, 'hex'), trust, labels)
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
  const contradicted = new Set<number>()
  if ('segments' in proof) {
    const entries = proof.segments as unknown as SegmentEntry[]

    // §7: a verifier that did not recompute says so. Skipping the recomputation
    // stays conformant — a sidecar without a demuxable container, a light
    // library — but the two answers differ: on vector 39 the same file reads
    // *verified_clip* without the recomputation and *tampered* with it. An
    // unevaluated check is a weaker verdict, never a silence.
    if (!recomputeSegments) labels.push('segment content not recomputed')

    // §5: the bytes must be the bytes that were signed. A mismatch here is not
    // a clip — a clip is missing segments, this is a present segment whose
    // content was replaced inside a range a signature covers.
    if (recomputeSegments) {
      let recomputed: Segment[]
      try {
        recomputed = containerSegments(media)
      } catch (e) {
        return tampered(`the container could not be read: ${(e as Error).message}`)
      }
      // Only GOPs a vcap SEI identified take part: an unidentified GOP is
      // evidence of nothing, and matching it by position is how a clip gets
      // called forged (§5).
      const byIndex = new Map(
        recomputed
          .filter((segment): segment is Segment & { index: number } => segment.index !== null)
          .map((segment) => [segment.index, segment.contentHash.toString('base64url')])
      )
      for (const entry of entries) {
        const actual = byIndex.get(entry.gop)
        // A segment the file no longer contains is the clip case, not this one:
        // it is absent, not contradicted.
        if (actual !== undefined && actual !== entry.hash) contradicted.add(entry.gop)
      }
    }

    const chain = verifyChain(Buffer.from(proof.capture_id as string, 'base64url'), mediaObj.segment_count as number, entries, publicKey)
    // A contradicted segment is not a verified one, whatever its signature
    // says: the signature covers a hash the file no longer produces.
    segments = { verified: chain.verified.filter((index) => !contradicted.has(index)) }
    if (contradicted.size > 0) {
      const which = [...contradicted].sort((a, b) => a - b).join(', ')
      return { ...tampered(`segment ${which}: content recomputed from the container does not match the signed content_hash`), segments }
    }
    if (chain.status === 'tampered') return { ...tampered(chain.reason ?? 'segment chain'), segments }
    if (!mediaMatches || chain.status === 'clip') {
      return { outcome: 'verified_clip', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash, segments, reason: mediaMatches ? 'segments missing' : 'media.hash does not match the received file' }
    }
  } else if (!mediaMatches) {
    return tampered('media.hash does not match the canonical bytes')
  }

  return {
    outcome: 'authentic', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash,
    ...(segments ? { segments } : {}),
    ...level(proof, spki, Buffer.from(hash, 'hex'), labels, trust, clock, registry, keyStatus, anchor, timestamp)
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
  // The instant (§7). This layer evaluates neither `timestamp` nor `anchor`
  // yet, so the two trusted sources are not reachable here and the instant is
  // the device's claim — which is exactly why the claim caps the verdict.
  // §7's order of trust for the instant: a timestamp token first (not
  // evaluated by this layer yet), then a verified anchor's block, then the
  // device's own clock. The anchor is the first source here that nobody can
  // move, which is why it outranks `device_clock` rather than corroborating it.
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

  // §6.2: the chain's revocation status, frozen while the chain was current.
  const frozen = isObject(proof.attestation_status) ? frozenRevocation(proof.attestation_status, coreHash, trust) : null
  if (chain && proven !== 'none') {
    if (frozen === null || frozen.checked === false) labels.push('chain revocation not checked')
    else if (frozen.revokedAt !== null && frozen.revokedAt <= instant.getTime()) { proven = 'none'; labels.push('attestation key revoked') }
    else if (frozen.revokedAt !== null) labels.push('attestation key revoked after the capture')
  }

  if (chain && proven !== 'none' && (RANK[claimed] ?? 0) > (RANK[proven] ?? 0)) labels.push('inconsistent claim')

  // A leaf's `secure_hw` is the level the log saw proven at registration. §6.2
  // forbids it from exceeding what `attestation` proves, and the honest label
  // is the one the format already has for a claim above its evidence.
  if (registry.ok && (RANK[registry.secureHw] ?? 0) > (RANK[proven] ?? 0) && !labels.includes('inconsistent claim')) {
    labels.push('inconsistent claim')
  }

  // Green needs a proven level *and* the key in the log before the capture.
  // Red is for a chain, or a key, already revoked at the capture.
  // Every amber cause has to be checked, not just the two nearest: §7's table
  // caps the verdict on an unchecked chain revocation and on a capture time
  // only the device vouches for, and a green that ignored either would be a
  // stronger claim than the evidence.
  const amberCauses = ['inconsistent claim', 'chain revocation not checked', 'revocation not checked',
                       'attestation chain expired, capture time not proven', 'registry evidence invalid']
  const green = proven !== 'none' && registry.ok && registry.beforeCapture &&
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
type RegistryVerdict = { ok: false } | { ok: true, secureHw: string, beforeCapture: boolean }

type AnchorVerdict = { ok: false } | { ok: true, blockTime: number | null }

type TimestampVerdict = { ok: false } | { ok: true, genTime: Date }

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
  return { ok: true, genTime: outcome.genTime }
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

/** `time.device_clock`, or null when the proof declares none. */
const deviceClockOf = (proof: Proof): number | null =>
  isObject(proof.time) && typeof proof.time.device_clock === 'number' ? proof.time.device_clock : null

const registryOutcome = (
  proof: Proof, spki: Buffer, trust: TrustBundle | undefined, labels: string[], deviceClock: number | null
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
  // The tree head is when the log signed a tree containing the key. Later than
  // the declared capture means the key was logged after the fact, which is
  // shown and caps the verdict rather than invalidating anything.
  const beforeCapture = deviceClock === null || outcome.treeHeadTimestamp <= deviceClock
  if (!beforeCapture) labels.push('registered after the declared capture')
  return { ok: true, secureHw: outcome.secureHw, beforeCapture }
}

/**
 * The `attestation_status` countersignature (§6.2). `checked: false` means the
 * evidence could not be used — no trusted log key, an unknown source, a
 * signature that does not verify — which is *not checked*, never *revoked*.
 */
const frozenRevocation = (
  attachment: { [key: string]: Json }, coreHash: Buffer, trust: TrustBundle | undefined
): { checked: boolean, revokedAt: number | null } => {
  const entries = attachment.entries
  const fetchedAt = attachment.fetched_at
  if (attachment.source !== 'googleStatusList' || !Array.isArray(entries) || typeof fetchedAt !== 'number') return { checked: false, revokedAt: null }
  const at = Buffer.alloc(8)
  at.writeBigUInt64BE(BigInt(fetchedAt))
  const message = Buffer.concat([coreHash, jcs(entries), at])
  let signature: Buffer
  try { signature = Buffer.from(attachment.sig as string, 'base64url') } catch { return { checked: false, revokedAt: null } }
  // §6.2: the key is the one that signs that log's tree heads. With no
  // registry attachment naming it, every trusted log key is tried and the
  // signature identifies the one that made it.
  const signed = (trust?.logs ?? []).some((log) => {
    const key = publicKeyFromSpki(Buffer.from(log.spki, 'base64'))
    return key !== null && verifyEs256(message, signature, key)
  })
  if (!signed) return { checked: false, revokedAt: null }
  const revoked = (entries as { status?: string }[]).some((e) => e.status !== 'valid')
  return { checked: true, revokedAt: revoked ? fetchedAt : null }
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
