import { createHash } from 'node:crypto'
import { type Json } from './jcs.js'
import { type Proof, coreBytes, coreHash, keyId, publicKeyFromSpki, verifyEs256 } from './core.js'
import { canonicalBytes, mediaHash } from './canonical.js'
import { Flag, parseTrailer } from './trailer.js'
import { type SegmentEntry, verifyChain } from './segments.js'
import { type Segment, containerSegments } from './container.js'

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
  reason?: string
}

const ABSENT_LABELS: [string, string][] = [
  ['timestamp', 'no trusted time'],
  ['anchor', 'not anchored'],
  ['registry', 'key not in transparency log'],
  ['attestation', 'origin not hardware-attested'],
  ['integrity', 'integrity unevaluated'],
  ['watermark', 'no watermark']
]

const KNOWN_KEYS = new Set([
  'v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy',
  'sig', 'segments', 'attestation', 'registry', 'timestamp', 'anchor', 'integrity'
])

const PLATFORMS = new Set(['android', 'ios', 'web'])
const SECURE_HW = new Set(['strongbox', 'tee', 'secureEnclave', 'none'])

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
  if (!isObject(proof.device) || !PLATFORMS.has(proof.device.platform as string) || !SECURE_HW.has(proof.device.secure_hw as string) || typeof proof.device.key_id !== 'string') return 'device incomplete'
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
}

export const verifyFile = ({ file, sidecar, recomputeSegments }: FileInput): Verdict => {
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

  return { outcome: 'authentic', labels: labels.sort(), not_evaluated: notEvaluated, core_hash: hash, ...(segments ? { segments } : {}) }
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
