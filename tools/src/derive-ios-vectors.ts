/**
 * Builds the two iOS vectors from what an iPhone actually produced, during the
 * S1 spike (`vcap-sdk-ios`, 10 September 2026, iPhone 11 Pro, iOS 18.6.2).
 *
 *   npx tsx src/derive-ios-vectors.ts <dir with the spike's device artifacts>
 *
 * Why a script and not two directories dropped into `vectors/`: same reason as
 * `derive-container-vectors.ts`. One of these files carries a signature made by
 * a Secure Enclave, so `npm run generate` cannot produce it and never will —
 * this is the audit trail instead. Point it at the artifacts and it writes the
 * same two vectors again.
 *
 * The two are not the same kind of evidence, and the difference is the point:
 *
 *   47  the device sealed it. Real key, real signature, nothing here re-signs
 *       anything — the file is copied byte for byte.
 *   48  the device muxed it, and only that. The spike inserted vcap SEIs and
 *       never sealed a video, so the proof over this container is synthesized
 *       here with the repository's public test key. What the vector exercises
 *       is §5 recomputation against a file written by `AVAssetWriter`; the
 *       signature layer is covered by 25-31 and by 36-39.
 */
import { createPrivateKey, KeyObject } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { mediaHash } from './canonical.js'
import { coreBytes, keyId, spkiOf, type Proof } from './core.js'
import { containerSegments } from './container.js'
import { jcs, type Json } from './jcs.js'
import { signChain, signEs256 } from './sign.js'
import { TEST_KEY_PKCS8_BASE64 } from './testkey.js'
import { buildTrailer, Flag, parseTrailer } from './trailer.js'
import { verifyFile } from './verify.js'

const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')

const source = process.argv[2]
if (!source) throw new Error("usage: derive-ios-vectors.ts <dir with the spike's device artifacts>")

const DEVICE = 'An iPhone 11 Pro (`iPhone12,3`, iOS 18.6.2) during the S1 spike, 10 September 2026' +
  ' (`vcap-sdk-ios`, `docs/s1-videotoolbox-spike.md`).'

const write = (name: string, input: Buffer, proof: Proof, notes: string): void => {
  const dir = join(VECTORS, name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'proof.json'), JSON.stringify(proof, null, 2) + '\n')
  writeFileSync(join(dir, 'NOTES.md'), `# ${name}\n\n${notes}\n`)
  const verdict = verifyFile({ file: input, recomputeSegments: true })
  console.log(`[vcap] ${name}: ${verdict.outcome} core=${verdict.core_hash?.slice(0, 12)} segments=${JSON.stringify(verdict.segments?.verified)} ${verdict.reason ?? ''}`)
}

// ---- 47: a photo the device sealed itself ----------------------------------
// Copied, not rebuilt. The signature is the Secure Enclave's and nothing in
// this repository holds the key that made it.
{
  const name = '47-heic-sealed-ios'
  const file = readFileSync(join(source, 's1-sealed.heic'))
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error(`the sealed photo has no readable trailer: ${trailer.kind}`)
  const proof = JSON.parse(trailer.payload.toString('utf8')) as Proof
  mkdirSync(join(VECTORS, name), { recursive: true })
  copyFileSync(join(source, 's1-sealed.heic'), join(VECTORS, name, 'input.heic'))
  write(name, file, proof,
    `The corpus's first proof from an iPhone, and its first from any device other than the two Androids: \`platform: "ios"\`, \`secure_hw: "secureEnclave"\`, and a \`sig.value\` made by a Secure Enclave over the canonical core bytes. 1600×1200 HEIC written by ImageIO, sealed on the device in 34.5 ms.

Its worth is that two independent implementations meet on one number here. The device computed the core hash \`18750c77…\` and so does \`tools/src/verify.ts\`, from the same JCS rules applied to the same core — and getting there means the writer's JCS, its DER→P1363 conversion and its low-\`s\` normalization are all right *together*. Any one of them wrong and this vector would not exist.

One note for anyone writing a signer, learned by breaking it: \`SecKeyCreateSignature\` returns **DER of variable length** — 71 bytes on this device, 72 in the simulator — so a conversion that assumes 72 works until it does not.

${DEVICE} The proof is the device's own; nothing here re-signs it.`)
}

// ---- 48: a container Apple muxed -------------------------------------------
{
  const name = '48-mov-container-ios'
  const media = readFileSync(join(source, 's1-sei-hevc-720p.mov'))

  // The spike signed nothing over video, so the chain below is ours. What is
  // the device's is every `content_hash`: each one is recomputed out of this
  // file's NAL units by the same §5 reader a verifier would use.
  const segments = containerSegments(media)
  if (segments.length !== 3) throw new Error(`expected 3 segments, read ${segments.length}`)
  segments.forEach((s, i) => {
    if (!s.located || s.index !== i) throw new Error(`segment at position ${i} reads as index ${s.index} (located: ${s.located})`)
  })

  // The capture id the spike compiled in. Asserted against the SEIs rather
  // than trusted: a proof whose capture_id is not the one in the file would
  // still verify against itself, so nothing downstream would catch the drift.
  const captureId = Buffer.from('112233445566778899aabbccddeeff00', 'hex')
  assertSeiCaptureId(media, captureId, segments.length)

  const privateKey: KeyObject = createPrivateKey({ key: Buffer.from(TEST_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
  const spki = spkiOf(privateKey)
  const core: Proof = {
    v: 'vcap/1.0',
    capture_id: captureId.toString('base64url'),
    media: {
      mime: 'video/quicktime',
      w: 1280,
      h: 720,
      // 90 frames at 30 fps; `mvhd` says 1800 over a timescale of 600.
      duration_ms: 3000,
      hash: mediaHash(media),
      segment_count: segments.length
    },
    device: { platform: 'ios', secure_hw: 'secureEnclave', key_id: keyId(spki) },
    time: { device_clock: 1789037738426 },
    segments: signChain(captureId, segments.map((s) => s.contentHash), privateKey) as unknown as Json
  }
  const proof: Proof = { ...core, sig: { alg: 'ES256', value: signEs256(coreBytes(core), privateKey).toString('base64url'), pub: spki.toString('base64url') } }
  const input = Buffer.concat([media, buildTrailer(jcs(proof as Json), { flags: Flag.SEGMENTS })])
  mkdirSync(join(VECTORS, name), { recursive: true })
  writeFileSync(join(VECTORS, name, 'input.mov'), input)

  write(name, input, proof,
    `The §5 question of vectors 36-39 asked of a container **Apple** wrote. Until this vector every demuxed file in the corpus came out of Android's \`MediaMuxer\`, so a reader could pass all of them and still be reading one muxer's habits rather than ISO-BMFF:

- \`ftyp\` says \`qt  \`, not \`mp42\`. A reader that gates on brand rejects it outright.
- A \`wide\` box sits between \`ftyp\` and \`mdat\` — a QuickTime pad with no ISO meaning. A box walker that knows a fixed set of top-level types stops here.
- Chunk offsets are in \`stco\`, 32-bit. Every container vector before this one carried \`co64\`, so the 32-bit branch of the corpus was **never executed** — the one place a wrong sample offset moves every hash at once.
- Unknown boxes inside the ones that matter: \`tapt\` in \`trak\`, \`sdtp\` in \`stbl\`.
- The movie timescale is 600, QuickTime's, not 90000 or 1000.
- An edit list is present and says nothing: one entry, \`media_time = 0\`. Vector 36 proves a reader must not *ignore* an edit; this one proves it must not read a shift into an identity.
- \`media.mime\` is \`video/quicktime\`, the corpus's first video that is not \`video/mp4\`. §8 decides "this is a video" on the \`video/\` prefix, and a verifier that matched the string \`video/mp4\` would take this file for a photo and stop requiring segments.

HEVC, no audio track, 1280×720, three one-second GOPs, \`hvc1\`. Each vcap SEI carries two emulation-prevention bytes rather than one, because this capture id ends in \`0x00\` and the index that follows it is zero-heavy: the escape straddles the boundary between \`capture_id\` and \`n\`, so un-escaping only the index field is not enough. A reader that does not un-escape at all reads index 196608 for all three GOPs — the same wrong answer three times, which looks like a malformed chain and not like a parse bug. That reader is not hypothetical; it is the first checker written for this file.

**The chain here is synthesized.** The spike inserted SEIs and never sealed a video, so the proof carries the repository's test key, and \`sig\`/\`segments\` prove nothing about iOS. What is the device's is the container and every \`content_hash\` recomputed from it. Vector 47 is the one with a real signature on it.

${DEVICE}`)
}

/**
 * Cross-check: every vcap SEI in the file names `captureId`, and the indexes
 * run 0..count-1. Deliberately a second, dumber reader than `container.ts` —
 * two readers that agree are worth something, one reader agreeing with itself
 * is not.
 */
function assertSeiCaptureId (file: Buffer, captureId: Buffer, count: number): void {
  const uuid = Buffer.from('caa653d1ed1763c7af388aea76527336', 'hex')
  const seen: number[] = []
  for (let at = file.indexOf(uuid); at >= 0; at = file.indexOf(uuid, at + 1)) {
    const payload = unescapeRbsp(file.subarray(at + uuid.length, at + uuid.length + 24))
    if (!payload.subarray(0, 16).equals(captureId)) {
      throw new Error(`SEI at ${at}: capture_id is ${payload.subarray(0, 16).toString('hex')}, not ${captureId.toString('hex')}`)
    }
    seen.push(payload.readUInt32BE(16))
  }
  const expected = [...Array(count).keys()]
  if (seen.length !== count || seen.some((n, i) => n !== expected[i])) {
    throw new Error(`SEI indexes read ${JSON.stringify(seen)}, expected ${JSON.stringify(expected)}`)
  }
}

/** Drops the emulation-prevention byte: 0x03 after two zero bytes. */
function unescapeRbsp (bytes: Buffer): Buffer {
  const out: number[] = []
  let zeros = 0
  for (const b of bytes) {
    if (zeros === 2 && b === 0x03) { zeros = 0; continue }
    out.push(b)
    zeros = b === 0 ? zeros + 1 : 0
  }
  return Buffer.from(out)
}
