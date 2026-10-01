/**
 * Builds the two container-level video vectors sealed by real hardware, 36
 * (H.264 with audio) and 37 (HEVC), from the files the device produced.
 *
 * Why a script and not two files dropped into `vectors/`: `npm run generate`
 * cannot make these — it has no camera and no device key — so this is the
 * audit trail instead: point it at the pair of files a device produced and it
 * writes the same two vectors again.
 *
 *   npx tsx src/derive-container-vectors.ts <dir with sealed.mp4, sealed-hevc.mp4>
 *
 * The device signatures stay untouched. Nothing here re-signs anything: these
 * vectors carry a real device's key in `sig.pub`, which is the point — an
 * implementation that only ever meets the repository's own test key never
 * learns whether it reads a real one. Their proofs predate `media.presentation`,
 * so since corpus 5.0.0 they read *no proof found*; the edits of these
 * captures (38, 39, 86-94, 156, 158-163, 166) are made by `npm run generate`
 * under a core re-signed with the test key.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { parseTrailer } from './trailer.js'
import { verifyFile } from './verify.js'

const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')

const source = process.argv[2]
if (!source) throw new Error('usage: derive-container-vectors.ts <dir with the sealed files>')

/** Splits a sealed file into its media bytes and its proof. */
const open = (file: Buffer): { media: Buffer, proof: Record<string, unknown> } => {
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error(`the source file has no readable trailer: ${trailer.kind}`)
  return { media: file.subarray(0, trailer.mediaEnd), proof: JSON.parse(trailer.payload.toString('utf8')) }
}

const write = (name: string, input: Buffer, proof: Record<string, unknown>, notes: string): void => {
  const dir = join(VECTORS, name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'input.mp4'), input)
  writeFileSync(join(dir, 'proof.json'), JSON.stringify(proof, null, 2) + '\n')
  writeFileSync(join(dir, 'NOTES.md'), `# ${name}\n\n${notes}\n`)
  const verdict = verifyFile({ file: input, recomputeSegments: true })
  console.log(`[vcap] ${name}: ${verdict.outcome} segments=${JSON.stringify(verdict.segments?.verified)} ${verdict.reason ?? ''}`)
}

const provenance = 'Sealed by the reference Android SDK on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox),' +
  ' 640×360 at 30 fps with one-second GOPs, recorded by its on-device video pipeline test. The signatures are' +
  ' the device\'s: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts`' +
  ' rebuilds them from the sealed files.'

// ---- 36: the reference container run ---------------------------------------
const h264 = readFileSync(join(source, 'sealed.mp4'))
const { proof: h264Proof } = open(h264)
write('36-mp4-container-verified', h264, h264Proof,
  `A real H.264 recording with an audio track, three segments, every \`content_hash\` recomputed from the container: the NAL units of each GOP with the vcap SEI excluded, then the audio frames of the GOP's time range (§5).

Two things only a real file can carry are in here. The video track has an **empty edit** (\`elst\` with \`media_time = -1\`, 473 ms) because the microphone started before the camera, so the tracks do not both begin at zero: a verifier that ignores the edit list pulls 23 audio frames into segment 0 and gets three wrong hashes. And each GOP carries a vcap SEI, which is excluded from its own hash — an implementation that hashes it produces three wrong hashes too, in a file that looks perfectly well formed.

${provenance}`)

// ---- 37: the HEVC branch ---------------------------------------------------
const hevc = readFileSync(join(source, 'sealed-hevc.mp4'))
const { proof: hevcProof } = open(hevc)
write('37-mp4-container-hevc', hevc, hevcProof,
  `The same rule on HEVC, with no audio track: a two-byte NAL header, SEI NAL types 39 and 40 instead of 6, \`hvcC\` instead of \`avcC\` for the length prefix width, and segments that close at the next IDR with no audio to select.

No edit list here — with no audio track there is nothing for the muxer to delay the video behind, which is why the H.264 vector is the one that catches that mistake.

${provenance}`)
