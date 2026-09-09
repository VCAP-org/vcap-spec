/**
 * Builds the container-level video vectors from two files sealed by real
 * hardware, and derives the two negative cases from the first of them.
 *
 * Why a script and not four files dropped into `vectors/`: the clip and the
 * replaced-frame cases are *edits* of a real capture, and an edit nobody can
 * reproduce is an assertion. `npm run generate` cannot make these — it has no
 * camera and no device key — so this is the audit trail instead: point it at
 * the pair of files a device produced and it writes the same four vectors
 * again.
 *
 *   npx tsx src/derive-container-vectors.ts <dir with sealed.mp4, sealed-hevc.mp4>
 *
 * The device signatures stay untouched. Nothing here re-signs anything: these
 * vectors carry a real device's key in `sig.pub`, which is the point — an
 * implementation that only ever meets the repository's own test key never
 * learns whether it reads a real one.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { buildTrailer, Flag, parseTrailer } from './trailer.js'
import { verifyFile } from './verify.js'
import { containerSegments } from './container.js'

const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')

const source = process.argv[2]
if (!source) throw new Error('usage: derive-container-vectors.ts <dir with the sealed files>')

/** Splits a sealed file into its media bytes and its proof. */
const open = (file: Buffer): { media: Buffer, proof: Record<string, unknown> } => {
  const trailer = parseTrailer(file)
  if (trailer.kind !== 'ok') throw new Error(`the source file has no readable trailer: ${trailer.kind}`)
  return { media: file.subarray(0, trailer.mediaEnd), proof: JSON.parse(trailer.payload.toString('utf8')) }
}

/** Re-seals media with a proof, keeping the §3 flags the proof implies. */
const seal = (media: Buffer, proof: Record<string, unknown>): Buffer => {
  const payload = Buffer.from(JSON.stringify(proof), 'utf8')
  const policy = proof.policy as { pseudonymous?: boolean } | undefined
  const flags = ('segments' in proof ? Flag.SEGMENTS : 0) | (policy?.pseudonymous ? Flag.PSEUDONYMOUS : 0)
  return Buffer.concat([media, buildTrailer(payload, { flags })])
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

const provenance = 'Sealed by `SDK-Android` on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox),' +
  ' 640×360 at 30 fps with one-second GOPs, recorded by `VideoPipelineOnDeviceTest`. The signatures are' +
  ' the device\'s: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts`' +
  ' rebuilds them from the sealed files.'

// ---- 36: the reference container run ---------------------------------------
const h264 = readFileSync(join(source, 'sealed.mp4'))
const { media: h264Media, proof: h264Proof } = open(h264)
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

// ---- 38: a clip, at container level ----------------------------------------
const clipProof = { ...h264Proof, segments: (h264Proof.segments as unknown[]).slice(1) }
write('38-mp4-container-clip', seal(h264Media, clipProof), clipProof,
  `The file of vector 36 with the entry for segment 0 removed from the proof, so \`media.segment_count\` is 3 and two segments are present: **verified clip** (§5), reporting 1 and 2.

The trap is index mapping. The file still contains all three GOPs, and its first GOP is segment 0 — the one with no entry. A verifier that matched GOPs to entries by position would check GOP 0's bytes against segment 1's signature, fail, and call a clip tampered. The vcap SEI is what says which GOP is which, and §5 allows exactly that use and no more: it locates, it does not prove.

${provenance}`)

// ---- 39: one replaced frame ------------------------------------------------
const recomputed = containerSegments(h264Media)
const target = recomputed[1]
if (!target) throw new Error('the source file has fewer than two segments')
const edited = Buffer.from(h264)
// The last byte of the segment's video range: inside a signed range, far from
// any header, so nothing but the content hash and media.hash can notice.
const at = target.range.end - 1
edited[at] = (edited[at] as number) ^ 0x01
write('39-mp4-container-frame-replaced', edited, h264Proof,
  `Vector 36 with a single bit flipped inside segment 1's video samples: byte ${at} of the file, the last byte of that GOP's range.

Every signature still verifies, because a signature covers the hash a writer declared and not the bytes a reader received. \`media.hash\` fails, and segment 1's \`content_hash\` recomputed from the container fails; segments 0 and 2 still match. The verdict is **tampered**, and it names the segments that survived — a clip is missing segments, this is a present segment whose content was replaced inside a range a signature covers.

Without this vector the corpus cannot tell a verifier that recomputes from one that does not: every other container vector passes for both.

${provenance}`)
