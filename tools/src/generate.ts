import { createHash, createPrivateKey, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Json, jcs } from './jcs.js'
import { type Proof, coreBytes, coreHash, flipS, keyId, p1363ToDer, signEs256, spkiOf } from './core.js'
import { mediaHash } from './canonical.js'
import { Flag, buildTrailer } from './trailer.js'
import { type SegmentEntry, SEPARATOR, ZERO_LINK, linkOf, segmentMessage, signChain } from './segments.js'
import { TEST_KEY_PKCS8_BASE64 } from './testkey.js'
import { type Verdict, verifyFile, verifySegments } from './verify.js'
import { validateProof } from './schema.js'

/**
 * Writes vectors/. Each vector's expected verdict is decided here, in words,
 * from the spec — then the reference verifier is run and any disagreement
 * aborts the generation: a vector the reference verifier fails is a bug in
 * one of the two, never something to paper over.
 */
const ROOT = join(import.meta.dirname, '..', '..')
const VECTORS = join(ROOT, 'vectors')
const MEDIA = join(VECTORS, '_media')

const privateKey = createPrivateKey({ key: Buffer.from(TEST_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
const spki = spkiOf(privateKey)
const PUB = spki.toString('base64url')
const KEY_ID = keyId(spki)
const CAPTURE_ID = Buffer.from('00112233445566778899aabbccddeeff', 'hex')

const baseJpeg = readFileSync(join(MEDIA, 'base.jpg'))
const baseHeic = readFileSync(join(MEDIA, 'base.heic'))

// ---- proof building -------------------------------------------------------

const photoCore = (media: Buffer, mime: string, extra: Proof = {}): Proof => ({
  v: 'vcap/1.0',
  capture_id: CAPTURE_ID.toString('base64url'),
  media: { mime, w: 16, h: 16, hash: mediaHash(media) },
  device: { platform: 'android', secure_hw: 'tee', key_id: KEY_ID },
  watermark: { algo: 'videoseal', layout: 'photo-bch-v3', payload_bits: 128, ecc: 'bch-255-131', strength: 8 },
  time: { device_clock: 1757332800000 },
  location: { level: 'declared', lat_udeg: 45464664, lon_udeg: 9188540, acc_cm: 1250, evidence: [] },
  policy: { pseudonymous: false },
  ...extra
})

const sign = (proof: Proof, mutate: (sig: Buffer) => Buffer = (s) => s): Proof => ({
  ...proof,
  sig: { alg: 'ES256', value: mutate(signEs256(coreBytes(proof), privateKey)).toString('base64url'), pub: PUB }
})

const seal = (media: Buffer, proof: Proof, o: { payload?: Buffer, flags?: number, crcOverride?: number } = {}): Buffer =>
  Buffer.concat([media, buildTrailer(o.payload ?? jcs(proof as Json), { flags: o.flags ?? flagsFor(proof), crcOverride: o.crcOverride })])

const flagsFor = (proof: Proof): number =>
  ('segments' in proof ? Flag.SEGMENTS : 0) | ((proof.policy as Proof | undefined)?.pseudonymous === true ? Flag.PSEUDONYMOUS : 0)

// A JPEG APP11 segment. JUMBF ones start with "JP"; C2PA writes those.
const app11 = (payload: Buffer): Buffer => {
  const length = Buffer.alloc(2)
  length.writeUInt16BE(payload.length + 2, 0)
  return Buffer.concat([Buffer.from([0xff, 0xeb]), length, payload])
}
const jumbf = app11(Buffer.concat([Buffer.from('JP', 'ascii'), Buffer.from([0, 1, 0, 0, 0, 1]), Buffer.from('000000186a756d620000001063327061', 'hex')]))
const notJumbf = app11(Buffer.concat([Buffer.from('XX', 'ascii'), randomBytes(12)]))

// Inserts a segment right after SOI + APP0 (the first marker segment).
const insertAfterApp0 = (jpeg: Buffer, segment: Buffer): Buffer => {
  const app0Len = jpeg.readUInt16BE(4)
  const cut = 2 + 2 + app0Len
  return Buffer.concat([jpeg.subarray(0, cut), segment, jpeg.subarray(cut)])
}

// Flips one byte deep in the entropy-coded data.
const editPixels = (jpeg: Buffer): Buffer => {
  const out = Buffer.from(jpeg)
  const at = out.length - 40
  out[at] = (out[at] as number) ^ 0x55
  return out
}

const bmffBox = (type: string, payload: Buffer): Buffer => {
  const header = Buffer.alloc(8)
  header.writeUInt32BE(8 + payload.length, 0)
  header.write(type, 4, 'ascii')
  return Buffer.concat([header, payload])
}

// ---- vectors --------------------------------------------------------------

interface FileVector { kind: 'file', name: string, ext: string, file: Buffer, sidecar?: Buffer, proof?: Proof, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, schemaValid?: boolean, notes: string }
interface SegVector { kind: 'segments', name: string, input: { capture_id: string, pub: string, segment_count: number, segments: SegmentEntry[] }, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, notes: string, debug?: Json }
interface JcsVector { kind: 'jcs', name: string, input: Json, expected: { core_bytes_hex: string, core_hash: string }, notes: string }
type Vector = FileVector | SegVector | JcsVector

const PHOTO_LABELS = ['integrity unevaluated', 'key not in transparency log', 'no trusted time', 'not anchored', 'origin not hardware-attested']

const jpegProof = sign(photoCore(baseJpeg, 'image/jpeg'))
const jpegSealed = seal(baseJpeg, jpegProof)
const hashOf = (p: Proof): string => coreHash(p).toString('hex')

const vectors: Vector[] = []
const sortedLabels = <T extends { labels?: string[] }>(e: T): T => e.labels ? { ...e, labels: [...e.labels].sort() } : e
const file = (v: Omit<FileVector, 'kind'>): void => { vectors.push({ kind: 'file', ...v, expected: sortedLabels(v.expected) }) }
const seg = (v: Omit<SegVector, 'kind'>): void => { vectors.push({ kind: 'segments', ...v }) }

file({ name: '01-jpeg-sealed', ext: 'jpg', file: jpegSealed, proof: jpegProof,
  expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'A JPEG sealed with a complete core and no attachments. Every absent attachment produces its §8 label; none is an error. The proof level is not evaluated by this layer.' })

file({ name: '02-jpeg-c2pa-added-after-sealing', ext: 'jpg', file: insertAfterApp0(jpegSealed, jumbf), proof: jpegProof,
  expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'Vector 01 with a C2PA-style APP11 segment (payload starting "JP") inserted after sealing. §4.1 excludes such segments from the canonical bytes, so media.hash still matches.' })

{
  const withNotJumbf = insertAfterApp0(baseJpeg, notJumbf)
  const proof = sign(photoCore(withNotJumbf, 'image/jpeg'))
  file({ name: '03-jpeg-app11-non-jumbf-present-at-sealing', ext: 'jpg', file: seal(withNotJumbf, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'An APP11 segment whose payload does not start with "JP", present when the file was sealed. It is part of the canonical bytes and the hash covers it.' })
}

file({ name: '04-jpeg-app11-non-jumbf-added-after-sealing', ext: 'jpg', file: insertAfterApp0(jpegSealed, notJumbf), proof: jpegProof,
  expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'Vector 01 with a non-JUMBF APP11 inserted after sealing. Only JUMBF APP11 is excluded; this one changes the canonical bytes, so media.hash no longer matches: tampered.' })

file({ name: '05-jpeg-no-trailer', ext: 'jpg', file: baseJpeg,
  expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
  notes: 'The unsealed base image. No footer: no proof found, not an error.' })

file({ name: '06-jpeg-footer-crc-mismatch', ext: 'jpg', file: seal(baseJpeg, jpegProof, { crcOverride: 0xdeadbeef }), proof: jpegProof,
  expected: { outcome: 'corrupted_proof', labels: [], not_evaluated: [] },
  notes: 'Structurally valid footer and box, CRC-32 does not match the payload. Corrupted proof, distinct from no proof found.' })

{
  const fake = Buffer.alloc(16)
  Buffer.from('VCAP').copy(fake, 0); fake[4] = 1; fake.writeUInt32BE(40, 8); fake.writeUInt32BE(0x12345678, 12)
  file({ name: '07-jpeg-fake-magic-without-structure', ext: 'jpg', file: Buffer.concat([baseJpeg, fake]),
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    notes: 'Sixteen bytes that start with "VCAP" and a plausible payload_len, but no box header where the footer says it is. Structure fails before the CRC is looked at: no proof found, not corrupted. An unsealed file cannot be made to look edited.' })
}

{
  const sealed = seal(baseJpeg, jpegProof)
  const truncated = Buffer.from(sealed)
  truncated.writeUInt32BE(1_000_000, truncated.length - 8)
  file({ name: '08-jpeg-truncated-payload', ext: 'jpg', file: truncated,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    notes: 'payload_len points beyond the start of the file. The footer structure is invalid: no proof found.' })
}

{
  const inner = jpegSealed
  const outerProof = sign(photoCore(inner, 'image/jpeg', { device: { platform: 'web', secure_hw: 'none', key_id: KEY_ID } }))
  file({ name: '09-jpeg-double-sealed', ext: 'jpg', file: seal(inner, outerProof), proof: outerProof,
    expected: { outcome: 'nested_proof', labels: [], not_evaluated: [] },
    notes: 'A sealed file sealed again with a weaker (web, none) proof. The outer trailer is valid and its media.hash covers the inner trailer; §3 requires the verifier to report the nesting and not to present the outer proof as authoritative.' })
}

{
  const edited: Proof = { ...jpegProof, location: { ...(jpegProof.location as Proof), lon_udeg: 12492373 } }
  file({ name: '10-jpeg-core-edited', ext: 'jpg', file: seal(baseJpeg, edited), proof: edited,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(edited) },
    notes: 'Vector 01 with location.lon_udeg changed from Milan to Rome, payload re-canonicalized and CRC recomputed. The core signature fails: tampered. This is the attack the core/attachment split exists for.' })
}

file({ name: '11-jpeg-pixels-edited', ext: 'jpg', file: seal(editPixels(baseJpeg), jpegProof), proof: jpegProof,
  expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'One byte of entropy-coded data flipped, proof untouched. The signature is valid but media.hash does not match the canonical bytes: on a photo this is tampered. A red verdict carries its reason only, no absence labels (§8).' })

{
  const proof = sign(photoCore(baseJpeg, 'image/jpeg'), flipS)
  file({ name: '12-jpeg-sig-high-s', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'The signature s value is in the high half of the group order. Writers MUST emit low s; verifiers MUST accept both (§4.2). A verifier that rejects this fails conformance.' })
}

{
  const proof = sign(photoCore(baseJpeg, 'image/jpeg'), p1363ToDer)
  file({ name: '13-jpeg-sig-der', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(proof) },
    schemaValid: false,
    notes: 'A DER-encoded ECDSA signature instead of P1363. Not 64 bytes: the signature is malformed, and a present-but-invalid signature is tampered (§8). A verifier that transparently accepts DER fails conformance.' })
}

{
  const proof = sign(photoCore(baseJpeg, 'image/jpeg', { device: { platform: 'android', secure_hw: 'tee', key_id: keyId(randomBytes(91)) } }))
  file({ name: '14-jpeg-key-id-mismatch', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'The signature is valid but device.key_id is not SHA-256 of sig.pub. key_id is derived, never free (§6.1): tampered.' })
}

{
  const proof = sign(photoCore(baseJpeg, 'image/jpeg', { v: 'vcap/1.7' }))
  const withFuture: Proof = { ...proof, future_field: { anything: 1 } }
  file({ name: '15-jpeg-unknown-minor', ext: 'jpg', file: seal(baseJpeg, withFuture), proof: withFuture,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: ['future_field'], core_hash: hashOf(proof) },
    notes: 'v is vcap/1.7 and there is an unknown top-level key. Same major: verify what you know, list the unknown key as not evaluated, never fail (§9). The unknown key is outside the core, so the signature is unaffected.' })
}

{
  const proof = sign(photoCore(baseJpeg, 'image/jpeg', { v: 'vcap/2.0' }))
  file({ name: '16-jpeg-unknown-major', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'unsupported_format_version', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'v is vcap/2.0. Unsupported format version, with the version shown (§9).' })
}

file({ name: '17-jpeg-sidecar-only', ext: 'jpg', file: baseJpeg, sidecar: jcs(jpegProof as Json), proof: jpegProof,
  expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'The unsealed file with the proof in a sidecar (input.jpg.vcap). The sidecar has no footer; the canonical bytes are the whole file.' })

{
  const other = sign(photoCore(baseJpeg, 'image/jpeg', { time: { device_clock: 1757332800001 } }))
  file({ name: '18-jpeg-sidecar-differs', ext: 'jpg', file: jpegSealed, sidecar: jcs(other as Json), proof: jpegProof,
    expected: { outcome: 'authentic', labels: [...PHOTO_LABELS, 'sidecar differs'], not_evaluated: [], core_hash: hashOf(jpegProof) },
    notes: 'Trailer and sidecar both present and different. The trailer is authoritative; the sidecar is reported and not used (§3).' })
}

file({ name: '19-jpeg-flags-disagree', ext: 'jpg', file: seal(baseJpeg, jpegProof, { flags: Flag.PSEUDONYMOUS }), proof: jpegProof,
  expected: { outcome: 'authentic', labels: [...PHOTO_LABELS, 'flags disagree'], not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'Footer flags claim a pseudonymous capture; the JSON says false. Flags are a hint, the JSON wins, a verifier may warn (§3).' })

file({ name: '20-jpeg-payload-not-canonical', ext: 'jpg', file: seal(baseJpeg, jpegProof, { payload: Buffer.from(JSON.stringify(jpegProof, null, 2)) }), proof: jpegProof,
  expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(jpegProof) },
  notes: 'The trailer payload is pretty-printed, keys in writer order, not JCS. The verifier recomputes JCS(core) from the parsed JSON (§4.2): the bytes in the trailer are not authoritative. Writers MUST still emit canonical JSON; this vector tests the reader.' })

{
  const { capture_id: _dropped, ...rest } = jpegProof
  file({ name: '21-jpeg-missing-capture-id', ext: 'jpg', file: seal(baseJpeg, rest), proof: rest,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'A required core field is missing. §8: missing or unparseable is no proof found, not tampered — there is nothing to verify.' })
}

{
  const proof = sign(photoCore(baseJpeg, 'image/jpeg', { location: { level: 'declared', lat_udeg: 45464664, lon_udeg: 9188540, acc_cm: 12.5, evidence: [] } }))
  file({ name: '22-jpeg-float-in-core', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'acc_cm is 12.5. The core contains no floating-point numbers (§6.1): JCS number serialization is not portable, so a proof with a float in the core is not a vcap/1.0 proof.' })
}

{
  const proof = sign(photoCore(baseHeic, 'image/heic'))
  file({ name: '23-heic-sealed', ext: 'heic', file: seal(baseHeic, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'An ISO-BMFF still image. Canonical bytes are the file minus the trailer, nothing removed (§4.1).' })
}

{
  const withFree = Buffer.concat([baseHeic, bmffBox('free', Buffer.from('unrelated padding box'))])
  const proof = sign(photoCore(withFree, 'image/heic'))
  file({ name: '24-heic-existing-free-box', ext: 'heic', file: seal(withFree, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'The media already ends with an unrelated free box. Only the vcap trailer (identified by its footer) is stripped; the other free box is content.' })
}

// ---- segment chain, message layer ------------------------------------------

const contentHashes = [0, 1, 2].map((i) => createHash('sha256').update(`segment content ${i}`).digest())
const chain = signChain(CAPTURE_ID, contentHashes, privateKey)
const segInput = (segments: SegmentEntry[], count = 3) => ({ capture_id: CAPTURE_ID.toString('base64url'), pub: PUB, segment_count: count, segments })
const messages = contentHashes.map((h, i) => segmentMessage(CAPTURE_ID, i, h, i === 0 ? ZERO_LINK : linkOf(segmentMessage(CAPTURE_ID, i - 1, contentHashes[i - 1] as Buffer, i === 1 ? ZERO_LINK : linkOf(segmentMessage(CAPTURE_ID, 0, contentHashes[0] as Buffer, ZERO_LINK))))))
const debug: Json = { separator_hex: SEPARATOR.toString('hex'), messages_hex: messages.map((m) => m.toString('hex')), prev_links_hex: chain.map((s) => Buffer.from(s.prev, 'base64url').toString('hex')) }

seg({ name: '25-seg-chain-complete', input: segInput(chain), debug,
  expected: { outcome: 'authentic', labels: [], not_evaluated: [], segments: { verified: [0, 1, 2] } },
  notes: 'Three segments, all present, chain unbroken from index 0, count matches. debug.messages_hex gives the 96-byte messages so an implementation can compare byte for byte before touching signatures.' })

{
  const reordered = [chain[0], { ...(chain[2] as SegmentEntry), gop: 1 }, { ...(chain[1] as SegmentEntry), gop: 2 }] as SegmentEntry[]
  seg({ name: '26-seg-chain-reordered', input: segInput(reordered),
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], segments: { verified: [0] } },
    notes: 'Segments 1 and 2 swapped (content, prev and sig of one presented under the index of the other). The stored prev_link of the segment now at index 1 is not SHA-256(message(0)): chain broken where contiguity is claimed.' })
}

seg({ name: '27-seg-chain-clip-from-middle', input: segInput([chain[1], chain[2]] as SegmentEntry[]),
  expected: { outcome: 'verified_clip', labels: [], not_evaluated: [], segments: { verified: [1, 2] } },
  notes: 'Segments 1 and 2 of 3, index 0 absent. Segment 1 verifies over its stored prev_link (its predecessor is absent, nothing to compare against); segment 2 verifies against SHA-256(message(1)). A clip, verifiably from the middle of an original.' })

seg({ name: '28-seg-chain-gap', input: segInput([chain[0], chain[2]] as SegmentEntry[]),
  expected: { outcome: 'verified_clip', labels: [], not_evaluated: [], segments: { verified: [0, 2] } },
  notes: 'Segments 0 and 2 of 3. Both verify; segment 2 over its stored prev_link because 1 is absent. Not complete: verified clip, reporting which indexes verified.' })

{
  const flipped = chain.map((s, i) => i === 0 ? { ...s, sig: flipS(Buffer.from(s.sig, 'base64url')).toString('base64url') } : s)
  seg({ name: '29-seg-chain-sig-high-s', input: segInput(flipped),
    expected: { outcome: 'authentic', labels: [], not_evaluated: [], segments: { verified: [0, 1, 2] } },
    notes: 'sig(0) replaced by its malleated twin (r, n − s). It is still a valid signature for message(0), and the chain hashes messages, not signatures (§5), so nothing breaks. Under the earlier draft (prev_link = SHA-256(sig)) this genuine original would have read as tampered.' })
}

{
  const wrongSeparator = Buffer.from('vcap/1.1/seg', 'ascii')
  const entries: SegmentEntry[] = []
  let prev: Buffer = ZERO_LINK
  contentHashes.forEach((h, i) => {
    const m = segmentMessage(CAPTURE_ID, i, h, prev, wrongSeparator)
    entries.push({ gop: i, hash: h.toString('base64url'), prev: prev.toString('base64url'), sig: signEs256(m, privateKey).toString('base64url') })
    prev = linkOf(m)
  })
  seg({ name: '30-seg-chain-wrong-separator', input: segInput(entries),
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], segments: { verified: [] } },
    notes: 'Messages built with the separator "vcap/1.1/seg". A v1.0 verifier rebuilds messages with "vcap/1.0/seg": every signature fails. Domain separation working as intended.' })
}

{
  const forged = chain.map((s, i) => i === 2 ? { ...s, prev: randomBytes(32).toString('base64url') } : s)
  seg({ name: '31-seg-chain-prev-link-forged', input: segInput(forged),
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], segments: { verified: [0, 1] } },
    notes: 'Segment 2 carries a prev_link that is not SHA-256(message(1)) while segment 1 is present. Contiguity is claimed and broken: tampered, even though sig(2) itself might have been valid over the forged message.' })
}

// ---- video proofs at file level (§8: media.mime decides) ---------------------

const baseMp4 = readFileSync(join(MEDIA, 'base.mp4'))
const videoCore = (media: Buffer, extra: Proof = {}): Proof => photoCore(media, 'video/mp4', {
  media: { mime: 'video/mp4', w: 16, h: 16, duration_ms: 67, hash: mediaHash(media), segment_count: 3 },
  watermark: { algo: 'videoseal', layout: 'video-rep-v1', payload_bits: 128, ecc: 'bch-255-131', strength: 8 },
  ...extra
})

{
  const proof = sign(videoCore(baseMp4, { segments: chain as unknown as Json }))
  file({ name: '33-mp4-video-sealed', ext: 'mp4', file: seal(baseMp4, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof), segments: { verified: [0, 1, 2] } },
    notes: 'An ISO-BMFF video with media.mime video/mp4, segment_count 3 and the complete chain of vector 25 in the trailer (flag SEGMENTS set). Canonical bytes are the file minus the trailer (§4.1); the chain is verified at message level — content hashes are given, the container is not demuxed by this layer.' })
}

{
  const proof = sign(videoCore(baseMp4))
  file({ name: '34-mp4-video-without-segments', ext: 'mp4', file: seal(baseMp4, proof), proof,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'Same video, valid signature, segment_count present, no segments. §8: media.mime starting with video/ makes this a video proof, and segments is required for one — missing required field, no proof found. A verifier that branches on the presence of segments alone would say authentic here.' })
}

// ---- JCS -----------------------------------------------------------------

{
  // Deliberately unsorted, nested, with negative and zero integers.
  const messy: Json = {
    policy: { pseudonymous: false },
    v: 'vcap/1.0',
    location: { lon_udeg: -122419416, acc_cm: 0, lat_udeg: 37774929, level: 'declared', evidence: [] },
    media: { w: 16, hash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', h: 16, mime: 'image/jpeg' },
    device: { secure_hw: 'strongbox', platform: 'android', key_id: KEY_ID },
    capture_id: CAPTURE_ID.toString('base64url'),
    time: { device_clock: 1757332800000 },
    watermark: { strength: 8, payload_bits: 128, layout: 'photo-bch-v3', ecc: 'bch-255-131', algo: 'videoseal' },
    sig: { alg: 'ES256', value: 'not-part-of-the-core', pub: PUB },
    registry: { log_id: 'not-part-of-the-core' }
  }
  const bytes = coreBytes(messy as Proof)
  vectors.push({ kind: 'jcs', name: '32-jcs-core-canonicalization', input: messy,
    expected: { core_bytes_hex: bytes.toString('hex'), core_hash: createHash('sha256').update(bytes).digest('hex') },
    notes: 'A proof with keys in writer order, a negative integer and a zero. The core is the eight §6.1 keys only (sig and registry are excluded), serialized per RFC 8785: keys sorted by UTF-16 code units at every level, no whitespace, integers as plain decimals.' })
}

// ---- write and self-check ---------------------------------------------------

const pick = (v: Verdict, expected: object): object => Object.fromEntries(Object.keys(expected).map((k) => [k, (v as unknown as Record<string, unknown>)[k]]))

// Regenerating replaces every numbered vector; _media and README stay.
if (existsSync(VECTORS)) for (const entry of readdirSync(VECTORS)) if (/^\d\d-/.test(entry)) rmSync(join(VECTORS, entry), { recursive: true })

let failures = 0
for (const vector of vectors) {
  const dir = join(VECTORS, vector.name)
  mkdirSync(dir, { recursive: true })
  let actual: object | null = null

  if (vector.kind === 'file') {
    writeFileSync(join(dir, `input.${vector.ext}`), vector.file)
    if (vector.sidecar) writeFileSync(join(dir, `input.${vector.ext}.vcap`), vector.sidecar)
    if (vector.proof) writeFileSync(join(dir, 'proof.json'), JSON.stringify(vector.proof, null, 2) + '\n')
    const schemaValid = vector.schemaValid ?? true
    writeFileSync(join(dir, 'expected.json'), JSON.stringify({ kind: 'file', ...vector.expected, ...(vector.proof ? { schema_valid: schemaValid } : {}) }, null, 2) + '\n')
    actual = pick(verifyFile({ file: vector.file, sidecar: vector.sidecar }), vector.expected)
    // The schema must agree with the review too: a proof the review calls
    // conforming that the schema refuses is a bug in one of the two.
    if (vector.proof) {
      const schema = validateProof(vector.proof)
      if (schema.valid !== schemaValid) {
        failures++
        console.error(`[vcap] ${vector.name}: schema says ${schema.valid ? 'valid' : 'invalid'}, review says ${schemaValid ? 'valid' : 'invalid'} ${schema.errors.join('; ')}`)
      }
    }
  } else if (vector.kind === 'segments') {
    writeFileSync(join(dir, 'segments.json'), JSON.stringify(vector.input, null, 2) + '\n')
    writeFileSync(join(dir, 'expected.json'), JSON.stringify({ kind: 'segments', ...vector.expected, ...(vector.debug ? { debug: vector.debug } : {}) }, null, 2) + '\n')
    actual = pick(verifySegments(vector.input), vector.expected)
  } else {
    writeFileSync(join(dir, 'core.json'), JSON.stringify(vector.input, null, 2) + '\n')
    writeFileSync(join(dir, 'expected.json'), JSON.stringify({ kind: 'jcs', ...vector.expected }, null, 2) + '\n')
  }
  writeFileSync(join(dir, 'NOTES.md'), `# ${vector.name}\n\n${vector.notes}\n\nGenerated by \`tools/src/generate.ts\` with the test key in \`tools/src/testkey.ts\`.\n`)

  if (actual && JSON.stringify(actual) !== JSON.stringify(vector.expected)) {
    failures++
    console.error(`[vcap] ${vector.name}: expected ${JSON.stringify(vector.expected)} got ${JSON.stringify(actual)}`)
  }
}

console.log(`[vcap] ${vectors.length} vectors written${failures ? `, ${failures} DISAGREE with the reference verifier` : ''}`)
if (failures) process.exit(1)
