import { createHash, createPrivateKey, generateKeyPairSync } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Json, jcs } from './jcs.js'
import { type Proof, coreBytes, coreHash, flipS, keyId, p1363ToDer, spkiOf } from './core.js'
import { mediaHash } from './canonical.js'
import { Flag, buildTrailer } from './trailer.js'
import { type SegmentEntry, SEPARATOR, ZERO_LINK, linkOf, segmentMessage } from './segments.js'
// Deterministic ES256 (RFC 6979): regenerating an unchanged vector must not
// change its bytes. See sign.ts.
import { signChain, signEs256 } from './sign.js'
import { TEST_KEY_PKCS8_BASE64 } from './testkey.js'
import { TEST_LOG_KEY_PKCS8_BASE64 } from './testlogkey.js'
import { type KeyStatusStatement, keyStatusMessage, leafHash, leafKeyId, nodeHash, treeHeadMessage } from './registry.js'
import { type ChainRead } from './anchor.js'
import { loadTrust } from './trust.js'
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
// The anchors a verifier is assumed to hold while checking this corpus.
const trust = loadTrust(join(VECTORS, '_trust'))

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
// Fixed bytes, not random ones: the payload's content is irrelevant to what
// the vector tests (an APP11 that is not JUMBF), while randomness made the
// sealed file — and therefore its media.hash and core_hash — change on every
// regeneration.
const notJumbf = app11(Buffer.concat([Buffer.from('XX', 'ascii'), Buffer.alloc(12, 0x5a)]))

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

interface FileVector { kind: 'file', name: string, ext: string, file: Buffer, sidecar?: Buffer, proof?: Proof, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, schemaValid?: boolean, notes: string, verifierClock?: number, keyStatus?: Json, chainRead?: Json }
interface SegVector { kind: 'segments', name: string, input: { capture_id: string, pub: string, segment_count: number, segments: SegmentEntry[] }, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, notes: string, debug?: Json }
interface JcsVector { kind: 'jcs', name: string, input: Json, expected: { core_bytes_hex: string, core_hash: string }, notes: string }
type Vector = FileVector | SegVector | JcsVector

// Every sealed vector declares `watermark`, and no verifier here has a
// detector: *watermark not evaluated* belongs on all of them (§7).
const PHOTO_LABELS = ['integrity unevaluated', 'key not in transparency log', 'no trusted time', 'not anchored', 'origin not hardware-attested', 'watermark not evaluated']

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
  const proof = sign(photoCore(baseJpeg, 'image/jpeg', { device: { platform: 'android', secure_hw: 'tee', key_id: keyId(Buffer.alloc(91, 0x11)) } }))
  file({ name: '14-jpeg-key-id-mismatch', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'The signature is valid but device.key_id is not SHA-256 of sig.pub. key_id is derived, never free (§6.1): tampered.' })
}

{
  // A value no v1.0 verifier knows, in a field §9 declares NOT extensible.
  // Non-extensible means a writer may not invent one without a version bump —
  // it does not mean a reader may refuse the file. §7 is explicit: treat it as
  // `none`. The verdict is therefore the ordinary photo verdict, and the claim
  // simply proves nothing, which is what an unverified claim is worth anyway.
  const proof = sign(photoCore(baseJpeg, 'image/jpeg', {
    device: { platform: 'android', secure_hw: 'titanM', key_id: KEY_ID }
  }))
  file({ name: '40-jpeg-unknown-secure-hw', ext: 'jpg', file: seal(baseJpeg, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
    schemaValid: false,
    notes: 'device.secure_hw is `titanM`, a value v1.0 does not define. A verifier MUST treat it as `none` and MUST NOT refuse the proof (§7, §9): the signature over the core is valid and the capture is readable. The JSON Schema describes v1.0, so it rejects the document — schema_valid is false while the verdict is authentic, and the two disagreeing is the point: the schema says "not a v1.0 document", the verifier says "still verifiable".' })
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
  // A fixed wrong link: what matters is that it is not the real one.
  const forged = chain.map((s, i) => i === 2 ? { ...s, prev: Buffer.alloc(32, 0x7f).toString('base64url') } : s)
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
    expected: { outcome: 'authentic', labels: [...PHOTO_LABELS, 'segment content not recomputed'], not_evaluated: [], core_hash: hashOf(proof), segments: { verified: [0, 1, 2] } },
    notes: 'An ISO-BMFF video with media.mime video/mp4, segment_count 3 and the complete chain of vector 25 in the trailer (flag SEGMENTS set). Canonical bytes are the file minus the trailer (§4.1); the chain is verified at message level — content hashes are given, the container is not demuxed by this layer, and the verdict says so with *segment content not recomputed* (§7). Vectors 36-39 are the same question asked of the container.' })
}

{
  const proof = sign(videoCore(baseMp4))
  file({ name: '34-mp4-video-without-segments', ext: 'mp4', file: seal(baseMp4, proof), proof,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'Same video, valid signature, segment_count present, no segments. §8: media.mime starting with video/ makes this a video proof, and segments is required for one — missing required field, no proof found. A verifier that branches on the presence of segments alone would say authentic here.' })
}

// ---- media.w/h are required (§8) ---------------------------------------------

{
  const { w: _w, h: _h, ...media } = jpegProof.media as Record<string, Json>
  const stripped = { ...jpegProof, media } as unknown as Proof
  file({ name: '46-jpeg-missing-media-dimensions', ext: 'jpg', file: seal(baseJpeg, stripped), proof: stripped,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'Vector 01 with media.w and media.h removed after signing. §8 requires them: every writer holds the dimensions at capture, and a reader that cannot say how large the frame is cannot place a watermark payload or a segment in it. Missing is malformed — no proof found, not tampered — the same shape as an absent capture_id (vector 21), and like that vector the signature is never examined: the shape check of §8 fires first, so a verifier that reported *tampered* here would be reporting a check it had not run.' })
}

// ---- JPEG fill bytes (§4.1: kept, not judged) ---------------------------------

{
  // One 0xFF fill byte before the marker that follows APP0. Legal JPEG; a walker
  // that reads it as a marker misparses the file.
  const withFill = insertAfterApp0(baseJpeg, Buffer.from([0xff]))
  const proof = sign(photoCore(withFill, 'image/jpeg'))
  file({ name: '35-jpeg-fill-bytes', ext: 'jpg', file: seal(withFill, proof), proof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
    notes: 'A 0xFF fill byte precedes a marker in the header. §4.1 keeps fill bytes and length-less markers where they are: the canonical bytes are the file minus the trailer, and media.hash matches. A walker that treats the fill byte as a marker misparses the file and fails this vector.' })
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

// ---- §7 proof level: what a chain proves, when, and what revokes it -------
//
// The chains come from `vectors/_chains/` and the anchors from
// `vectors/_trust/`, both committed: see `make-attestation-chains.ts` for why
// they are not minted here. The root is a test root standing in for a pinned
// Google root, so these vectors prove the logic of §7 and not that an
// implementation can walk a real Google chain — the real chains live in the
// two verifier repositories.
{
  const CAPTURE = 1757332800000
  const day = 86_400_000
  const chainOf = (name: string): string[] => (JSON.parse(readFileSync(join(VECTORS, '_chains', `${name}.json`), 'utf8')) as { chain: string[] }).chain
  // Attested photos keep every absence label except the attestation one.
  const ATTESTED_LABELS = PHOTO_LABELS.filter((l) => l !== 'origin not hardware-attested')
  const logKey = createPrivateKey({ key: Buffer.from(TEST_LOG_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })

  // §6.2: `core_hash ‖ JCS(entries) ‖ uint64 BE fetched_at`, signed by the key
  // that signs the log's tree heads.
  const statusAttachment = (proof: Proof, fetchedAt: number, entries: Json): Proof => {
    const at = Buffer.alloc(8)
    at.writeBigUInt64BE(BigInt(fetchedAt))
    const message = Buffer.concat([coreHash(proof), jcs(entries), at])
    return { source: 'googleStatusList', fetched_at: fetchedAt, entries, sig: signEs256(message, logKey).toString('base64url') }
  }

  const attested = (o: { chain: string[], secureHw?: string, status?: Proof }): Proof => {
    const core = photoCore(baseJpeg, 'image/jpeg', o.secureHw ? { device: { platform: 'android', secure_hw: o.secureHw, key_id: KEY_ID } } : {})
    return { ...sign(core), attestation: o.chain, ...(o.status ? { attestation_status: o.status } : {}) }
  }

  {
    const proof = attested({ chain: chainOf('tee') })
    file({ name: '41-jpeg-attested-tee', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'chain revocation not checked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A chain to the pinned test root, TEE at both levels, verified boot on a locked device: the proven level is `tee`, and it is proven by the chain rather than claimed by `device.secure_hw`. Amber, not green: the key is not in the transparency log (§7), and the chain\'s revocation is not established without an `attestation_status` attachment. The instant every certificate is validated at is `time.device_clock`, which is the device\'s own word — hence the ceiling.' })
  }

  {
    const proof = attested({ chain: chainOf('strongbox'), secureHw: 'strongbox' })
    file({ name: '42-jpeg-attested-strongbox', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'chain revocation not checked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'strongbox', proven: 'strongbox', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'StrongBox at both levels. The proven level is the weaker of `attestationSecurityLevel` and `keyMintSecurityLevel` (§7), which here agree; a StrongBox attestation of a TEE key would prove `tee`.' })
  }

  {
    const proof = attested({ chain: chainOf('expiring') })
    file({ name: '43-jpeg-attestation-expired-since', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 365 * day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'attestation chain expired, capture time not proven', 'chain revocation not checked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The intermediate lives twelve days, the life of a real RKP intermediate, and the verifier reads the proof a year later. §7: the path is validated at the proven instant of the capture, so the level **stands** — an expired chain says the verifier is late, not that the capture is forged. What is missing is an independent instant: with only `time.device_clock` nothing but the device places the capture inside the chain\'s validity, so the label says so and the ceiling stays amber. `verifier_clock` is pinned in `expected.json` because otherwise this vector would answer differently as the calendar moves.' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE - 3600000, [{ serial: '02', status: 'revoked', reason: 'KEY_COMPROMISE' }])
    const proof = { ...base, attestation_status: status }
    file({ name: '44-jpeg-attestation-revoked-before-capture', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'attestation key revoked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'red' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The frozen snapshot (§6.2) says the intermediate was already revoked an hour before the declared capture. The chain therefore proves nothing at that instant: `proven` drops to `none` and the level is **red**. The outcome stays `authentic` — the file is intact and the core signature is valid — which is the distinction §7 exists to keep: what the bytes are, and what the origin is worth, are two answers.' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE + 30 * day, [{ serial: '02', status: 'revoked', reason: 'SUPERSEDED' }])
    const proof = { ...base, attestation_status: status }
    file({ name: '45-jpeg-attestation-revoked-after-capture', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 60 * day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'attestation key revoked after the capture'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The same snapshot, taken thirty days later: the certificate was revoked **after** the capture. Revocation is temporal (§6.2), so the level at the proven instant stands and the revocation is shown rather than applied — a batch key withdrawn later does not un-attest what it attested. The pair 44/45 is the whole rule: the same entries, two verdicts, decided by the instant.' })
  }
}

// Regenerating replaces the vectors this file declares, and only those.
//
// It used to delete every numbered directory, which quietly destroyed the
// container vectors: they are sealed by real hardware and signed by a device
// key nobody here holds, so a rewrite is not a rewrite but a loss. Owning only

// ---- registry: the key in the transparency log, and the first green ---------
//
// §6.2's `registry` is the one attachment a verifier checks entirely offline:
// the proof carries the leaf, its RFC 6962 audit path and a signed tree head,
// so "the key was in the log when that head was signed" needs no server. What
// it cannot carry is the *absence* of a later revocation leaf — nothing in a
// Merkle tree proves a leaf does not exist — which is why §6.2 makes
// revocation a signed statement fetched online instead.
//
// These are the vectors that make **green** reachable for the first time. Up to
// vector 45 the corpus topped out at amber and said why: the key was not in the
// log. Now it can be, and the four failures around it are here too, because a
// green that cannot be refused is a green nobody should trust.
{
  const CAPTURE = 1757332800000
  const day = 86_400_000
  const chainOf = (name: string): string[] => (JSON.parse(readFileSync(join(VECTORS, '_chains', `${name}.json`), 'utf8')) as { chain: string[] }).chain
  const logKey = createPrivateKey({ key: Buffer.from(TEST_LOG_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
  const digest = (...parts: Buffer[]): Buffer => parts.reduce((h, part) => h.update(part), createHash('sha256')).digest()
  // `log_id` is the log key's own identifier: SHA-256 of its DER SPKI,
  // base64url — the same derivation `device.key_id` uses for a signing key.
  const LOG_ID = digest(spkiOf(logKey)).toString('base64url')

  const statusAttachment = (proof: Proof, fetchedAt: number, entries: Json): Proof => {
    const at = Buffer.alloc(8)
    at.writeBigUInt64BE(BigInt(fetchedAt))
    const message = Buffer.concat([coreHash(proof), jcs(entries), at])
    return { source: 'googleStatusList', fetched_at: fetchedAt, entries, sig: signEs256(message, logKey).toString('base64url') }
  }

  /**
   * A tree of `size` leaves with ours at `index`, and the audit path for it.
   *
   * The other leaves are stand-ins: what a path proves is the shape of the
   * tree, so their content is irrelevant and their *number* is not — a
   * one-leaf tree would exercise no path at all, and a power of two would hide
   * the incomplete-level case that trips a naive verifier.
   */
  const treeWith = (leaf: Buffer, index: number, size: number): { root: Buffer, path: Buffer[] } => {
    let level = Array.from({ length: size }, (_, i) => i === index ? leaf : leafHash(Buffer.from(`filler ${i}`, 'utf8')))
    const path: Buffer[] = []
    let position = index
    while (level.length > 1) {
      if (position % 2 === 1) path.push(level[position - 1] as Buffer)
      else if (position + 1 < level.length) path.push(level[position + 1] as Buffer)
      const next: Buffer[] = []
      for (let i = 0; i < level.length; i += 2) {
        next.push(i + 1 < level.length ? nodeHash(level[i] as Buffer, level[i + 1] as Buffer) : level[i] as Buffer)
      }
      level = next
      position = Math.floor(position / 2)
    }
    return { root: level[0] as Buffer, path }
  }

  /** The §6.2 attachment for a key, with every field the spec names. */
  const registryFor = (o: {
    keyId?: string, pub?: string, secureHw?: string, headTimestamp?: number,
    logId?: string, forgePath?: boolean, index?: number, size?: number
  } = {}): Proof => {
    const leaf: Proof = {
      type: 'key',
      // Hex, which is how a log leaf records the digest that `device.key_id`
      // carries in base64url. One value, two encodings.
      key_id: leafKeyId(o.keyId ?? KEY_ID) as string,
      public_key: (o.pub ?? spkiOf(privateKey).toString('base64')),
      secure_hw: o.secureHw ?? 'tee',
      attestation_digest: digest(Buffer.from('the chain as the log received it', 'utf8')).toString('hex'),
      registered_at: CAPTURE - day
    }
    const index = o.index ?? 3
    const size = o.size ?? 7
    const { root, path } = treeWith(leafHash(jcs(leaf as Json)), index, size)
    const timestamp = o.headTimestamp ?? CAPTURE - 3600000
    return {
      log_id: o.logId ?? LOG_ID,
      leaf_index: index,
      leaf,
      inclusion_path: (o.forgePath
        ? path.map(() => digest(Buffer.from('not the sibling', 'utf8')))
        : path).map((hash) => hash.toString('base64url')),
      tree_head: {
        tree_size: size,
        timestamp,
        root_hash: root.toString('base64url'),
        signature: signEs256(treeHeadMessage(size, timestamp, root), logKey).toString('base64url')
      }
    }
  }

  /** An attested photo with a registry attachment and a clean status list. */
  const registered = (o: Parameters<typeof registryFor>[0] = {}, statusEntries: Json = [{ serial: '02', status: 'valid' }]): Proof => {
    const base = { ...sign(photoCore(baseJpeg, 'image/jpeg')), attestation: chainOf('tee') }
    return { ...base, attestation_status: statusAttachment(base, CAPTURE - 1800000, statusEntries), registry: registryFor(o) }
  }

  // Every absence label except the three this vector answers.
  const GREEN_LABELS = PHOTO_LABELS.filter((l) =>
    l !== 'origin not hardware-attested' && l !== 'key not in transparency log')

  /** §6.2's online status, signed by the log for one instant only. */
  const statusStatement = (at: number, status: 0 | 1 | 2, treeSize = 7): Json => ({
    log_id: LOG_ID,
    at,
    tree_size: treeSize,
    status,
    signature: signEs256(keyStatusMessage(Buffer.from(KEY_ID, 'base64url'), at, treeSize, status), logKey).toString('base64url')
  })

  {
    const proof = registered()
    file({ name: '49-jpeg-registry-verified', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS, 'revocation not checked'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The corpus\'s first **green**. Everything §7 asks for is present and checkable offline: a chain that proves `tee` to the pinned test root, a signed status list saying its certificates were valid, and a `registry` attachment whose tree head the log signed before the declared capture, with an RFC 6962 audit path that lands on the signed root and a leaf naming this key and this public key.\n\nThe tree has **seven** leaves and ours is the fourth. Neither number is arbitrary: a one-leaf tree exercises no path, and a power of two hides the incomplete level where an implementation that pads instead of promoting a lone node gets a different root.\n\n`key not in transparency log` is gone — the label everything up to vector 45 carried — and the ceiling is still **amber**, for the one reason that remains: an inclusion proof shows the key was in the log when a head was signed and cannot show it was not revoked afterwards, because a revocation is a later leaf and nothing in a Merkle tree proves a leaf\'s absence. So *revocation not checked*, and vector 54 is the same proof with the log\'s signed answer supplied.' })
  }

  {
    const proof = registered({ forgePath: true })
    file({ name: '50-jpeg-registry-path-forged', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS, 'key not in transparency log', 'registry evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The same proof with every hash in the audit path replaced. The tree head signature still verifies — it is the log\'s, over a root the log really signed — and the leaf still names this key, so the only thing that fails is the walk from the leaf to the root, which is the whole point of an inclusion proof.\n\n**Two labels, not one.** *key not in transparency log* is the §7 consequence: nothing here establishes the registration, so the ceiling drops to amber exactly as if the attachment were absent. *registry evidence invalid* is the fact a reader can act on — somebody handed this verifier a forged proof, which is a different thing from nobody having registered the key, and a verifier that reported only the first would throw away the part worth telling a user. The **core is untouched**: the capture is still signed by the key it says, and the outcome stays `authentic`.' })
  }

  {
    // Another key's id and another key's public half: a leaf that is genuinely
    // in the log, for somebody else.
    const other = createPrivateKey({ key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'der' }), format: 'der', type: 'pkcs8' })
    const otherSpki = spkiOf(other)
    const proof = registered({ keyId: keyId(otherSpki), pub: otherSpki.toString('base64') })
    file({ name: '51-jpeg-registry-other-key', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS, 'key not in transparency log', 'registry evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A registry attachment that is internally perfect — signed head, valid inclusion, a real leaf — and about **another key**. This is the attachment a client would embed by mistake after enrolling twice, or one an attacker would lift from somebody else\'s proof, and the reason §6.2 requires `leaf.key_id == device.key_id` **and** `leaf.public_key == sig.pub`. Checking the id alone is not enough: an id is a hash of a key, so a leaf whose two fields disagreed would be a leaf the log should never have accepted, and the mismatch has to be caught here rather than assumed away.' })
  }

  {
    const proof = registered({ logId: digest(Buffer.from('a log nobody pinned', 'utf8')).toString('base64url') })
    file({ name: '52-jpeg-registry-log-not-trusted', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS, 'log not trusted'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A well-formed attachment naming a `log_id` this verifier does not hold a key for. **One label, and not the invalid one.** "Nobody I trust runs that log" is the same fact as an absent attachment — nobody can check the registration — while a forged path (vector 50) is evidence that does not hold up. §8\'s rule is that absent evidence is a weaker verdict and never an error, and a log outside the trust set is absent evidence, not a lie.\n\nIt is also the vector that says a verdict is only ever green *against a named set of anchors*: the same bytes are green for a verifier that pins this log and amber for one that does not, and both are right.' })
  }

  {
    const proof = registered()
    file({ name: '54-jpeg-registry-green', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(CAPTURE, 1),
      expected: {
        outcome: 'authentic',
        labels: GREEN_LABELS,
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'green' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The corpus\'s first **green**, and it takes one more input than vector 49: the log\'s signed answer about this key at the instant the capture is validated at.\n\n`key_status` in `expected.json` is an **input**, like `verifier_clock` — the verifier fetched it, the corpus declares what it fetched. It has to be, because §6.2 makes revocation an online question: the proof cannot carry the absence of a later revocation leaf, so no file on its own can be green. A conformance corpus that pretended otherwise would be testing a verdict no verifier can reach.\n\nThe statement is bound to **this key and this instant** — `"vcap/1.0/status" ‖ key_id ‖ at ‖ tree_size ‖ status`, signed by the log\'s tree-head key — so a statement about last week, correctly signed, is a valid answer to the wrong question and is refused as one. Everything §7 asks for is now present: `tee` proven by a chain to the pinned root, the chain\'s certificates valid in a signed status list, the key in the log before the capture, and the key not revoked at that instant. Change any one and the ceiling drops, which is what the four vectors around this one are for.' })
  }

  {
    const proof = registered({ headTimestamp: CAPTURE + day })
    file({ name: '53-jpeg-registry-after-capture', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 2 * day,
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS, 'registered after the declared capture', 'revocation not checked'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'Valid evidence, a day late. The tree head was signed after `time.device_clock`, so what the log proves is that the key was registered **at some point**, not that it was registered when this capture claims to have happened — a key enrolled after the fact could have signed a file dated before it.\n\nAmber and shown, not rejected: the registration is real and the label says what is missing. `key not in transparency log` is **absent** here, which is the distinction the two labels exist to draw — the key is in the log, and the timing is what does not line up.' })
  }
}


// ---- anchor: existence before a block, and the first instant nobody asserts -
//
// §6.2's `anchor` is two halves and only one is offline. Recomputing the batch
// root from `core_hash`, `index`, `tree_size` and `merkle_path` needs nothing
// but the proof; comparing it with what the contract recorded needs a chain
// read, which the corpus declares as an input the way it declares `key_status`.
//
// The half that matters most is the block's timestamp. Every instant in the
// corpus so far has been `time.device_clock` — the device's own word, which is
// exactly why §7 caps those verdicts. Vector 57 is the first vector whose
// proven instant is one nobody can move.
{
  const CAPTURE = 1757332800000
  const BLOCK = CAPTURE + 90_000
  const day = 86_400_000

  /** The anchor tree: leaves are `SHA-256(0x00 ‖ core_hash)`, same as the log. */
  const batchWith = (coreHashBytes: Buffer, index: number, size: number): { root: Buffer, path: Buffer[] } => {
    let level = Array.from({ length: size }, (_, i) =>
      i === index ? leafHash(coreHashBytes) : leafHash(createHash('sha256').update(`another capture ${i}`).digest()))
    const path: Buffer[] = []
    let position = index
    while (level.length > 1) {
      if (position % 2 === 1) path.push(level[position - 1] as Buffer)
      else if (position + 1 < level.length) path.push(level[position + 1] as Buffer)
      const next: Buffer[] = []
      for (let i = 0; i < level.length; i += 2) {
        next.push(i + 1 < level.length ? nodeHash(level[i] as Buffer, level[i + 1] as Buffer) : level[i] as Buffer)
      }
      level = next
      position = Math.floor(position / 2)
    }
    return { root: level[0] as Buffer, path }
  }

  const anchorFor = (proof: Proof, o: { forgePath?: boolean, index?: number, size?: number } = {}): Proof => {
    const index = o.index ?? 2
    const size = o.size ?? 5
    const { root, path } = batchWith(coreHash(proof), index, size)
    return {
      chain: 'base-sepolia',
      tx: '0x' + createHash('sha256').update('the anchoring transaction').digest('hex'),
      block: 46561942,
      anchor_id: 0,
      index,
      tree_size: size,
      root: root.toString('base64url'),
      merkle_path: (o.forgePath
        ? path.map(() => createHash('sha256').update('not the sibling').digest())
        : path).map((hash) => hash.toString('base64url'))
    }
  }

  // A plain photo, so the anchor is the only thing under test.
  const anchored = (o: Parameters<typeof anchorFor>[1] = {}): Proof => {
    const proof = sign(photoCore(baseJpeg, 'image/jpeg'))
    return { ...proof, anchor: anchorFor(proof, o) }
  }
  const ANCHOR_LABELS = PHOTO_LABELS.filter((l) => l !== 'not anchored')

  {
    const proof = anchored()
    file({ name: '55-jpeg-anchor-path-only', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ANCHOR_LABELS, 'anchoring not verified'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The offline half of §6.2\'s `anchor`: the audit path recomputes the batch root from `core_hash`, `index` and `tree_size`, with leaves `SHA-256(0x00 ‖ core_hash)` — deliberately the same tree as the transparency log, so a verifier carries one Merkle implementation and not two.\n\nAnd it proves nothing yet. The root is still only the proof\'s word about itself until somebody reads what the contract recorded, so the label is *anchoring not verified* and the ceiling is amber — **never red**, because a verifier with no network has learned nothing bad. *not anchored* is gone, which is the label an absent attachment carries; the difference between "no anchor" and "an anchor I could not check" is the whole point of two labels.\n\nFive leaves, ours third: an odd size, so the walk meets the incomplete level, and an odd position, so it meets a sibling on each side.' })
  }

  {
    const proof = anchored({ forgePath: true })
    file({ name: '56-jpeg-anchor-path-forged', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ANCHOR_LABELS, 'not anchored', 'anchor evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'Every hash in the audit path replaced, so the recomputed root is not the one the attachment claims. Detectable **offline**, with no chain and no network, which is why this is `anchor evidence invalid` and not the same answer as vector 55.\n\nTwo labels, by the rule §8 states once for every attachment: the absent label is what a reader is shown — nothing here anchors this capture — and the invalid label is what an operator can act on, since somebody presented a path that does not hold up. The core is untouched and the outcome stays `authentic`: an anchor is evidence added after the capture, and bad evidence about a signed file does not unsign it.' })
  }

  {
    const proof = anchored()
    const root = (proof.anchor as Proof).root as string
    file({ name: '57-jpeg-anchor-on-chain', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      chainRead: { root, tree_size: 5, block_time: BLOCK },
      expected: {
        outcome: 'authentic',
        labels: ANCHOR_LABELS,
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(BLOCK).toISOString(), source: 'anchor' }
      },
      notes: '**The first vector whose proven instant is not the device\'s word.** `chain_read` is an input — the corpus declares what a caller read from the contract, the way it declares `key_status` — and with it the recomputed root matches what the contract recorded for this `anchor_id`, so the block\'s timestamp becomes the instant the proof is validated at: `validated_at.source` is `anchor`, ninety seconds after `time.device_clock`.\n\nThat is the point of anchoring, and it is worth being precise about what it proves: an upper bound. The capture existed **before** that block, which nobody can move; it says nothing about how long before. The device\'s claim is still a claim, and now it is a claim bounded by a fact.\n\nThe ceiling is amber for an unrelated reason — this photo carries no attestation, so the proven level is `none` and §7 never lets that be green whatever the instant. Vectors 49-54 are the other half of that sentence.' })
  }

  {
    const proof = anchored()
    file({ name: '58-jpeg-anchor-chain-disagrees', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      chainRead: { root: createHash('sha256').update('a root the contract never recorded').digest().toString('base64url'), tree_size: 5, block_time: BLOCK },
      expected: {
        outcome: 'authentic',
        labels: [...ANCHOR_LABELS, 'not anchored', 'anchor evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A perfect audit path to a root the contract does not have. This is the case the chain read exists for, and the one an implementation is most likely to get wrong by comparing only the root: a batch of a different size can share a root with this one when it is a prefix, so `tree_size` is compared too.\n\nNote what happens to the instant. The block time is present in the read and is **not used**: an anchor whose root the chain contradicts proves nothing, so `validated_at` falls back to `device_clock` and the verdict says the anchor is invalid. A verifier that took the block time from an anchor it had just rejected would be dating a capture by a transaction that does not contain it.' })
  }
}

// what it can rebuild is the difference between a generator and a broom.
const owned = new Set(vectors.map((v) => v.name))
if (existsSync(VECTORS)) {
  const foreign: string[] = []
  for (const entry of readdirSync(VECTORS)) {
    if (!/^\d\d-/.test(entry)) continue
    if (owned.has(entry)) rmSync(join(VECTORS, entry), { recursive: true })
    else foreign.push(entry)
  }
  if (foreign.length > 0) console.log(`[vcap] left untouched, not generated here: ${foreign.join(', ')}`)
}


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
    writeFileSync(join(dir, 'expected.json'), JSON.stringify({
      kind: 'file',
      // An input, not an expectation: a §7 verdict depends on when the verifier
      // runs (a chain expires), so a vector that did not pin the clock would
      // change its own answer with the calendar.
      ...(vector.verifierClock ? { verifier_clock: vector.verifierClock } : {}),
      // Also an input: §6.2 makes revocation an online question, so a vector
      // that needs it declares what the verifier is assumed to have fetched.
      ...(vector.keyStatus ? { key_status: vector.keyStatus } : {}),
      ...(vector.chainRead ? { chain_read: vector.chainRead } : {}),
      ...vector.expected,
      ...(vector.proof ? { schema_valid: schemaValid } : {})
    }, null, 2) + '\n')
    actual = pick(verifyFile({ file: vector.file, sidecar: vector.sidecar, trust, clock: vector.verifierClock ? new Date(vector.verifierClock) : undefined, keyStatus: vector.keyStatus as KeyStatusStatement | undefined, chainRead: vector.chainRead as ChainRead | undefined }), vector.expected)
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
