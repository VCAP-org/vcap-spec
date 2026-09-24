import { createHash, createPrivateKey } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Json, jcs } from './jcs.js'
import { type Proof, coreBytes, coreHash, flipS, keyId, p1363ToDer, spkiOf } from './core.js'
import { mediaHash } from './canonical.js'
import { Flag, buildTrailer, parseTrailer } from './trailer.js'
import { type Box, boxes, children, codecOf, find, readContainer, samplesOf } from './container.js'
import { remux } from './remux.js'
import { type SegmentEntry, SEPARATOR, ZERO_LINK, linkOf, segmentMessage } from './segments.js'
// Deterministic ES256 (RFC 6979): regenerating an unchanged vector must not
// change its bytes. See sign.ts.
import { signChain, signEs256 } from './sign.js'
import { TEST_KEY_PKCS8_BASE64, TEST_OTHER_KEY_PKCS8_BASE64 } from './testkey.js'
import { TEST_LOG_KEY_PKCS8_BASE64 } from './testlogkey.js'
import { type KeyStatusStatement, integrityMessage, keyStatusMessage, leafHash, leafKeyId, nodeHash, treeHeadMessage } from './registry.js'
import { type ChainRead } from './anchor.js'
import { corroborationMessage } from './location.js'
import { loadTrust } from './trust.js'
import { type Verdict, verifyFile, verifySegments } from './verify.js'
import { validateProof } from './schema.js'
import { isVectorDir } from './corpus-names.js'

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
// Somebody else's key: another device, or a signer no verifier here trusts.
const otherKey = createPrivateKey({ key: Buffer.from(TEST_OTHER_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
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

interface FileVector { kind: 'file', container?: boolean, name: string, ext: string, file: Buffer, sidecar?: Buffer, proof?: Proof, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, schemaValid?: boolean, notes: string, verifierClock?: number, keyStatus?: Json, chainRead?: Json }
interface SegVector { kind: 'segments', name: string, input: { capture_id: string, pub: string, segment_count: number, segments: SegmentEntry[] }, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, notes: string, debug?: Json }
interface JcsVector { kind: 'jcs', name: string, input: Json, expected: { core_bytes_hex: string, core_hash: string }, notes: string }
type Vector = FileVector | SegVector | JcsVector

// Every sealed vector declares `watermark`, and no verifier here has a
// detector: *watermark not evaluated* belongs on all of them (§7).
const PHOTO_LABELS = ['integrity unevaluated', 'key not in transparency log', 'location declared only', 'no trusted time', 'not anchored', 'origin not hardware-attested', 'watermark not evaluated']

const jpegProof = sign(photoCore(baseJpeg, 'image/jpeg'))
const jpegSealed = seal(baseJpeg, jpegProof)
const hashOf = (p: Proof): string => coreHash(p).toString('hex')

/**
 * A committed RFC 3161 token from `vectors/_timestamps/`, refused when it is
 * over another core: see `make-timestamp-tokens.ts`.
 */
const tokenNamed = (name: string, coreHashHex: string): { tsr: string, genTime: string } => {
  const token = JSON.parse(readFileSync(join(VECTORS, '_timestamps', `${name}.json`), 'utf8')) as { core_hash: string, gen_time: string, tsr: string }
  if (token.core_hash !== coreHashHex) {
    throw new Error(
      `_timestamps/${name}.json is a token over ${token.core_hash}, and this vector's core hash is ${coreHashHex}. ` +
      'Re-mint: npx tsx src/make-timestamp-tokens.ts ' + coreHashHex)
  }
  return { tsr: token.tsr, genTime: token.gen_time }
}

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
    expected: { outcome: 'authentic', labels: [...PHOTO_LABELS, 'segment content not recomputed'], not_evaluated: [], core_hash: hashOf(proof), segments: { verified: [] } },
    notes: 'An ISO-BMFF video with media.mime video/mp4, segment_count 3 and the complete chain of vector 25 in the trailer (flag SEGMENTS set). Canonical bytes are the file minus the trailer (§4.1) and `media.hash` matches, so the file is the one the device sealed: **authentic**. The chain is checked at message level only — this is a `file` vector, the container is not demuxed — and the verdict says so with *segment content not recomputed* (§7).\n\n`segments.verified` is **empty**, and that is the rule of §5 (*Locating segments*): a segment counts as verified only once a GOP of this file has been located and its `content_hash` recomputed. Here the signatures hold and nothing was compared; the file is authentic because `media.hash` covers every byte, not because any segment was checked. Vectors 36-39 and 86-94 are the same question asked of the container.' })
}

{
  const proof = sign(videoCore(baseMp4))
  file({ name: '34-mp4-video-without-segments', ext: 'mp4', file: seal(baseMp4, proof), proof,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    schemaValid: false,
    notes: 'Same video, valid signature, segment_count present, no segments. §8: media.mime starting with video/ makes this a video proof, and segments is required for one — missing required field, no proof found. A verifier that branches on the presence of segments alone would say authentic here.' })
}


// ---- §5 binding: a signed segment is verified only where the file has it ----
//
// Until corpus 2.0.0 a segment "verified" when its signature did: a GOP with no
// vcap SEI, or with an index nobody signed, was skipped, and a proof lifted
// onto an unrelated clip read *verified clip*. These vectors are edits of the
// device captures 36 (H.264 with audio) and 37 (HEVC, no audio) — the device
// signatures untouched — and each one is a way a file can stop being the file
// the proof describes. `remux.ts` rewrites sample tables only; `npm run
// generate` rebuilds all of them from the committed 36 and 37.
{
  const deviceFile = (name: string): { file: Buffer, media: Buffer, trailer: Buffer, payload: Buffer, proof: Proof } => {
    const file = readFileSync(join(VECTORS, name, 'input.mp4'))
    const parsed = parseTrailer(file)
    if (parsed.kind !== 'ok') throw new Error(`${name}: no readable trailer`)
    return { file, media: file.subarray(0, parsed.mediaEnd), trailer: file.subarray(parsed.mediaEnd), payload: parsed.payload, proof: JSON.parse(parsed.payload.toString('utf8')) as Proof }
  }
  const h264 = deviceFile('36-mp4-container-verified')
  const hevc = deviceFile('37-mp4-container-hevc')
  const DEVICE_LABELS = ['integrity unevaluated', 'key not in transparency log', 'no trusted time', 'no watermark', 'not anchored', 'origin not hardware-attested']
  const provenance = 'Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.'
  const device = (v: Omit<FileVector, 'kind' | 'container' | 'ext' | 'notes'> & { notes: string }): void =>
    file({ ...v, container: true, ext: 'mp4', notes: `${v.notes}\n\n${provenance}` })

  // Sample ranges per GOP, from the IDRs `readContainer` found.
  const gopsOf = (media: Buffer): { first: number, count: number }[] => {
    const reading = readContainer(media)
    if (reading.kind !== 'gops') throw new Error('not a readable video')
    const kids = children(media, find(boxes(media, 0, media.length), 'moov') as Box)
    const video = kids.filter((b) => b.type === 'trak').map((trak) => {
      const stbl = find(children(media, find(children(media, find(children(media, trak), 'mdia') as Box), 'minf') as Box), 'stbl') as Box
      return { stbl, kind: codecOf(media, find(children(media, stbl), 'stsd') as Box).kind }
    }).find((t) => t.kind === 'video') as { stbl: Box }
    const samples = samplesOf(media, video.stbl)
    const starts = reading.gops.map((g) => samples.findIndex((s) => s.offset === g.range.start))
    return starts.map((first, i) => ({ first, count: (starts[i + 1] ?? samples.length) - first }))
  }
  const range = (g: { first: number, count: number }): number[] => Array.from({ length: g.count }, (_, i) => g.first + i)

  // The vcap SEI NAL of a GOP, located in the file: offset of its RBSP-level
  // index bytes. The index is the last four payload bytes before the trailing
  // 0x80; in these files emulation prevention inserts one 0x03 into
  // 00 00 00 0n, so the stored form is 00 00 03 00 0n.
  const seiIndexAt = (media: Buffer, gop: { range: { start: number } }, index: number): number => {
    const stored = Buffer.from([0x00, 0x00, 0x03, 0x00, index, 0x80])
    const at = media.indexOf(stored, gop.range.start)
    if (at < 0 || at > gop.range.start + 256) throw new Error(`no vcap SEI index ${index} near ${gop.range.start}`)
    return at + 4
  }

  {
    device({ name: '86-mp4-container-stolen-proof-sidecar', file: hevc.media, sidecar: h264.payload, proof: h264.proof,
      expected: { outcome: 'frames_not_compared', labels: DEVICE_LABELS, not_evaluated: [], core_hash: hashOf(h264.proof), segments: { verified: [] }, location: { claimed: 'none', level: 'none' } },
      notes: 'The proof of vector 36, as a sidecar, next to an unrelated recording — vector 37\'s frames with its trailer removed. Every signature in the proof holds: the core, the three segments, the chain. None of it is about this file. Each GOP here carries a vcap SEI, and each names **another capture**, so no GOP of this proof\'s capture can be located (§5, *Locating segments*).\n\nThe outcome is **frames not compared**: the signatures hold and nothing ties them to the frames in front of the reader. Never *verified clip* — a clip is frames that were compared — and this is the case that read *verified clip* with segments 0, 1 and 2 before the binding rule existed, because a GOP that no SEI of this capture names was skipped rather than counted against the file.' })
  }

  {
    const base = readFileSync(join(MEDIA, 'base.mp4'))
    device({ name: '87-mp4-container-proof-over-unmarked-video', file: base, sidecar: h264.payload, proof: h264.proof,
      expected: { outcome: 'frames_not_compared', labels: DEVICE_LABELS, not_evaluated: [], core_hash: hashOf(h264.proof), segments: { verified: [] }, location: { claimed: 'none', level: 'none' } },
      notes: 'The proof of vector 36 as a sidecar over `_media/base.mp4`, a two-frame H.264 file that carries **no vcap SEI at all** — what a re-encoder or an SEI-stripping remuxer leaves behind. No GOP can be located, so nothing is compared and no segment is credited: **frames not compared**. Vector 86 is the same verdict reached through SEIs that name another capture; here there is nothing to read.\n\nA verifier MUST NOT fall back to position — the first GOP of the file is not segment 0 of a proof just because it comes first (§5).' })
  }

  {
    const gops = (readContainer(h264.media) as { kind: 'gops', gops: { range: { start: number } }[] }).gops
    const edited = Buffer.from(h264.file)
    const at = seiIndexAt(edited, gops[1] as { range: { start: number } }, 1)
    edited[at] = 3
    device({ name: '88-mp4-container-sei-index-altered', file: edited, proof: h264.proof,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(h264.proof), segments: { verified: [0, 2] } },
      notes: `Vector 36 with one byte changed: the index in the second GOP's vcap SEI, 1 → 3 (file byte ${at}; the stored form is \`00 00 03 00 03\`, so emulation prevention still holds). A vcap SEI is excluded from \`content_hash\`, so the GOP's bytes still hash to segment 1's signed value — and segment 1 is no longer located, while a GOP names segment 3, which the proof does not sign.\n\n**Tampered**, with segments 0 and 2 verified: a GOP whose SEI index is not a signed segment is content no signature covers (§5). Before the binding rule this file read *verified clip* with 0, 1 and 2 — segment 1 counted as verified because its signature held, though no GOP of the file was ever compared with it.` })
  }

  {
    // Drop GOP 0 from both tracks, keep every surviving sample at its instant.
    // The movie timeline moves to 90 kHz so both delays are exact: video is
    // already 90 kHz, audio's 1024-sample frames at 48 kHz are 1920 ticks.
    const gops = gopsOf(h264.media)
    const kids = children(h264.media, find(boxes(h264.media, 0, h264.media.length), 'moov') as Box)
    const tables = kids.filter((b) => b.type === 'trak').map((trak) => find(children(h264.media, find(children(h264.media, find(children(h264.media, trak), 'mdia') as Box), 'minf') as Box), 'stbl') as Box)
    const [audioStbl, videoStbl] = tables.map((t) => ({ t, kind: codecOf(h264.media, find(children(h264.media, t), 'stsd') as Box).kind }))
      .sort((a, b) => a.kind.localeCompare(b.kind)).map((x) => x.t) as [Box, Box]
    const video = samplesOf(h264.media, videoStbl)
    const audio = samplesOf(h264.media, audioStbl)
    const firstKept = (gops[1] as { first: number }).first
    const cutAt = (video[firstKept] as { dts: bigint }).dts // 90 kHz, media time 0
    const videoDelay = 4731n * 9n + cutAt // the original 473.1 ms empty edit, at 90 kHz, plus GOP 0
    // Audio starts at 0 on the movie timeline (no edit): keep what falls at or
    // after the cut, on the same timeline.
    const keptAudio = audio.map((s, i) => ({ s, i })).filter(({ s }) => s.dts * 90000n >= videoDelay * 48000n)
    const audioDelay = (keptAudio[0] as { s: { dts: bigint } }).s.dts * 90000n / 48000n
    const cut = remux(h264.media, {
      movieTimescale: 90000,
      video: { samples: gops.slice(1).flatMap(range), delay: videoDelay, sync: 'keep' },
      audio: { samples: keptAudio.map(({ i }) => i), delay: audioDelay }
    })
    device({ name: '89-mp4-container-cut-clip', file: Buffer.concat([cut, h264.trailer]), proof: h264.proof,
      expected: { outcome: 'verified_clip', labels: DEVICE_LABELS, not_evaluated: [], core_hash: hashOf(h264.proof), segments: { verified: [1, 2] }, location: { claimed: 'none', level: 'none' } },
      notes: 'Vector 36 **cut**: its first GOP removed from the video track, the audio frames before the cut removed with it, and the full proof — all three segments — still in the trailer. This is what a clip is: the file lacks segment 0, the proof does not.\n\nEvery surviving sample keeps its instant on the movie timeline (the movie timescale becomes 90 kHz and each track gets an empty edit for the time that was cut), so §5\'s audio rule assigns the same frames to segments 1 and 2 as in the original, and both recompute. **Verified clip**, 1 and 2 of 3. Segment 0 is signed and absent, which is the clip case and never *tampered*; `media.hash` does not match, which is what says this is not the original.\n\nVector 38, which used to be the corpus\'s clip, removed segment 0 from the **proof** and left it in the file; under the binding rule that is a GOP no signature covers, and it now reads *tampered*.' })
  }

  {
    const gops = gopsOf(hevc.media)
    const [g0, g1, g2] = gops as [{ first: number, count: number }, { first: number, count: number }, { first: number, count: number }]
    device({ name: '90-mp4-container-gops-reordered', file: Buffer.concat([remux(hevc.media, { video: { samples: [...range(g0), ...range(g2), ...range(g1)], sync: 'keep' } }), hevc.trailer]), proof: hevc.proof,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(hevc.proof), segments: { verified: [0, 1, 2] } },
      notes: 'Vector 37 with its last two GOPs swapped in decode order: segment 0, then 2, then 1. Every GOP is located and every one recomputes to its signed `content_hash` — the bytes of each are untouched, which is why `segments.verified` lists all three.\n\nAnd the file is **tampered**: vcap SEI indices MUST be strictly increasing in decode order (§5). The chain proves the order of the *messages*; only this rule proves the order of the *frames*, and without it a verifier would accept any shuffle of a signed recording as long as each piece was genuine. Vector 26 asked this question at message level, where no file had to be read.' })

    device({ name: '91-mp4-container-gop-duplicated', file: Buffer.concat([remux(hevc.media, { video: { samples: [...range(g0), ...range(g1), ...range(g1), ...range(g2)], sync: 'keep' } }), hevc.trailer]), proof: hevc.proof,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(hevc.proof), segments: { verified: [0, 2] } },
      notes: 'Vector 37 with its second GOP played twice: 0, 1, 1, 2. Both copies of segment 1 recompute to its signed hash. A signed segment counts only when **exactly one** GOP of the file carries its index (§5), so segment 1 is not verified, and a duplicated index is **tampered** — a recording in which one second of footage appears twice is not the recording that was signed, however genuine each copy is.' })

    device({ name: '94-mp4-container-sync-table-not-idr', file: Buffer.concat([remux(hevc.media, { video: { samples: [...range(g0), ...range(g1), ...range(g2)], sync: 'all' } }), hevc.trailer]), proof: hevc.proof,
      expected: { outcome: 'verified_clip', labels: DEVICE_LABELS, not_evaluated: [], core_hash: hashOf(hevc.proof), segments: { verified: [0, 1, 2] } },
      notes: 'Vector 37 with its sync sample table rewritten to mark **every** sample as a sync sample; the frames are untouched. Segment boundaries are IDR access units, read from the NAL unit types (§5), not `stss`: a verifier that cut at sync samples would find seventy GOPs, sixty-seven of them without a vcap SEI, and call the file tampered. Read by IDR, the three GOPs are where they were and all three recompute. **Verified clip**, not authentic, because the rewritten table is inside the canonical bytes and `media.hash` no longer matches.\n\nThe real-world version of this trap is HEVC\'s CRA picture: a random-access point `stss` lists that is not an IDR.' })
  }

  {
    // One length prefix in the second GOP made one byte too long.
    const gops = gopsOf(hevc.media)
    const kids = children(hevc.media, find(boxes(hevc.media, 0, hevc.media.length), 'moov') as Box)
    const stbl = find(children(hevc.media, find(children(hevc.media, find(children(hevc.media, kids.find((b) => b.type === 'trak') as Box), 'mdia') as Box), 'minf') as Box), 'stbl') as Box
    const sample = samplesOf(hevc.media, stbl)[(gops[1] as { first: number }).first + 1] as { offset: number, size: number }
    const edited = Buffer.from(hevc.file)
    edited.writeUInt32BE(edited.readUInt32BE(sample.offset) + 1, sample.offset)
    device({ name: '92-mp4-container-nal-length-overrun', file: edited, proof: hevc.proof,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(hevc.proof), segments: { verified: [] } },
      notes: `Vector 37 with the first NAL length prefix of the second sample of GOP 1 increased by one (file byte ${sample.offset}), so the units no longer tile the sample. The NAL units of a sample MUST cover it exactly (§5): a verifier that stopped at the first length that does not fit — which the reference verifier used to do — would leave the rest of the sample out of every hash and still call the GOP verified. **Tampered**, and no segment is credited: a malformed container is not a partial answer.` })
  }

  {
    // GOP 1's vcap SEI NAL rebuilt with a second user_data_unregistered
    // message after ours: a NAL that is still "a vcap SEI" to a verifier that
    // looks for the UUID, and that hides twenty unsigned bytes if it is
    // excluded whole.
    const gops = gopsOf(h264.media)
    const kids = children(h264.media, find(boxes(h264.media, 0, h264.media.length), 'moov') as Box)
    const videoStbl = kids.filter((b) => b.type === 'trak').map((trak) => find(children(h264.media, find(children(h264.media, find(children(h264.media, trak), 'mdia') as Box), 'minf') as Box), 'stbl') as Box)
      .find((t) => codecOf(h264.media, find(children(h264.media, t), 'stsd') as Box).kind === 'video') as Box
    const index = (gops[1] as { first: number }).first
    const sample = samplesOf(h264.media, videoStbl)[index] as { offset: number, size: number }
    const bytes = h264.media.subarray(sample.offset, sample.offset + sample.size)
    const nals: Buffer[] = []
    for (let at = 0; at < bytes.length;) { const n = bytes.readUInt32BE(at); nals.push(bytes.subarray(at + 4, at + 4 + n)); at += 4 + n }
    const sei = nals.findIndex((n) => ((n[0] as number) & 0x1f) === 6 && n.includes(Buffer.from('caa653d1ed1763c7af388aea76527336', 'hex')))
    if (sei < 0) throw new Error('no vcap SEI in the GOP 1 IDR sample')
    const original = nals[sei] as Buffer
    // Drop the trailing 0x80, append a second message, restore the stop bit.
    const hidden = Buffer.concat([Buffer.from([0x05, 20]), Buffer.from('0123456789abcdef', 'ascii'), Buffer.from('HIDE', 'ascii')])
    nals[sei] = Buffer.concat([original.subarray(0, original.length - 1), hidden, Buffer.from([0x80])])
    const rebuilt = Buffer.concat(nals.flatMap((n) => { const l = Buffer.alloc(4); l.writeUInt32BE(n.length); return [l, n] }))
    const video = gops.flatMap(range)
    device({ name: '93-mp4-container-sei-extra-message', file: Buffer.concat([remux(h264.media, { video: { samples: video, delay: 4731n, sync: 'keep', replace: new Map([[index, rebuilt]]) } }), h264.trailer]), proof: h264.proof,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(h264.proof), segments: { verified: [0, 2] } },
      notes: 'Vector 36 with the vcap SEI NAL of GOP 1 rebuilt to carry a **second** SEI message after ours: another `user_data_unregistered` with twenty bytes nobody signed. A vcap SEI NAL carries exactly one message, the 36-byte vcap one, followed by `rbsp_trailing_bits` (§5). A verifier that excluded any SEI NAL containing the vcap UUID — the reference verifier did — would hash GOP 1 exactly as the device did and call it verified, with those twenty bytes inside it and outside every hash.\n\n**Tampered**, 0 and 2 verified. The sample is rewritten through `remux.ts` (it grew by twenty-two bytes) and the audio track is untouched.' })
  }
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

  // Every certificate of the chain but the pinned root has an entry (§6.2):
  // the leaf is serial 03, the intermediate 02.
  const VALID = [{ serial: '03', status: 'valid' }, { serial: '02', status: 'valid' }]
  const revokedIntermediate = (o: { reason: string, revokedAt?: number }): Json =>
    [{ serial: '03', status: 'valid' }, { serial: '02', status: 'revoked', reason: o.reason, ...(o.revokedAt !== undefined ? { revoked_at: o.revokedAt } : {}) }]
  // The standard photo core is the one `_timestamps/valid.json` stamps: an
  // attachment is outside the core, so adding a chain does not move it.
  const withToken = (proof: Proof): { proof: Proof, genTime: string } => {
    const token = tokenNamed('valid', hashOf(proof))
    return { proof: { ...proof, timestamp: { tsr: token.tsr } }, genTime: token.genTime }
  }
  const STAMPED_LABELS = ATTESTED_LABELS.filter((l) => l !== 'no trusted time')

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE - 3600000, revokedIntermediate({ reason: 'KEY_COMPROMISE', revokedAt: CAPTURE - 7200000 }))
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
      notes: 'The frozen snapshot (§6.2) says the intermediate is revoked, for `KEY_COMPROMISE`, with a revocation date two hours before the declared capture. The chain therefore proves nothing: `proven` drops to `none` and the level is **red**. Nothing here could save it — the only instant is the device\'s clock, and a compromise reaches back to the key\'s first use whatever the date says. The outcome stays `authentic` — the file is intact and the core signature is valid — which is the distinction §7 exists to keep: what the bytes are, and what the origin is worth, are two answers.' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE + 30 * day, revokedIntermediate({ reason: 'SUPERSEDED', revokedAt: CAPTURE + 30 * day }))
    const { proof, genTime } = withToken({ ...base, attestation_status: status })
    file({ name: '45-jpeg-attestation-revoked-after-capture', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 60 * day,
      expected: {
        outcome: 'authentic',
        labels: [...STAMPED_LABELS, 'attestation key revoked after the capture'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'The intermediate is revoked, for `SUPERSEDED`, and the source gives the revocation date: thirty days after the capture. A timestamp token over this core places the capture one minute after the declared time — an instant the device does not choose — and that is before the revocation date, so the level at the proven instant **stands**, and the revocation is shown rather than applied: a batch key withdrawn later does not un-attest what it attested (§6.2).\n\nAll three conditions are needed and each has a vector that lacks it: an instant nobody can move (96 has only the device clock), a revocation date the source gives (97 has only `fetched_at`), and a reason that does not reach back (44). Amber for an unrelated reason: the key is not in the transparency log.' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE + 30 * day, revokedIntermediate({ reason: 'SUPERSEDED', revokedAt: CAPTURE + 30 * day }))
    const proof = { ...base, attestation_status: status }
    file({ name: '96-jpeg-attestation-revoked-after-device-clock', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 60 * day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'attestation key revoked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'red' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'Vector 45 without the timestamp token. The revocation date is thirty days after `time.device_clock` — and the device clock is set by whoever holds the device key, which after a leaked keybox is exactly the person the revocation is about. A thief who signs today with the clock set to last month would read *revoked after the capture* and keep the level. So a device clock never places a capture before a revocation: **red** (§6.2, §7).' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE + 30 * day, revokedIntermediate({ reason: 'SUPERSEDED' }))
    const { proof, genTime } = withToken({ ...base, attestation_status: status })
    file({ name: '97-jpeg-attestation-revoked-without-date', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 60 * day,
      expected: {
        outcome: 'authentic',
        labels: [...STAMPED_LABELS, 'attestation key revoked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'red' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'A revoked intermediate with no `revoked_at`, in a snapshot the registry took thirty days after the capture, and a timestamp token that places the capture firmly before that. Still **red**: `fetched_at` is when the registry read the list, not when anything was revoked, and a revocation first seen a month late may have happened a year early. Only a date the source itself gives can place a revocation after the capture (§6.2).' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE + 1800000, [{ serial: '03', status: 'valid' }, { serial: '02', status: 'unknown' }])
    const proof = { ...base, attestation_status: status }
    file({ name: '98-jpeg-attestation-status-unknown', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'chain revocation not checked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The snapshot says `unknown` for the intermediate. That is the registry not knowing, and a verifier that read it as revoked — the reference verifier did — would turn silence into an accusation. **Amber**, *chain revocation not checked*, the level stands (§6.2).' })
  }

  {
    const base = attested({ chain: chainOf('tee') })
    const status = statusAttachment(base, CAPTURE + 1800000, [{ serial: '02', status: 'valid' }])
    const proof = { ...base, attestation_status: status }
    file({ name: '99-jpeg-attestation-status-uncovered', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...ATTESTED_LABELS, 'chain revocation not checked'],
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A correctly signed snapshot that says the intermediate (serial 02) is valid and says nothing about the leaf (serial 03). A snapshot answers for the certificates it names and no others: every certificate of the chain but the pinned root needs an entry, and one without is *chain revocation not checked*, **amber** (§6.2). A verifier that checked only the entries present would call a chain clean on the strength of one certificate.' })
  }

  {
    // An attested key that signs a leaf of its own, claiming StrongBox.
    const proof = attested({ chain: chainOf('forged-leaf'), secureHw: 'strongbox' })
    file({ name: '105-jpeg-attestation-forged-leaf', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...PHOTO_LABELS, 'attestation evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'strongbox', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A four-certificate chain in which a genuine attested TEE key — its own leaf, KeyDescription and all, under the real intermediate — has signed a **fifth-column leaf**: this proof\'s key, with a KeyDescription that says StrongBox. Every signature in the chain verifies and it ends in the pinned root.\n\n§7 refuses it twice. The key attestation extension belongs to the leaf and only the leaf, and certificate 1 carries one; and every certificate above the leaf MUST be a CA with `keyCertSign`, which an attested key is not. Proven level **none**, with both labels of §8 for a present attachment that does not hold up. Without those two rules a single genuine hardware key could mint "StrongBox" for any key it liked.' })
  }

  {
    // The chain is about the test key; the proof is signed by another one.
    const otherSpki = spkiOf(otherKey)
    const core = photoCore(baseJpeg, 'image/jpeg', { device: { platform: 'android', secure_hw: 'tee', key_id: keyId(otherSpki) } })
    const signed = { ...core, sig: { alg: 'ES256', value: signEs256(coreBytes(core), otherKey).toString('base64url'), pub: otherSpki.toString('base64url') } }
    const proof = { ...signed, attestation: chainOf('tee') }
    file({ name: '108-jpeg-attestation-leaf-not-signing-key', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(proof) },
      notes: 'A proof signed by one key carrying the genuine attestation chain of another. The core signature is valid under `sig.pub`, and the chain is perfect — for a different key. §6.2: the leaf\'s SubjectPublicKeyInfo MUST equal `sig.pub`, otherwise **tampered**. This is the signature swap of `threat-model.md` §5.1: re-sign a file with your own key and borrow somebody\'s hardware evidence. Weak evidence would be amber; evidence about someone else attached to your signature is red.' })
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
  const registered = (o: Parameters<typeof registryFor>[0] = {}, statusEntries: Json = [{ serial: '03', status: 'valid' }, { serial: '02', status: 'valid' }], chain = 'tee', core: Proof = {}): Proof => {
    const base = { ...sign(photoCore(baseJpeg, 'image/jpeg', core)), attestation: chainOf(chain) }
    return { ...base, attestation_status: statusAttachment(base, CAPTURE + 1800000, statusEntries), registry: registryFor(o) }
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
    const otherSpki = spkiOf(otherKey)
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
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'Everything §7 asks for except one thing, and the one thing is time. `tee` proven by a chain to the pinned root, every certificate of the chain valid in a signed status snapshot, the key in the log before the declared capture, the app that made the key one the log admits, and the log\'s signed answer that the key was not revoked at that instant — `key_status` in `expected.json` is an **input**, like `verifier_clock`, because §6.2 makes revocation an online question.\n\nAnd the ceiling is **amber**. The only instant is `time.device_clock`, and a device clock caps the verdict at amber whatever else holds (§7): it is set by whoever holds the device, so every check made "at the capture" is a check made at a moment the signer chose. This vector used to be the corpus\'s green, in contradiction with that sentence; the text was right and the vector was not. Vector 100 is this proof with an instant nobody can move, and it is green.' })
  }

  // The standard core is the one `_timestamps/valid.json` stamps; every
  // attachment here is outside it.
  const stampedRegistered = (o: Parameters<typeof registryFor>[0] = {}, statusEntries?: Json, chain?: string): { proof: Proof, genTime: string } => {
    const proof = registered(o, statusEntries, chain)
    const token = tokenNamed('valid', hashOf(proof))
    return { proof: { ...proof, timestamp: { tsr: token.tsr } }, genTime: token.genTime }
  }
  const STAMPED_GREEN = GREEN_LABELS.filter((l) => l !== 'no trusted time')

  {
    const { proof, genTime } = stampedRegistered()
    file({ name: '100-jpeg-registry-green-timestamped', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(Date.parse(genTime), 1),
      expected: {
        outcome: 'authentic',
        labels: STAMPED_GREEN,
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'green' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'The corpus\'s **green**: vector 54 with an RFC 3161 token over its core. The token\'s `genTime` becomes the proven instant (§7), every certificate path is validated there, the log\'s signed status answers for that instant, and the tree head predates both the declared capture and the token (§6.2).\n\nWhat green says here, and only here: the key is in secure hardware of a device whose boot was verified, created by an app the log admits, registered in the log before the capture and not revoked at the instant a time-stamping authority vouches for; the chain\'s certificates were not revoked when the registry looked; and the bytes are the ones that key signed. Change any one input and one of the vectors around this one says which.' })
  }

  {
    // No `time` in the core, so no declared capture time; a verified anchor
    // supplies the instant, so the time cap is not what stops green here.
    const base = registered({}, undefined, 'tee', { time: undefined as unknown as Json })
    delete (base as Record<string, unknown>).time
    const core = { ...base }
    const leafIndex = 2
    const size = 5
    let level = Array.from({ length: size }, (_, i) => i === leafIndex ? leafHash(coreHash(core)) : leafHash(createHash('sha256').update(`another capture ${i}`).digest()))
    const path: Buffer[] = []
    let position = leafIndex
    while (level.length > 1) {
      if (position % 2 === 1) path.push(level[position - 1] as Buffer)
      else if (position + 1 < level.length) path.push(level[position + 1] as Buffer)
      const next: Buffer[] = []
      for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeHash(level[i] as Buffer, level[i + 1] as Buffer) : level[i] as Buffer)
      level = next
      position = Math.floor(position / 2)
    }
    const root = level[0] as Buffer
    const BLOCK = CAPTURE + 90_000
    const proof = { ...core, anchor: { chain: 'base-sepolia', tx: '0x' + createHash('sha256').update('the anchoring transaction').digest('hex'), block: 46561942, anchor_id: 0, index: leafIndex, tree_size: size, root: root.toString('base64url'), merkle_path: path.map((h) => h.toString('base64url')) } }
    file({ name: '101-jpeg-registry-no-device-clock', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(BLOCK, 1),
      chainRead: { root: root.toString('base64url'), tree_size: size, block_time: BLOCK },
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS.filter((l) => l !== 'not anchored'), 'capture time not declared'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: new Date(BLOCK).toISOString(), source: 'anchor' }
      },
      notes: 'A core with **no `time`**, everything else of vector 100, and a verified anchor for the instant. The reference verifier used to read a missing `device_clock` as "registered before the capture" — an absent field giving a *stronger* verdict than a present one, since a declared time can at least be late.\n\nNow the absence is shown, *capture time not declared*, and nothing that needs a declared capture time is established: the log\'s tree head cannot be placed before a capture nobody dated, so the ceiling is **amber**. The block time is an upper bound on the capture and says nothing about how long before it the key was registered.' })
  }

  {
    const { proof, genTime } = stampedRegistered({ headTimestamp: CAPTURE + 120_000 })
    file({ name: '102-jpeg-registry-after-trusted-time', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(Date.parse(genTime), 1),
      expected: {
        outcome: 'authentic',
        labels: [...STAMPED_GREEN, 'registered after the declared capture', 'registered after the trusted time'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'Vector 100 with a tree head signed two minutes after the capture — after the declared time **and** after the token\'s `genTime`. §6.2 requires `tree_head.timestamp` to exceed neither; the reference verifier used to check only the first. The second is the one that matters: the token is an instant the device does not choose, and a key logged after it was not in the log when the capture was stamped. Both labels, **amber**.' })
  }

  {
    // A token one minute after the capture, and an anchor half a minute after.
    const proof0 = sign(photoCore(baseJpeg, 'image/jpeg'))
    const token = tokenNamed('valid', hashOf(proof0))
    const anchorOf = (block: number): { anchor: Proof, read: Json } => {
      const leafIndex = 1
      const size = 3
      const leaves = Array.from({ length: size }, (_, i) => i === leafIndex ? leafHash(coreHash(proof0)) : leafHash(createHash('sha256').update(`another capture ${i}`).digest()))
      const left = nodeHash(leaves[0] as Buffer, leaves[1] as Buffer)
      const root = nodeHash(left, leaves[2] as Buffer)
      return {
        anchor: { chain: 'base-sepolia', tx: '0x' + createHash('sha256').update(`block ${block}`).digest('hex'), block: 46561942, anchor_id: 1, index: leafIndex, tree_size: size, root: root.toString('base64url'), merkle_path: [leaves[0] as Buffer, leaves[2] as Buffer].map((h) => h.toString('base64url')) },
        read: { root: root.toString('base64url'), tree_size: size, block_time: block }
      }
    }
    const TS_ANCHOR_LABELS = PHOTO_LABELS.filter((l) => l !== 'not anchored' && l !== 'no trusted time')
    {
      const early = CAPTURE + 30_000
      const { anchor, read } = anchorOf(early)
      const proof = { ...proof0, timestamp: { tsr: token.tsr }, anchor }
      file({ name: '103-jpeg-timestamp-after-anchor-block', ext: 'jpg', file: seal(baseJpeg, proof), proof,
        verifierClock: CAPTURE + day,
        chainRead: read,
        expected: {
          outcome: 'authentic',
          labels: [...TS_ANCHOR_LABELS, 'no trusted time', 'timestamp evidence invalid'].sort(),
          not_evaluated: [],
          core_hash: hashOf(proof),
          level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
          validated_at: { instant: new Date(early).toISOString(), source: 'anchor' }
        },
        notes: 'A valid token and a verified anchor over the same core, and the token\'s `genTime` is **after** the block that already anchors it. A token is validated at its own `genTime`, which whoever holds the TSA key chooses; the block time is chosen by nobody. When both are present the token must predate the block, and its signer certificate must still have been valid at the block (§6.2). This one fails the first: both labels of §8 for the token, and the block dates the capture.' })
    }
    {
      const late = CAPTURE + 400 * day
      const { anchor, read } = anchorOf(late)
      const proof = { ...proof0, timestamp: { tsr: token.tsr }, anchor }
      file({ name: '104-jpeg-timestamp-signer-expired-at-anchor', ext: 'jpg', file: seal(baseJpeg, proof), proof,
        verifierClock: CAPTURE + 500 * day,
        chainRead: read,
        expected: {
          outcome: 'authentic',
          labels: [...TS_ANCHOR_LABELS, 'no trusted time', 'timestamp evidence invalid'].sort(),
          not_evaluated: [],
          core_hash: hashOf(proof),
          level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
          validated_at: { instant: new Date(late).toISOString(), source: 'anchor' }
        },
        notes: 'The same token, and an anchor mined **400 days** after the capture — after the TSA signer\'s certificate expired (it lives a year). The token\'s `genTime` is inside that certificate\'s life and predates the block, so validated at `genTime` alone it holds. But a core first anchored after the certificate expired was stamped, as far as anything can show, by a key that was no longer valid: exactly what a TSA key leaked after its expiry would produce, backdated into the window. With an anchor, the signer must also be valid at the block time (§6.2); without one nothing bounds that risk, and `threat-model.md` §5.4 says so.' })
    }
  }

  {
    const { proof, genTime } = stampedRegistered({}, undefined, 'other-app')
    file({ name: '106-jpeg-attestation-app-not-admitted', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(Date.parse(genTime), 1),
      expected: {
        outcome: 'authentic',
        labels: [...STAMPED_GREEN, 'attestation app not admitted'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'Vector 100 with a chain whose leaf says the key was created by an app signed with a certificate the log does not admit: `attestationApplicationId.signature_digests` holds no digest from the log\'s `app_signing_digests` in `_trust/logs.json` (§7). The hardware is genuine and the key is in the log, so the level stands; the app is not one the registry vouches for, so the ceiling is **amber**, *attestation app not admitted*. Not red: this is a claim the evidence does not reach, not a forgery.' })
  }

  {
    const { proof, genTime } = stampedRegistered({}, undefined, 'no-app-id')
    file({ name: '107-jpeg-attestation-app-not-checked', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(Date.parse(genTime), 1),
      expected: {
        outcome: 'authentic',
        labels: [...STAMPED_GREEN, 'attestation app not checked'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'Vector 100 with a chain whose leaf carries no `attestationApplicationId`. There is nothing to compare with the log\'s declared digests, and a verifier holding no declaration for the log is in the same place: *attestation app not checked*, **amber**, never red (§7). Green claims the key was created by a known app build (`threat-model.md` §1), so a verifier that cannot check it does not say green.' })
  }

  {
    const { proof: stamped, genTime } = stampedRegistered()
    const body: { [key: string]: Json } = { source: 'playIntegrity', verdict: 'failed', evaluated_at: CAPTURE + 1000 }
    const proof = { ...stamped, integrity: { ...body, sig: signEs256(integrityMessage(coreHash(stamped), body), logKey).toString('base64url') } }
    file({ name: '109-jpeg-integrity-failed-caps-green', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(Date.parse(genTime), 1),
      expected: {
        outcome: 'authentic',
        labels: [...STAMPED_GREEN.filter((l) => l !== 'integrity unevaluated'), 'integrity failed'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'Vector 100, the green, with a registry-signed integrity verdict of `failed`. §7: a valid `failed` caps the ceiling at **amber** and is shown prominently — the chain proves where the key lives, and Google\'s word that this device failed its integrity check is a reason not to say green however good the chain is. The level stands (`tee`): the verdict is about the device\'s state, not about the key.\n\nThe cap works in one direction only. Deleting the attachment gives *integrity unevaluated*, which caps nothing — so no integrity verdict can be a condition *for* green, and the format does not pretend it is. What a present `failed` can do is refuse green, and a relabelling cannot fake that away: the verdict is inside the signed message.' })
  }

  {
    // iOS: no chain in the proof; the level comes from the registry's leaf.
    const signed = sign(photoCore(baseJpeg, 'image/jpeg', { device: { platform: 'ios', secure_hw: 'secureEnclave', key_id: KEY_ID } }))
    const leaves = [0, 1, 2].map((i) => i === 1 ? leafHash(coreHash(signed)) : leafHash(createHash('sha256').update(`another capture ${i}`).digest()))
    const root = nodeHash(nodeHash(leaves[0] as Buffer, leaves[1] as Buffer), leaves[2] as Buffer)
    const BLOCK = CAPTURE + 90_000
    const proof = {
      ...signed,
      registry: registryFor({ secureHw: 'secureEnclave' }),
      anchor: { chain: 'base-sepolia', tx: '0x' + createHash('sha256').update('the ios anchoring transaction').digest('hex'), block: 46561942, anchor_id: 2, index: 1, tree_size: 3, root: root.toString('base64url'), merkle_path: [leaves[0] as Buffer, leaves[2] as Buffer].map((h) => h.toString('base64url')) }
    }
    file({ name: '110-jpeg-secure-enclave-from-registry', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      keyStatus: statusStatement(BLOCK, 1),
      chainRead: { root: root.toString('base64url'), tree_size: 3, block_time: BLOCK },
      expected: {
        outcome: 'authentic',
        labels: [...GREEN_LABELS.filter((l) => l !== 'not anchored'), 'level from registry records'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'secureEnclave', proven: 'secureEnclave', ceiling: 'green' },
        validated_at: { instant: new Date(BLOCK).toISOString(), source: 'anchor' }
      },
      notes: 'An iOS capture: no attestation chain in the proof, a `registry` attachment whose leaf records `secureEnclave` for this key, a verified anchor for the instant and the log\'s signed status at it. §7, *The Secure Enclave level*: this version defines no offline binding between a proof and an App Attest attestation, so the level is reachable **only through the registry**, and it is shown as what it is — *level from registry records*, the registry\'s word, like *corroborated* for a position. The inclusion proof shows the log recorded it; nothing in the file shows the Secure Enclave. A verifier that presented this level as checkable without the registry would be claiming a check it did not make.' })
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


// ---- timestamp: an instant a device does not assert about itself -----------
//
// §6.2's `timestamp.tsr` is an RFC 3161 TimeStampToken whose `messageImprint`
// **is** `core_hash`. Over the media alone a stamp would let a writer restate
// the time, place and device afterwards and keep it; over the core it covers
// the pixels and the claims, at the same cost.
//
// The tokens are committed in `vectors/_timestamps/`, minted by
// `make-timestamp-tokens.ts`, for the reason the attestation chains are: a CMS
// signature is ECDSA, so minting again would rewrite every timestamp vector on
// every run for nothing. The generator refuses a token whose imprint is not
// the core hash it just built, so a changed core fails loudly instead of
// producing a vector whose timestamp is about a different proof.
{
  const CAPTURE = 1757332800000
  const day = 86_400_000
  const chainOf = (name: string): string[] => (JSON.parse(readFileSync(join(VECTORS, '_chains', `${name}.json`), 'utf8')) as { chain: string[] }).chain


  const stamped = (name: string, extra: Proof = {}): { proof: Proof, genTime: string } => {
    const base = { ...sign(photoCore(baseJpeg, 'image/jpeg')), ...extra }
    const token = tokenNamed(name, hashOf(base))
    return { proof: { ...base, timestamp: { tsr: token.tsr } }, genTime: token.genTime }
  }

  const TS_LABELS = PHOTO_LABELS.filter((l) => l !== 'no trusted time')

  {
    const { proof, genTime } = stamped('valid')
    file({ name: '59-jpeg-timestamped', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: TS_LABELS,
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'An RFC 3161 TimeStampToken over `core_hash`, from a TSA whose root the corpus pins in `_trust/tsa-roots.pem`. `validated_at.source` is `timestamp`, one minute after the declared capture, and *no trusted time* is gone.\n\nThis is the only instant in a **file** that a device does not assert about itself, and unlike the anchor of vector 57 it needs no network to check: the evidence travels with the proof. A TimeStampToken is CMS SignedData carrying a TSTInfo, so a verifier checks the imprint, the `messageDigest` signed attribute, the signature over the attributes **re-encoded as a `SET OF`** (RFC 5652 §5.4, the one-byte difference every CMS implementation gets wrong once), the signer\'s chain to a pinned root at `genTime`, and the signer\'s `timeStamping` extended key usage.\n\nThe ceiling is amber for an unrelated reason: this photo carries no attestation, so the proven level is `none` and §7 never lets that be green whatever the instant.' })
  }

  {
    const { proof } = stamped('other-imprint')
    file({ name: '60-jpeg-timestamp-other-imprint', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...TS_LABELS, 'no trusted time', 'timestamp evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A genuine token from the trusted TSA, over **somebody else\'s** core hash. Every signature in it verifies; it simply timestamps a different proof.\n\nThis is the case that makes the imprint check the first one worth doing, and the one a naive implementation misses by validating the CMS and reading `genTime` without asking what was stamped. A verifier that did would date this capture by a stamp taken over an unrelated file. The instant falls back to `device_clock` and both labels of §8 are shown.' })
  }

  {
    const { proof } = stamped('untrusted-root')
    file({ name: '61-jpeg-timestamp-untrusted-tsa', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...TS_LABELS, 'no trusted time', 'timestamp evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'The right imprint, a well-formed token, and a TSA whose root nobody pinned. Anyone can run a TSA and stamp anything with any time, so the root is the whole of the trust: without it the token is a signed assertion by a stranger.\n\nUnlike a transparency log outside the trust set — vector 52, which is *log not trusted* alone — this is a failure of the evidence and carries both labels. The difference is what a reader can do about it: a log this verifier does not follow may still be a log somebody trusts, while a timestamp is only ever worth the TSA behind it.' })
  }

  {
    const { proof } = stamped('no-eku')
    file({ name: '62-jpeg-timestamp-no-eku', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...TS_LABELS, 'no trusted time', 'timestamp evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A signer certificate issued by the **trusted** root, with the right imprint and a valid signature, and no `timeStamping` extended key usage.\n\nThe check that catches it is the one easiest to leave out, because everything else about the token is impeccable. A TSA root signs more than its own stamping key — TLS certificates, other services — and without the EKU any of those could stamp. RFC 3161 requires the extension and requires it critical; this is the vector that says a verifier must read it.' })
  }

  {
    // The same core as vector 43, because an attachment is outside the core:
    // the expired chain and the token can be added to one proof and the core
    // hash does not move, which is the §6.2 property this vector leans on.
    const { proof, genTime } = stamped('valid', { attestation: chainOf('expiring') })
    file({ name: '63-jpeg-expired-chain-timestamped', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + 365 * day,
      expected: {
        outcome: 'authentic',
        labels: TS_LABELS.filter((l) => l !== 'origin not hardware-attested').concat('chain revocation not checked').sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'tee', ceiling: 'amber' },
        validated_at: { instant: genTime, source: 'timestamp' }
      },
      notes: 'Why a timestamp is worth carrying, in one vector. This is vector 43\'s situation — a chain whose intermediate lives twelve days, read a year later — with a token added.\n\nVector 43 says *attestation chain expired, capture time not proven*: the path is validated at the proven instant and the level stands, but nothing except the device places the capture inside the chain\'s validity. Here the token does, so **the label is gone**. §7\'s table says that caveat only when the capture time is `time.device_clock` alone, and the reference verifier used to show it unconditionally — its own comment said otherwise, which is how this vector found the gap.\n\nStill amber, and for a reason worth naming: an `attestation_status` attachment is absent, so the chain\'s revocation is unestablished. Vector 54 is the one where every question has an answer.' })
  }
}


// ---- integrity: the attachment that changes no ceiling ---------------------
//
// §6.2's `integrity` relays a Play Integrity or App Attest verdict about the
// device, signed by the registry over `core_hash ‖ UTF-8(verdict)`. A device
// cannot carry one itself: the verdict arrives as a token only the developer's
// server can decrypt, so in the core it would be a self-declaration — and a
// self-declaration by the app is worthless against the compromised device it
// exists to flag.
//
// It corroborates and never carries. §7 takes the proven level from
// `attestation`, and the same rooted device that fails an integrity check also
// fails to produce a chain, so a `failed` verdict is shown and moves no
// ceiling. Vector 66 is the one that pins that, and it is the vector most
// likely to be "fixed" by somebody who reads it as too lenient.
{
  const CAPTURE = 1757332800000
  const day = 86_400_000
  const logKey = createPrivateKey({ key: Buffer.from(TEST_LOG_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })

  /** §6.2: `"vcap/1.0/integrity" ‖ core_hash ‖ JCS(body)`, signed by the registry's key. */
  const integrityFor = (proof: Proof, o: { verdict?: string, source?: string, forge?: boolean, otherKey?: boolean } = {}): Proof => {
    const body: { [key: string]: Json } = { source: o.source ?? 'playIntegrity', verdict: o.verdict ?? 'hardware', evaluated_at: CAPTURE + 1000 }
    const key = o.otherKey ? otherKey : logKey
    const signature = o.forge
      // A signature over another verdict: the bytes are real, the claim is not.
      ? signEs256(integrityMessage(coreHash(proof), { ...body, verdict: 'basic' }), key)
      : signEs256(integrityMessage(coreHash(proof), body), key)
    return { ...body, sig: signature.toString('base64url') }
  }

  const withIntegrity = (o: Parameters<typeof integrityFor>[1] = {}): Proof => {
    const proof = sign(photoCore(baseJpeg, 'image/jpeg'))
    return { ...proof, integrity: integrityFor(proof, o) }
  }
  const NO_INTEGRITY_LABEL = PHOTO_LABELS.filter((l) => l !== 'integrity unevaluated')

  {
    const proof = withIntegrity()
    file({ name: '64-jpeg-integrity-hardware', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...NO_INTEGRITY_LABEL, 'integrity hardware'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A Play Integrity verdict of `hardware`, relayed and signed by the registry over `core_hash ‖ UTF-8("hardware")`. *integrity unevaluated* is gone and the label names what came back.\n\nThe verdict is inside the signature, which is the reason a string this short is signed at all: a relay that covered only the core hash could be re-labelled after the fact, and `failed` would become `hardware` with the signature still checking out.\n\nThe key is the one that signs the log\'s tree heads (§6.2), so a verifier needs nothing it does not already hold — and a verifier holding no log key reports the absence rather than a failure, which is vector 67.' })
  }

  {
    const proof = withIntegrity({ verdict: 'failed', source: 'playIntegrity' })
    file({ name: '65-jpeg-integrity-failed', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: [...NO_INTEGRITY_LABEL, 'integrity failed'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: '**The vector most likely to be "fixed" by somebody who reads it as too lenient.** Google says this device failed its integrity check, the registry relays it, and the outcome is still `authentic` with the ceiling unmoved.\n\nThat is deliberate and it is §7. The proven level comes from `attestation`, and the same rooted device that fails an integrity check also fails to produce a chain to a hardware root — so the level already says `none` here, and lowering it further on the strength of a corroborating signal would be counting one fact twice. The format\'s promise is that this file was signed by the key it names; the state of the device is a different question, answered from different evidence.\n\nWhat the verdict must do is **show it**, which is what the label is for. A reader shown nothing would take no news for good news, and this is news.' })
  }

  {
    const proof = withIntegrity({ forge: true })
    file({ name: '66-jpeg-integrity-relabelled', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic',
        labels: PHOTO_LABELS,
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A genuine registry signature over `core_hash ‖ "basic"`, presented with `verdict: "hardware"`. Every byte of the signature is real; the field beside it was changed after the signing.\n\nIt reads as **one label, and it is the absent one** — and that is the honest answer rather than a shortcoming. A verifier cannot tell a relabelled verdict from one signed by a registry it does not follow: both are "no key of mine made this signature", and inventing a distinction it cannot support would be worse than reporting the weaker reading.\n\nNor does the relabelling gain anything. An attacker who wanted to suppress a `failed` verdict could simply **delete the attachment**, which produces the same *integrity unevaluated*. That is inherent to a corroborating attachment and it is why §7 gives this one no ceiling: something whose absence and whose invalidity are the same answer cannot be load-bearing.\n\nWhat the signature *does* buy is the other direction: a verdict cannot be strengthened. `failed` cannot become `hardware`, because the verdict is inside the signed message — which is the reason a string this short is signed at all.' })
  }

  {
    const proof = withIntegrity({ verdict: 'green' })
    file({ name: '67-jpeg-integrity-unknown-verdict', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      schemaValid: false,
      expected: {
        outcome: 'authentic',
        labels: [...NO_INTEGRITY_LABEL, 'integrity unevaluated', 'integrity evidence invalid'].sort(),
        not_evaluated: [],
        core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A verdict of `green`, correctly signed by the registry over `core_hash ‖ UTF-8("green")`. §6.2 lists four verdicts and this is not one of them, so the attachment is **readable, genuine and meaningless**.\n\nThis is where *integrity evidence invalid* belongs and where the relabelled vector 66 could not reach it: a signature nobody recognises is indistinguishable from absence, while a value outside the enumeration is present evidence that does not parse into anything a reader can be told. Both labels of §8.\n\nAlso schema-invalid, which is the point of having both gates: the schema refuses it on the shape and the verifier refuses it on the meaning, and a proof that passed one and not the other would say the two disagree about the format.' })
  }
}

{
  const CAPTURE = 1757332800000
  const day = 86_400_000
  const logKey = createPrivateKey({ key: Buffer.from(TEST_LOG_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
  {
    const proof0 = sign(photoCore(baseJpeg, 'image/jpeg'))
    const body: { [key: string]: Json } = { source: 'deviceCheck', verdict: 'hardware', evaluated_at: CAPTURE + 1000 }
    const proof = { ...proof0, integrity: { ...body, sig: signEs256(integrityMessage(coreHash(proof0), body), logKey).toString('base64url') } }
    file({ name: '121-jpeg-integrity-unknown-source', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: {
        outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof),
        level: { claimed: 'tee', proven: 'none', ceiling: 'amber' },
        validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
      },
      notes: 'A correctly signed integrity statement whose `source` is `deviceCheck`, a value this version does not define. `integrity.source` is extensible (§9), so this is a verifier meeting a later minor: it cannot weigh a verdict from a source it does not know, and reads the attachment as absent — *integrity unevaluated*, and not *integrity evidence invalid*. The schema accepts it: an identifier is an identifier. Until corpus 2.0.0 both the schema and the reference verifier refused the value §9 declares extensible.' })
  }
  {
    const proof = sign(photoCore(baseJpeg, 'image/jpeg', { watermark: { algo: 'videoseal', layout: 'photo-bch-v4', payload_bits: 128, ecc: 'bch-255-131', strength: 8 } }))
    file({ name: '95-jpeg-watermark-unknown-layout', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
      notes: 'A core declaring `watermark.layout: photo-bch-v4`, a layout this version does not define. The field is extensible (§9): the proof is schema-valid and the verdict is the ordinary one, with *watermark not evaluated* — the answer §8 gives for a layout a verifier does not implement, never a refusal of the file.' })
  }
}

// ---- C2PA co-existence and the sidecar (§3.1, spec/c2pa-interop-1.0.md) ----

{
  // The C2PA manifest store is in the JPEG header (APP11, before SOS) and the
  // vcap trailer is after EOI, so in byte order the manifest is always before
  // the trailer. The order a vector can vary is temporal: vector 02 adds the
  // manifest after sealing, this one seals a file that already carries it.
  // §4.1 strips JUMBF APP11 either way, so the canonical bytes — and with them
  // media.hash, the core and the signature — are those of vector 01.
  file({ name: '68-jpeg-c2pa-present-at-sealing', ext: 'jpg', file: seal(insertAfterApp0(baseJpeg, jumbf), jpegProof), proof: jpegProof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(jpegProof) },
    notes: 'A C2PA-style APP11 JUMBF segment present **when the file was sealed**, the mirror of vector 02 where it is added afterwards. The proof is byte-identical to vector 01\'s — same `media.hash`, same `core_hash`, same signature — because §4.1 excludes JUMBF APP11 from the canonical bytes whichever came first.\n\nThis is the vector for "what if the C2PA manifest is placed after the vcap trailer": in a JPEG it cannot be. The manifest store lives in APP11 marker segments in the header (C2PA 2.4, Annex A.3.1), before SOS; the trailer follows EOI. The only order that varies is the order in time, and this vector and vector 02 are its two values. What differs between them is the *C2PA* side, not ours: here the trailer was appended after the manifest\'s `c2pa.hash.data` was computed, so the C2PA hard binding — which covers every byte not excluded, EOI to end of file included — no longer matches (`spec/c2pa-interop-1.0.md` §3).' })
}

{
  // A C2PA `uuid` box as Annex A.5.1 defines it: FullBox with the C2PA
  // extended type, then `box_purpose` as a NUL-terminated string, then data.
  // An update manifest store "shall exist as the last box of the file"
  // (A.5.3) — the position the vcap footer needs.
  const C2PA_UUID = Buffer.from('d8fec3d61b0e483c92975828877ec481', 'hex')
  const c2paUuidBox = (purpose: string, data: Buffer): Buffer =>
    bmffBox('uuid', Buffer.concat([C2PA_UUID, Buffer.alloc(4), Buffer.from(`${purpose}\0`, 'ascii'), data]))
  const heicProof = sign(photoCore(baseHeic, 'image/heic'))
  const updateAppended = Buffer.concat([seal(baseHeic, heicProof), c2paUuidBox('update', Buffer.from('000000186a756d620000001063327061', 'hex'))])

  file({ name: '69-heic-c2pa-update-box-after-trailer', ext: 'heic', file: updateAppended, proof: heicProof,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
    notes: 'Vector 23 with a C2PA `uuid` box of purpose `update` appended **after** the vcap trailer, where C2PA 2.4 Annex A.5.3 says an update manifest store goes: "the last box of the file". The vcap footer must be the last 16 bytes (§3), so the two formats claim the same position and the later writer wins. Here it is C2PA: the footer is no longer at the end, the file carries no trailer a §3 reader can find, and the verdict is *no proof found* — not *corrupted*, because nothing structurally valid was found and broken.\n\nThis is why `spec/c2pa-interop-1.0.md` §3 forbids appending a C2PA update manifest to a sealed ISO-BMFF file, and why the reverse order — the trailer re-appended after the update box — is not available either: C2PA requires its box last. A verifier that scanned the file for a footer that is not at the end would be violating §3 ("found by seeking from the end, never by scanning") and would turn this vector into an authentic verdict for a file whose end nobody signed.' })

  file({ name: '70-heic-c2pa-update-box-after-trailer-sidecar', ext: 'heic', file: updateAppended, sidecar: jcs(heicProof as Json), proof: heicProof,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(heicProof) },
    notes: 'Vector 69 with the proof also in a sidecar. The sidecar is read because no trailer is found (§3.1), and the canonical bytes are then the **whole** received file — the original bytes, the stale trailer and the appended C2PA box (§4.1 step 1: no valid footer, `F\' = F`). `media.hash` does not match and on a photo that is *tampered* (§8).\n\nThe verdict is honest and it is the point: a sidecar restores full verification only over bytes that did not change, and here they did. A verifier must not carve out "the bytes that look like a trailer" to rescue the match — §3 finds a trailer at the end or not at all, and a reader that recognised trailers by their shape anywhere in a file would accept a proof that somebody merely pasted in.' })

  // The C2PA store goes after `ftyp` (Annex A.5.3). Inserted into a sealed
  // file it sits inside the canonical bytes: §4.1 removes nothing from BMFF.
  const ftypEnd = baseHeic.readUInt32BE(0)
  const sealedHeic = seal(baseHeic, heicProof)
  const manifestInserted = Buffer.concat([sealedHeic.subarray(0, ftypEnd), c2paUuidBox('manifest', Buffer.concat([Buffer.alloc(8), Buffer.from('000000186a756d620000001063327061', 'hex')])), sealedHeic.subarray(ftypEnd)])
  file({ name: '73-heic-c2pa-added-after-sealing', ext: 'heic', file: manifestInserted, proof: heicProof,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(heicProof) },
    notes: 'Vector 23 with a C2PA `uuid` manifest box inserted after `ftyp` — where C2PA 2.4 Annex A.5.3 puts the manifest store — **after** sealing. The mirror of vector 02: on a JPEG §4.1 excludes the JUMBF APP11 and the manifest may come and go; on ISO-BMFF nothing is excluded, the box is inside the canonical bytes, `media.hash` no longer matches and the photo is *tampered*.\n\nThis is the vector behind §4.1\'s "video embeds the manifest BEFORE sealing" and the same rule for HEIC. The asymmetry is not a preference: a C2PA `c2pa.hash.data` over a JPEG covers to end of file, so a manifest written before the trailer would be broken by the trailer, while a `c2pa.hash.bmff.v3` with `/free` excluded is not — so each container has exactly one order in which both bindings hold (`spec/c2pa-interop-1.0.md` §3).' })
}

// §3.1: a sidecar never rescues a trailer that was found and is broken. The
// trailer is structurally valid and its CRC fails: somebody edited the file,
// and that is the verdict whatever sits next to it.
file({ name: '72-jpeg-footer-crc-mismatch-sidecar', ext: 'jpg', file: seal(baseJpeg, jpegProof, { crcOverride: 0xdeadbeef }), sidecar: jcs(jpegProof as Json), proof: jpegProof,
  expected: { outcome: 'corrupted_proof', labels: [], not_evaluated: [] },
  notes: 'Vector 06 — a structurally valid footer whose CRC does not match the payload — with an intact copy of the proof in a sidecar. The verdict stays *corrupted proof* (§3.1): the sidecar is a fallback for a trailer that is **absent**, not a substitute for one that is present and broken. The CRC exists to tell corruption from stripping, and a file whose trailer was found and fails its CRC was edited after sealing; showing the sidecar\'s proof as the file\'s would hide exactly that.' })

{
  // Removes the JFIF APP0 segment (the first marker segment of base.jpg):
  // what a metadata-stripping pipeline does to a header, without touching
  // the entropy-coded data.
  const stripApp0 = (jpeg: Buffer): Buffer => {
    const app0Len = jpeg.readUInt16BE(4)
    return Buffer.concat([jpeg.subarray(0, 2), jpeg.subarray(2 + 2 + app0Len)])
  }
  file({ name: '71-jpeg-sidecar-metadata-stripped', ext: 'jpg', file: stripApp0(baseJpeg), sidecar: jcs(jpegProof as Json), proof: jpegProof,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(jpegProof) },
    notes: 'The proof of vector 01 in a sidecar next to a copy of the image whose APP0 segment was removed — the header a metadata-stripping pipeline leaves, with the pixels untouched. Vector 17 is the same sidecar over the unchanged file and reads *authentic*; this one reads *tampered*, because the canonical bytes (§4.1) include every header segment that is not a JUMBF APP11, and the signature is valid over a `media.hash` the received bytes no longer produce.\n\nThis is the row of the transformation table in `spec/c2pa-interop-1.0.md` §5 that a reader is most tempted to soften: a platform that re-encodes or strips metadata leaves a file whose sidecar cannot restore the verdict. The format has no "probably the same picture" outcome for a photo — §8 says a `media.hash` mismatch with a valid `sig` is red — and what remains is the watermark, which a detector may turn into *origin traced*, never into authentic.' })
}


// ---- the position level (§7.1): declared, corroborated, and the two that are not
//
// Every photo in this corpus already declares a position — Milan, ±12.5 m —
// and reads *location declared only*: the device signed the coordinates and
// nothing else vouches for them. These vectors are the rest of §7.1: the
// attachment that raises the level to `corroborated`, the four ways it fails
// to, and the claims a core can make that no evidence here supports.
//
// The attachment is the registry's word about an operator's answer, signed
// with the key that signs tree heads, over
// `"vcap/1.0/location" ‖ core_hash ‖ JCS(body)`. It never carries a phone
// number. And it is orthogonal to the verdict: nothing below moves a ceiling.
{
  const CAPTURE = 1757332800000
  const day = 86_400_000
  const logKey = createPrivateKey({ key: Buffer.from(TEST_LOG_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
  const DECLARED_LABELS = PHOTO_LABELS
  const CORROBORATED_LABELS = [...PHOTO_LABELS.filter((l) => l !== 'location declared only'), 'location corroborated'].sort()

  /** §6.2's attachment, signed over this proof's core hash unless told otherwise. */
  const corroborationFor = (proof: Proof, o: { method?: string, result?: string, radius?: number | null, key?: typeof logKey, over?: Proof } = {}): Proof => {
    const method = o.method ?? 'camara-location-verification'
    const body: Proof = {
      method,
      result: o.result ?? 'match',
      ...(o.radius === null ? {} : { radius_m: o.radius ?? 2000 }),
      at: CAPTURE + 42_000,
      operator_ref: 'op-it-01'
    }
    const message = corroborationMessage(coreHash(o.over ?? proof), body as { [key: string]: Json })
    return { ...body, sig: signEs256(message, o.key ?? logKey).toString('base64url') }
  }

  const corroborated = (o: Parameters<typeof corroborationFor>[1] = {}, core: Proof = {}): Proof => {
    const proof = sign(photoCore(baseJpeg, 'image/jpeg', core))
    return { ...proof, location_corroboration: corroborationFor(proof, o) }
  }
  const at = (core: Proof): { level: { claimed: string, proven: string, ceiling: 'amber' }, validated_at: { instant: string, source: 'device_clock' } } => ({
    level: { claimed: (core.device as Proof | undefined)?.secure_hw as string ?? 'tee', proven: 'none', ceiling: 'amber' },
    validated_at: { instant: new Date(CAPTURE).toISOString(), source: 'device_clock' }
  })

  {
    // The full claim: altitude, source and the fix time, all integers.
    const proof = sign(photoCore(baseJpeg, 'image/jpeg', {
      location: { level: 'declared', lat_udeg: 45464664, lon_udeg: 9188540, alt_cm: 12240, acc_cm: 1250, source: 'gnss', at: CAPTURE - 1500, evidence: [] }
    }))
    file({ name: '74-jpeg-location-declared', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: DECLARED_LABELS, not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: 'The complete §6.1 position claim: coordinates in microdegrees, height above the WGS 84 ellipsoid and accuracy in centimetres, `source: gnss`, and `at`, the device clock when the fix was taken, 1.5 s before the capture. Every number is an integer, because the core has no other kind (§6.1).\n\nThe level is **declared** and the label says *location declared only*: the device signed these coordinates, and the signature proves the device said them — nothing about whether they are true. Android lets an app hand the OS a mock provider and iOS lets a simulator do the same, and the OS is the only thing standing between the app and any coordinates it likes (`threat-model.md` §5.7). That is the honest worth of a signed position, and the verifier names it rather than letting coordinates on a green verdict read as verified.' })
  }

  {
    const proof = corroborated()
    file({ name: '75-jpeg-location-corroborated', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: CORROBORATED_LABELS, not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'corroborated' } },
      notes: 'A `location_corroboration` attachment: the registry called the operator\'s CAMARA Location Verification about a 2 km circle around the declared position, the operator answered `TRUE`, and the registry signed `match` with the key that signs its tree heads, over `"vcap/1.0/location" ‖ core_hash ‖ JCS(body)`. The level is **corroborated**.\n\nWhat a verifier must say about it, in these words or ones that keep their meaning: *the registry attests that the operator confirmed the zone, radius 2000 m*. Not "verified by the operator" — the operator\'s answer is JSON over TLS with no transportable signature, so the only thing a proof can carry is the registry\'s countersignature of what the registry saw (§6.2). That is trust in the registry, stated, and it is the same construction as `integrity`.\n\nAnd it is orthogonal to the verdict. The ceiling is amber for the reason every unattested photo\'s is, and it would be amber with the attachment deleted: the position level says how much the coordinates are worth, never how much the file is.' })
  }

  {
    const proof = corroborated({ key: otherKey })
    file({ name: '76-jpeg-location-corroboration-other-signer', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location corroboration not verified'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: 'The same attachment, signed by a key no verifier here trusts — a registry nobody follows, or nobody at all. The level falls back to **declared** and the label is *location corroboration not verified*, next to *location declared only*: the absent-evidence label a reader is shown, and the one that says why.\n\nNot *evidence invalid*: a signature no trusted key made is indistinguishable from one made by a registry this verifier does not follow, exactly as for `integrity` (vector 66), and the honest report is the weaker one. Vector 77 is the other case this label covers.' })
  }

  {
    // A genuine registry statement about another capture, lifted onto this one.
    const other = sign(photoCore(baseJpeg, 'image/jpeg', { time: { device_clock: CAPTURE - day } }))
    const proof = corroborated({ over: other })
    file({ name: '77-jpeg-location-corroboration-other-core', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location corroboration not verified'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: 'A corroboration the trusted registry really signed — over **another proof\'s** core hash, and moved onto this one. Every byte of the signature is genuine; it corroborates a different capture. Under this core hash it does not verify, so the answer is the one vector 76 gives: **declared**, *location corroboration not verified*.\n\nThe two vectors share an `expected.json` on purpose. To a verifier they are the same fact — no key it trusts signed this message — and a spec that asked it to tell them apart would be asking for a distinction the bytes do not carry. What binds a corroboration to a position is the core hash inside the signed message: the core carries the coordinates, so a statement about this core is a statement about these coordinates, and about no others.' })
  }

  {
    const proof = corroborated({ method: 'camara-geofencing', radius: null })
    file({ name: '78-jpeg-location-corroboration-unknown-method', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location corroboration not evaluated'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: 'A correctly signed corroboration whose `method` is `camara-geofencing`, a value §6.2 does not define. `method` is extensible (§9), so this is a v1.0 verifier reading a proof from a later minor: it does not know what was checked, and it says so — **declared**, *location corroboration not evaluated* — the same reading §7 gives an unknown `secure_hw`. Evidence this verifier cannot read is absent evidence, not a lie (§8), so the *invalid* label stays away.\n\nThe schema accepts it, because an identifier is an identifier; whether a verifier understands the value is the verifier\'s business, not the format\'s.' })
  }

  {
    const proof = corroborated({ result: 'no-match' })
    file({ name: '79-jpeg-location-contradicted', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location contradicted'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: 'The operator said the line was **not** in the 2 km circle around the declared position, and the registry relayed that. The level is what the device alone can reach, **declared**, and the label is *location contradicted*.\n\nIt does not touch the ceiling, and that is the line §7.1 draws: the position level is orthogonal to the verdict. A contradicted position is news a reader must be shown — shown, not silently downgraded, because a verifier that turned it into amber would be saying the file is less authentic, and the file is exactly as authentic as it was. What is less believable is where it says it was taken. The SIM being elsewhere is also the honest limit of the method: it is the SIM the operator locates, not the camera (`threat-model.md` §5.7).' })
  }

  {
    const proof = corroborated({ result: 'TRUE' })
    file({ name: '80-jpeg-location-corroboration-unknown-result', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      schemaValid: false,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location corroboration evidence invalid'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: 'A result of `TRUE` — the operator\'s raw CAMARA value, which a registry MUST map onto §6.2\'s three before signing — correctly signed by the trusted registry. `result` is **not** extensible: it decides the level, so a value outside `match`, `no-match`, `unknown` is present, genuine and meaningless, and this is where *location corroboration evidence invalid* belongs (the same place vector 67 puts `integrity`\'s). Also schema-invalid, and the two gates agreeing is the point: the schema refuses the shape, the verifier refuses the meaning.' })
  }

  {
    // A claim of the top level, with the evidence array a later minor would fill.
    const core: Proof = { location: { level: 'authenticated', lat_udeg: 45464664, lon_udeg: 9188540, acc_cm: 1250, source: 'gnss', evidence: [{ kind: 'osnma' }] } }
    const proof = sign(photoCore(baseJpeg, 'image/jpeg', core))
    file({ name: '81-jpeg-location-claimed-authenticated', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location claimed above evidence', 'location evidence not evaluated'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'authenticated', level: 'declared' } },
      notes: 'The core claims **authenticated** and carries an evidence entry of kind `osnma` — the shape a future writer would use for a Galileo OSNMA-authenticated fix. §7.1 reserves the level and defines no evidence kind that reaches it in this version, so a v1.0 verifier weighs what it can: the coordinates are signed, **declared**, with *location claimed above evidence* for the claim and *location evidence not evaluated* for the array it cannot read.\n\nBoth labels are true from where this verifier stands and neither is an accusation: a later verifier that implements the kind may reach the level. What no verifier of any version may do is take the claim\'s word for it — `location.level` is what the device says it reached, and a claim never raises a level (§7.1), for the same reason `device.secure_hw` never does.' })
  }

  {
    const core: Proof = { location: { level: 'corroborated', lat_udeg: 45464664, lon_udeg: 9188540, acc_cm: 1250, evidence: [] } }
    const proof = sign(photoCore(baseJpeg, 'image/jpeg', core))
    file({ name: '82-jpeg-location-claimed-corroborated', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...DECLARED_LABELS, 'location claimed above evidence'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'corroborated', level: 'declared' } },
      notes: 'A core claiming **corroborated** with no attachment behind it. Corroboration happens after the capture, in the registry, and lives in `location_corroboration`; a writer has nothing to base the claim on at signing time and §6.1 forbids it. The verifier does not argue: the level is what the evidence reaches, **declared**, and *location claimed above evidence* says the core asked for more than it showed. Schema-valid, because the value is one the enumeration defines — the schema gates shapes, the verifier weighs claims.' })
  }

  {
    const core: Proof = { location: { level: 'surveyed', lat_udeg: 45464664, lon_udeg: 9188540, acc_cm: 1250, evidence: [] } }
    const proof = sign(photoCore(baseJpeg, 'image/jpeg', core))
    file({ name: '83-jpeg-location-unknown-claimed-level', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      schemaValid: false,
      expected: { outcome: 'authentic', labels: DECLARED_LABELS, not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'declared', level: 'declared' } },
      notes: '`location.level` is `surveyed`, a value no version defines. The field is not extensible (§9), so the schema rejects the document; the verifier, as §7 says of an unknown `secure_hw`, treats rather than refuses: a signed position is worth **declared** whatever word sits next to it, so the claim is read as `declared` and nothing is flagged — there is no claim above the evidence, only a word this verifier does not know. Authentic, schema-invalid, and the two disagreeing means what it meant in vector 40: "not a v1.0 document" and "still verifiable" are different statements.' })
  }

  {
    // A `location` with a level and no coordinates: a claim about nothing,
    // with a genuine corroboration of it.
    const proof = corroborated({}, { location: { level: 'declared', evidence: [] } })
    file({ name: '84-jpeg-location-corroboration-without-position', ext: 'jpg', file: seal(baseJpeg, proof), proof,
      verifierClock: CAPTURE + day,
      expected: { outcome: 'authentic', labels: [...PHOTO_LABELS.filter((l) => l !== 'location declared only'), 'location corroboration not evaluated'].sort(), not_evaluated: [], core_hash: hashOf(proof), ...at({}), location: { claimed: 'none', level: 'none' } },
      notes: 'A core whose `location` has a `level` and **no coordinates**, and a correctly signed corroboration of it. A position is two coordinates; without both the core declares nothing, whatever `level` says, and the level is **none** — the same as a proof with no `location` at all (vector 47), and with the same silence: absence is not a claim about place, so no label. The attachment has nothing to corroborate and is listed as *location corroboration not evaluated*: it may well be genuine, and it is about nothing this verifier can point to on a map.' })
  }
}

// ---- reading the JSON and the trailer: one proof, one reading --------------
//
// Each of these is a proof two correct JSON parsers can read two ways, or a
// file two readers can walk two ways. §6.1 and §3 now decide each one, and the
// decision is always the conservative one: *no proof found* for a proof that
// is not well formed, *unsupported format version* for a footer this version
// predates.
{
  const text = jcs(jpegProof as Json).toString('utf8')
  const withPayload = (payload: string | Buffer): Buffer => seal(baseJpeg, jpegProof, { payload: Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8') })
  const NOT_FOUND = { outcome: 'no_proof_found' as const, labels: [], not_evaluated: [] }

  {
    // A second `capture_id` ahead of the real one: JavaScript keeps the last.
    const payload = text.replace('{"capture_id":', '{"capture_id":"AAAAAAAAAAAAAAAAAAAAAA","capture_id":')
    file({ name: '111-jpeg-duplicate-key', ext: 'jpg', file: withPayload(payload), expected: NOT_FOUND,
      notes: 'Vector 01\'s payload with `capture_id` written twice, a zero id first and the signed one second. JSON leaves duplicate member names undefined, and parsers split: JavaScript keeps the last and verifies the signature, others keep the first and see a different core. One file, two verdicts, depending on the library. §6.1: a proof with a duplicate member name, at any depth, is not well formed — **no proof found**, the same answer everywhere.' })
  }

  {
    const big = text.replace('"acc_cm":1250', '"acc_cm":9007199254740993')
    file({ name: '112-jpeg-integer-above-2-53', ext: 'jpg', file: withPayload(big), expected: NOT_FOUND,
      notes: 'Vector 01\'s payload with `location.acc_cm` set to 2^53 + 1. An IEEE 754 double cannot hold it: JavaScript reads 9007199254740992, a 64-bit integer parser reads the number written, and JCS of the two cores differs by one digit. §6.1: every integer in a proof lies within ±(2^53 − 1), the range every JSON implementation reads exactly — outside it, **no proof found**. The schema bounds `acc_cm` to uint32 as well.' })
  }

  {
    // A core signed over 1250, written as 1.25e3: JavaScript reads the same
    // number, so the signature would verify.
    const exponent = text.replace('"acc_cm":1250', '"acc_cm":1.25e3')
    file({ name: '113-jpeg-exponent-literal', ext: 'jpg', file: withPayload(exponent), expected: NOT_FOUND,
      notes: 'Vector 01\'s payload with `acc_cm` written as `1.25e3`. JavaScript\'s `JSON.parse` reads 1250, JCS re-serializes it as `1250`, and the signature over the core verifies — a reference verifier built on it said *authentic*. A parser that keeps number types reads a float and refuses the core. §6.1: integers are written as integer literals, `-?(0|[1-9][0-9]*)`, and nothing else — no exponent, no fraction, no `4032.0`. **No proof found**.' })
  }

  {
    file({ name: '114-jpeg-payload-bom', ext: 'jpg', file: withPayload(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, 'utf8')])), expected: NOT_FOUND,
      notes: 'Vector 01\'s payload preceded by a UTF-8 byte-order mark. §3: the payload is UTF-8 with no BOM; some readers skip one and some do not. **No proof found**, whatever the rest says.' })
  }

  {
    const trailer = buildTrailer(jcs(jpegProof as Json), { major: 2, flags: flagsFor(jpegProof) })
    file({ name: '115-jpeg-footer-major-2', ext: 'jpg', file: Buffer.concat([baseJpeg, trailer]), expected: { outcome: 'unsupported_format_version', labels: [], not_evaluated: [] },
      notes: 'A trailer whose footer says major version 2. The magic says a vcap trailer is here; the major says it is not one this reader implements. **Unsupported format version** (§3, §9) — not *no proof found*, which would tell a reader the platform stripped a proof that is sitting at the end of the file in a format this verifier predates. A v1 reader does not interpret the rest of a footer whose major it does not know.' })
  }

  {
    // APP0's length made to run past the end of the file.
    const broken = Buffer.from(baseJpeg)
    broken.writeUInt16BE(0xfff0, 4)
    const core = photoCore(baseJpeg, 'image/jpeg', { media: { mime: 'image/jpeg', w: 16, h: 16, hash: createHash('sha256').update(broken).digest('base64url') } })
    const proof = sign(core)
    file({ name: '116-jpeg-malformed-segment-length', ext: 'jpg', file: seal(broken, proof), proof, expected: NOT_FOUND,
      notes: 'A JPEG whose APP0 length runs past the end of the file, sealed with a `media.hash` over its raw bytes. §4.1\'s walk cannot find the segments, so the file has no canonical bytes and the proof covers nothing a verifier can compute: **no proof found**. The reference verifier used to throw out of `verifyFile` here; a verifier that crashes on hostile input has given the attacker a verdict of their choosing, which is none.' })
  }

  file({ name: '117-empty-file', ext: 'jpg', file: Buffer.alloc(0), expected: NOT_FOUND,
    notes: 'Zero bytes. No footer, no sidecar: **no proof found**, and no exception on the way there.' })

  {
    const sealed = Buffer.from(jpegSealed)
    sealed.writeUInt32BE(0xffffffff, sealed.length - 8)
    file({ name: '118-jpeg-payload-len-max', ext: 'jpg', file: sealed, expected: NOT_FOUND,
      notes: 'Vector 01 with `payload_len` set to 2^32 − 1. `8 + payload_len + 16` then exceeds 2^32, and a reader computing it in 32 bits wraps to 23 and looks for a box header inside the footer. §3: the sum is computed without overflow and compared with the file length first — **no proof found**.' })
  }

  file({ name: '119-jpeg-reserved-flags', ext: 'jpg', file: seal(baseJpeg, jpegProof, { flags: 0xfff8 }), proof: jpegProof,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(jpegProof) },
    notes: 'Vector 01 with footer bits 3–15 set. They are reserved and written as zero, and a reader ignores them (§3): they carry nothing, and refusing a file for them would make a later minor that assigns one unreadable. **Authentic**, and not *flags disagree* — bits 1 and 2 still agree with the JSON.' })

  {
    // Integer-like member names and a `__proto__` member, in the one place a
    // core may carry object members nobody enumerated: an evidence entry.
    const messy: Json = JSON.parse('{"v":"vcap/1.0","capture_id":"' + CAPTURE_ID.toString('base64url') + '","media":{"mime":"image/jpeg","w":16,"h":16,"hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"device":{"platform":"android","secure_hw":"tee","key_id":"' + KEY_ID + '"},"location":{"level":"declared","lat_udeg":1,"lon_udeg":2,"evidence":[{"kind":"x","b":1,"10":2,"9":3,"__proto__":4}]}}') as Json
    const bytes = coreBytes(messy as Proof)
    if (!bytes.toString('utf8').includes('{"10":2,"9":3,"__proto__":4,"b":1,"kind":"x"}')) throw new Error('JCS member order regressed')
    vectors.push({ kind: 'jcs', name: '120-jcs-integer-like-and-proto-keys', input: messy,
      expected: { core_bytes_hex: bytes.toString('hex'), core_hash: createHash('sha256').update(bytes).digest('hex') },
      notes: 'A core whose evidence entry has members named `b`, `10`, `9`, `__proto__` and `kind`. RFC 8785 sorts member names by UTF-16 code units: `10`, `9`, `__proto__`, `b`, `kind`. Two things get in the way in JavaScript, and the reference implementation fell for both: an object enumerates integer-like keys first in numeric order (`9` before `10`) whatever order they were added in, and assigning a `__proto__` member sets the prototype instead of adding the member, which then vanishes from the output. A canonicalizer that builds a sorted object and hands it to `JSON.stringify` produces neither the order nor the member; one that writes members itself produces both.' })
  }
}

// what it can rebuild is the difference between a generator and a broom.
const owned = new Set(vectors.map((v) => v.name))
if (existsSync(VECTORS)) {
  const foreign: string[] = []
  for (const entry of readdirSync(VECTORS)) {
    if (!isVectorDir(entry)) continue
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
      kind: vector.container ? 'container' : 'file',
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
    actual = pick(verifyFile({ file: vector.file, sidecar: vector.sidecar, recomputeSegments: vector.container === true, trust, clock: vector.verifierClock ? new Date(vector.verifierClock) : undefined, keyStatus: vector.keyStatus as KeyStatusStatement | undefined, chainRead: vector.chainRead as ChainRead | undefined }), vector.expected)
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
  // A container vector carries a device's signature, not the test key's: its
  // notes say where it came from instead.
  const footer = vector.kind === 'file' && vector.container ? '' : '\n\nGenerated by `tools/src/generate.ts` with the test key in `tools/src/testkey.ts`.'
  writeFileSync(join(dir, 'NOTES.md'), `# ${vector.name}\n\n${vector.notes}${footer}\n`)

  if (actual && JSON.stringify(actual) !== JSON.stringify(vector.expected)) {
    failures++
    console.error(`[vcap] ${vector.name}: expected ${JSON.stringify(vector.expected)} got ${JSON.stringify(actual)}`)
  }
}

console.log(`[vcap] ${vectors.length} vectors written${failures ? `, ${failures} DISAGREE with the reference verifier` : ''}`)
if (failures) process.exit(1)
