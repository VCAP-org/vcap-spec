import { createHash, createPrivateKey } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Json, jcs } from './jcs.js'
import { type Proof, coreHash, keyId, spkiOf } from './core.js'
import { mediaHash } from './canonical.js'
import { BOX_HEADER_LEN, FOOTER_LEN, buildTrailer } from './trailer.js'
import { signEs256 } from './sign.js'
import { TEST_KEY_PKCS8_BASE64 } from './testkey.js'
import { loadTrust } from './trust.js'
import { type Verdict, verifyFile } from './verify.js'
import { validateProof } from './schema.js'

/**
 * The edge-case generator (C19, second half): frontier vectors produced by
 * sweeping a boundary systematically instead of hand-picking one example at a
 * time — every offset a trailer can be cut at, every byte its magic can be
 * flipped in, every required field a writer could forget, the JCS corners
 * RFC 8785 pins to ECMAScript's own serialization. It owns
 * `vectors/edge-cases/` only, a sibling of the numbered corpus `generate.ts`
 * owns: nothing here renumbers, deletes or reinterprets vectors/NN-*, and the
 * two-digit prefix convention `vcap-verifier`'s snapshot regex and
 * `vcap-sdk-android`'s digit-first filter rely on is left alone.
 *
 * Deterministic: every case here is an exhaustive sweep over a small,
 * enumerated domain (byte offsets, field names, version numbers), so there is
 * nothing for a seed to randomize except the one category that flips a single
 * byte at a random offset (`payload-bit-flip`) — `--seed` picks that offset,
 * and the same seed always picks the same one. Every generated vector is run
 * through the reference verifier before being written, exactly as
 * `generate.ts` does for the hand-picked corpus: a case the verifier
 * disagrees with is aborted, never papered over (`AGENTS.md`).
 *
 * What this generator cannot do: exercise the watermark's BCH(255,131)
 * correction radius. `tools/src/verify.ts` ships no watermark detector (see
 * its own file comment and `vectors/README.md`, "Not here yet"), so there is
 * no decoder in this repository to hand a marred payload to — the off-by-one
 * a bit-error-count budget invites belongs to whichever component owns the
 * decoder (`vcap-ml` / the SDK cores), not to the proof-format layer this
 * tool generates for. Left out rather than faked; see the branch's report.
 */
const ROOT = join(import.meta.dirname, '..', '..')
const VECTORS = join(ROOT, 'vectors')
const EDGE = join(VECTORS, 'edge-cases')
const MEDIA = join(VECTORS, '_media')
const trust = loadTrust(join(VECTORS, '_trust'))

const seedArg = process.argv.findIndex((a) => a === '--seed')
const SEED = seedArg >= 0 ? Number(process.argv[seedArg + 1]) : 1

// A tiny deterministic PRNG (mulberry32): good enough to pick reproducible
// offsets, not to be mistaken for anything cryptographic.
const rng = (seed: number): (() => number) => {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const privateKey = createPrivateKey({ key: Buffer.from(TEST_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' })
const spki = spkiOf(privateKey)
const PUB = spki.toString('base64url')
const KEY_ID = keyId(spki)
const CAPTURE_ID = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
const baseJpeg = readFileSync(join(MEDIA, 'base.jpg'))

const coreOf = (extra: Proof = {}): Proof => ({
  v: 'vcap/1.0',
  capture_id: CAPTURE_ID.toString('base64url'),
  media: { mime: 'image/jpeg', w: 16, h: 16, hash: mediaHash(baseJpeg) },
  device: { platform: 'android', secure_hw: 'tee', key_id: KEY_ID },
  watermark: { algo: 'videoseal', layout: 'photo-bch-v3', payload_bits: 128, ecc: 'bch-255-131', strength: 8 },
  time: { device_clock: 1757332800000 },
  policy: { pseudonymous: false },
  ...extra
})

const sign = (proof: Proof): Proof => ({
  ...proof,
  sig: { alg: 'ES256', value: signEs256(jcs(coreOnly(proof) as Json), privateKey).toString('base64url'), pub: PUB }
})

// Mirrors core.ts's CORE_KEYS without importing extractCore, so a case that
// deliberately deletes a core key still signs over exactly what is left —
// coreBytes(proof) would do the same, this just says so locally.
const CORE_KEYS = ['v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy'] as const
const coreOnly = (proof: Proof): Proof => {
  const out: Proof = {}
  for (const key of CORE_KEYS) if (key in proof) out[key] = proof[key] as Json
  return out
}

const seal = (media: Buffer, proof: Proof): Buffer => Buffer.concat([media, buildTrailer(jcs(proof as Json))])

const hashOf = (proof: Proof): string => coreHash(proof).toString('hex')

const PHOTO_LABELS = ['integrity unevaluated', 'key not in transparency log', 'location declared only', 'no trusted time', 'not anchored', 'origin not hardware-attested', 'watermark not evaluated']
// The base core here has no `location`, unlike generate.ts's: dropping a
// required field is the point of half this file, and a location that always
// declares would hide "location declared only" moving in and out of the label
// set for no reason related to the case under test.
const NO_LOCATION_LABELS = PHOTO_LABELS.filter((l) => l !== 'location declared only')

// ---- vector bookkeeping ----------------------------------------------------

interface FileCase { name: string, ext: 'jpg', file: Buffer, proof?: Proof, expected: Partial<Verdict> & { outcome: Verdict['outcome'] }, schemaValid?: boolean, notes: string }
interface JcsCase { name: string, input: Json, expected: { core_bytes_hex: string, core_hash: string }, notes: string }
const fileCases: FileCase[] = []
const jcsCases: JcsCase[] = []

// Compares only the fields a case asks about, at every depth — the same rule
// generate.ts's own writer follows, so extra diagnostics the verifier adds
// later (a new label, a new field) never read as a generator failure here.
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const pick = (actual: unknown, expected: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(expected).map(([k, want]) => {
    const got = isPlain(actual) ? actual[k] : undefined
    return [k, isPlain(want) && isPlain(got) ? pick(got, want) : got]
  }))

// ---- category 1: truncated trailer ----------------------------------------
// Every offset that removes part of the footer, part of the box header, or
// crosses the boundary between them — not the one length review picked for
// vector 08, every length that could plausibly be "one byte short".
{
  const proof = sign(coreOf())
  const sealed = seal(baseJpeg, proof)
  const cuts = [1, 2, 4, 8, FOOTER_LEN - 1, FOOTER_LEN, FOOTER_LEN + 1, FOOTER_LEN + BOX_HEADER_LEN]
  cuts.forEach((cut, i) => {
    fileCases.push({
      name: `trailer-truncated-${String(i + 1).padStart(2, '0')}-cut-${cut}`,
      ext: 'jpg',
      file: sealed.subarray(0, sealed.length - cut),
      expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
      notes: `The sealed file with its last ${cut} bytes removed (footer is ${FOOTER_LEN} bytes, box header ${BOX_HEADER_LEN}). Every cut in this sweep leaves either a torn magic or a payload length the remaining bytes cannot satisfy, so §3's structural check fails before the CRC is ever read: *no proof found*, never *corrupted* — a platform stripping the tail and an attacker editing it must not read the same at this boundary, and this sweep is the boundary.`
    })
  })
}

// ---- category 2: corrupted magic -------------------------------------------
// Every one of the 4 magic bytes, flipped alone.
{
  const proof = sign(coreOf())
  const sealed = seal(baseJpeg, proof)
  for (let i = 0; i < 4; i++) {
    const corrupted = Buffer.from(sealed)
    const at = corrupted.length - FOOTER_LEN + i
    corrupted[at] = (corrupted[at] as number) ^ 0xff
    fileCases.push({
      name: `magic-corrupted-${String(i + 1).padStart(2, '0')}-byte-${i}`,
      ext: 'jpg',
      file: corrupted,
      expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
      notes: `Byte ${i} of "VCAP" flipped (0xff XOR), the other 3 magic bytes and the rest of the footer left alone. §3 requires all four magic bytes to match before anything else is read, so one wrong byte anywhere in the magic reads the same as no trailer at all: *no proof found*.`
    })
  }
}

// ---- category 3: unsupported major, swept -----------------------------------
// vector 16 picks major 2; this sweeps the boundary and the far end.
{
  for (const major of [0, 2, 3, 9, 255]) {
    const proof = sign(coreOf({ v: `vcap/${major}.0` }))
    fileCases.push({
      name: `major-unsupported-${String(major).padStart(3, '0')}`,
      ext: 'jpg',
      file: seal(baseJpeg, proof),
      proof,
      schemaValid: false,
      expected: { outcome: 'unsupported_format_version', labels: [], not_evaluated: [] },
      notes: `\`v\` is \`vcap/${major}.0\`. §9: a major other than 1 is a different, unreadable contract, reported before anything about the core is trusted (no \`core_hash\` in the verdict — the shape below it was never checked). Schema-invalid for the same value, by the same pattern rule that admits only \`vcap/1.N\`.`
    })
  }
}

// ---- category 4: unknown minor, swept --------------------------------------
// vector 15 picks minor 7 with one unknown field; this sweeps several minors,
// each with its own unknown field, to pin that the count of unknown fields
// (not their presence) is what changes.
{
  for (const minor of [1, 2, 9, 42, 255]) {
    const field = `future_field_${minor}`
    const proof = sign(coreOf({ v: `vcap/1.${minor}`, [field]: true }))
    fileCases.push({
      name: `minor-unknown-${String(minor).padStart(3, '0')}`,
      ext: 'jpg',
      file: seal(baseJpeg, proof),
      proof,
      expected: { outcome: 'authentic', labels: NO_LOCATION_LABELS, not_evaluated: [field], core_hash: hashOf(proof) },
      notes: `\`v\` is \`vcap/1.${minor}\` with one unknown top-level key, \`${field}\`. Same major: §9 says verify what you know and list the rest as not evaluated, whatever the minor number is — this is vector 15's case swept across the minor range instead of asserted once at 7.`
    })
  }
}

// ---- category 5: required fields missing, swept ----------------------------
// Every field shapeProblem() or the version check names, dropped alone. All
// land on *no proof found*: a proof this malformed never reaches the
// signature check, so none of them can read as *tampered* — the two outcomes
// answer different questions ("is this a proof" vs "is this proof's core
// hash still what was signed") and a missing required field is the first one.
{
  const drop = (obj: Proof, path: string): Proof => {
    const parts = path.split('.')
    const clone = JSON.parse(JSON.stringify(obj)) as Proof
    let cursor: Json = clone
    for (let i = 0; i < parts.length - 1; i++) cursor = (cursor as Proof)[parts[i] as string] as Json
    delete (cursor as Proof)[parts[parts.length - 1] as string]
    return clone
  }
  const REQUIRED = ['v', 'capture_id', 'media', 'media.hash', 'media.mime', 'media.w', 'media.h', 'device', 'device.platform', 'device.secure_hw', 'device.key_id', 'sig', 'sig.value', 'sig.pub', 'sig.alg']
  REQUIRED.forEach((path, i) => {
    const full = sign(coreOf())
    const proof = drop(full, path)
    fileCases.push({
      name: `required-missing-${String(i + 1).padStart(2, '0')}-${path.replace(/\./g, '-')}`,
      ext: 'jpg',
      file: seal(baseJpeg, proof),
      proof,
      schemaValid: false,
      expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [] },
      notes: `A sealed file whose proof is missing \`${path}\` (dropped after signing the full core, so the trailer still parses and the JSON is otherwise the vector's usual one). §6.1/§8 require it; the reference verifier's shape check catches its absence before the signature is even read, the same *no proof found* an unparseable payload gets. Schema-invalid for the same reason.`
    })
  })
}

// ---- category 6: JCS at the limit ------------------------------------------
// RFC 8785 defines string and number serialization as ECMAScript's; these are
// the corners where a canonicalizer copied from a spec paragraph and one
// copied from `JSON.stringify`'s actual behavior first disagree.
{
  const jcsCase = (name: string, input: Json, notes: string): void => {
    const bytes = jcs(input)
    jcsCases.push({ name, input, expected: { core_bytes_hex: bytes.toString('hex'), core_hash: createHash('sha256').update(bytes).digest('hex') }, notes })
  }
  jcsCase('jcs-edge-01-empty-object', {}, 'The empty object: `{}`, two bytes. The floor every other JCS vector in this repository builds on top of, pinned on its own.')
  jcsCase('jcs-edge-02-negative-zero', { n: -0 },
    'A member whose value is JavaScript `-0`. RFC 8785 §3.2.2 requires ECMAScript `Number::toString` (via `JSON.stringify`), which maps `-0` to the string `"0"` — the sign is not part of JSON\'s number grammar, only of the IEEE 754 value that produced it. A canonicalizer that special-cased negative numbers by checking a sign bit before formatting, instead of calling the same primitive `JSON.stringify` calls, is the implementation this vector catches.')
  jcsCase('jcs-edge-03-supplementary-plane-string', { s: '\u{1F600}' },
    'A string holding one supplementary-plane character (U+1F600, encoded as a UTF-16 surrogate pair in the JS source and as 4 UTF-8 bytes on the wire). RFC 8785 leaves strings outside the escaped set untouched; a canonicalizer built around UTF-16 code units (as this repository\'s own `jcs.ts` sorts keys by) must still emit valid UTF-8 for the pair as a unit, not two lone surrogates — the frontier between "sorts by code unit" and "encodes by code point".')
  jcsCase('jcs-edge-04-control-character-escape', { s: '' },
    'A string holding U+001F (unit separator), one of the control characters JSON requires escaped and RFC 8785 does not get to choose the spelling of: `JSON.stringify` emits `\\u001f`, lowercase hex. A canonicalizer that uppercases hex escapes (`\\u001F`, otherwise byte-identical) produces different bytes here and nowhere else in the corpus — the shortest string that is not also covered by the sidecar or trailer vectors, none of which carry a raw control character.')
  jcsCase('jcs-edge-05-key-sort-code-unit-order', { a: 1, A: 2, 'é': 3, 'Ａ': 4 },
    'Four one-character keys whose UTF-16 code-unit order (`A` 0x0041 < `a` 0x0061 < `é` 0x00e9 < fullwidth `A` 0xff21) is not their order under any locale collation, which is exactly the ordering a naive "sort the keys" port reaches for if it calls a locale-aware compare instead of comparing code units — RFC 8785 §3.2.3 names UTF-16 code unit order because it is the one order every ECMAScript engine already agrees on without a locale to disagree about.')
}

// ---- category 7: fill bytes in JPEG canonicalization -----------------------
// §4.1 keeps 0xFF fill bytes (padding before a marker) verbatim while
// stripping a JUMBF APP11; canonical.ts walks them one byte at a time
// (`pos += marker === 0xff ? 1 : 2`), so a run of them is the place an
// off-by-one in that walk would first show up as a wrong media.hash instead
// of a wrong byte count.
{
  const app11 = (payload: Buffer): Buffer => {
    const length = Buffer.alloc(2)
    length.writeUInt16BE(payload.length + 2, 0)
    return Buffer.concat([Buffer.from([0xff, 0xeb]), length, payload])
  }
  const jumbf = app11(Buffer.concat([Buffer.from('JP', 'ascii'), Buffer.from([0, 1, 0, 0, 0, 1]), Buffer.from('000000186a756d620000001063327061', 'hex')]))
  const insertAfterApp0 = (jpeg: Buffer, segment: Buffer): Buffer => {
    const app0Len = jpeg.readUInt16BE(4)
    const cut = 2 + 2 + app0Len
    return Buffer.concat([jpeg.subarray(0, cut), segment, jpeg.subarray(cut)])
  };
  [1, 2, 16].forEach((run, i) => {
    // `run` bytes of 0xFF padding, then the real APP11 marker pair.
    const withFillAndJumbf = insertAfterApp0(baseJpeg, Buffer.concat([Buffer.alloc(run, 0xff), jumbf]))
    const withFillOnly = insertAfterApp0(baseJpeg, Buffer.alloc(run, 0xff))
    const proof = sign(coreOf({ media: { mime: 'image/jpeg', w: 16, h: 16, hash: mediaHash(withFillOnly) } }))
    // media.hash must match the canonical bytes with the fill run kept and the
    // JUMBF segment stripped — the base image with the fill bytes inserted and
    // nothing else: §4.1 preserves fill bytes, they are not the segment being
    // dropped.
    fileCases.push({
      name: `fill-byte-run-${String(i + 1).padStart(2, '0')}-length-${run}`,
      ext: 'jpg',
      file: seal(withFillAndJumbf, proof),
      proof,
      expected: { outcome: 'authentic', labels: NO_LOCATION_LABELS, not_evaluated: [], core_hash: hashOf(proof) },
      notes: `A run of ${run} 0xFF fill byte(s) immediately before a JUMBF APP11 segment, inserted after sealing. §4.1 keeps fill bytes and drops only the JUMBF segment, so canonical bytes equal the unmodified base image and \`media.hash\` still matches. Run length ${run} exercises the marker-walk one byte at a time (\`pos += 1\` per fill byte) at a boundary generate.ts's single "APP11 present" vectors never sweep.`
    })
  })
}

// ---- category 8: one random payload bit flip, seeded -----------------------
// Not a boundary sweep — the one place this generator is genuinely seeded.
{
  const proof = sign(coreOf())
  const sealed = seal(baseJpeg, proof)
  const payload = jcs(proof as Json)
  const random = rng(SEED)
  const offset = Math.floor(random() * payload.length)
  const bit = 1 << Math.floor(random() * 8)
  const corrupted = Buffer.from(sealed)
  const payloadStart = corrupted.length - FOOTER_LEN - payload.length
  corrupted[payloadStart + offset] = (corrupted[payloadStart + offset] as number) ^ bit
  fileCases.push({
    name: `payload-bit-flip-seed-${SEED}`,
    ext: 'jpg',
    file: corrupted,
    proof,
    expected: { outcome: 'corrupted_proof', labels: [], not_evaluated: [] },
    notes: `Seed ${SEED} picked byte offset ${offset} of the payload and bit 0x${bit.toString(16)}; flipping it changes the payload without touching the footer, so the CRC — computed over the unmutated payload — no longer matches: *corrupted proof*. The only case in this generator where "same seed, same bytes" is doing real work: every other case is an exhaustive sweep with nothing left to a seed.`
  })
}

// ---- write ------------------------------------------------------------------

rmSync(EDGE, { recursive: true, force: true })
mkdirSync(EDGE, { recursive: true })

let failures = 0
for (const c of fileCases) {
  const dir = join(EDGE, c.name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, `input.${c.ext}`), c.file)
  if (c.proof) writeFileSync(join(dir, 'proof.json'), JSON.stringify(c.proof, null, 2) + '\n')
  const schemaValid = c.schemaValid ?? true
  writeFileSync(join(dir, 'expected.json'), JSON.stringify({ kind: 'file', ...c.expected, ...(c.proof ? { schema_valid: schemaValid } : {}) }, null, 2) + '\n')
  writeFileSync(join(dir, 'NOTES.md'), `# ${c.name}\n\n${c.notes}\n\nGenerated by \`tools/src/generate-edge-cases.ts\` (seed ${SEED}) with the test key in \`tools/src/testkey.ts\`.\n`)

  const actual = pick(verifyFile({ file: c.file, trust }), c.expected)
  if (JSON.stringify(actual) !== JSON.stringify(c.expected)) {
    failures++
    console.error(`[vcap] ${c.name}: expected ${JSON.stringify(c.expected)} got ${JSON.stringify(actual)}`)
  }
  if (c.proof) {
    const schema = validateProof(c.proof)
    if (schema.valid !== schemaValid) {
      failures++
      console.error(`[vcap] ${c.name}: schema says ${schema.valid ? 'valid' : 'invalid'}, expected ${schemaValid ? 'valid' : 'invalid'} ${schema.errors.join('; ')}`)
    }
  }
}

for (const c of jcsCases) {
  const dir = join(EDGE, c.name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'core.json'), JSON.stringify(c.input, null, 2) + '\n')
  writeFileSync(join(dir, 'expected.json'), JSON.stringify({ kind: 'jcs', ...c.expected }, null, 2) + '\n')
  writeFileSync(join(dir, 'NOTES.md'), `# ${c.name}\n\n${c.notes}\n\nGenerated by \`tools/src/generate-edge-cases.ts\` (seed ${SEED}).\n`)
}

console.log(`[vcap] ${fileCases.length + jcsCases.length} edge-case vectors written to vectors/edge-cases/${failures ? `, ${failures} DISAGREE with the reference verifier` : ''}`)
if (failures) process.exit(1)
