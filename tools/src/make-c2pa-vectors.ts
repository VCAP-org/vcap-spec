import 'reflect-metadata'
import { Builder, Reader } from '@contentauth/c2pa-node'
import * as x509 from '@peculiar/x509'
import { p256 } from '@noble/curves/nist.js'
import { createHash, createPrivateKey, createPublicKey, webcrypto } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Json, jcs } from './jcs.js'
import { type Proof, coreBytes, coreHash } from './core.js'
import { mediaHash } from './canonical.js'
import { Flag, buildTrailer, parseTrailer } from './trailer.js'
import { type Box, boxes, children, codecOf, find, readContainer, samplesOf } from './container.js'
import { REDACTION_UUID, TYPE, jumbfGroups } from './jumbf.js'
import { PROOF_LABEL, jpegCarriesStore } from './carrier.js'
import { signEs256 } from './sign.js'
import { TEST_KEY_PKCS8_BASE64 } from './testkey.js'
import { C2PA_TEST_ROOT_PKCS8_BASE64, C2PA_TEST_SIGNER_PKCS8_BASE64 } from './testc2pakey.js'
import { loadTrust } from './trust.js'
import { type Verdict, verifyFile } from './verify.js'
import { validateProof } from './schema.js'

/**
 * Mints the vectors whose files carry a real C2PA Manifest Store (122 is the
 * one that does not need one and lives in `generate.ts`). Run on demand, like
 * `make-attestation-chains.ts`, and never by `npm run generate`, for the same
 * reason: the bytes are not reproducible.
 *
 * What is fixed: every vcap proof (the test key, RFC 6979), the C2PA test
 * credential (`vectors/_trust/c2pa-test/`, keys in `testc2pakey.ts`), the claim
 * signature (RFC 6979 through c2pa-node's callback signer, so it is a function
 * of the claim), the manifest labels and instance IDs (set in every
 * definition), no thumbnail, and no time-stamp: no TSA is ever called, so no
 * manifest carries `sigTst`/`sigTst2` and a validator judges the certificate at
 * its own clock (the leaf is valid until 2046). What is not: c2pa-rs draws a
 * fresh 16-byte salt for every assertion from the operating system's RNG
 * (C2PA 8.4.2.3 asks for random salts) and offers no hook to seed it. Each
 * salt changes the claim, and so its signature, so a second run rewrites every
 * store. The committed files are the vectors; this script is how they were
 * made, and it refuses to write one the reference verifier disagrees with.
 *
 *   npm run generate:c2pa                 # rewrite 123–147
 *   npm run generate:c2pa -- --mint-ca    # re-mint the test CA first
 *
 * With `C2PATOOL` pointing at a c2patool binary, each vector's NOTES.md
 * records what that validator reports too.
 */
const ROOT = join(import.meta.dirname, '..', '..')
const VECTORS = join(ROOT, 'vectors')
const CA_DIR = join(VECTORS, '_trust', 'c2pa-test')
const trust = loadTrust(join(VECTORS, '_trust'))
const C2PATOOL = process.env.C2PATOOL

// ---- the test credential ---------------------------------------------------

const pkcs8 = (b64: string): ReturnType<typeof createPrivateKey> => createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' })
const signerKey = pkcs8(C2PA_TEST_SIGNER_PKCS8_BASE64)

/**
 * The corpus's C2PA signer: a root "vcap-spec test CA" and one claim-signing
 * leaf under it, the profile c2pa-rs 0.91 accepts (C2PA 14.5.1): P-256, v3,
 * not self-signed, AKI and SKI, digitalSignature only, EKU C2PA claim signing
 * (1.3.6.1.4.1.62558.2.1) plus emailProtection, which the default trust
 * configuration requires. No person's name anywhere. Twenty years of validity,
 * because without a trusted time-stamp a validator judges the leaf at its
 * own clock.
 */
const mintCa = async (): Promise<void> => {
  x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0])
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
  const pair = async (b64: string): Promise<webcrypto.CryptoKeyPair> => {
    const der = Buffer.from(b64, 'base64')
    const spki = createPublicKey(pkcs8(b64)).export({ type: 'spki', format: 'der' })
    return {
      privateKey: await webcrypto.subtle.importKey('pkcs8', der, alg, true, ['sign']),
      publicKey: await webcrypto.subtle.importKey('spki', spki, alg, true, ['verify'])
    }
  }
  const rootKeys = await pair(C2PA_TEST_ROOT_PKCS8_BASE64)
  const leafKeys = await pair(C2PA_TEST_SIGNER_PKCS8_BASE64)
  const notBefore = new Date('2026-01-01T00:00:00Z')
  const notAfter = new Date('2046-01-01T00:00:00Z')
  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01', name: 'CN=vcap-spec test CA, OU=FOR TESTING ONLY, O=vcap-spec test', notBefore, notAfter, keys: rootKeys, signingAlgorithm: alg,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey)
    ]
  })
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '02', subject: 'CN=vcap-spec test C2PA signer, OU=FOR TESTING ONLY, O=vcap-spec test', issuer: root.subject, notBefore, notAfter,
    signingAlgorithm: alg, publicKey: leafKeys.publicKey, signingKey: rootKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.4.1.62558.2.1', '1.3.6.1.5.5.7.3.4'], false),
      await x509.SubjectKeyIdentifierExtension.create(leafKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(rootKeys.publicKey)
    ]
  })
  mkdirSync(CA_DIR, { recursive: true })
  writeFileSync(join(CA_DIR, 'root.pem'), root.toString('pem') + '\n')
  writeFileSync(join(CA_DIR, 'signer.pem'), leaf.toString('pem') + '\n')
}

if (process.argv.includes('--mint-ca')) await mintCa()
const rootPem = readFileSync(join(CA_DIR, 'root.pem'), 'utf8')
const signerPem = readFileSync(join(CA_DIR, 'signer.pem'), 'utf8')
const signerScalar = new Uint8Array(Buffer.from((signerKey.export({ format: 'jwk' }) as { d: string }).d, 'base64url'))

// ---- c2pa-node -------------------------------------------------------------

// No thumbnail (it would be most of every file), no automatic time-stamp
// assertion, and `/free` excluded from BMFF hashes unless a vector says not.
const buildSettings = (excludeFree = true): object => ({
  builder: { thumbnail: { enabled: false }, auto_timestamp_assertion: { enabled: false }, bmff_hash_exclude_free_and_skip_boxes: excludeFree },
  verify: { ocsp_fetch: false, remote_manifest_fetch: false }
})
// What a validator is assumed to trust: this corpus's test root, nothing else.
const readSettings = { trust: { trust_anchors: rootPem }, verify: { ocsp_fetch: false, remote_manifest_fetch: false } }

interface ManifestSpec {
  asset: Buffer
  mime: string
  label: string
  proof?: Proof | string
  proofLabel?: string
  /** `edit`: c2pa-rs opens the source (or `parent`) as `parentOf`. */
  parent?: { asset: Buffer, mime: string }
  components?: { asset: Buffer, mime: string }[]
  actions?: string[]
  redactions?: string[]
  noEmbed?: boolean
  excludeFree?: boolean
}

const c2paSign = async (spec: ManifestSpec): Promise<{ file: Buffer, store: Buffer }> => {
  const assertions: object[] = []
  if (spec.proof !== undefined) assertions.push({ label: spec.proofLabel ?? PROOF_LABEL, data: typeof spec.proof === 'string' ? JSON.parse(spec.proof) : spec.proof, kind: 'Json' })
  const builder = Builder.withJson({
    claim_generator_info: [{ name: 'vcap-spec vector generator', version: '2.1.0' }],
    title: `input.${spec.mime === 'image/jpeg' ? 'jpg' : 'mp4'}`,
    format: spec.mime,
    instance_id: `xmp:iid:${spec.label.slice('urn:c2pa:'.length)}`,
    label: spec.label,
    assertions
  } as never, buildSettings(spec.excludeFree))
  builder.setIntent('edit')
  if (spec.parent) await builder.addIngredient(JSON.stringify({ title: 'parent', relationship: 'parentOf', label: 'parent' }), { buffer: spec.parent.asset, mimeType: spec.parent.mime })
  for (const [i, c] of (spec.components ?? []).entries()) await builder.addIngredient(JSON.stringify({ title: `component ${i}`, relationship: 'componentOf', label: `component-${i}` }), { buffer: c.asset, mimeType: c.mime })
  for (const action of spec.actions ?? []) builder.addAction(JSON.stringify({ action }))
  for (const uri of spec.redactions ?? []) builder.addRedaction(uri, 'c2pa.PII.present')
  if (spec.noEmbed) builder.setNoEmbed(true)
  const out = { buffer: null as Buffer | null }
  const store = await builder.signConfigAsync(
    async (data: Buffer) => Buffer.from(p256.sign(new Uint8Array(createHash('sha256').update(data).digest()), signerScalar, { lowS: true, prehash: false })),
    { alg: 'es256', certs: [Buffer.from(signerPem)], reserveSize: 2048, directCoseHandling: false },
    { buffer: spec.asset, mimeType: spec.mime }, out)
  return { file: out.buffer ?? spec.asset, store }
}

type C2paBlock = { validator: string, validation_state: string, success: string[], informational: string[], failure: string[] } | { validator: string, error: string }
const VALIDATOR = 'c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem'
const codes = (list: { code: string }[] | undefined): string[] => [...new Set((list ?? []).map((c) => c.code))].sort()

const c2paReport = async (file: Buffer, mime: string, external?: Buffer): Promise<C2paBlock> => {
  try {
    const reader = external
      ? await Reader.fromManifestDataAndAsset(external, { buffer: file, mimeType: mime }, readSettings)
      : await Reader.fromAsset({ buffer: file, mimeType: mime }, readSettings)
    if (!reader) return { validator: VALIDATOR, error: 'no C2PA Manifest Store found' }
    const store = reader.json() as { validation_state?: string, validation_results?: { activeManifest?: { success?: { code: string }[], informational?: { code: string }[], failure?: { code: string }[] } } }
    const active = store.validation_results?.activeManifest
    return { validator: VALIDATOR, validation_state: store.validation_state ?? 'unknown', success: codes(active?.success), informational: codes(active?.informational), failure: codes(active?.failure) }
  } catch (e) {
    return { validator: VALIDATOR, error: String((e as Error).message ?? e) }
  }
}

/** c2patool's answer, for NOTES.md; not an expectation. */
const c2patool = (dir: string, input: string, external: string | null): string => {
  if (!C2PATOOL) return 'c2patool was not run for this vector.'
  const args = [join(dir, input), ...(external ? ['--external-manifest', join(dir, external)] : []), 'trust', '--trust_anchors', join(CA_DIR, 'root.pem')]
  const version = execFileSync(C2PATOOL, ['--version'], { encoding: 'utf8' }).trim()
  try {
    const out = JSON.parse(execFileSync(C2PATOOL, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })) as { validation_state?: string, validation_results?: { activeManifest?: { success?: { code: string }[], informational?: { code: string }[], failure?: { code: string }[] } } }
    const a = out.validation_results?.activeManifest
    const list = (name: string, l: string[]): string => `${name}: ${l.length ? l.map((c) => `\`${c}\``).join(', ') : 'none'}`
    return `${version} (trust anchor \`_trust/c2pa-test/root.pem\`): **${out.validation_state ?? 'no state'}**; ${list('success', codes(a?.success))}; ${list('informational', codes(a?.informational))}; ${list('failure', codes(a?.failure))}.`
  } catch (e) {
    const err = e as { stderr?: string, stdout?: string, message: string }
    const said = `${err.stdout ?? ''}${err.stderr ?? ''}`.trim().split('\n').filter(Boolean).pop() ?? err.message
    return `${version} (trust anchor \`_trust/c2pa-test/root.pem\`): refused the file — \`${said.replace(/`/g, "'")}\`.`
  }
}

// ---- JUMBF editing, for the vectors a claim generator would not write -------

interface RawSuper { kind: 'super', description: Buffer, type: string, toggles: number, label: string | null, children: RawNode[] }
type RawNode = RawSuper | { kind: 'box', bytes: Buffer }

const rawParse = (bytes: Buffer): RawSuper => {
  const list = (start: number, end: number): { start: number, end: number, type: string }[] => {
    const out: { start: number, end: number, type: string }[] = []
    for (let at = start; at < end;) { const size = bytes.readUInt32BE(at); out.push({ start: at, end: at + size, type: bytes.toString('latin1', at + 4, at + 8) }); at += size }
    return out
  }
  const node = (start: number, end: number): RawSuper => {
    const [description, ...rest] = list(start + 8, end) as [{ start: number, end: number }, ...{ start: number, end: number, type: string }[]]
    const d = bytes.subarray(description.start, description.end)
    const toggles = d[24] as number
    const label = toggles & 0x02 ? d.toString('utf8', 25, d.indexOf(0, 25)) : null
    return { kind: 'super', description: d, type: d.subarray(8, 24).toString('hex'), toggles, label, children: rest.map((c) => c.type === 'jumb' ? node(c.start, c.end) : { kind: 'box', bytes: bytes.subarray(c.start, c.end) }) }
  }
  return node(0, bytes.readUInt32BE(0))
}

const box = (type: string, payload: Buffer): Buffer => {
  const header = Buffer.alloc(8)
  header.writeUInt32BE(8 + payload.length, 0)
  header.write(type, 4, 'latin1')
  return Buffer.concat([header, payload])
}
const rawSerialize = (n: RawNode): Buffer => n.kind === 'box' ? n.bytes : box('jumb', Buffer.concat([n.description, ...n.children.map(rawSerialize)]))
const description = (type: string, toggles: number, label: string): Buffer => box('jumd', Buffer.concat([Buffer.from(type, 'hex'), Buffer.from([toggles]), Buffer.from(`${label}\0`, 'utf8')]))
const supers = (n: RawSuper): RawSuper[] => n.children.filter((c): c is RawSuper => c.kind === 'super')
const manifestNamed = (store: RawSuper, label: string): RawSuper => supers(store).find((m) => m.label === label) as RawSuper
const assertionsOf = (m: RawSuper): RawSuper => supers(m).find((c) => c.type === TYPE.assertionStore) as RawSuper

/** The store of a JPEG, and the JPEG with that store replaced by another. */
const jpegStore = (jpeg: Buffer): { en: number, bytes: Buffer, first: number, end: number } => {
  const group = jumbfGroups(jpeg).find((g) => g.type === TYPE.store)
  if (!group) throw new Error('no C2PA store in the JPEG')
  const [first] = group.segments
  const last = group.segments[group.segments.length - 1] as { end: number }
  const bytes = Buffer.concat(group.segments.map((s, i) => i === 0 ? s.packet : s.packet.subarray(8)))
  return { en: group.en as number, bytes, first: (first as { start: number }).start, end: last.end }
}

// A.3.1 and ISO 19566-5 D.2: CI, En, Z, then the box; every packet after the
// first repeats LBox and TBox.
const app11Packets = (store: Buffer, en: number): Buffer => {
  const room = 65535 - 2 - 8
  const out: Buffer[] = []
  for (let at = 0, z = 1; at < store.length; z++) {
    const chunk = at === 0 ? store.subarray(0, room) : Buffer.concat([store.subarray(0, 8), store.subarray(at, at + room - 8)])
    at += at === 0 ? chunk.length : chunk.length - 8
    const head = Buffer.alloc(12)
    head.writeUInt16BE(0xffeb, 0)
    head.writeUInt16BE(2 + 8 + chunk.length, 2)
    head.write('JP', 4, 'latin1')
    head.writeUInt16BE(en, 6)
    head.writeUInt32BE(z, 8)
    out.push(head, chunk)
  }
  return Buffer.concat(out)
}
const jpegWithStore = (jpeg: Buffer, store: RawSuper | Buffer): Buffer => {
  const old = jpegStore(jpeg)
  const bytes = Buffer.isBuffer(store) ? store : rawSerialize(store)
  return Buffer.concat([jpeg.subarray(0, old.first), app11Packets(bytes, old.en), jpeg.subarray(old.end)])
}

// ---- vcap ------------------------------------------------------------------

const testKey = pkcs8(TEST_KEY_PKCS8_BASE64)
const readVector = (name: string, file: string): Buffer => readFileSync(join(VECTORS, name, file))
const proofOf = (name: string): Proof => JSON.parse(readVector(name, 'proof.json').toString('utf8')) as Proof
const flagsFor = (proof: Proof): number =>
  ('segments' in proof ? Flag.SEGMENTS : 0) | ((proof.policy as Proof | undefined)?.pseudonymous === true ? Flag.PSEUDONYMOUS : 0)
const seal = (media: Buffer, proof: Proof, crcOverride?: number): Buffer =>
  Buffer.concat([media, buildTrailer(jcs(proof as Json), { flags: flagsFor(proof), crcOverride })])
const unsealed = (file: Buffer): Buffer => { const t = parseTrailer(file); if (t.kind !== 'ok') throw new Error('no trailer'); return file.subarray(0, t.mediaEnd) }
const hashOf = (p: Proof): string => coreHash(p).toString('hex')
const resign = (proof: Proof): Proof => ({ ...proof, sig: { ...(proof.sig as Proof), value: signEs256(coreBytes(proof), testKey).toString('base64url') } })

const baseJpeg = readFileSync(join(VECTORS, '_media', 'base.jpg'))
const baseMp4 = readFileSync(join(VECTORS, '_media', 'base.mp4'))
const photo = proofOf('01-jpeg-sealed')
const sealedJpeg = readVector('01-jpeg-sealed', 'input.jpg')
const timestamped = proofOf('59-jpeg-timestamped')
const device = readVector('36-mp4-container-verified', 'input.mp4')
const deviceProof = JSON.parse((parseTrailer(device) as { payload: Buffer }).payload.toString('utf8')) as Proof
const cutClip = unsealed(readVector('89-mp4-container-cut-clip', 'input.mp4'))

// Flips one byte deep in the entropy-coded data (generate.ts does the same).
const editPixels = (jpeg: Buffer): Buffer => { const out = Buffer.from(jpeg); const at = out.length - 40; out[at] = (out[at] as number) ^ 0x55; return out }

const label = (vector: number, role: number): string => `urn:c2pa:76636170-0000-4000-8000-${String(vector).padStart(8, '0')}${String(role).padStart(4, '0')}`

const PHOTO_LABELS = ['integrity unevaluated', 'key not in transparency log', 'location declared only', 'no trusted time', 'not anchored', 'origin not hardware-attested', 'watermark not evaluated']
const DEVICE_LABELS = ['integrity unevaluated', 'key not in transparency log', 'no trusted time', 'no watermark', 'not anchored', 'origin not hardware-attested']
const NOT_FOUND = { outcome: 'no_proof_found' as const, labels: [], not_evaluated: [] }
const NOT_COVERED = { expect: 'not_covered', reason: 'the proof travels in a C2PA manifest, which no vcap writer produces' }

interface C2paVector {
  name: string
  ext: 'jpg' | 'mp4'
  kind: 'file' | 'container'
  file: Buffer
  sidecar?: Buffer
  externalStore?: Buffer
  proof?: Proof
  verifierClock?: number
  expected: Partial<Verdict> & { outcome: Verdict['outcome'] }
  writer?: { expect: string, error?: string, reason?: string }
  notes: string
}

const vectors: C2paVector[] = []
const add = (v: C2paVector): void => { vectors.push({ writer: NOT_COVERED, ...v, expected: { ...v.expected, ...(v.expected.labels ? { labels: [...v.expected.labels].sort() } : {}) } }) }
const src = (depth: number, manifest: string): Verdict['proof_source'] => ({ kind: 'c2pa', manifest, depth })

// ---- JPEG: the carrier and the precedence (§3.1, §3.2) ---------------------

// A claim generator that receives a sealed photo and writes Content
// Credentials over it, carrying the proof as a gathered assertion: the order
// `c2pa-interop-1.0.md` §3.1 requires for JPEG, and the file the rest of the
// JPEG vectors are cut from.
const carried = await c2paSign({ asset: sealedJpeg, mime: 'image/jpeg', label: label(123, 1), proof: photo })
const stripped = unsealed(carried.file)

add({ name: '123-jpeg-c2pa-carrier-after-sealing', ext: 'jpg', kind: 'file', file: carried.file, proof: photo,
  expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(photo), proof_source: { kind: 'trailer' } },
  notes: 'Vector 01 — a sealed photo — after a C2PA claim generator wrote Content Credentials over it, carrying the proof as `io.github.vcap-org.vcap.proof` in `gathered_assertions`: the order `spec/c2pa-interop-1.0.md` §3.1 requires for JPEG, and the only one in which both bindings hold. The `c2pa.hash.data` covers every byte after EOI, the trailer included.\n\nThe trailer is the proof (§3.1, step 1). The manifest\'s copy is not byte-identical to the payload — c2pa-rs re-serializes the JSON it is given — and it is the same proof, because copies are compared as `JCS(parse(a)) == JCS(parse(b))`: a reader that compared bytes here would report *manifest copy differs* on a file nobody touched. **Authentic**, the verdict of vector 01; `media.hash` is unchanged because §4.1 removes the C2PA store\'s APP11 segments.' })

add({ name: '124-jpeg-c2pa-carrier-trailer-stripped', ext: 'jpg', kind: 'file', file: stripped, proof: photo,
  expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(photo), proof_source: src(0, label(123, 1)) },
  notes: 'Vector 123 cut at EOI: the trailer is gone, the Content Credentials are not — what a tool that truncates a JPEG at its end marker leaves. No footer, so the proof is read from the active manifest (§3.1, step 4; §3.2, depth 0), and the canonical bytes are the whole received file minus the store\'s APP11 segments (§4.1), which are the canonical bytes of vector 01. **Authentic**, with `proof_source` naming the manifest; where the proof sat is diagnostic and never a label.\n\nThe C2PA side reads the same file the other way: its data hash covered the trailer, so the manifest no longer matches. Each format is right about the bytes it binds.' })

// The J1 case: an attachment arrives after the manifest was written, and the
// trailer is replaced without re-issuing the manifest.
add({ name: '125-jpeg-c2pa-manifest-copy-differs', ext: 'jpg', kind: 'file', file: seal(stripped, timestamped), proof: timestamped, verifierClock: 1757419200000,
  expected: { outcome: 'authentic', labels: ['integrity unevaluated', 'key not in transparency log', 'location declared only', 'manifest copy differs', 'not anchored', 'origin not hardware-attested', 'watermark not evaluated'], not_evaluated: [], core_hash: hashOf(timestamped), level: { claimed: 'tee', proven: 'none', ceiling: 'amber' }, validated_at: { instant: '2025-09-08T12:01:00.000Z', source: 'timestamp' }, proof_source: { kind: 'trailer' } },
  notes: 'Vector 123 after its trailer was replaced (§3, *Replacing the trailer*) to add a time-stamp token that arrived later — vector 59\'s proof, same core, one more attachment — **without re-issuing the manifest**, which still carries the proof as it was. This is what rule J1 (`spec/c2pa-interop-1.0.md` §2.1) forbids a writer, and the reason is on the C2PA side: the manifest\'s data hash covered the old trailer and no longer matches.\n\nThe reader is unaffected: the trailer wins (§3.1, step 1), the verdict is vector 59\'s, and the manifest\'s copy differs from it as JCS, so the verdict carries *manifest copy differs* — a warning on an otherwise valid verdict, like *sidecar differs*.' })

add({ name: '126-jpeg-c2pa-carrier-footer-crc-mismatch', ext: 'jpg', kind: 'file', file: (await c2paSign({ asset: seal(baseJpeg, photo, 0xdeadbeef), mime: 'image/jpeg', label: label(126, 1), proof: photo })).file, proof: photo,
  expected: { outcome: 'corrupted_proof', labels: [], not_evaluated: [] },
  notes: 'Vector 06 — a structurally valid footer whose CRC does not match — with Content Credentials written over it that carry an intact copy of the proof. **Corrupted proof**, whatever the store holds (§3.1, step 2), exactly as vector 72 is with an intact sidecar: the carrier is a fallback for a trailer that is absent, never a substitute for one that was found and is broken.' })

add({ name: '127-jpeg-c2pa-carrier-sidecar-differs', ext: 'jpg', kind: 'file', file: stripped, sidecar: jcs(timestamped as Json), proof: photo,
  expected: { outcome: 'authentic', labels: [...PHOTO_LABELS, 'sidecar differs'], not_evaluated: [], core_hash: hashOf(photo), proof_source: src(0, label(123, 1)) },
  notes: 'Vector 124 with a sidecar that holds vector 59\'s proof. With no footer the active manifest\'s proof outranks the sidecar (§3.1, step 4): it travelled inside the bytes it binds, as C2PA\'s embedded store outranks a remote one (15.5.2.1). The sidecar is compared with it as JCS and differs: **authentic** on the manifest\'s proof — vector 01\'s verdict — with *sidecar differs*.' })

add({ name: '128-jpeg-c2pa-foreign-proof', ext: 'jpg', kind: 'file', file: (await c2paSign({ asset: editPixels(baseJpeg), mime: 'image/jpeg', label: label(128, 1), proof: photo })).file, proof: photo,
  expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(photo), proof_source: src(0, label(128, 1)) },
  notes: 'A photo that is not vector 01\'s — one byte of entropy-coded data changed — with a manifest that carries vector 01\'s proof in its **active** manifest. Depth 0 reads like a sidecar (§3.2): the manifest presents the proof as this file\'s, the canonical bytes are not the ones the key sealed, and on a photo that is **tampered** (§8), the verdict of vector 71. The C2PA side is valid — its signer vouches for these bytes, not for the proof inside.' })

// A source photo with its proof carried at depth 1, edited by a C2PA-aware
// editor that declared the edit.
{
  const edited = await c2paSign({ asset: editPixels(baseJpeg), mime: 'image/jpeg', label: label(129, 1), parent: { asset: carried.file, mime: 'image/jpeg' }, actions: ['c2pa.edited'] })
  add({ name: '129-jpeg-c2pa-ancestor-edited', ext: 'jpg', kind: 'file', file: edited.file, proof: photo,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [], core_hash: hashOf(photo), proof_source: src(1, label(123, 1)) },
    notes: 'An edit of vector 123, declared: its active manifest opens vector 123 as `parentOf`, records `c2pa.edited`, and carries no proof of its own; vector 123\'s manifest travels in the store as the ingredient\'s. No footer, no proof at depth 0, no sidecar: the proof is found one step up the `parentOf` chain (§3.2, depth 1), and it is the proof of the **source** capture.\n\nThe pixels are not the source\'s, and nothing locates the source in them, so the outcome is **no proof found**, reason *Content Credentials carry the proof of a source capture*, with `proof_source` at depth 1 — **never tampered**: a modification declared in C2PA is not an accusation the proof can make. Vector 130 is the same file with the proof beside it.' })
  add({ name: '130-jpeg-c2pa-ancestor-edited-sidecar', ext: 'jpg', kind: 'file', file: edited.file, sidecar: jcs(photo as Json), proof: photo,
    expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(photo), proof_source: { kind: 'sidecar' } },
    notes: 'Vector 129 with vector 01\'s proof in a sidecar. The sidecar outranks the `parentOf` chain (§3.1, step 4): it is presented as **this** file\'s proof, and this file is not the one the key sealed — **tampered**, as vector 71. Beside vector 129 it pins the order: a reader that consulted the chain before the sidecar would say *no proof found*.' })
}

// ---- JPEG: the writer's guard ------------------------------------------------

const withStore = await c2paSign({ asset: baseJpeg, mime: 'image/jpeg', label: label(131, 1) })
{
  if (!jpegCarriesStore(withStore.file)) throw new Error('131: the guard does not see the store')
  add({ name: '131-jpeg-c2pa-store-refused-for-sealing', ext: 'jpg', kind: 'file', file: withStore.file,
    expected: NOT_FOUND,
    writer: { expect: 'refuse', error: 'VCAP_C2PA_MANIFEST_PRESENT' },
    notes: 'An unsealed photo that already carries Content Credentials, with no proof in them. A **reader** finds no footer, no proof in the active manifest, nothing up the chain: **no proof found**.\n\nA **writer** asked to seal it MUST refuse, error `VCAP_C2PA_MANIFEST_PRESENT` (`spec/c2pa-interop-1.0.md` §2.1): the store\'s `c2pa.hash.data` covers every byte after EOI, so appending a trailer breaks somebody else\'s signature. `expected.json` says so in `writer`. The pipeline that wants both seals first and writes the manifest afterwards (vector 123).' })
}

// ---- JPEG: an external store (§3.2) ------------------------------------------

{
  const external = await c2paSign({ asset: baseJpeg, mime: 'image/jpeg', label: label(132, 1), proof: photo, noEmbed: true })
  if (!external.file.equals(baseJpeg)) throw new Error('132: a no-embed signature changed the asset')
  add({ name: '132-jpeg-c2pa-external-store', ext: 'jpg', kind: 'file', file: baseJpeg, externalStore: external.store, proof: photo,
    expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(photo), proof_source: src(0, label(132, 1)) },
    notes: 'The unsealed photo of `_media/`, with its Content Credentials as a separate store, `input.c2pa` (`application/c2pa`, C2PA 11.4), which the caller hands over — the verifier looks nowhere and fetches nothing (§3.2). The file embeds no store, so the external one is read: the proof in its active manifest, depth 0, over the canonical bytes of the whole file. **Authentic**, `proof_source` naming the external store\'s manifest (kind `c2pa`, as for an embedded store). An embedded store, when there is one, outranks an external store, as C2PA 15.5.2.1 has it.' })
}

// ---- JPEG: the assertion's box (c2pa-interop §2.1) ----------------------------

{
  const store = () => rawParse(jumbfBytes(stripped))
  const proofBox = (s: RawSuper): RawSuper => supers(assertionsOf(manifestNamed(s, label(123, 1)))).find((a) => a.label === PROOF_LABEL) as RawSuper

  {
    const s = store()
    const b = proofBox(s)
    b.description = description(TYPE.json, 0x03, PROOF_LABEL)
    add({ name: '133-jpeg-c2pa-assertion-unsalted', ext: 'jpg', kind: 'file', file: jpegWithStore(stripped, s), proof: photo,
      expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(photo), proof_source: src(0, label(123, 1)) },
      notes: 'Vector 124 with the proof assertion\'s description box rewritten without its salt: toggles `0x03` (requestable, label) instead of c2pa-rs\'s `0x13` (requestable, label, private `c2sh` salt box). A reader accepts both (`spec/c2pa-interop-1.0.md` §2.1): the salt is for redaction (C2PA 6.6, 8.4.2.3) and says nothing about the proof. **Authentic** at depth 0.\n\nThe edit is ours, not a claim generator\'s, so the C2PA side no longer matches the assertion\'s hash: a JUMBF box a validator recomputes and the vcap reader never does.' })
  }
  {
    const s = store()
    manifestNamed(s, label(123, 1)).description = description(TYPE.legacyManifest, 0x03, label(123, 1))
    add({ name: '134-jpeg-c2pa-legacy-manifest-type', ext: 'jpg', kind: 'file', file: jpegWithStore(stripped, s), proof: photo,
      expected: { outcome: 'authentic', labels: PHOTO_LABELS, not_evaluated: [], core_hash: hashOf(photo), proof_source: src(0, label(123, 1)) },
      notes: 'Vector 124 with its manifest typed `c2md` (63326D64-…) instead of `c2ma`: the legacy standard-manifest type that C2PA 11.2.2 says manifest consumers accept and claim generators do not write. A reader reads `c2ma`, `c2um` and `c2md` alike: **authentic** at depth 0.' })
  }
  {
    const s = store()
    proofBox(s).description = description(TYPE.json, 0x03, `${PROOF_LABEL}__1`)
    add({ name: '135-jpeg-c2pa-assertion-instance-suffixed', ext: 'jpg', kind: 'file', file: jpegWithStore(stripped, s), proof: photo,
      expected: NOT_FOUND,
      notes: `Vector 124 whose only proof assertion is labelled \`${PROOF_LABEL}__1\` — the second-instance form of C2PA 6.4. One instance per manifest, and only the unsuffixed label is it (\`spec/c2pa-interop-1.0.md\` §2.1): a \`__n\` instance is ignored, so this manifest carries no proof. **No proof found**; a reader that matched the label by prefix would say *authentic*.` })
  }
}

// ---- JPEG: redaction (C2PA 6.8) — both forms read as absence -------------------

{
  const m0 = label(123, 1)
  const uri = `self#jumbf=/c2pa/${m0}/c2pa.assertions/${PROOF_LABEL}`
  const redacting = await c2paSign({ asset: baseJpeg, mime: 'image/jpeg', label: label(136, 1), parent: { asset: carried.file, mime: 'image/jpeg' }, redactions: [uri] })
  const original = supers(assertionsOf(manifestNamed(rawParse(jumbfBytes(stripped)), m0))).find((a) => a.label === PROOF_LABEL) as RawSuper
  const graft = (withBox: RawSuper): Buffer => {
    const s = rawParse(jumbfBytes(redacting.file))
    const store = assertionsOf(manifestNamed(s, m0))
    store.children = [...store.children.filter((c) => !(c.kind === 'super' && c.label === PROOF_LABEL)), withBox]
    return jpegWithStore(redacting.file, s)
  }
  add({ name: '136-jpeg-c2pa-assertion-redacted-listed', ext: 'jpg', kind: 'file', file: graft(original), proof: photo,
    expected: NOT_FOUND,
    notes: `The unsealed photo with Content Credentials whose active manifest opens vector 123 as \`parentOf\` and **redacts** its proof: \`${uri}\` is in the active claim's \`redacted_assertions\` (C2PA 6.8). c2pa-rs removed the box; this vector puts it back, intact, so the only thing saying it is gone is the claim. An assertion any claim of the store lists as redacted is absent, whatever box is still there (§3.2): **no proof found**. A reader that ignored the list would find vector 01's proof at depth 1 over bytes it matches, and say *authentic*.` })
  const zeroed: RawSuper = { ...original, children: [{ kind: 'box', bytes: box('uuid', Buffer.concat([Buffer.from(REDACTION_UUID, 'hex'), Buffer.alloc(64)])) }] }
  add({ name: '137-jpeg-c2pa-assertion-redacted-uuid-box', ext: 'jpg', kind: 'file', file: graft(zeroed), proof: photo,
    expected: NOT_FOUND,
    notes: 'Vector 136 with the second form of redaction C2PA 6.8 allows: the labelled assertion box is kept and its content replaced by a single UUID content box carrying the C2PA Redaction UUID (CAA98EEE-9D4D-F80E-86AD-4DFFCA263973) and zeros. No JSON content box, no proof: **no proof found**. Both forms read as absence (§3.2).' })
}

// ---- JPEG: where a reader must not look ----------------------------------------

{
  const s = rawParse(jumbfBytes(stripped))
  manifestNamed(s, label(123, 1)).description = description(TYPE.compressedManifest, 0x03, label(123, 1))
  add({ name: '138-jpeg-c2pa-compressed-active-manifest', ext: 'jpg', kind: 'file', file: jpegWithStore(stripped, s), proof: photo,
    expected: NOT_FOUND,
    notes: 'Vector 124 with its active manifest typed `c2cm` — a compressed manifest (C2PA 11.2.4), whose content is a Brotli `brob` box. It is not one here: the type was relabelled over an uncompressed manifest so that a reader that ignored the type would find the proof. A compressed manifest is not read in this version (§3.2): no proof in it, no chain through it. **No proof found**.' })
}

{
  // Three generations, then the middle one's parent reference pointed at the
  // youngest: 2 → 1 → 2. The proof sits in generation 0, which only a reader
  // that searched every manifest instead of walking the chain would reach.
  const g0 = await c2paSign({ asset: sealedJpeg, mime: 'image/jpeg', label: label(139, 0), proof: photo })
  const g1 = await c2paSign({ asset: baseJpeg, mime: 'image/jpeg', label: label(139, 1), parent: { asset: g0.file, mime: 'image/jpeg' } })
  const g2 = await c2paSign({ asset: baseJpeg, mime: 'image/jpeg', label: label(139, 2), parent: { asset: g1.file, mime: 'image/jpeg' } })
  const bytes = jumbfBytes(g2.file)
  const from = Buffer.from(`self#jumbf=/c2pa/${label(139, 0)}`, 'utf8')
  const to = Buffer.from(`self#jumbf=/c2pa/${label(139, 2)}`, 'utf8')
  const g1Store = rawSerialize(manifestNamed(rawParse(bytes), label(139, 1)))
  const at = bytes.indexOf(g1Store)
  const cyclic = Buffer.from(bytes)
  let hits = 0
  // Every reference inside generation 1 — the ingredient's activeManifest and
  // claimSignature both start with the manifest's URI.
  for (let hit = cyclic.indexOf(from, at); hit >= 0 && hit < at + g1Store.length; hit = cyclic.indexOf(from, hit + 1)) { to.copy(cyclic, hit); hits++ }
  if (at < 0 || hits === 0) throw new Error('139: generation 1 does not reference generation 0')
  add({ name: '139-jpeg-c2pa-ingredient-cycle', ext: 'jpg', kind: 'file', file: jpegWithStore(g2.file, cyclic), proof: photo,
    expected: NOT_FOUND,
    notes: `A store of three manifests — ${label(139, 0)} carrying vector 01's proof, ${label(139, 1)} opening it as \`parentOf\`, ${label(139, 2)} (active) opening that — in which generation 1's parent reference was rewritten to point at generation 2: the chain is 2 → 1 → 2. A reader follows \`parentOf\` without revisiting a manifest (§3.2), so it stops at the second step with nothing found: **no proof found**. The proof in generation 0 is reachable only by a reader that searched every manifest, which §3.2 forbids; the file is the unsealed photo it would have matched.` })
}

{
  const composite = await c2paSign({ asset: baseJpeg, mime: 'image/jpeg', label: label(140, 1), components: [{ asset: carried.file, mime: 'image/jpeg' }] })
  add({ name: '140-jpeg-c2pa-component-only', ext: 'jpg', kind: 'file', file: composite.file, proof: photo,
    expected: NOT_FOUND,
    notes: 'The unsealed photo with Content Credentials whose active manifest has vector 123 as a `componentOf` ingredient — placed into this asset, not the asset it was made from — and a `parentOf` ingredient with no manifest (the photo itself, opened). `componentOf` and `inputTo` are never followed (§3.2): a component\'s proof is about a part, and a reader that followed it would attribute a capture to a composite. **No proof found**; a reader that followed it would read vector 01\'s proof over bytes it happens to match, and say *authentic*.' })
}

{
  const one = jpegStore(stripped)
  const twice = Buffer.concat([stripped.subarray(0, one.end), app11Packets(one.bytes, one.en + 1), stripped.subarray(one.end)])
  add({ name: '141-jpeg-c2pa-two-stores', ext: 'jpg', kind: 'file', file: twice, proof: photo,
    expected: NOT_FOUND,
    notes: 'Vector 124 with its C2PA Manifest Store embedded twice, as two JUMBF APP11 boxes with different `En`. C2PA 15.5.2.1: with more than one embedded store, all are invalid and validation proceeds as if none were found. The reader does the same — no carrier (§3.2) — and with no footer and no sidecar the verdict is **no proof found**. A reader that took the first store would say *authentic*.' })
}

{
  // Vector 131's manifest with vector 123's proof box placed in its assertion
  // store, and its claim left as it was.
  const s = rawParse(jumbfBytes(withStore.file))
  const box = supers(assertionsOf(manifestNamed(rawParse(jumbfBytes(stripped)), label(123, 1)))).find((a) => a.label === PROOF_LABEL) as RawSuper
  assertionsOf(manifestNamed(s, label(131, 1))).children.push(box)
  add({ name: '142-jpeg-c2pa-assertion-not-in-claim', ext: 'jpg', kind: 'file', file: jpegWithStore(withStore.file, s), proof: photo,
    expected: NOT_FOUND,
    notes: 'Vector 131 — the unsealed photo with a manifest that carries no proof — with vector 123\'s proof assertion box placed in the manifest\'s assertion store and the claim left as it was: neither `created_assertions` nor `gathered_assertions` lists it. An assertion the claim does not list is not part of the manifest (C2PA 6.6, 10.2.2), and the reader ignores it (§3.2): **no proof found**. A reader that took any box with the right label would read vector 01\'s proof over bytes it matches and say *authentic*.' })
}

// ---- ISO-BMFF: the manifest before the seal (c2pa-interop §3.2) ----------------

{
  const reference = proofOf('33-mp4-video-sealed')
  for (const [n, excludeFree] of [[143, true], [144, false]] as const) {
    const signed = await c2paSign({ asset: baseMp4, mime: 'video/mp4', label: label(n, 1), excludeFree })
    const proof = resign({ ...reference, media: { ...(reference.media as Proof), hash: mediaHash(signed.file) } })
    add({ name: excludeFree ? '143-mp4-c2pa-free-excluded' : '144-mp4-c2pa-free-hashed', ext: 'mp4', kind: 'file', file: seal(signed.file, proof), proof,
      expected: { outcome: 'authentic', labels: [...PHOTO_LABELS, 'segment content not recomputed'], not_evaluated: [], core_hash: hashOf(proof), segments: { verified: [] }, proof_source: { kind: 'trailer' } },
      notes: excludeFree
        ? 'The two-frame MP4 of `_media/`, given Content Credentials **before** sealing (the order `spec/c2pa-interop-1.0.md` §3.2 requires for ISO-BMFF) with c2pa-rs\'s default `c2pa.hash.bmff.v3` exclusions — the C2PA `uuid` box, `/ftyp`, `/mfra`, and `/free` and `/skip` — then sealed: the proof of vector 33 with `media.hash` over the file as it now is, manifest box included, and the trailer appended as the last box.\n\nvcap: **authentic**, the manifest is content inside `media.hash` (§4.1), and the chain is checked at message level only, as in vector 33. C2PA: the trailer is a `free` box, excluded, so the BMFF hash still matches — and c2pa-rs reports the informational `assertion.bmffHash.additionalExclusionsPresent` for `/free` and `/skip` all the same, recorded in `expected.json` so no implementation promises otherwise.'
        : 'Vector 143 signed with `/free` and `/skip` **not** on the exclusion list (`builder.bmff_hash_exclude_free_and_skip_boxes = false`), then sealed. vcap: **authentic**, exactly as 143 — nothing about the C2PA hash reaches `media.hash`. C2PA: the trailer is a box the hash covers and it was appended after signing, so the manifest no longer matches: `assertion.bmffHash.mismatch`. A claim generator that means both bindings to hold excludes `/free` (§3.2); one that does not has its own binding broken by the trailer, and the vcap verifier cannot tell.' })
  }
}

// ---- ISO-BMFF: a clip, and the `parentOf` chain (§3.2) -------------------------

{
  // Generation 0: the Android capture of vector 36, sealed, after a C2PA claim
  // generator wrote a manifest carrying its proof. On ISO-BMFF that manifest
  // sits inside media.hash, so this file itself reads tampered (vector 73) —
  // it is an ingredient here, not a vector.
  const g0 = await c2paSign({ asset: device, mime: 'video/mp4', label: label(145, 0), proof: deviceProof })
  const clipOf = async (n: number, asset: Buffer, actions: string[], o: { parent?: Buffer, proof?: Proof } = {}): Promise<Buffer> =>
    (await c2paSign({ asset, mime: 'video/mp4', label: label(n, 1), parent: { asset: o.parent ?? g0.file, mime: 'video/mp4' }, actions, proof: o.proof })).file
  const provenance = 'The source is the Android capture of vector 36 (Samsung SM-S908B, StrongBox, device signatures untouched); the clip bytes are vector 89\'s cut.'

  add({ name: '145-mp4-c2pa-clip-parent-of', ext: 'mp4', kind: 'container', file: await clipOf(145, cutClip, ['c2pa.trimmed']), proof: deviceProof,
    expected: { outcome: 'verified_clip', labels: DEVICE_LABELS, not_evaluated: [], core_hash: hashOf(deviceProof), segments: { verified: [1, 2] }, location: { claimed: 'none', level: 'none' }, proof_source: src(1, label(145, 0)), frames_name_capture: true },
    notes: `A clip made by a C2PA-aware cutter: vector 89's cut of vector 36 — GOP 0 removed, no re-encoding, the vcap SEIs intact — with no trailer, signed with a manifest that opens the source as \`parentOf\` and records \`c2pa.trimmed\`. The source's manifest (generation 0, ${label(145, 0)}) carries vector 36's proof and travels in the clip's store as its ingredient.\n\nNo footer, no proof at depth 0, no sidecar: the proof is found at depth 1 (§3.2), the nearest ancestor that carries one. The frames name the capture (\`frames_name_capture\`, a locating hint), GOPs 1 and 2 are located and recompute under §5, and the outcome is **verified clip**, 1 and 2 of 3 — vector 89's verdict, reached without a trailer. ${provenance}` })

  {
    // One byte of the last GOP's IDR slice data changed, then signed by a
    // cutter that carried the proof in its own manifest.
    const reading = readContainer(cutClip)
    if (reading.kind !== 'gops') throw new Error('146: not a readable clip')
    const kids = children(cutClip, find(boxes(cutClip, 0, cutClip.length), 'moov') as Box)
    const videoStbl = kids.filter((b) => b.type === 'trak').map((trak) => find(children(cutClip, find(children(cutClip, find(children(cutClip, trak), 'mdia') as Box), 'minf') as Box), 'stbl') as Box)
      .find((t) => codecOf(cutClip, find(children(cutClip, t), 'stsd') as Box).kind === 'video') as Box
    const gop = reading.gops[reading.gops.length - 1] as { range: { start: number } }
    const idr = samplesOf(cutClip, videoStbl).find((s) => s.offset === gop.range.start) as { offset: number, size: number }
    const edited = Buffer.from(cutClip)
    const at = idr.offset + idr.size - 16
    edited[at] = (edited[at] as number) ^ 0x55
    add({ name: '146-mp4-c2pa-clip-gop-replaced', ext: 'mp4', kind: 'container', file: await clipOf(146, edited, ['c2pa.trimmed'], { parent: device, proof: deviceProof }), proof: deviceProof,
      expected: { outcome: 'tampered', labels: [], not_evaluated: [], core_hash: hashOf(deviceProof), segments: { verified: [1] }, proof_source: src(0, label(146, 1)), frames_name_capture: true },
      notes: `Vector 145's clip with one byte of the last GOP's IDR slice data changed (clip byte ${at}), signed by a cutter that opens vector 36 as \`parentOf\` and carries its proof in **its own** manifest, as the clip's: a GOP whose vcap SEI still names the capture and segment 2, and whose bytes are not the ones segment 2 signs. The cutter's manifest is valid — it vouches for the bytes it saw — and declares a trim, not this.\n\nDepth 0 reads like a sidecar (§3.2): §5 applies, a located segment that does not recompute is **tampered**, with segment 1 verified. Vector 147 is the other side of the rule: at depth ≥ 1 the same failure would read *no proof found*, because a proof found up the chain is the source's and is never held against a derivation. ${provenance}` })
  }

  add({ name: '147-mp4-c2pa-clip-reencoded', ext: 'mp4', kind: 'container', file: await clipOf(147, baseMp4, ['c2pa.transcoded']), proof: deviceProof,
    expected: { outcome: 'no_proof_found', labels: [], not_evaluated: [], core_hash: hashOf(deviceProof), proof_source: src(1, label(145, 0)), frames_name_capture: false },
    notes: `What a re-encoding editor leaves: new frames with no vcap SEI (the two-frame MP4 of \`_media/\` stands in for them), signed with a manifest that opens the capture of vector 36 as \`parentOf\` and records \`c2pa.transcoded\`. The proof is found at depth 1; no GOP names the capture (\`frames_name_capture\` false) and \`media.hash\` does not match. §5 alone would say *frames not compared*; at depth ≥ 1 that becomes **no proof found**, reason *Content Credentials carry the proof of a source capture* (§3.2) — never *tampered*. A detector may still add *origin traced* from the watermark. ${provenance}` })
}

// ---- helpers used above --------------------------------------------------------

function jumbfBytes (jpeg: Buffer): Buffer { return jpegStore(jpeg).bytes }

// ---- check, then write -----------------------------------------------------------

const pick = (v: Verdict, expected: object): object => Object.fromEntries(Object.keys(expected).map((k) => [k, (v as unknown as Record<string, unknown>)[k]]))

let failures = 0
const written: { v: C2paVector, c2pa: C2paBlock }[] = []
for (const v of vectors) {
  const verdict = verifyFile({ file: v.file, sidecar: v.sidecar, externalStore: v.externalStore, recomputeSegments: v.kind === 'container', trust, clock: v.verifierClock ? new Date(v.verifierClock) : undefined })
  const got = pick(verdict, v.expected)
  if (JSON.stringify(got) !== JSON.stringify(v.expected)) { failures++; console.error(`[vcap] ${v.name}: expected ${JSON.stringify(v.expected)} got ${JSON.stringify(got)} (${verdict.reason ?? ''})`) }
  if (v.proof && !validateProof(v.proof).valid) { failures++; console.error(`[vcap] ${v.name}: proof.json is not schema-valid`) }
  written.push({ v, c2pa: await c2paReport(v.file, v.ext === 'jpg' ? 'image/jpeg' : 'video/mp4', v.externalStore) })
}
if (failures) { console.error(`[vcap] ${failures} disagreement(s): nothing written`); process.exit(1) }

for (const { v, c2pa } of written) {
  const dir = join(VECTORS, v.name)
  if (existsSync(dir)) rmSync(dir, { recursive: true })
  mkdirSync(dir)
  writeFileSync(join(dir, `input.${v.ext}`), v.file)
  if (v.sidecar) writeFileSync(join(dir, `input.${v.ext}.vcap`), v.sidecar)
  if (v.externalStore) writeFileSync(join(dir, 'input.c2pa'), v.externalStore)
  if (v.proof) writeFileSync(join(dir, 'proof.json'), JSON.stringify(v.proof, null, 2) + '\n')
  writeFileSync(join(dir, 'expected.json'), JSON.stringify({
    kind: v.kind,
    ...(v.verifierClock ? { verifier_clock: v.verifierClock } : {}),
    ...v.expected,
    ...(v.proof ? { schema_valid: true } : {}),
    writer: v.writer,
    c2pa
  }, null, 2) + '\n')
  const tool = c2patool(dir, `input.${v.ext}`, v.externalStore ? 'input.c2pa' : null)
  writeFileSync(join(dir, 'NOTES.md'), `# ${v.name}\n\n${v.notes}\n\n## C2PA\n\n- \`expected.json\` \`c2pa\`: what ${VALIDATOR} reports. Informative: no vcap verdict reads it.\n- ${tool}\n\nMinted by \`tools/src/make-c2pa-vectors.ts\` with the test key in \`tools/src/testkey.ts\` and the C2PA test signer in \`vectors/_trust/c2pa-test/\`. Committed, not regenerated: c2pa-rs salts every assertion at random (\`vectors/README.md\`).\n`)
}
console.log(`[vcap] ${written.length} C2PA vectors written`)
