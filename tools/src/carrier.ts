import { type CborValue, CborError, decodeCbor } from './cbor.js'
import { type JumbfSuperbox, JumbfError, TYPE, embeddedStores, storeSuperbox, superChildren } from './jumbf.js'
import { jcs } from './jcs.js'
import { ProofSyntaxError, parseProofJson } from './json.js'
import { parseTrailer } from './trailer.js'

/**
 * Content Credentials as a carrier of the proof (`vcap-proof-1.0.md` §3.2,
 * `c2pa-interop-1.0.md` §2.1): where a reader finds the proof when the file
 * has no trailer, and which copy wins when there are several.
 *
 * Only navigation is read — manifest types, labels, a claim's
 * `redacted_assertions`, an ingredient's `relationship` and manifest
 * reference. No hash, no COSE, no certificate: whatever a manifest says about
 * itself is not evidence here, and the proof it carries is checked exactly as a
 * sidecar's would be.
 */
export const PROOF_LABEL = 'io.github.vcap-org.vcap.proof'
/** §3.2: the `parentOf` chain is followed this far, and no further. */
export const MAX_DEPTH = 16

const MANIFEST_TYPES = new Set<string>([TYPE.manifest, TYPE.updateManifest, TYPE.legacyManifest, TYPE.compressedManifest])
const INGREDIENT = /^c2pa\.ingredient(\.v[23])?(__\d+)?$/

export interface CarriedProof { bytes: Buffer, manifest: string, depth: number }

export interface Carrier {
  /** Where the store came from; `none` when there is none, or it is unusable. */
  store: 'embedded' | 'external' | 'none'
  /** Why there is no usable store, for a reader who asks. */
  reason?: string
  /** The proof in the active manifest (depth 0). */
  active: CarriedProof | null
  /** The first proof up the `parentOf` chain, depth 1–16. */
  ancestor: CarriedProof | null
}

const NONE: Carrier = { store: 'none', active: null, ancestor: null }

const childOfType = (box: JumbfSuperbox, type: string): JumbfSuperbox | null => {
  const found = superChildren(box).filter((c) => c.type === type)
  return found.length === 1 ? found[0] as JumbfSuperbox : null
}

const cborOf = (box: JumbfSuperbox): CborValue => {
  const content = box.children.filter((c) => c.kind === 'content')
  if (content.length !== 1 || content[0]?.kind !== 'content' || content[0].box !== 'cbor') return undefined
  try { return decodeCbor(content[0].data) } catch (e) { if (e instanceof CborError) return undefined; throw e }
}

const isMap = (v: CborValue): v is { [key: string]: CborValue } => typeof v === 'object' && v !== null && !Array.isArray(v) && !Buffer.isBuffer(v)

const uriOf = (v: CborValue): string | null => typeof v === 'string' ? v : isMap(v) && typeof v.url === 'string' ? v.url : null

/** `self#jumbf=/c2pa/<label>` (a trailing `/` allowed) → the manifest label. */
const manifestLabelOf = (uri: string | null): string | null => {
  const m = uri === null ? null : /^self#jumbf=\/c2pa\/([^/]+)\/?$/.exec(uri)
  return m ? m[1] as string : null
}

const assertionUri = (manifest: string, assertion: string): string => `self#jumbf=/c2pa/${manifest}/c2pa.assertions/${assertion}`

/**
 * Walks one store: the proof in the active manifest, then the `parentOf`
 * chain. `componentOf` and `inputTo` are never followed, a manifest is never
 * visited twice, an assertion its own claim does not list is not part of the
 * manifest (C2PA 6.6, 10.2.2), and an assertion any claim of the store lists
 * in `redacted_assertions` is absent whatever box is still there (6.8).
 */
const walk = (store: JumbfSuperbox): Omit<Carrier, 'store'> => {
  const manifests = superChildren(store).filter((m) => MANIFEST_TYPES.has(m.type))
  const byLabel = (label: string): JumbfSuperbox | null => {
    const found = manifests.filter((m) => m.label === label)
    return found.length === 1 ? found[0] as JumbfSuperbox : null
  }
  // A compressed manifest (c2cm) is not decompressed: it carries nothing a
  // v1.x reader sees, and it points nowhere.
  const readable = (m: JumbfSuperbox): boolean => m.type !== TYPE.compressedManifest && m.label !== null
  const claimOf = (m: JumbfSuperbox): { [key: string]: CborValue } | null => {
    const claim = readable(m) ? childOfType(m, TYPE.claim) : null
    const body = claim ? cborOf(claim) : undefined
    return isMap(body) ? body : null
  }
  const redacted = new Set<string>()
  for (const m of manifests) {
    const list = claimOf(m)?.redacted_assertions
    if (Array.isArray(list)) for (const entry of list) { const uri = uriOf(entry); if (uri !== null) redacted.add(uri) }
  }
  // The labels of the assertions a manifest's claim lists — `created_assertions`
  // and `gathered_assertions` (claim v2), `assertions` (v1) — by relative or
  // absolute JUMBF URI (8.4.2.1), minus the redacted ones.
  const listed = (m: JumbfSuperbox): Set<string> => {
    const claim = claimOf(m)
    const out = new Set<string>()
    if (claim === null) return out
    const self = `self#jumbf=/c2pa/${m.label as string}/c2pa.assertions/`
    for (const key of ['created_assertions', 'gathered_assertions', 'assertions']) {
      const list = claim[key]
      if (!Array.isArray(list)) continue
      for (const entry of list) {
        const uri = uriOf(entry)
        const name = uri === null ? null : uri.startsWith('self#jumbf=c2pa.assertions/') ? uri.slice('self#jumbf=c2pa.assertions/'.length) : uri.startsWith(self) ? uri.slice(self.length) : null
        if (name !== null && !name.includes('/') && !redacted.has(assertionUri(m.label as string, name))) out.add(name)
      }
    }
    return out
  }
  const assertionsIn = (m: JumbfSuperbox): JumbfSuperbox[] => {
    const store = readable(m) ? childOfType(m, TYPE.assertionStore) : null
    if (!store) return []
    const names = listed(m)
    return superChildren(store).filter((a) => a.label !== null && names.has(a.label))
  }

  const proofIn = (m: JumbfSuperbox): Buffer | null => {
    // Exactly one box with exactly this label: `__n` instances are other
    // assertions, and two boxes with one label resolve to nothing (8.4.1).
    const boxes = assertionsIn(m).filter((a) => a.label === PROOF_LABEL)
    const box = boxes.length === 1 ? boxes[0] as JumbfSuperbox : null
    if (!box || box.type !== TYPE.json || (box.toggles !== 0x03 && box.toggles !== 0x13)) return null
    const content = box.children.filter((c) => c.kind === 'content')
    // The redaction UUID box (6.8) — or anything else that is not one JSON
    // content box — is no proof.
    if (content.length !== 1 || content[0]?.kind !== 'content' || content[0].box !== 'json') return null
    return content[0].data
  }

  const parentOf = (m: JumbfSuperbox): JumbfSuperbox | null => {
    const parents = assertionsIn(m)
      .filter((a) => INGREDIENT.test(a.label as string))
      .map(cborOf)
      .filter((body) => isMap(body) && body.relationship === 'parentOf') as { [key: string]: CborValue }[]
    // C2PA allows one parent (15.10.1.2, `manifest.multipleParents`); with
    // more, which is "the" source is not a question a reader answers, so the
    // chain stops.
    if (parents.length !== 1) return null
    const body = parents[0] as { [key: string]: CborValue }
    const label = manifestLabelOf(uriOf(body.activeManifest ?? body.c2pa_manifest))
    return label === null ? null : byLabel(label)
  }

  const active = manifests[manifests.length - 1]
  if (!active) return { reason: 'the store holds no manifest', active: null, ancestor: null }
  const own = proofIn(active)
  const found = (m: JumbfSuperbox, bytes: Buffer, depth: number): CarriedProof => ({ bytes, manifest: m.label as string, depth })
  let ancestor: CarriedProof | null = null
  const visited = new Set<JumbfSuperbox>([active])
  let current: JumbfSuperbox | null = parentOf(active)
  for (let depth = 1; depth <= MAX_DEPTH && current !== null && !visited.has(current); depth++) {
    visited.add(current)
    const bytes = proofIn(current)
    if (bytes !== null) { ancestor = found(current, bytes, depth); break }
    current = parentOf(current)
  }
  return { active: own === null ? null : found(active, own, 0), ancestor }
}

/**
 * The carrier of a file: its embedded store, or — only when the file embeds
 * none — the `.c2pa` store its caller hands over. Nothing is fetched. More
 * than one embedded store is no carrier at all (C2PA 15.5.2.1), and so is a
 * store that cannot be read.
 */
export const carrierOf = (media: Buffer, externalStore?: Buffer): Carrier => {
  const embedded = embeddedStores(media)
  if (embedded.length > 1) return { ...NONE, reason: 'more than one embedded C2PA Manifest Store' }
  let bytes: Buffer | null
  let store: Carrier['store']
  if (embedded.length === 1) { bytes = embedded[0] as Buffer | null; store = 'embedded' } else if (externalStore) { bytes = externalStore; store = 'external' } else return { ...NONE, reason: 'no C2PA Manifest Store' }
  const superbox = bytes === null ? null : storeSuperbox(bytes)
  if (superbox === null) return { ...NONE, reason: 'the C2PA Manifest Store cannot be read' }
  try {
    return { store, ...walk(superbox) }
  } catch (e) {
    if (e instanceof JumbfError) return { ...NONE, reason: 'the C2PA Manifest Store cannot be read' }
    throw e
  }
}

/**
 * Two copies of one proof are the same proof when `JCS(parse(a)) ==
 * JCS(parse(b))`: a C2PA claim generator re-serializes the JSON it is given
 * (c2pa-rs through serde_json), so bytes are not comparable across a manifest.
 * A copy that is not a well-formed proof differs from any other.
 */
export const sameProof = (a: Buffer, b: Buffer): boolean => {
  try {
    return jcs(parseProofJson(a)).equals(jcs(parseProofJson(b)))
  } catch (e) {
    if (e instanceof ProofSyntaxError) return false
    throw e
  }
}

/** Where the proof was read (§3.2). An external store reads as `c2pa` too. */
export type ProofSource =
  | { kind: 'trailer' }
  | { kind: 'sidecar' }
  | { kind: 'c2pa', manifest: string, depth: number }

export type Extraction =
  | { kind: 'none', reason: string }
  | { kind: 'corrupted' }
  | { kind: 'unsupported', major: number }
  | { kind: 'nested' }
  | {
      kind: 'proof'
      payload: Buffer
      /** The bytes §4.1 starts from: the file minus the trailer, or all of it. */
      media: Buffer
      /** Footer flags, when the proof came from a trailer. */
      flags: number | null
      source: ProofSource
      /** *sidecar differs*, *manifest copy differs*. */
      labels: string[]
    }

/**
 * §3.1–§3.2 precedence, from the end of the file:
 *
 * 1. a valid footer whose CRC matches: the trailer is the proof; a sidecar is
 *    compared byte for byte, the active manifest's copy as JCS;
 * 2. a valid footer whose CRC fails: *corrupted proof*, whatever else exists;
 * 3. `VCAP` with a major ≠ 1: *unsupported format version*;
 * 4. no footer: the active manifest's proof, then the sidecar, then the first
 *    proof up the `parentOf` chain.
 */
export const extractProof = (file: Buffer, sidecar?: Buffer, externalStore?: Buffer): Extraction => {
  const trailer = parseTrailer(file)
  if (trailer.kind === 'corrupted') return { kind: 'corrupted' }
  if (trailer.kind === 'unsupported') return { kind: 'unsupported', major: trailer.major }
  if (trailer.kind === 'ok') {
    const media = file.subarray(0, trailer.mediaEnd)
    if (parseTrailer(media).kind !== 'none') return { kind: 'nested' }
    const labels: string[] = []
    if (sidecar && !sidecar.equals(trailer.payload)) labels.push('sidecar differs')
    const copy = carrierOf(media, externalStore).active
    if (copy && !sameProof(copy.bytes, trailer.payload)) labels.push('manifest copy differs')
    return { kind: 'proof', payload: trailer.payload, media, flags: trailer.flags, source: { kind: 'trailer' }, labels }
  }
  const carrier = carrierOf(file, externalStore)
  const kind = 'c2pa' as const
  if (carrier.active) {
    const labels = sidecar && !sameProof(sidecar, carrier.active.bytes) ? ['sidecar differs'] : []
    return { kind: 'proof', payload: carrier.active.bytes, media: file, flags: null, source: { kind, manifest: carrier.active.manifest, depth: 0 }, labels }
  }
  if (sidecar) return { kind: 'proof', payload: sidecar, media: file, flags: null, source: { kind: 'sidecar' }, labels: [] }
  if (carrier.ancestor) return { kind: 'proof', payload: carrier.ancestor.bytes, media: file, flags: null, source: { kind, manifest: carrier.ancestor.manifest, depth: carrier.ancestor.depth }, labels: [] }
  return { kind: 'none', reason: carrier.reason ?? 'no proof in the Content Credentials' }
}

/**
 * The writer's guard (`c2pa-interop-1.0.md` §2.1): a JPEG that already embeds
 * a C2PA Manifest Store is not sealed, because the store's `c2pa.hash.data`
 * covers every byte after EOI and the trailer would break somebody else's
 * signature. Error code `VCAP_C2PA_MANIFEST_PRESENT`.
 */
export const jpegCarriesStore = (file: Buffer): boolean =>
  file.length >= 2 && file[0] === 0xff && file[1] === 0xd8 && embeddedStores(file).length > 0
