import { boxes } from './container.js'

/**
 * Where a C2PA Manifest Store sits in a file, and the JUMBF boxes it is made
 * of (ISO 19566-5, as C2PA 2.4 uses it: 11.1 *Use of JUMBF*, Annex A.3.1 for
 * JPEG, A.5 for ISO-BMFF). Structure only: no hash is recomputed and no
 * signature checked, because nothing a carrier holds is trusted for what it
 * says — the proof inside authenticates itself (`c2pa-interop-1.0.md` §2.1).
 *
 * Every parse is bounded by the bytes it was given and fails with
 * `JumbfError`; a caller reads that as "no carrier here", never as a verdict.
 */
export class JumbfError extends Error {}

// A JUMBF type is a 16-byte UUID; C2PA's are four ASCII letters followed by
// the ISO suffix 0011-0010-8000-00AA00389B71 (11.1.4).
const ISO_SUFFIX = '00110010800000aa00389b71'
const iso = (fourcc: string): string => Buffer.from(fourcc, 'ascii').toString('hex') + ISO_SUFFIX
export const TYPE = {
  store: iso('c2pa'),
  manifest: iso('c2ma'),
  updateManifest: iso('c2um'),
  legacyManifest: iso('c2md'),
  compressedManifest: iso('c2cm'),
  assertionStore: iso('c2as'),
  claim: iso('c2cl'),
  json: iso('json'),
  cbor: iso('cbor')
} as const
/** 6.8: the UUID a redacted assertion's single content box carries. */
export const REDACTION_UUID = 'caa98eee9d4df80e86ad4dffca263973'
/** A.5.1.1: the extended type of the C2PA `uuid` box in ISO-BMFF. */
export const C2PA_BMFF_UUID = 'd8fec3d61b0e483c92975828877ec481'

export type JumbfNode = JumbfSuperbox | { kind: 'content', box: string, data: Buffer }
export interface JumbfSuperbox { kind: 'super', type: string, toggles: number, label: string | null, children: JumbfNode[] }

const MAX_DEPTH = 16
const utf8 = new TextDecoder('utf-8', { fatal: true })

/** The boxes of `buf[start, end)`: LBox 0 runs to the end, LBox 1 has an XLBox. */
const boxList = (buf: Buffer, start: number, end: number): { type: string, start: number, payload: number, end: number }[] => {
  const out: { type: string, start: number, payload: number, end: number }[] = []
  let at = start
  while (at < end) {
    if (end - at < 8) throw new JumbfError('box header cut short')
    let size = buf.readUInt32BE(at)
    let payload = at + 8
    if (size === 1) {
      if (end - at < 16) throw new JumbfError('XLBox cut short')
      const large = buf.readBigUInt64BE(at + 8)
      if (large > BigInt(end - at)) throw new JumbfError('box runs past its container')
      size = Number(large)
      payload = at + 16
    } else if (size === 0) {
      size = end - at
    }
    if (size < payload - at || size > end - at) throw new JumbfError('box length out of range')
    out.push({ type: buf.toString('latin1', at + 4, at + 8), start: at, payload, end: at + size })
    at += size
  }
  return out
}

/**
 * One JUMBF superbox spanning exactly `buf`: a `jumb` box whose first child is
 * its description box (`jumd`: TYPE, TOGGLES, then the label when bit 1 is
 * set, an ID with bit 2, a signature with bit 3, a private box with bit 4).
 */
export const parseSuperbox = (buf: Buffer, depth = 0): JumbfSuperbox => {
  if (depth > MAX_DEPTH) throw new JumbfError('superboxes nested too deeply')
  const [outer, ...rest] = boxList(buf, 0, buf.length)
  if (!outer || rest.length > 0 || outer.type !== 'jumb') throw new JumbfError('not one jumb superbox')
  const [description, ...contents] = boxList(buf, outer.payload, outer.end)
  if (!description || description.type !== 'jumd') throw new JumbfError('superbox without a description box')
  const d = buf.subarray(description.payload, description.end)
  if (d.length < 17) throw new JumbfError('description box cut short')
  const toggles = d[16] as number
  let label: string | null = null
  if (toggles & 0x02) {
    const nul = d.indexOf(0, 17)
    if (nul < 0) throw new JumbfError('label without its terminator')
    try { label = utf8.decode(d.subarray(17, nul)) } catch { throw new JumbfError('label is not UTF-8') }
  }
  const children: JumbfNode[] = contents.map((box) => box.type === 'jumb'
    ? parseSuperbox(buf.subarray(box.start, box.end), depth + 1)
    : { kind: 'content' as const, box: box.type, data: buf.subarray(box.payload, box.end) })
  return { kind: 'super', type: d.subarray(0, 16).toString('hex'), toggles, label, children }
}

/** The superbox children of a superbox. */
export const superChildren = (box: JumbfSuperbox): JumbfSuperbox[] =>
  box.children.filter((c): c is JumbfSuperbox => c.kind === 'super')

// ---- JPEG ------------------------------------------------------------------

export interface JpegSegment { marker: number, start: number, end: number }

const APP11 = 0xeb
const SOS = 0xda
const JP = Buffer.from('JP', 'ascii')

/**
 * The marker segments of a JPEG up to SOS, in order (§4.1's walk). Fill bytes
 * and length-less markers (TEM, RSTn) are not segments and are skipped over;
 * a length below 2 or past the end of the file makes the JPEG malformed.
 */
export const jpegSegments = (jpeg: Buffer): JpegSegment[] => {
  const out: JpegSegment[] = []
  let pos = 2
  while (pos + 4 <= jpeg.length) {
    if (jpeg[pos] !== 0xff) throw new Error('JPEG: marker expected')
    const marker = jpeg[pos + 1] as number
    if (marker === 0xff || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { pos += marker === 0xff ? 1 : 2; continue }
    if (marker === SOS) break
    const length = jpeg.readUInt16BE(pos + 2)
    if (length < 2 || pos + 2 + length > jpeg.length) throw new Error('JPEG: a segment length runs past the end of the file')
    out.push({ marker, start: pos, end: pos + 2 + length })
    pos += 2 + length
  }
  return out
}

/**
 * The JUMBF APP11 segments (payload starting "JP", ISO 19566-5 D.2), grouped
 * by box instance number `En`. A group's JUMBF type is read from its packet
 * with sequence number `Z` = 1: `LBox`, `TBox` = `jumb` (`XLBox` when `LBox` =
 * 1), then the description box's TYPE. `type` is null when that cannot be
 * read — no `Z` = 1 packet, a packet too short, a box that is not `jumb`.
 */
export interface JumbfGroup { en: number | null, type: string | null, segments: { start: number, end: number, z: number | null, packet: Buffer }[] }

export const jumbfGroups = (jpeg: Buffer, segments = jpegSegments(jpeg)): JumbfGroup[] => {
  const groups: JumbfGroup[] = []
  for (const s of segments) {
    if (s.marker !== APP11) continue
    const payload = jpeg.subarray(s.start + 4, s.end)
    if (!payload.subarray(0, 2).equals(JP)) continue
    const en = payload.length >= 8 ? payload.readUInt16BE(2) : null
    const z = payload.length >= 8 ? payload.readUInt32BE(4) : null
    const segment = { start: s.start, end: s.end, z, packet: payload.subarray(8) }
    // A packet without En belongs to no box; it still is a JUMBF segment.
    const group = en === null ? undefined : groups.find((g) => g.en === en)
    if (group) group.segments.push(segment)
    else groups.push({ en, type: null, segments: [segment] })
  }
  for (const g of groups) {
    const first = g.segments.find((s) => s.z === 1)
    g.type = first ? packetType(first.packet) : null
  }
  return groups
}

const packetType = (packet: Buffer): string | null => {
  if (packet.length < 8 || packet.toString('latin1', 4, 8) !== 'jumb') return null
  const header = packet.readUInt32BE(0) === 1 ? 16 : 8
  if (packet.length < header + 24 || packet.toString('latin1', header + 4, header + 8) !== 'jumd') return null
  return packet.subarray(header + 8, header + 24).toString('hex')
}

/**
 * A group's box, reassembled: packets in file order with `Z` = 1, 2, 3 …, the
 * first taken whole, every later one without the `LBox`/`TBox` (and `XLBox`)
 * it repeats (ISO 19566-5 D.2; C2PA A.3.1 requires them contiguous and in
 * order). Null when the sequence is broken.
 */
const reassemble = (group: JumbfGroup): Buffer | null => {
  const [first] = group.segments
  if (!first || first.packet.length < 8) return null
  const header = first.packet.readUInt32BE(0) === 1 ? 16 : 8
  const parts: Buffer[] = []
  for (const [i, s] of group.segments.entries()) {
    if (s.z !== i + 1) return null
    if (i > 0 && s.packet.length < header) return null
    parts.push(i === 0 ? s.packet : s.packet.subarray(header))
  }
  return Buffer.concat(parts)
}

// ---- where the store is ----------------------------------------------------

/**
 * The embedded C2PA Manifest Stores of a file, as bytes, or null for one that
 * is present and cannot be reassembled. JPEG: every JUMBF APP11 group whose
 * type is the store's (A.3.1). ISO-BMFF: every top-level `uuid` box with the
 * C2PA extended type and `box_purpose` `manifest`, `original` or `update`,
 * whose data starts with the 8-byte offset A.5.3 defines (c2pa-rs skips it for
 * all three). Anything after the store's superbox is padding.
 */
export const embeddedStores = (file: Buffer): (Buffer | null)[] => {
  if (file.length >= 2 && file[0] === 0xff && file[1] === 0xd8) {
    let groups: JumbfGroup[]
    try { groups = jumbfGroups(file) } catch { return [] }
    return groups.filter((g) => g.type === TYPE.store).map(reassemble)
  }
  if (file.length >= 8 && file.toString('latin1', 4, 8) === 'ftyp') {
    const stores: (Buffer | null)[] = []
    let top: ReturnType<typeof boxes>
    try { top = boxes(file, 0, file.length) } catch { return [] }
    for (const box of top) {
      if (box.type !== 'uuid' || box.end - box.payload < 20) continue
      if (file.subarray(box.payload, box.payload + 16).toString('hex') !== C2PA_BMFF_UUID) continue
      const body = file.subarray(box.payload + 20, box.end)
      const nul = body.indexOf(0)
      const purpose = nul < 0 ? null : body.toString('latin1', 0, nul)
      if (purpose !== 'manifest' && purpose !== 'original' && purpose !== 'update') continue
      const data = body.subarray(nul + 1)
      stores.push(data.length < 8 ? null : data.subarray(8))
    }
    return stores
  }
  return []
}

/** The leading superbox of store bytes (padding after it ignored), or null. */
export const storeSuperbox = (bytes: Buffer): JumbfSuperbox | null => {
  try {
    if (bytes.length < 8) return null
    const lbox = bytes.readUInt32BE(0)
    const size = lbox === 1 && bytes.length >= 16 ? bytes.readBigUInt64BE(8) : BigInt(lbox === 0 ? bytes.length : lbox)
    if (size > BigInt(bytes.length)) return null
    const store = parseSuperbox(bytes.subarray(0, Number(size)))
    return store.type === TYPE.store ? store : null
  } catch (e) {
    if (e instanceof JumbfError) return null
    throw e
  }
}
