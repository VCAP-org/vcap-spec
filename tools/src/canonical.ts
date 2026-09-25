import { createHash } from 'node:crypto'
import { TYPE, jpegSegments, jumbfGroups } from './jumbf.js'

/**
 * §4.1 canonical bytes. The trailer is already stripped by the caller; this is
 * the container normalization: JPEG loses its C2PA APP11 segments, ISO-BMFF is
 * taken as is.
 *
 * The container is decided by the first bytes of the file, never by
 * `media.mime` (§4.1): the MIME type is a claim inside the proof, and letting
 * a claim choose how the bytes it describes are hashed would let a writer pick
 * the rule its file passes.
 */
export type Container = 'jpeg' | 'bmff' | 'unknown'

export const detectContainer = (bytes: Buffer): Container => {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) return 'jpeg'
  if (bytes.length >= 8 && bytes.toString('ascii', 4, 8) === 'ftyp') return 'bmff'
  return 'unknown'
}

/**
 * §4.1 for JPEG: remove the JUMBF APP11 segments (payload starting "JP") —
 * except those of a JUMBF box that is readable and is **not** a C2PA Manifest
 * Store. Those are content, as they are to C2PA (15.12.1.2: APP11 segments of
 * JPEG 360 or JPEG Privacy and Security are hashed), so a box of that kind
 * added after sealing is an edit. A JUMBF segment whose box type cannot be
 * read stays excluded, as every JUMBF segment was before 1.1: the vectors that
 * carry one (02, 68) keep their verdict.
 *
 * The walk stops at SOS; entropy-coded data, fill bytes and length-less
 * markers are kept where they are.
 */
export const stripC2paFromJpeg = (jpeg: Buffer): Buffer => {
  const segments = jpegSegments(jpeg)
  const dropped = new Set<number>()
  for (const group of jumbfGroups(jpeg, segments)) {
    if (group.type !== null && group.type !== TYPE.store) continue
    for (const s of group.segments) dropped.add(s.start)
  }
  const kept: Buffer[] = []
  let at = 0
  for (const s of segments) {
    if (!dropped.has(s.start)) continue
    kept.push(jpeg.subarray(at, s.start))
    at = s.end
  }
  kept.push(jpeg.subarray(at))
  return Buffer.concat(kept)
}

export const canonicalBytes = (media: Buffer): Buffer => {
  switch (detectContainer(media)) {
    case 'jpeg': return stripC2paFromJpeg(media)
    default: return media
  }
}

export const mediaHash = (media: Buffer): string =>
  createHash('sha256').update(canonicalBytes(media)).digest('base64url')
