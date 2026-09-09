import { createHash } from 'node:crypto'

/**
 * §4.1 canonical bytes. The trailer is already stripped by the caller; this is
 * the container normalization: JPEG loses its C2PA APP11 segments, ISO-BMFF is
 * taken as is.
 */
export type Container = 'jpeg' | 'bmff' | 'unknown'

export const detectContainer = (bytes: Buffer): Container => {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) return 'jpeg'
  if (bytes.length >= 8 && bytes.toString('ascii', 4, 8) === 'ftyp') return 'bmff'
  return 'unknown'
}

const APP11 = 0xeb
const SOS = 0xda
const JUMBF_ID = Buffer.from('JP', 'ascii')

// Walks the marker segments up to SOS; entropy-coded data and everything after
// it are copied verbatim. Only APP11 segments whose payload starts with "JP"
// are dropped — those are the JUMBF boxes C2PA writes after sealing.
export const stripC2paFromJpeg = (jpeg: Buffer): Buffer => {
  const kept: Buffer[] = [jpeg.subarray(0, 2)]
  let pos = 2
  while (pos + 4 <= jpeg.length) {
    if (jpeg[pos] !== 0xff) throw new Error('JPEG: marker expected')
    const marker = jpeg[pos + 1] as number
    // §4.1 keeps fill bytes (0xFF padding before a marker) and length-less
    // markers (TEM, RSTn) as they are: they are content, not a segment to judge.
    if (marker === 0xff || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { kept.push(jpeg.subarray(pos, pos + 1 + (marker === 0xff ? 0 : 1))); pos += marker === 0xff ? 1 : 2; continue }
    if (marker === SOS) break
    const length = jpeg.readUInt16BE(pos + 2)
    const segment = jpeg.subarray(pos, pos + 2 + length)
    const payload = segment.subarray(4)
    const isC2pa = marker === APP11 && payload.subarray(0, 2).equals(JUMBF_ID)
    if (!isC2pa) kept.push(segment)
    pos += 2 + length
  }
  kept.push(jpeg.subarray(pos))
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
