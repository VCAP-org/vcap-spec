import { crc32 } from 'node:zlib'

/**
 * The trailer of §3: an ISO-BMFF `free` box wrapping the proof JSON, followed
 * by a 16-byte footer that is always the last 16 bytes of the file.
 */
export const MAGIC = Buffer.from('VCAP', 'ascii')
export const FOOTER_LEN = 16
export const BOX_HEADER_LEN = 8

export const Flag = { SIDECAR: 1 << 0, SEGMENTS: 1 << 1, PSEUDONYMOUS: 1 << 2 } as const

export interface TrailerOptions {
  major?: number
  minor?: number
  flags?: number
  // Wrong on purpose, for the corruption vectors.
  crcOverride?: number
  boxTypeOverride?: string
}

export const buildTrailer = (payload: Buffer, o: TrailerOptions = {}): Buffer => {
  const box = Buffer.alloc(BOX_HEADER_LEN)
  box.writeUInt32BE(BOX_HEADER_LEN + payload.length + FOOTER_LEN, 0)
  box.write(o.boxTypeOverride ?? 'free', 4, 'ascii')

  const footer = Buffer.alloc(FOOTER_LEN)
  MAGIC.copy(footer, 0)
  footer.writeUInt8(o.major ?? 1, 4)
  footer.writeUInt8(o.minor ?? 0, 5)
  footer.writeUInt16BE(o.flags ?? 0, 6)
  footer.writeUInt32BE(payload.length, 8)
  footer.writeUInt32BE(o.crcOverride ?? crc32(payload), 12)

  return Buffer.concat([box, payload, footer])
}

export type ParsedTrailer =
  | { kind: 'none' }
  | { kind: 'corrupted' }
  /** `VCAP` magic with a major this reader does not implement (§3, §9). */
  | { kind: 'unsupported', major: number }
  | { kind: 'ok', payload: Buffer, flags: number, minor: number, mediaEnd: number }

/**
 * §3 reading procedure. Structure first, CRC second: only a structurally valid
 * footer with a failing CRC is *corrupted*; anything else is *no trailer*.
 */
export const parseTrailer = (file: Buffer): ParsedTrailer => {
  if (file.length < FOOTER_LEN + BOX_HEADER_LEN) return { kind: 'none' }
  const footer = file.subarray(file.length - FOOTER_LEN)
  if (!footer.subarray(0, 4).equals(MAGIC)) return { kind: 'none' }
  // The magic says "a vcap trailer" and the major says "not this version".
  // A v1 reader does not interpret the rest of a footer it does not
  // implement, and it does not call it absent either: *no proof found* would
  // tell a reader the platform stripped the proof, when the proof is there in
  // a format this verifier predates.
  const major = footer.readUInt8(4)
  if (major !== 1) return { kind: 'unsupported', major }

  const payloadLen = footer.readUInt32BE(8)
  const total = BOX_HEADER_LEN + payloadLen + FOOTER_LEN
  if (total > file.length) return { kind: 'none' }

  const boxStart = file.length - total
  if (file.readUInt32BE(boxStart) !== total) return { kind: 'none' }
  if (file.toString('ascii', boxStart + 4, boxStart + 8) !== 'free') return { kind: 'none' }

  const payload = file.subarray(boxStart + BOX_HEADER_LEN, file.length - FOOTER_LEN)
  if (crc32(payload) !== footer.readUInt32BE(12)) return { kind: 'corrupted' }

  return { kind: 'ok', payload, flags: footer.readUInt16BE(6), minor: footer.readUInt8(5), mediaEnd: boxStart }
}
