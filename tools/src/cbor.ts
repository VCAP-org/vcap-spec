/**
 * The CBOR a carrier reader needs (RFC 8949), and nothing more: a claim's
 * `redacted_assertions` and an ingredient assertion's `relationship` and
 * manifest reference (`c2pa-interop-1.0.md` §2.1). Definite lengths only, text
 * keys only, 32 levels at most. Anything else is `CborError`, which the caller
 * reads as "this box carries nothing", never as a verdict.
 *
 * It decodes no COSE and checks no signature: the proof a carrier transports
 * authenticates itself (§4.2), so the claim around it is read for navigation,
 * not for trust.
 */
export class CborError extends Error {}

export type CborValue = number | bigint | string | Buffer | boolean | null | undefined | CborValue[] | { [key: string]: CborValue }

const MAX_DEPTH = 32

export const decodeCbor = (bytes: Buffer): CborValue => {
  let at = 0
  const need = (n: number): void => { if (n > bytes.length - at) throw new CborError('truncated') }

  // The argument of a head: the value itself for small ones, or 1/2/4/8
  // following bytes. 28–30 are reserved and 31 is an indefinite length.
  const argument = (info: number): number | bigint => {
    if (info < 24) return info
    if (info === 24) { need(1); return bytes[at++] as number }
    if (info === 25) { need(2); const v = bytes.readUInt16BE(at); at += 2; return v }
    if (info === 26) { need(4); const v = bytes.readUInt32BE(at); at += 4; return v }
    if (info === 27) { need(8); const v = bytes.readBigUInt64BE(at); at += 8; return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v }
    throw new CborError(info === 31 ? 'indefinite length' : 'reserved additional information')
  }
  // A length is a count of bytes or items that must fit what is left: a
  // hostile head cannot make the reader allocate more than the input holds.
  const length = (info: number): number => {
    const n = argument(info)
    if (typeof n === 'bigint' || n > bytes.length - at) throw new CborError('length beyond the input')
    return n
  }

  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new CborError('nested too deeply')
    need(1)
    const head = bytes[at++] as number
    const major = head >> 5
    const info = head & 0x1f
    switch (major) {
      case 0: return argument(info)
      case 1: { const n = argument(info); return typeof n === 'bigint' ? -1n - n : -1 - n }
      case 2: { const n = length(info); const v = Buffer.from(bytes.subarray(at, at + n)); at += n; return v }
      case 3: {
        const n = length(info)
        try {
          const v = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(at, at + n))
          at += n
          return v
        } catch { throw new CborError('text string is not UTF-8') }
      }
      case 4: { const n = length(info); const v: CborValue[] = []; for (let i = 0; i < n; i++) v.push(item(depth + 1)); return v }
      case 5: {
        const n = length(info)
        const v: { [key: string]: CborValue } = Object.create(null) as { [key: string]: CborValue }
        for (let i = 0; i < n; i++) {
          const key = item(depth + 1)
          if (typeof key !== 'string') throw new CborError('map key is not a text string')
          if (Object.prototype.hasOwnProperty.call(v, key)) throw new CborError('duplicate map key')
          v[key] = item(depth + 1)
        }
        return v
      }
      // A tag annotates the item after it (a date, a URI); the item is what is read.
      case 6: argument(info); return item(depth + 1)
      default: {
        if (info === 20) return false
        if (info === 21) return true
        if (info === 22) return null
        if (info === 23) return undefined
        if (info === 25) { need(2); const half = bytes.readUInt16BE(at); at += 2; return halfToNumber(half) }
        if (info === 26) { need(4); const v = bytes.readFloatBE(at); at += 4; return v }
        if (info === 27) { need(8); const v = bytes.readDoubleBE(at); at += 8; return v }
        throw new CborError('unsupported simple value')
      }
    }
  }

  const value = item(0)
  if (at !== bytes.length) throw new CborError('bytes after the data item')
  return value
}

const halfToNumber = (half: number): number => {
  const exponent = (half >> 10) & 0x1f
  const mantissa = half & 0x3ff
  const sign = half & 0x8000 ? -1 : 1
  if (exponent === 0) return sign * 2 ** -14 * (mantissa / 1024)
  if (exponent === 31) return mantissa === 0 ? sign * Infinity : NaN
  return sign * 2 ** (exponent - 15) * (1 + mantissa / 1024)
}
