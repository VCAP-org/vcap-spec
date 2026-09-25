import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CborError, decodeCbor } from '../src/cbor.js'
import { carrierOf, extractProof } from '../src/carrier.js'
import { embeddedStores } from '../src/jumbf.js'
import { verifyFile } from '../src/verify.js'

/**
 * The carrier reader against hostile input. A C2PA store is bytes somebody
 * else wrote, read before any signature is checked, so every malformation has
 * to end in "no carrier" — never an exception, never a hang. The numbered
 * vectors pin the verdicts; these pin that nothing on the way throws.
 */
const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')
const input = (name: string, file = 'input.jpg'): Buffer => readFileSync(join(VECTORS, name, file))

describe('the carrier reader never throws on a malformed store', () => {
  const stripped = input('124-jpeg-c2pa-carrier-trailer-stripped')
  const clip = input('145-mp4-c2pa-clip-parent-of', 'input.mp4')
  const [store] = embeddedStores(stripped) as [Buffer]
  const storeAt = stripped.indexOf(store.subarray(0, 32))

  it('finds the store it is about to break', () => {
    expect(storeAt).toBeGreaterThan(0)
    expect(extractProof(stripped).kind).toBe('proof')
  })

  it('survives a flipped byte anywhere in the store', () => {
    for (let at = storeAt; at < storeAt + store.length; at += 7) {
      const hostile = Buffer.from(stripped)
      hostile[at] = (hostile[at] as number) ^ 0xff
      expect(() => verifyFile({ file: hostile })).not.toThrow()
    }
  })

  it('survives the store cut short at every length', () => {
    for (let n = 0; n < store.length; n += 11) expect(() => carrierOf(Buffer.alloc(0), store.subarray(0, n))).not.toThrow()
  })

  it('survives a BMFF file cut short anywhere', () => {
    for (let n = 0; n < clip.length; n += 997) expect(() => verifyFile({ file: clip.subarray(0, n), recomputeSegments: true })).not.toThrow()
  })

  it('reads an external store only when the file embeds none', () => {
    expect(extractProof(stripped, undefined, Buffer.from('not a store')).kind).toBe('proof')
    expect(carrierOf(Buffer.alloc(0), Buffer.from('not a store')).store).toBe('none')
  })
})

describe('the CBOR subset refuses what it does not read', () => {
  const refuses = (hex: string): void => { expect(() => decodeCbor(Buffer.from(hex, 'hex'))).toThrow(CborError) }
  it('indefinite lengths', () => refuses('9f01ff'))
  it('a length beyond the input', () => refuses('5b0000000100000000'))
  it('a map key that is not text', () => refuses('a10101'))
  it('a duplicate map key', () => refuses('a2616101616102'))
  it('nesting deeper than 32', () => refuses('81'.repeat(40) + '01'))
  it('bytes after the item', () => refuses('0101'))
  it('reads what a claim holds', () => {
    expect(decodeCbor(Buffer.from('a26375726c6161646861736842beef', 'hex'))).toEqual({ url: 'a', hash: Buffer.from('beef', 'hex') })
  })
})
