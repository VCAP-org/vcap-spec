import { type KeyObject, createHash } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { type SegmentEntry, ZERO_LINK, linkOf, segmentMessage } from './segments.js'

/**
 * The writer's side of the crypto: deterministic ES256 (RFC 6979).
 *
 * Why not `node:crypto`. ECDSA picks a random `k` per signature, so signing
 * the same bytes twice produces two valid, different signatures — and
 * `npm run generate` rewrote all forty vectors on every run. A diff of forty
 * changed signatures hides the one change that was intended, and reviewing the
 * corpus becomes reading the same claim over and over: *these bytes changed,
 * trust me that nothing did*. RFC 6979 derives `k` from the key and the
 * message, so regenerating is a no-op when nothing changed.
 *
 * It stays out of `core.ts` on purpose: the reference verifier must be
 * readable as the spec implemented, and it never signs anything. Nothing on
 * the verification path loads this file or its dependency.
 */

// The private scalar, from whatever shape the key arrives in.
const scalarOf = (privateKey: KeyObject): Uint8Array => {
  const jwk = privateKey.export({ format: 'jwk' }) as { d?: string }
  if (!jwk.d) throw new Error('[vcap] not a private EC key')
  return new Uint8Array(Buffer.from(jwk.d, 'base64url'))
}

/** ES256 over `bytes`, P1363, low `s`, deterministic. */
export const signEs256 = (bytes: Buffer, privateKey: KeyObject): Buffer => {
  const hash = createHash('sha256').update(bytes).digest()
  // lowS is the library's default and §4.2's rule; named here because a
  // verifier that only accepts low s would reject the other half of the
  // signatures if it ever changed.
  const signature = p256.sign(new Uint8Array(hash), scalarOf(privateKey), { lowS: true, prehash: false })
  return Buffer.from(signature)
}

/** Signs a full chain from content hashes (§5): the writer's side. */
export const signChain = (captureId: Buffer, contentHashes: Buffer[], privateKey: KeyObject): SegmentEntry[] => {
  const entries: SegmentEntry[] = []
  let prev: Buffer = ZERO_LINK
  contentHashes.forEach((hash, index) => {
    const message = segmentMessage(captureId, index, hash, prev)
    entries.push({ gop: index, hash: hash.toString('base64url'), prev: prev.toString('base64url'), sig: signEs256(message, privateKey).toString('base64url') })
    prev = linkOf(message)
  })
  return entries
}
