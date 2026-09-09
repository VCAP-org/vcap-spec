import { type KeyObject, createHash, createPublicKey, createVerify } from 'node:crypto'
import { type Json, jcs } from './jcs.js'

/** §6.1: exactly these top-level keys form the signed core. */
export const CORE_KEYS = ['v', 'capture_id', 'media', 'device', 'watermark', 'time', 'location', 'policy'] as const

export type Proof = { [key: string]: Json }

export const extractCore = (proof: Proof): Proof => {
  const core: Proof = {}
  for (const key of CORE_KEYS) if (key in proof) core[key] = proof[key] as Json
  return core
}

export const coreBytes = (proof: Proof): Buffer => jcs(extractCore(proof))
export const coreHash = (proof: Proof): Buffer => createHash('sha256').update(coreBytes(proof)).digest()

export const keyId = (spkiDer: Buffer): string => createHash('sha256').update(spkiDer).digest('base64url')

// Order of the P-256 group, for low-s normalization (§4.2).
const N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
const HALF_N = N >> 1n

const toBig = (b: Buffer): bigint => BigInt(`0x${b.toString('hex')}`)
const toBuf32 = (n: bigint): Buffer => Buffer.from(n.toString(16).padStart(64, '0'), 'hex')

export const isLowS = (sig: Buffer): boolean => toBig(sig.subarray(32)) <= HALF_N

/** Flips s to n − s: the other valid signature for the same message. */
export const flipS = (sig: Buffer): Buffer => Buffer.concat([sig.subarray(0, 32), toBuf32(N - toBig(sig.subarray(32)))])

export const verifyEs256 = (bytes: Buffer, sig: Buffer, publicKey: KeyObject): boolean =>
  sig.length === 64 && createVerify('SHA256').update(bytes).verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, sig)

export const publicKeyFromSpki = (spkiDer: Buffer): KeyObject | null => {
  try {
    const key = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' })
    return key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1' ? key : null
  } catch {
    return null
  }
}

export const spkiOf = (key: KeyObject): Buffer => createPublicKey(key).export({ type: 'spki', format: 'der' })

/** P1363 → DER, for the vector that must be refused. */
export const p1363ToDer = (sig: Buffer): Buffer => {
  const int = (b: Buffer): Buffer => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    let v = b.subarray(i)
    if ((v[0] as number) & 0x80) v = Buffer.concat([Buffer.from([0]), v])
    return Buffer.concat([Buffer.from([0x02, v.length]), v])
  }
  const body = Buffer.concat([int(sig.subarray(0, 32)), int(sig.subarray(32))])
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}
