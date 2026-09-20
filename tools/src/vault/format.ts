import { createHash, createPrivateKey, createPublicKey, webcrypto } from 'node:crypto'
import { Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core'

export const CHUNK_BYTES = 1_048_576
export const MAX_BYTES = 500_000_000
export const VERSION = 'vcap-vault/1'
export interface Manifest {
  version: typeof VERSION
  object_id: string
  capture_id: string
  org_key_id: string
  nonce_prefix: string
  plaintext_bytes: number
  chunk_bytes: typeof CHUNK_BYTES
  wrapped_key: { enc: string, ciphertext: string }
  ciphertext_sha256: string
}

export const sha256 = (bytes: Uint8Array): Buffer => createHash('sha256').update(bytes).digest()
export const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
const u64 = (n: number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b }
const fail = (): never => { throw new Error('VCAP_VAULT_INVALID_MANIFEST') }
const keys = (value: unknown, expected: string[]): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === expected.sort().join(',')

export function base64url (value: unknown, bytes: number): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) return fail()
  const decoded = Buffer.from(value, 'base64url')
  if (decoded.length !== bytes || decoded.toString('base64url') !== value) return fail()
  return decoded
}

/** Validate bounds before opening a key or allocating a segment. */
export function manifest (value: unknown): Manifest {
  if (!keys(value, ['version', 'object_id', 'capture_id', 'org_key_id', 'nonce_prefix', 'plaintext_bytes', 'chunk_bytes', 'wrapped_key', 'ciphertext_sha256'])) return fail()
  if (value.version !== VERSION || value.chunk_bytes !== CHUNK_BYTES ||
      !Number.isSafeInteger(value.plaintext_bytes) || (value.plaintext_bytes as number) < 0 || (value.plaintext_bytes as number) > MAX_BYTES) return fail()
  if (typeof value.object_id !== 'string' || !/^[0-9a-f]{32}$/.test(value.object_id) ||
      typeof value.org_key_id !== 'string' || !/^[0-9a-f]{64}$/.test(value.org_key_id) ||
      typeof value.ciphertext_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.ciphertext_sha256)) return fail()
  base64url(value.capture_id, 16)
  base64url(value.nonce_prefix, 8)
  if (!keys(value.wrapped_key, ['enc', 'ciphertext'])) return fail()
  const enc = base64url(value.wrapped_key.enc, 65)
  if (enc[0] !== 4) return fail() // RFC 9180 P-256 uncompressed point
  base64url(value.wrapped_key.ciphertext, 48)
  return value as unknown as Manifest
}

/** Binary metadata, with fixed-width fields; never JSON serialization. */
export function header (m: Manifest): Buffer {
  return Buffer.concat([
    Buffer.from('vcap/1.0/vault/header\0', 'utf8'),
    Buffer.from(m.object_id, 'hex'), base64url(m.capture_id, 16), Buffer.from(m.org_key_id, 'hex'),
    base64url(m.nonce_prefix, 8), u64(m.plaintext_bytes), u32(m.chunk_bytes)
  ])
}
export const chunkCount = (m: Manifest): number => Math.max(1, Math.ceil(m.plaintext_bytes / CHUNK_BYTES))
export const ciphertextBytes = (m: Manifest): number => m.plaintext_bytes + 16 * chunkCount(m)
export const chunkSize = (m: Manifest, index: number): number => Math.min(CHUNK_BYTES, m.plaintext_bytes - index * CHUNK_BYTES)
export const nonce = (m: Manifest, index: number): Buffer => Buffer.concat([base64url(m.nonce_prefix, 8), u32(index)])
export const info = (m: Manifest): Buffer => Buffer.concat([Buffer.from('vcap/1.0/vault\0'), sha256(header(m))])
export const aad = (m: Manifest, index: number): Buffer => Buffer.concat([
  Buffer.from('vcap/1.0/vault/chunk\0'), sha256(header(m)), u32(index), Buffer.from([index === chunkCount(m) - 1 ? 1 : 0])
])

/** PKCS#8 DER or PEM; neither the key nor decrypted bytes are logged. */
export async function unwrap (m: Manifest, pkcs8: Buffer): Promise<webcrypto.CryptoKey> {
  const key = pkcs8.subarray(0, 11).toString() === '-----BEGIN '
    ? createPrivateKey(pkcs8)
    : createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('VCAP_VAULT_WRONG_KEY')
  // Normalize to an uncompressed named-curve SPKI before fingerprinting.
  const publicJwk = createPublicKey(key).export({ format: 'jwk' })
  const spki = createPublicKey({ key: publicJwk, format: 'jwk' }).export({ format: 'der', type: 'spki' })
  if (sha256(spki).toString('hex') !== m.org_key_id) throw new Error('VCAP_VAULT_WRONG_KEY')
  const privateKey = await webcrypto.subtle.importKey('pkcs8', key.export({ format: 'der', type: 'pkcs8' }), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const publicKey = await webcrypto.subtle.importKey('spki', spki, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() })
  const recipient = await suite.createRecipientContext({ recipientKey: { privateKey, publicKey }, enc: base64url(m.wrapped_key.enc, 65), info: info(m) })
  const raw = new Uint8Array(await recipient.open(base64url(m.wrapped_key.ciphertext, 48), header(m)))
  try {
    if (raw.length !== 32) throw new Error('VCAP_VAULT_INVALID_KEY')
    return await webcrypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt'])
  } finally { raw.fill(0) }
}

export async function decryptChunk (m: Manifest, key: webcrypto.CryptoKey, index: number, encrypted: Buffer): Promise<Buffer> {
  if (!Number.isInteger(index) || index < 0 || index >= chunkCount(m) || encrypted.length !== chunkSize(m, index) + 16) throw new Error('VCAP_VAULT_INVALID_CHUNK')
  return Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce(m, index), additionalData: aad(m, index), tagLength: 128 }, key, encrypted))
}
