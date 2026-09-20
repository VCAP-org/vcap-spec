// TEST DATA ONLY. Independent encoder for interoperability vectors; never use
// deterministic keys, DEKs or nonces with real files. The decoder uses hpke-js
// and WebCrypto. This encoder uses Node crypto and RFC 9180's labeled schedule,
// not the decoder's HPKE implementation or binary-format helpers.
import { createCipheriv, createECDH, createHash, createHmac, createPrivateKey, createPublicKey } from 'node:crypto'
import { TEST_KEY_PKCS8_BASE64 } from '../testkey.js'
import type { Manifest } from './format.js'
const cat = (...values: Uint8Array[]): Buffer => Buffer.concat(values)
const text = (value: string): Buffer => Buffer.from(value)
const u16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b }
const u32 = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
const u64 = (n: number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b }
const hash = (b: Uint8Array): Buffer => createHash('sha256').update(b).digest()
const extract = (salt: Uint8Array, ikm: Uint8Array): Buffer => createHmac('sha256', salt).update(ikm).digest()
const expand = (prk: Uint8Array, info: Uint8Array, length: number): Buffer => {
  let previous: Buffer = Buffer.alloc(0)
  const blocks: Buffer[] = []
  for (let index = 1; blocks.length * 32 < length; index++) {
    previous = createHmac('sha256', prk).update(cat(previous, info, Buffer.from([index]))).digest()
    blocks.push(previous)
  }
  return cat(...blocks).subarray(0, length)
}
const labeledExtract = (suite: Buffer, salt: Buffer, label: string, ikm: Buffer): Buffer =>
  extract(salt, cat(text('HPKE-v1'), suite, text(label), ikm))
const labeledExpand = (suite: Buffer, prk: Buffer, label: string, info: Buffer, length: number): Buffer =>
  expand(prk, cat(u16(length), text('HPKE-v1'), suite, text(label), info), length)
const encrypt = (key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer): Buffer => {
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  return cat(cipher.update(plaintext), cipher.final(), cipher.getAuthTag())
}
export const fixtureKey = Buffer.from(TEST_KEY_PKCS8_BASE64, 'base64')
export function fixture (plaintext: Buffer, markFinal = true): { manifest: Manifest, ciphertext: Buffer } {
  const recipient = createPrivateKey({ key: fixtureKey, format: 'der', type: 'pkcs8' })
  const jwk = createPublicKey(recipient).export({ format: 'jwk' })
  const publicPoint = cat(Buffer.from([4]), Buffer.from(jwk.x!, 'base64url'), Buffer.from(jwk.y!, 'base64url'))
  const spki = createPublicKey(recipient).export({ format: 'der', type: 'spki' })
  const ephemeral = createECDH('prime256v1')
  ephemeral.setPrivateKey(Buffer.from('00'.repeat(31) + '02', 'hex'))
  const enc = ephemeral.getPublicKey()
  const empty = Buffer.alloc(0)
  const kemSuite = cat(text('KEM'), u16(0x0010))
  const eaePrk = labeledExtract(kemSuite, empty, 'eae_prk', ephemeral.computeSecret(publicPoint))
  const shared = labeledExpand(kemSuite, eaePrk, 'shared_secret', cat(enc, publicPoint), 32)
  const m: Manifest = {
    version: 'vcap-vault/1', object_id: '10'.repeat(16), capture_id: Buffer.alloc(16, 0x20).toString('base64url'),
    org_key_id: hash(spki).toString('hex'), nonce_prefix: Buffer.alloc(8, 0x30).toString('base64url'),
    plaintext_bytes: plaintext.length, chunk_bytes: 1_048_576,
    wrapped_key: { enc: enc.toString('base64url'), ciphertext: '' }, ciphertext_sha256: ''
  }
  const header = cat(text('vcap/1.0/vault/header\0'), Buffer.from(m.object_id, 'hex'), Buffer.from(m.capture_id, 'base64url'), hash(spki), Buffer.from(m.nonce_prefix, 'base64url'), u64(plaintext.length), u32(m.chunk_bytes))
  const headerHash = hash(header)
  const hpkeInfo = cat(text('vcap/1.0/vault\0'), headerHash)
  const suite = cat(text('HPKE'), u16(0x0010), u16(0x0001), u16(0x0002))
  const schedule = cat(Buffer.from([0]), labeledExtract(suite, empty, 'psk_id_hash', empty), labeledExtract(suite, empty, 'info_hash', hpkeInfo))
  const secret = labeledExtract(suite, shared, 'secret', empty)
  const key = labeledExpand(suite, secret, 'key', schedule, 32)
  const baseNonce = labeledExpand(suite, secret, 'base_nonce', schedule, 12)
  const dek = Buffer.alloc(32, 0x40)
  m.wrapped_key.ciphertext = encrypt(key, baseNonce, header, dek).toString('base64url')
  const segments = Math.max(1, Math.ceil(plaintext.length / m.chunk_bytes))
  const ciphertext = cat(...Array.from({ length: segments }, (_, index) => encrypt(
    dek, cat(Buffer.from(m.nonce_prefix, 'base64url'), u32(index)),
    cat(text('vcap/1.0/vault/chunk\0'), headerHash, u32(index), Buffer.from([markFinal && index === segments - 1 ? 1 : 0])),
    plaintext.subarray(index * m.chunk_bytes, (index + 1) * m.chunk_bytes)
  )))
  m.ciphertext_sha256 = hash(ciphertext).toString('hex')
  return { manifest: m, ciphertext }
}
