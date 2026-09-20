import { afterEach, describe, expect, it } from 'vitest'
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { createPrivateKey } from 'node:crypto'
import { decryptFile } from '../src/vault/decrypt.js'
import { CHUNK_BYTES, MAX_BYTES, manifest, sha256 } from '../src/vault/format.js'
import { fixture, fixtureKey } from '../src/vault/fixture.js'
import { validateVault } from '../src/schema.js'
import { TEST_OTHER_KEY_PKCS8_BASE64 } from '../src/testkey.js'

const folders: string[] = []
const vectors = fileURLToPath(new URL('./vault-vectors/', import.meta.url))
afterEach(async () => { await Promise.all(folders.splice(0).map(async path => await rm(path, { recursive: true, force: true }))) })
const folder = async (): Promise<string> => { const path = await mkdtemp(join(tmpdir(), 'vcap-vault-')); folders.push(path); return path }
const files = async (value = fixture(Buffer.from('recovered bytes')), key: Buffer = fixtureKey): Promise<string> => {
  const path = await folder()
  await writeFile(join(path, 'manifest.json'), JSON.stringify(value.manifest))
  await writeFile(join(path, 'ciphertext.bin'), value.ciphertext)
  await writeFile(join(path, 'key.pk8'), key)
  return path
}
const decrypt = async (path: string): Promise<void> => await decryptFile(join(path, 'manifest.json'), join(path, 'ciphertext.bin'), join(path, 'key.pk8'), join(path, 'output.bin'))
const refused = async (path: string): Promise<void> => {
  const before = await readdir(path)
  await expect(decrypt(path)).rejects.toThrow()
  expect((await readdir(path)).sort()).toEqual(before.sort())
}

describe('offline vault reference format', () => {
  it('opens committed bytes from the independent encoder and regenerates them exactly', async () => {
    const path = await folder()
    await decryptFile(join(vectors, 'manifest.json'), join(vectors, 'ciphertext.bin'), join(vectors, 'organization-test-key.pk8'), join(path, 'recovered'))
    const plaintext = await readFile(join(vectors, 'plaintext.bin'))
    expect(await readFile(join(path, 'recovered'))).toEqual(plaintext)
    const regenerated = fixture(plaintext)
    expect(validateVault(regenerated.manifest).valid).toBe(true)
    expect(regenerated.manifest).toEqual(JSON.parse(await readFile(join(vectors, 'manifest.json'), 'utf8')))
    expect(regenerated.ciphertext).toEqual(await readFile(join(vectors, 'ciphertext.bin')))
    expect(fixtureKey).toEqual(await readFile(join(vectors, 'organization-test-key.pk8')))
    expect((await stat(join(path, 'recovered'))).mode & 0o777).toBe(0o600)
  })

  it.each([0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, 2 * CHUNK_BYTES])('recovers %i bytes including empty and exact-boundary final segments', async length => {
    const plaintext = Buffer.alloc(length, 0xa7)
    const path = await files(fixture(plaintext))
    await decrypt(path)
    expect(await readFile(join(path, 'output.bin'))).toEqual(plaintext)
  })

  it('accepts a PKCS#8 PEM export as well as DER', async () => {
    const key = createPrivateKey({ key: fixtureKey, type: 'pkcs8', format: 'der' }).export({ type: 'pkcs8', format: 'pem' })
    const path = await files(undefined, Buffer.from(key))
    await decrypt(path)
    expect(await readFile(join(path, 'output.bin'), 'utf8')).toBe('recovered bytes')
  })

  it('never overwrites existing evidence', async () => {
    const path = await files()
    await writeFile(join(path, 'output.bin'), 'existing evidence')
    await refused(path)
    expect(await readFile(join(path, 'output.bin'), 'utf8')).toBe('existing evidence')
  })

  it('rejects the wrong organization key', async () => {
    await refused(await files(undefined, Buffer.from(TEST_OTHER_KEY_PKCS8_BASE64, 'base64')))
  })

  it.each(['object_id', 'capture_id', 'nonce_prefix', 'org_key_id', 'plaintext_bytes'] as const)('authenticates metadata: %s cannot be rebound', async field => {
    const value = fixture(Buffer.from('example'))
    if (field === 'plaintext_bytes') { value.manifest[field]++; value.ciphertext = Buffer.concat([value.ciphertext, Buffer.from([0])]) }
    else if (field === 'capture_id') value.manifest[field] = Buffer.alloc(16, 0x99).toString('base64url')
    else if (field === 'nonce_prefix') value.manifest[field] = Buffer.alloc(8, 0x99).toString('base64url')
    else value.manifest[field] = '9'.repeat(value.manifest[field].length)
    await refused(await files(value))
  })

  it.each(['truncate', 'append', 'change-tag', 'swap-segments', 'wrap-tag', 'enc-point', 'wrong-digest'] as const)('fails closed on %s and removes partial plaintext', async mutation => {
    const value = fixture(Buffer.alloc(CHUNK_BYTES + 100, 0xa3))
    if (mutation === 'truncate') value.ciphertext = value.ciphertext.subarray(0, -1)
    if (mutation === 'append') value.ciphertext = Buffer.concat([value.ciphertext, Buffer.from([0])])
    if (mutation === 'change-tag') value.ciphertext[value.ciphertext.length - 1]! ^= 1
    if (mutation === 'swap-segments') value.ciphertext = Buffer.concat([value.ciphertext.subarray(CHUNK_BYTES + 16), value.ciphertext.subarray(0, CHUNK_BYTES + 16)])
    if (mutation === 'wrap-tag') { const wrap = Buffer.from(value.manifest.wrapped_key.ciphertext, 'base64url'); wrap[47]! ^= 1; value.manifest.wrapped_key.ciphertext = wrap.toString('base64url') }
    if (mutation === 'enc-point') value.manifest.wrapped_key.enc = Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]).toString('base64url')
    // An attacker can recompute this unkeyed digest. Tags must still reject it.
    value.manifest.ciphertext_sha256 = mutation === 'wrong-digest' ? '0'.repeat(64) : sha256(value.ciphertext).toString('hex')
    await refused(await files(value))
  })

  it('requires an authenticated final marker even when all lengths and the digest match', async () => {
    await refused(await files(fixture(Buffer.alloc(CHUNK_BYTES + 3, 0x11), false)))
  })

  it.each([
    { version: 'vcap-vault/2' }, { chunk_bytes: 16 }, { plaintext_bytes: MAX_BYTES + 1 },
    { plaintext_bytes: -1 }, { plaintext_bytes: 1.5 }, { plaintext_bytes: Number.MAX_SAFE_INTEGER },
    { nonce_prefix: 'AAAAAAAAAAA=' }, { capture_id: 'not-an-id' }, { extra: true }
  ])('refuses unsupported or unbounded manifests before decryption: %o', patch => {
    const value = { ...fixture(Buffer.alloc(0)).manifest, ...patch }
    expect(validateVault(value).valid).toBe(false)
    expect(() => manifest(value)).toThrow('VCAP_VAULT_INVALID_MANIFEST')
  })

  it('accepts the exact size cap structurally without allocating the declared file', () => {
    const value = { ...fixture(Buffer.alloc(0)).manifest, plaintext_bytes: MAX_BYTES }
    expect(validateVault(value).valid).toBe(true)
    expect(manifest(value).plaintext_bytes).toBe(MAX_BYTES)
  })

  it('bounds key files before importing them', async () => {
    const path = await files()
    await writeFile(join(path, 'key.pk8'), Buffer.alloc(16_385))
    await refused(path)
  })

  it('bounds the manifest file before parsing', async () => {
    const path = await files()
    await writeFile(join(path, 'manifest.json'), ' '.repeat(16_385))
    await refused(path)
  })
})
