import { createHash, randomBytes } from 'node:crypto'
import { link, open, unlink } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { chunkCount, chunkSize, ciphertextBytes, decryptChunk, manifest, unwrap } from './format.js'

async function readSmallFile (path: string, limit: number): Promise<Buffer> {
  const file = await open(path, 'r')
  try {
    const state = await file.stat()
    if (!state.isFile() || state.size > limit) throw new Error('VCAP_VAULT_INPUT_TOO_LARGE')
    const bytes = Buffer.alloc(limit + 1)
    let received = 0
    while (received <= limit) {
      const { bytesRead } = await file.read(bytes, received, bytes.length - received, received)
      if (bytesRead === 0) break
      received += bytesRead
    }
    if (received > limit) { bytes.fill(0); throw new Error('VCAP_VAULT_INPUT_TOO_LARGE') }
    return bytes.subarray(0, received)
  } finally { await file.close() }
}

/** Streaming reference: never publish a partial, unauthenticated output. */
export async function decryptFile (manifestPath: string, inputPath: string, keyPath: string, outputPath: string): Promise<void> {
  const m = manifest(JSON.parse((await readSmallFile(manifestPath, 16_384)).toString('utf8')))
  const input = await open(inputPath, 'r')
  const temporary = join(dirname(outputPath), `.${basename(outputPath)}.${randomBytes(16).toString('hex')}.partial`)
  let output
  try {
    const inputState = await input.stat()
    if (!inputState.isFile() || inputState.size !== ciphertextBytes(m)) throw new Error('VCAP_VAULT_LENGTH_MISMATCH')
    const pkcs8 = await readSmallFile(keyPath, 16_384)
    let key
    try { key = await unwrap(m, pkcs8) } finally { pkcs8.fill(0) }
    output = await open(temporary, 'wx', 0o600)
    const digest = createHash('sha256')
    let position = 0
    for (let index = 0; index < chunkCount(m); index++) {
      const encrypted = Buffer.alloc(chunkSize(m, index) + 16)
      let received = 0
      while (received < encrypted.length) {
        const { bytesRead } = await input.read(encrypted, received, encrypted.length - received, position + received)
        if (bytesRead === 0) throw new Error('VCAP_VAULT_TRUNCATED')
        received += bytesRead
      }
      position += received
      digest.update(encrypted)
      const plaintext = await decryptChunk(m, key, index, encrypted)
      try { await output.writeFile(plaintext) } finally { plaintext.fill(0) }
    }
    // Detect concurrent append too; the digest and tags protect read contents.
    if ((await input.stat()).size !== position || digest.digest('hex') !== m.ciphertext_sha256) throw new Error('VCAP_VAULT_CIPHERTEXT_MISMATCH')
    await output.sync()
    await output.close()
    output = undefined
    // Same-directory hard link is atomic and refuses an existing destination.
    // rename() would silently overwrite evidence supplied by the caller.
    await link(temporary, outputPath)
  } finally {
    await input.close()
    await output?.close()
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error })
  }
}
