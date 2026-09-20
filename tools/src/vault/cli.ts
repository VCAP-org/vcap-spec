import { decryptFile } from './decrypt.js'
const args = process.argv.slice(2)
if (args.length !== 4) {
  console.error('Usage: npm run vault:decrypt -- manifest.json ciphertext.bin organization-key.pk8 recovered-file')
  process.exitCode = 2
} else {
  try {
    await decryptFile(args[0]!, args[1]!, args[2]!, args[3]!)
    console.log('[vcap] decrypted; verify the recovered proof independently')
  } catch {
    // Crypto-provider errors may contain key or input material. No payloads,
    // paths, passphrases or inner exceptions belong in a diagnostic here.
    console.error('[vcap] vault decryption failed; existing files were not overwritten')
    process.exitCode = 1
  }
}
