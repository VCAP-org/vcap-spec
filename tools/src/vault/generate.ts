import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { fixture, fixtureKey } from './fixture.js'
const destination = fileURLToPath(new URL('../../test/vault-vectors/', import.meta.url))
const plaintext = Buffer.from('VCAP vault interoperability vector\n')
const output = fixture(plaintext)
writeFileSync(destination + 'manifest.json', JSON.stringify(output.manifest, null, 2) + '\n')
writeFileSync(destination + 'ciphertext.bin', output.ciphertext)
writeFileSync(destination + 'plaintext.bin', plaintext)
writeFileSync(destination + 'organization-test-key.pk8', fixtureKey)
