// @peculiar/x509 pulls tsyringe, which needs this polyfill before it loads.
import 'reflect-metadata'
import { createPrivateKey, webcrypto } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { TEST_KEY_PKCS8_BASE64 } from './testkey.js'
import { TEST_LOG_KEY_PKCS8_BASE64 } from './testlogkey.js'
import { testChain, testRoot } from './testchain.js'
import { APP_SIGNING_DIGEST } from './testapp.js'
import { spkiOf } from './core.js'
import { createHash } from 'node:crypto'

/**
 * Writes `vectors/_trust/` and `vectors/_chains/`, on demand and **not** as
 * part of `npm run generate`.
 *
 * The reason is the same one that exempts the container vectors: a certificate
 * carries an ECDSA signature, so minting the chains again produces different
 * bytes, and `generate` would rewrite every attested vector on every run for
 * nothing. The chains are inputs, committed like the sealed video files, and
 * the generator reads them. Run this only to change what the chains say — and
 * then expect the attested vectors' bytes to change with them.
 */
const ROOT = join(import.meta.dirname, '..', '..')
const TRUST = join(ROOT, 'vectors', '_trust')
const CHAINS = join(ROOT, 'vectors', '_chains')

const CAPTURE = new Date(1757332800000)
const day = 86_400_000

const leafKey = await webcrypto.subtle.importKey(
  'spki',
  new Uint8Array(spkiOf(createPrivateKey({ key: Buffer.from(TEST_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' }))),
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['verify']
)

const root = await testRoot()
const long = { notBefore: new Date(CAPTURE.getTime() - day), notAfter: new Date('2040-01-01T00:00:00Z') }
// Twelve days, the life of a real RKP intermediate: valid at the capture and
// expired long before any verifier reads this corpus again.
const short = { notBefore: new Date(CAPTURE.getTime() - day), notAfter: new Date(CAPTURE.getTime() + 11 * day) }

// The app the test log admits keys from (§7, attestationApplicationId), and
// one it does not.
const app = APP_SIGNING_DIGEST
const otherApp = createHash('sha256').update('an app nobody admitted').digest()

const chains = {
  tee: await testChain({ root, leafPublicKey: leafKey, attestation: 'tee', keyMint: 'tee', appSigningDigest: app, ...long }),
  strongbox: await testChain({ root, leafPublicKey: leafKey, attestation: 'strongbox', keyMint: 'strongbox', appSigningDigest: app, ...long }),
  expiring: await testChain({ root, leafPublicKey: leafKey, attestation: 'tee', keyMint: 'tee', appSigningDigest: app, ...short }),
  'forged-leaf': await testChain({ root, leafPublicKey: leafKey, attestation: 'tee', keyMint: 'tee', forgedLeaf: 'strongbox', appSigningDigest: app, ...long }),
  'other-app': await testChain({ root, leafPublicKey: leafKey, attestation: 'tee', keyMint: 'tee', appSigningDigest: otherApp, ...long }),
  'no-app-id': await testChain({ root, leafPublicKey: leafKey, attestation: 'tee', keyMint: 'tee', appSigningDigest: null, ...long })
}

mkdirSync(TRUST, { recursive: true })
mkdirSync(CHAINS, { recursive: true })
for (const [name, built] of Object.entries(chains)) {
  writeFileSync(join(CHAINS, `${name}.json`), JSON.stringify({ chain: built.chain }, null, 2) + '\n')
}
writeFileSync(join(TRUST, 'attestation-roots.pem'), chains.tee.rootPem)

const logSpki = spkiOf(createPrivateKey({ key: Buffer.from(TEST_LOG_KEY_PKCS8_BASE64, 'base64'), format: 'der', type: 'pkcs8' }))
writeFileSync(join(TRUST, 'logs.json'), JSON.stringify({
  logs: [{
    log_id: createHash('sha256').update(logSpki).digest('base64url'),
    spki: logSpki.toString('base64'),
    app_signing_digests: [app.toString('hex')]
  }]
}, null, 2) + '\n')

console.log(`[vcap] wrote ${Object.keys(chains).length} chains, one attestation root and one log key`)
