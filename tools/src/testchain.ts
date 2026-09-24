import * as asn1js from 'asn1js'
import * as x509 from '@peculiar/x509'
import { webcrypto } from 'node:crypto'

// The DOM lib is off in this package (tsconfig lib: ES2023), so the WebCrypto
// types come from node's own namespace rather than from lib.dom.
type CryptoKey = webcrypto.CryptoKey
type CryptoKeyPair = webcrypto.CryptoKeyPair

import { KEY_DESCRIPTION_OID, type Level } from './attestation.js'

/**
 * Attestation chains for the corpus. Generation only: the reference verifier in
 * `verify.ts` reads chains and never builds one, which is why this file's
 * dependency on a certificate library does not reach it.
 *
 * The root here stands in for a pinned Google root. It has to: Google's roots
 * sign chains minted by real hardware, and no test can make one. What these
 * vectors therefore prove is the **logic** of §7 — which level a chain
 * establishes, at which instant, and what a revoked certificate does to it —
 * and not that an implementation can walk a real Google chain. That is proved
 * elsewhere, by the real device chains the verifier implementations carry.
 */
const ALG: webcrypto.EcKeyGenParams & webcrypto.EcdsaParams = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }

x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0])

const LEVELS: Record<Level, number> = { software: 0, tee: 1, strongbox: 2 }

/** The KeyDescription of schema version 300, with the fields §7 reads. */
export const keyDescription = (o: { attestation: Level, keyMint: Level, locked?: boolean, bootState?: number, withRootOfTrust?: boolean, appSigningDigest?: Buffer | null }): x509.Extension => {
  const enumerated = (value: number) => new asn1js.Enumerated({ value })
  const octets = (bytes: Uint8Array) => new asn1js.OctetString({ valueHex: bytes.buffer as ArrayBuffer })
  const rootOfTrust = o.withRootOfTrust === false
    ? []
    : [new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 704 },
        value: [new asn1js.Sequence({ value: [
          octets(new Uint8Array(32)),
          new asn1js.Boolean({ value: o.locked ?? true }),
          enumerated(o.bootState ?? 0),
          octets(new Uint8Array(32))
        ] })]
      })]
  // attestationApplicationId [709]: the package and the digest of the
  // certificate that signed the app, in softwareEnforced as KeyMint puts it.
  const applicationId = o.appSigningDigest === null || o.appSigningDigest === undefined
    ? []
    : [new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 709 },
        value: [octets(new Uint8Array(new asn1js.Sequence({ value: [
          new asn1js.Set({ value: [new asn1js.Sequence({ value: [
            octets(new Uint8Array(Buffer.from('org.vcap.testapp', 'ascii'))),
            new asn1js.Integer({ value: 1 })
          ] })] }),
          new asn1js.Set({ value: [octets(new Uint8Array(o.appSigningDigest))] })
        ] }).toBER()))]
      })]
  const body = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 300 }), enumerated(LEVELS[o.attestation]),
    new asn1js.Integer({ value: 300 }), enumerated(LEVELS[o.keyMint]),
    octets(new Uint8Array([1, 2, 3])), octets(new Uint8Array(0)),
    new asn1js.Sequence({ value: applicationId }), new asn1js.Sequence({ value: rootOfTrust })
  ] }).toBER()
  return new x509.Extension(KEY_DESCRIPTION_OID, false, body)
}

export interface Issued { cert: x509.X509Certificate, keys: CryptoKeyPair }

const issue = async (o: {
  subject: string, issuer?: Issued, ca?: boolean, publicKey?: CryptoKey,
  extensions?: x509.Extension[], notBefore: Date, notAfter: Date, serial: string
}): Promise<Issued> => {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']) as CryptoKeyPair
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: o.serial,
    subject: o.subject,
    issuer: o.issuer ? o.issuer.cert.subject : o.subject,
    notBefore: o.notBefore,
    notAfter: o.notAfter,
    signingAlgorithm: ALG,
    publicKey: (o.publicKey ?? keys.publicKey) as CryptoKey,
    signingKey: (o.issuer ? o.issuer.keys.privateKey : keys.privateKey) as CryptoKey,
    // A CA carries keyCertSign as well as cA: §7 requires both of every
    // certificate above the leaf.
    extensions: [
      new x509.BasicConstraintsExtension(o.ca ?? false, undefined, true),
      ...(o.ca ? [new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] : []),
      ...(o.extensions ?? [])
    ]
  })
  return { cert, keys }
}

export interface TestChain {
  // Leaf first, each certificate DER in base64 — the `attestation` attachment.
  chain: string[]
  rootPem: string
  serials: { leaf: string, intermediate: string, root: string }
}

/**
 * A three-certificate chain over `leafPublicKey`, so the leaf's SPKI is the
 * proof's `sig.pub` as §6.2 requires. The short window belongs to the
 * intermediate and the leaf, which is the shape of a real RKP chain: a
 * per-device intermediate that lives days under a root that lives years.
 */
export const testRoot = async (): Promise<Issued> => issue({
  subject: 'CN=vcap test attestation root', ca: true, serial: '01',
  notBefore: new Date('2025-01-01T00:00:00Z'), notAfter: new Date('2045-01-01T00:00:00Z')
})

export const testChain = async (o: {
  root: Issued,
  leafPublicKey: CryptoKey,
  attestation?: Level,
  keyMint?: Level,
  locked?: boolean,
  bootState?: number,
  withRootOfTrust?: boolean,
  /** attestationApplicationId's signing digest; null writes none. */
  appSigningDigest?: Buffer | null,
  /**
   * An attested key that signs a leaf of its own: the genuine leaf becomes the
   * second certificate and the proof's key sits under it with whatever
   * KeyDescription the forger wants (§7: extension in the leaf only, CA
   * constraints above it).
   */
  forgedLeaf?: Level,
  notBefore: Date,
  notAfter: Date
}): Promise<TestChain> => {
  const root = o.root
  const intermediate = await issue({ subject: 'CN=vcap test attestation intermediate', issuer: root, ca: true, serial: '02', notBefore: o.notBefore, notAfter: o.notAfter })
  const description = (level: Level): x509.Extension => keyDescription({ attestation: level, keyMint: level, locked: o.locked, bootState: o.bootState, withRootOfTrust: o.withRootOfTrust, appSigningDigest: o.appSigningDigest })
  // §6.2: each certificate DER in base64url, like every other binary in a proof.
  const der = (c: x509.X509Certificate) => Buffer.from(c.rawData).toString('base64url')
  if (o.forgedLeaf) {
    const genuine = await issue({ subject: 'CN=Android Keystore Key', issuer: intermediate, serial: '03', notBefore: o.notBefore, notAfter: o.notAfter, extensions: [description(o.attestation ?? 'tee')] })
    const forged = await issue({ subject: 'CN=Android Keystore Key', issuer: genuine, publicKey: o.leafPublicKey, serial: '04', notBefore: o.notBefore, notAfter: o.notAfter, extensions: [description(o.forgedLeaf)] })
    return {
      chain: [der(forged.cert), der(genuine.cert), der(intermediate.cert), der(root.cert)],
      rootPem: root.cert.toString('pem') + '\n',
      serials: { leaf: '04', intermediate: '02', root: '01' }
    }
  }
  const leaf = await issue({
    subject: 'CN=Android Keystore Key',
    issuer: intermediate,
    publicKey: o.leafPublicKey,
    serial: '03',
    notBefore: o.notBefore,
    notAfter: o.notAfter,
    extensions: [description(o.attestation ?? 'tee')]
  })
  return {
    chain: [der(leaf.cert), der(intermediate.cert), der(root.cert)],
    rootPem: root.cert.toString('pem') + '\n',
    serials: { leaf: '03', intermediate: '02', root: '01' }
  }
}
