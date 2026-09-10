import 'reflect-metadata'
import * as x509 from '@peculiar/x509'
import * as asn1js from 'asn1js'
import { X509Certificate, createHash, createSign, randomBytes, webcrypto } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Mints the RFC 3161 tokens the timestamp vectors carry, and the TSA root a
 * verifier is assumed to pin.
 *
 *   npx tsx src/make-timestamp-tokens.ts <core_hash hex>
 *
 * Committed, not generated with the vectors, for the same reason the
 * attestation chains are: a CMS signature is ECDSA, so minting again produces
 * different bytes and every timestamp vector would be rewritten on every run
 * for nothing.
 *
 * The core hash is an **argument** rather than something this script derives.
 * It has to match the proof `generate.ts` builds, and the honest way to keep
 * the two in step is not to duplicate the core construction here but to have
 * the generator refuse a token whose `messageImprint` is not the core hash it
 * just computed. Change the standard photo core and the generator fails,
 * naming the mismatch, instead of writing a vector where the timestamp is
 * about a different proof.
 *
 * A test TSA root stands in for a real QTSP's, exactly as the attestation root
 * stands in for Google's: these vectors prove the logic of §6.2 and not that
 * anyone can walk a real qualified chain.
 */
x509.cryptoProvider.set(webcrypto)

const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')
const OUT = join(VECTORS, '_timestamps')
const TRUST = join(VECTORS, '_trust')

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  timeStamping: '1.3.6.1.5.5.7.3.8'
}

const EC256: webcrypto.EcKeyGenParams & webcrypto.EcdsaParams = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
const DAY = 86_400_000
/** The capture instant the corpus pins, so a genTime is not a moving target. */
const CAPTURE = 1757332800000

const coreHashHex = process.argv[2]
if (!coreHashHex || !/^[0-9a-f]{64}$/.test(coreHashHex)) {
  throw new Error('usage: make-timestamp-tokens.ts <core_hash hex, 64 chars>')
}
const coreHash = Buffer.from(coreHashHex, 'hex')

/** A positive DER INTEGER needs a leading zero when the top bit is set. */
const derPositive = (b: Buffer): Buffer => ((b[0] as number) & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b)

const makeRoot = async (name: string) => {
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' }, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomBytes(8).toString('hex'),
    name: `CN=${name}, O=vcap test`,
    notBefore: new Date(CAPTURE - 365 * DAY),
    notAfter: new Date(CAPTURE + 3650 * DAY),
    signingAlgorithm: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },
    keys,
    extensions: [new x509.BasicConstraintsExtension(true, 2, true)]
  }, webcrypto)
  return { cert, keys }
}

const makeSigner = async (root: Awaited<ReturnType<typeof makeRoot>>, o: { withoutTimeStamping?: boolean } = {}) => {
  const keys = await webcrypto.subtle.generateKey(EC256, true, ['sign', 'verify'])
  const extensions: x509.Extension[] = [new x509.BasicConstraintsExtension(false, undefined, true)]
  // The EKU is not decoration: without it any certificate under the root could
  // stamp, and a TSA root usually signs more than its own stamping key.
  if (!o.withoutTimeStamping) extensions.push(new x509.ExtendedKeyUsageExtension([OID.timeStamping], true))
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomBytes(8).toString('hex'),
    subject: 'CN=Test TSA Signer, O=vcap test',
    issuer: root.cert.subject,
    notBefore: new Date(CAPTURE - DAY),
    notAfter: new Date(CAPTURE + 365 * DAY),
    signingAlgorithm: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },
    publicKey: keys.publicKey,
    signingKey: root.keys.privateKey,
    extensions
  })
  return {
    cert: new X509Certificate(Buffer.from(cert.rawData)),
    pkcs8: Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey))
  }
}

/** A TimeStampToken: CMS SignedData over TSTInfo, as RFC 3161 lays it out. */
const mint = async (
  signer: Awaited<ReturnType<typeof makeSigner>>, imprint: Buffer, genTime: Date
): Promise<Buffer> => {
  const tstInfo = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 1 }),
    new asn1js.ObjectIdentifier({ value: '1.3.6.1.4.1.99999.1.1' }),
    new asn1js.Sequence({ value: [
      new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.sha256 }), new asn1js.Null()] }),
      new asn1js.OctetString({ valueHex: Uint8Array.from(imprint).buffer })
    ] }),
    new asn1js.Integer({ valueHex: Uint8Array.from(Buffer.concat([Buffer.from([0]), randomBytes(8)])).buffer }),
    new asn1js.GeneralizedTime({ valueDate: genTime })
  ] })
  const tstInfoDer = Buffer.from(tstInfo.toBER())

  const digest = createHash('sha256').update(tstInfoDer).digest()
  const signedAttrs = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.contentType }), new asn1js.Set({ value: [new asn1js.ObjectIdentifier({ value: OID.tstInfo })] })] }),
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.messageDigest }), new asn1js.Set({ value: [new asn1js.OctetString({ valueHex: Uint8Array.from(digest).buffer })] })] })
  ] })
  // The signature covers the attributes as a SET OF, not as the [0] IMPLICIT
  // they appear in — RFC 5652 §5.4, and the one-byte difference every CMS
  // implementation gets wrong once.
  const attrsAsSet = Buffer.from(signedAttrs.toBER())
  attrsAsSet[0] = 0x31
  const signature = createSign('sha256').update(attrsAsSet)
    .sign({ key: signer.pkcs8, format: 'der', type: 'pkcs8', dsaEncoding: 'der' })

  const issuerName = (asn1js.fromBER(Uint8Array.from(signer.cert.raw).buffer).result as asn1js.Sequence)
  const tbs = issuerName.valueBlock.value[0] as asn1js.Sequence
  const issuerDer = (tbs.valueBlock.value[3] as asn1js.AsnType).toBER()

  const signerInfo = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 1 }),
    new asn1js.Sequence({ value: [
      asn1js.fromBER(issuerDer).result,
      new asn1js.Integer({ valueHex: Uint8Array.from(derPositive(Buffer.from(signer.cert.serialNumber, 'hex'))).buffer })
    ] }),
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.sha256 }), new asn1js.Null()] }),
    signedAttrs,
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.ecdsaWithSHA256 })] }),
    new asn1js.OctetString({ valueHex: Uint8Array.from(signature).buffer })
  ] })

  const signedData = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 3 }),
    new asn1js.Set({ value: [new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.sha256 }), new asn1js.Null()] })] }),
    new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: OID.tstInfo }),
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [new asn1js.OctetString({ valueHex: Uint8Array.from(tstInfoDer).buffer })] })
    ] }),
    new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [asn1js.fromBER(Uint8Array.from(signer.cert.raw).buffer).result] }),
    new asn1js.Set({ value: [signerInfo] })
  ] })

  return Buffer.from(new asn1js.Sequence({ value: [
    new asn1js.ObjectIdentifier({ value: OID.signedData }),
    new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [signedData] })
  ] }).toBER())
}

const write = (name: string, token: Buffer, genTime: Date, imprint: Buffer, note: string): void => {
  writeFileSync(join(OUT, `${name}.json`), JSON.stringify({
    note,
    core_hash: imprint.toString('hex'),
    gen_time: genTime.toISOString(),
    tsr: token.toString('base64url')
  }, null, 2) + '\n')
  console.log(`[vcap] _timestamps/${name}.json  ${token.length} bytes, genTime ${genTime.toISOString()}`)
}

mkdirSync(OUT, { recursive: true })
const trusted = await makeRoot('Test TSA Root')
const other = await makeRoot('Another TSA Root Nobody Pinned')

const genTime = new Date(CAPTURE + 60_000)
const signer = await makeSigner(trusted)
write('valid', await mint(signer, coreHash, genTime), genTime, coreHash,
  'A token over the standard photo core, one minute after the declared capture.')
write('other-imprint', await mint(signer, createHash('sha256').update('another proof entirely').digest(), genTime), genTime, coreHash,
  'A genuine token, over somebody else\'s core hash.')
write('untrusted-root', await mint(await makeSigner(other), coreHash, genTime), genTime, coreHash,
  'The same token from a TSA whose root the corpus does not pin.')
write('no-eku', await mint(await makeSigner(trusted, { withoutTimeStamping: true }), coreHash, genTime), genTime, coreHash,
  'A signer under the trusted root with no timeStamping extended key usage.')

writeFileSync(join(TRUST, 'tsa-roots.pem'), trusted.cert.toString() + '\n')
console.log(`[vcap] _trust/tsa-roots.pem  ${trusted.cert.subject}`)
