import { X509Certificate, createHash, createVerify } from 'node:crypto'

/**
 * §6.2 `timestamp.tsr`: an RFC 3161 TimeStampToken whose `messageImprint`
 * **is** `core_hash`.
 *
 * What the token buys is the one thing a device cannot assert about itself: an
 * instant somebody else will vouch for. Over `core_hash` rather than
 * `media.hash` it covers the pixels *and* the claims about them, at the same
 * cost — a timestamp over the media alone would let a writer restate the
 * capture's time, place and device after the fact and keep the stamp.
 *
 * A TimeStampToken is CMS SignedData (RFC 5652) carrying a TSTInfo, so the
 * checks are the CMS ones plus two of RFC 3161's:
 *
 *  1. the imprint is SHA-256 and equals `core_hash`;
 *  2. the `messageDigest` signed attribute equals SHA-256 of the TSTInfo;
 *  3. the signature verifies over the signed attributes, re-encoded as a
 *     `SET OF` — RFC 5652 §5.4, and the one-byte difference every CMS
 *     implementation gets wrong once;
 *  4. the signer chains to a pinned TSA root and was valid at `genTime`;
 *  5. the signer carries the **timeStamping** extended key usage. Without that
 *     check any certificate under the root could stamp, and a TSA root signs
 *     more than its own stamping key.
 *
 * Written from the RFC and the spec, like the rest of this directory, and not
 * ported from `vcap-verifier`'s validator: the point of two implementations is
 * that they were not the same one twice.
 */
const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  extendedKeyUsage: '2.5.29.37'
}

// ---- DER, only as much as CMS needs ---------------------------------------

interface Node {
  /** 0 universal, 1 application, 2 context-specific, 3 private. */
  cls: number
  constructed: boolean
  tag: number
  body: Buffer
  /** The whole element including its header: what a signature covers. */
  raw: Buffer
  end: number
}

const read = (b: Buffer, at: number): Node => {
  const first = b[at] as number
  const cls = first >> 6
  const constructed = (first & 0x20) !== 0
  let tag = first & 0x1f
  let cursor = at + 1
  if (tag === 0x1f) {
    tag = 0
    for (;;) {
      const byte = b[cursor++] as number
      tag = (tag << 7) | (byte & 0x7f)
      if (!(byte & 0x80)) break
    }
  }
  let length = b[cursor++] as number
  if (length & 0x80) {
    const count = length & 0x7f
    length = 0
    for (let i = 0; i < count; i++) length = (length << 8) | (b[cursor++] as number)
  }
  const end = cursor + length
  return { cls, constructed, tag, body: b.subarray(cursor, end), raw: b.subarray(at, end), end }
}

const children = (body: Buffer): Node[] => {
  const out: Node[] = []
  let at = 0
  while (at < body.length) {
    const node = read(body, at)
    out.push(node)
    at = node.end
  }
  return out
}

/** An OBJECT IDENTIFIER as dotted decimal. */
const oid = (node: Node): string => {
  const bytes = node.body
  const first = bytes[0] as number
  const parts = [Math.floor(first / 40), first % 40]
  let value = 0
  for (const byte of bytes.subarray(1)) {
    value = (value << 7) | (byte & 0x7f)
    if (!(byte & 0x80)) {
      parts.push(value)
      value = 0
    }
  }
  return parts.join('.')
}

/** `GeneralizedTime`, which RFC 3161 requires in Z with no offset. */
const generalizedTime = (node: Node): Date | null => {
  const text = node.body.toString('ascii')
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(text)
  if (!match) return null
  const [, y, mo, d, h, mi, s, frac] = match
  const ms = frac ? Math.round(Number(`0.${frac}`) * 1000) : 0
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms))
}

// ---- the validator --------------------------------------------------------

export type TimestampOutcome =
  | { ok: true, genTime: Date }
  | { ok: false, reason: string }

export const verifyTimestampToken = (
  tsr: Buffer, coreHash: Buffer, roots: readonly X509Certificate[]
): TimestampOutcome => {
  if (roots.length === 0) return { ok: false, reason: 'no TSA root is pinned' }

  let signedData: Node[]
  let eContent: Buffer
  let signerInfo: Node[]
  let certificate: X509Certificate
  try {
    const contentInfo = children(read(tsr, 0).body)
    if (oid(contentInfo[0] as Node) !== OID.signedData) return { ok: false, reason: 'not CMS SignedData' }
    signedData = children(children((contentInfo[1] as Node).body)[0]!.body)

    // encapContentInfo: [ eContentType, [0] EXPLICIT eContent ]
    const encap = children((signedData[2] as Node).body)
    if (oid(encap[0] as Node) !== OID.tstInfo) return { ok: false, reason: 'the content is not a TSTInfo' }
    eContent = children((encap[1] as Node).body)[0]!.body

    const certs = signedData.find((node) => node.cls === 2 && node.tag === 0)
    if (!certs) return { ok: false, reason: 'the token carries no signer certificate' }
    certificate = new X509Certificate(children(certs.body)[0]!.raw)

    // `signerInfos` is the **last** field of SignedData, and taking the first
    // universal SET instead finds `digestAlgorithms` — which is also a SET,
    // also universal, and parses far enough to produce a confusing error three
    // checks later. Position is the only thing that distinguishes them.
    const signerInfos = signedData[signedData.length - 1] as Node
    if (signerInfos.cls !== 0 || signerInfos.tag !== 17) return { ok: false, reason: 'the token carries no SignerInfo' }
    signerInfo = children(children(signerInfos.body)[0]!.body)
  } catch {
    return { ok: false, reason: 'the token is not readable DER' }
  }

  // 1. The imprint is what this proof is about.
  let genTime: Date | null
  try {
    const tstInfo = children(read(eContent, 0).body)
    const imprint = children((tstInfo[2] as Node).body)
    if (oid(children((imprint[0] as Node).body)[0] as Node) !== OID.sha256) {
      return { ok: false, reason: 'the message imprint is not SHA-256' }
    }
    if (!(imprint[1] as Node).body.equals(coreHash)) {
      return { ok: false, reason: 'the message imprint is not this proof\'s core_hash' }
    }
    // TSTInfo: version, policy, messageImprint, serialNumber, genTime, ...
    genTime = generalizedTime(tstInfo[4] as Node)
    if (!genTime) return { ok: false, reason: 'genTime is not a readable GeneralizedTime' }
  } catch {
    return { ok: false, reason: 'the TSTInfo is not readable' }
  }

  // 2-3. The signed attributes: they say what was signed, and the signature is
  // over them rather than over the content directly.
  const attrs = signerInfo.find((node) => node.cls === 2 && node.tag === 0)
  if (!attrs) return { ok: false, reason: 'the SignerInfo carries no signed attributes' }
  let digestSeen: Buffer | null = null
  let contentTypeSeen: string | null = null
  for (const attribute of children(attrs.body)) {
    const parts = children(attribute.body)
    const type = oid(parts[0] as Node)
    const values = children((parts[1] as Node).body)
    if (type === OID.messageDigest) digestSeen = (values[0] as Node).body
    if (type === OID.contentType) contentTypeSeen = oid(values[0] as Node)
  }
  if (contentTypeSeen !== OID.tstInfo) return { ok: false, reason: 'the signed contentType is not id-ct-TSTInfo' }
  if (!digestSeen?.equals(createHash('sha256').update(eContent).digest())) {
    return { ok: false, reason: 'the signed messageDigest does not match the TSTInfo' }
  }

  const signature = signerInfo[signerInfo.length - 1] as Node
  // RFC 5652 §5.4: the signature covers the attributes as a SET OF, so the
  // implicit [0] tag becomes 0x31 before hashing. Copy rather than mutate —
  // `raw` is a view into the caller's buffer.
  const asSet = Buffer.from(attrs.raw)
  asSet[0] = 0x31
  const verified = createVerify('sha256').update(asSet)
    .verify({ key: certificate.publicKey, dsaEncoding: 'der' }, signature.body)
  if (!verified) return { ok: false, reason: 'the token signature does not verify' }

  // 4. The signer, at the instant it claims to have stamped.
  const root = roots.find((candidate) => candidate.raw.equals(certificate.raw) || certificate.verify(candidate.publicKey))
  if (!root) return { ok: false, reason: 'the signer does not chain to a pinned TSA root' }
  if (new Date(certificate.validFrom) > genTime || genTime > new Date(certificate.validTo)) {
    return { ok: false, reason: 'the signer certificate was not valid at genTime' }
  }

  // 5. And it was allowed to stamp.
  if (!hasTimeStamping(certificate)) {
    return { ok: false, reason: 'the signer has no timeStamping extended key usage' }
  }
  return { ok: true, genTime }
}

const hasTimeStamping = (certificate: X509Certificate): boolean => {
  try {
    const tbs = children(children(read(certificate.raw, 0).body)[0]!.body)
    const extensions = tbs.find((node) => node.cls === 2 && node.tag === 3)
    if (!extensions) return false
    for (const extension of children(children(extensions.body)[0]!.body)) {
      const parts = children(extension.body)
      if (oid(parts[0] as Node) !== OID.extendedKeyUsage) continue
      // [ extnID, critical?, extnValue OCTET STRING ]
      const value = parts[parts.length - 1] as Node
      return children(read(value.body, 0).body).some((usage) => oid(usage) === OID.timeStamping)
    }
    return false
  } catch {
    return false
  }
}
