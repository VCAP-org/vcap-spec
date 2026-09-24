import { X509Certificate, createHash } from 'node:crypto'

/**
 * Spec §7, proven level: what the `attestation` chain establishes about where
 * the key lives, as opposed to what `device.secure_hw` claims.
 *
 * Node's X509Certificate verifies and reads certificates but cannot make them:
 * this module is the reading half and the generator builds the chains. The
 * KeyDescription extension is parsed here rather than taken from a library,
 * because it is the one structure a verifier must read to decide a level, and a
 * reference implementation that borrowed it would prove nothing about the spec.
 */
export type Level = 'software' | 'tee' | 'strongbox'
export const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17'
export const RANK: Record<string, number> = { none: 0, software: 0, tee: 1, secureEnclave: 1, strongbox: 2 }

const LEVELS: Level[] = ['software', 'tee', 'strongbox']
const BOOT_STATES: Record<number, string> = { 0: 'verified', 1: 'selfSigned', 2: 'unverified', 3: 'failed' }
// KeyDescription.hardwareEnforced holds a sparse, version-dependent set; the
// tag number identifies rootOfTrust, never the position.
const ROOT_OF_TRUST_TAG = 704

// --- DER, only as much as the extension needs.
interface Node { cls: number, tagNumber: number, body: Buffer, end: number }

const read = (b: Buffer, at: number): Node => {
  if (at >= b.length) throw new Error('DER: read past the end')
  const cls = (b[at] as number) >> 6
  let tagNumber = (b[at] as number) & 0x1f
  let cursor = at + 1
  if (tagNumber === 0x1f) {
    // High tag number: base-128, continuation bit on every byte but the last.
    tagNumber = 0
    for (;;) {
      const byte = b[cursor++] as number
      tagNumber = (tagNumber << 7) | (byte & 0x7f)
      if (!(byte & 0x80)) break
    }
  }
  let length = b[cursor++] as number
  if (length & 0x80) {
    const count = length & 0x7f
    length = 0
    for (let i = 0; i < count; i++) length = (length << 8) | (b[cursor++] as number)
  }
  if (cursor + length > b.length) throw new Error('DER: length past the end')
  return { cls, tagNumber, body: b.subarray(cursor, cursor + length), end: cursor + length }
}

const children = (body: Buffer): Node[] => {
  const out: Node[] = []
  let at = 0
  while (at < body.length) { const node = read(body, at); out.push(node); at = node.end }
  return out
}

const asNumber = (node: Node): number => node.body.reduce((n, byte) => (n << 8) | byte, 0)

export interface KeyDescription {
  attestationVersion: number
  attestationLevel: Level
  keyMintLevel: Level
  rootOfTrust?: { locked: boolean, state: string }
  /**
   * `attestationApplicationId.signature_digests`, lowercase hex: the signing
   * certificates of the app that created the key. Null when the extension
   * carries no `attestationApplicationId`.
   */
  appSigningDigests: string[] | null
}

// AuthorizationList tag of attestationApplicationId: in softwareEnforced on
// every KeyMint version, and read from either list so a future move is not a
// silent miss.
const APPLICATION_ID_TAG = 709

/**
 * KeyDescription ::= SEQUENCE { attestationVersion, attestationSecurityLevel,
 * keyMintVersion, keyMintSecurityLevel, attestationChallenge, uniqueId,
 * softwareEnforced, hardwareEnforced }.
 */
export const parseKeyDescription = (der: Buffer): KeyDescription => {
  const fields = children(read(der, 0).body)
  const level = (node: Node | undefined, what: string): Level => {
    const value = node ? LEVELS[asNumber(node)] : undefined
    if (!value) throw new Error(`${what}: unknown security level`)
    return value
  }
  let rootOfTrust: KeyDescription['rootOfTrust']
  const hardware = fields[7]
  if (hardware) {
    const entry = children(hardware.body).find((n) => n.tagNumber === ROOT_OF_TRUST_TAG)
    if (entry) {
      // RootOfTrust ::= SEQUENCE { verifiedBootKey, deviceLocked,
      // verifiedBootState, verifiedBootHash }.
      const parts = children(read(entry.body, 0).body)
      const locked = (parts[1]?.body[0] ?? 0) !== 0
      rootOfTrust = { locked, state: BOOT_STATES[asNumber(parts[2] as Node)] ?? 'unknown' }
    }
  }
  // AttestationApplicationId ::= SEQUENCE { package_infos SET OF
  // AttestationPackageInfo, signature_digests SET OF OCTET STRING }, wrapped
  // in an OCTET STRING under its explicit tag.
  let appSigningDigests: string[] | null = null
  for (const list of [fields[6], fields[7]]) {
    const entry = list ? children(list.body).find((n) => n.tagNumber === APPLICATION_ID_TAG) : undefined
    if (!entry) continue
    const wrapped = read(entry.body, 0)
    const id = children(read(wrapped.body, 0).body)
    appSigningDigests = id[1] ? children(id[1].body).map((d) => d.body.toString('hex')) : []
  }
  return {
    attestationVersion: asNumber(fields[0] as Node),
    attestationLevel: level(fields[1], 'attestationSecurityLevel'),
    keyMintLevel: level(fields[3], 'keyMintSecurityLevel'),
    rootOfTrust,
    appSigningDigests
  }
}

// ---- X.509 extensions, read from the structure -----------------------------

const BASIC_CONSTRAINTS = '2.5.29.19'
const KEY_USAGE = '2.5.29.15'

const oidOf = (node: Node): string => {
  const bytes = node.body
  const first = bytes[0] as number
  const parts = [Math.floor(first / 40), first % 40]
  let value = 0
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f)
    if (!(byte & 0x80)) { parts.push(value); value = 0 }
  }
  return parts.join('.')
}

/** extnID → extnValue (the OCTET STRING's content), from TBSCertificate [3]. */
const extensionsOf = (cert: X509Certificate): Map<string, Buffer> => {
  const tbs = children(read(cert.raw, 0).body)[0] as Node
  const block = children(tbs.body).find((n) => n.cls === 2 && n.tagNumber === 3)
  const out = new Map<string, Buffer>()
  if (!block) return out
  for (const extension of children(read(block.body, 0).body)) {
    const parts = children(extension.body)
    // [ extnID, critical BOOLEAN?, extnValue OCTET STRING ]
    out.set(oidOf(parts[0] as Node), Buffer.from((parts[parts.length - 1] as Node).body))
  }
  return out
}

/** basicConstraints cA, and keyUsage with keyCertSign: what an issuer needs. */
const mayIssue = (cert: X509Certificate): boolean => {
  const extensions = extensionsOf(cert)
  const constraints = extensions.get(BASIC_CONSTRAINTS)
  const usage = extensions.get(KEY_USAGE)
  if (!constraints || !usage) return false
  // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
  const cA = children(read(constraints, 0).body)[0]
  if (!cA || cA.tagNumber !== 1 || (cA.body[0] ?? 0) === 0) return false
  // KeyUsage ::= BIT STRING; keyCertSign is bit 5, 0x04 in the first byte.
  const bits = read(usage, 0).body
  return (((bits[1] ?? 0) & 0x04) !== 0)
}

const spkiOf = (cert: X509Certificate): Buffer => cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer
const validAt = (cert: X509Certificate, at: Date): boolean => new Date(cert.validFrom) <= at && at <= new Date(cert.validTo)

/**
 * §7 and the instant rule: the path is validated **at** `at` — the proven
 * instant of the capture — and `clock` only tells the caller that a chain valid
 * then has expired since. Collapsing the two would make every attested capture
 * read as unattested once its short-lived intermediate expired.
 */
export const validateChain = (
  chainBase64: string[], sigPub: Buffer, roots: X509Certificate[], at: Date, clock: Date = new Date()
): ChainOutcome => {
  const failures: string[] = []
  let certs: X509Certificate[]
  try {
    certs = chainBase64.map((der) => new X509Certificate(Buffer.from(der, 'base64')))
  } catch {
    return { proven: 'none', failures: ['attestation is not a chain of DER certificates'], evidenceInvalid: true }
  }
  if (certs.length === 0) return { proven: 'none', failures: ['attestation chain is empty'], evidenceInvalid: true }
  const leaf = certs[0] as X509Certificate

  if (!spkiOf(leaf).equals(sigPub)) failures.push('attestation leaf key differs from sig.pub')
  for (let i = 0; i < certs.length - 1; i++) {
    if (!(certs[i] as X509Certificate).verify((certs[i + 1] as X509Certificate).publicKey)) {
      failures.push(`certificate ${i} is not signed by certificate ${i + 1}`)
      break
    }
  }
  const last = certs[certs.length - 1] as X509Certificate
  const walked = [...certs]
  const root = roots.find((r) => r.raw.equals(last.raw) || last.verify(r.publicKey))
  if (root) { if (!root.raw.equals(last.raw)) walked.push(root) } else failures.push('chain does not end in a pinned root')

  // Every certificate above the leaf issues the one below it, so each MUST be
  // a CA allowed to sign certificates. Without this an attested key — a leaf,
  // genuine hardware and all — could sign a "leaf" of its own with any
  // KeyDescription it liked, and the chain would still verify to the root.
  try {
    for (let i = 1; i < walked.length; i++) {
      if (!mayIssue(walked[i] as X509Certificate)) failures.push(`certificate ${i} is not a CA with keyCertSign`)
      // The attestation extension belongs to the leaf and only the leaf.
      if (keyDescriptionOf(walked[i] as X509Certificate) !== null) failures.push(`certificate ${i} carries a key attestation extension`)
    }
  } catch {
    failures.push('a certificate\'s extensions are unreadable')
  }

  const outside = walked.findIndex((c) => !validAt(c, at))
  let expiredSince: string | undefined
  if (outside !== -1) failures.push(`certificate ${outside} was not valid at ${at.toISOString()}`)
  else {
    const lapsed = walked.filter((c) => !validAt(c, clock)).map((c) => new Date(c.validTo).getTime())
    if (lapsed.length > 0) expiredSince = new Date(Math.min(...lapsed)).toISOString()
  }

  const extension = keyDescriptionOf(leaf)
  if (!extension) return { proven: 'none', failures: [...failures, 'leaf carries no key attestation extension'], evidenceInvalid: true, expiredSince }
  let description: KeyDescription
  try {
    description = parseKeyDescription(extension)
  } catch (e) {
    return { proven: 'none', failures: [...failures, `key attestation extension unreadable: ${(e as Error).message}`], evidenceInvalid: true, expiredSince }
  }
  // Up to here a failure means the evidence does not hold up. From here on
  // the evidence holds and proves too little: a genuine chain from an
  // unlocked device, or of a software key, is not a forged one.
  const evidenceInvalid = failures.length > 0
  // §7: verified boot on a locked device, from the hardware-enforced
  // rootOfTrust. An unlocked bootloader lets anything run above the TEE.
  if (!description.rootOfTrust) failures.push('no hardware-enforced rootOfTrust')
  else if (!(description.rootOfTrust.locked && description.rootOfTrust.state === 'verified')) {
    failures.push(`boot state ${description.rootOfTrust.state}, device ${description.rootOfTrust.locked ? 'locked' : 'unlocked'}`)
  }

  // The weaker of the two levels: a StrongBox attestation of a TEE key proves
  // a TEE key.
  const weakest = RANK[description.attestationLevel] as number <= (RANK[description.keyMintLevel] as number) ? description.attestationLevel : description.keyMintLevel
  if (weakest === 'software') failures.push('attestation or key is software')
  return {
    proven: failures.length === 0 && weakest !== 'software' ? weakest : 'none',
    failures,
    evidenceInvalid,
    bootState: description.rootOfTrust,
    expiredSince,
    appSigningDigests: description.appSigningDigests,
    serials: certs.filter((c) => !roots.some((r) => r.raw.equals(c.raw))).map((c) => normalSerial(c.serialNumber))
  }
}

/** Serials compare as lowercase hex without leading zeros (§6.2). */
export const normalSerial = (hex: string): string => hex.toLowerCase().replace(/^0+(?=.)/, '')

export interface ChainOutcome {
  proven: 'strongbox' | 'tee' | 'none'
  failures: string[]
  /** A failure of the evidence itself, as opposed to evidence of too little. */
  evidenceInvalid?: boolean
  bootState?: { locked: boolean, state: string }
  expiredSince?: string
  /** From the leaf's `attestationApplicationId`; null when it carries none. */
  appSigningDigests?: string[] | null
  /** Every certificate of the chain but the pinned root, normalized (§6.2). */
  serials?: string[]
}

/** The KeyDescription extension's value, or null when the certificate has none. */
const keyDescriptionOf = (cert: X509Certificate): Buffer | null => {
  try {
    return extensionsOf(cert).get(KEY_DESCRIPTION_OID) ?? null
  } catch {
    return null
  }
}

/** The SPKI of an attestation leaf given as base64url DER, or null when unreadable. */
export const leafSpki = (der: unknown): Buffer | null => {
  if (typeof der !== 'string') return null
  try {
    return spkiOf(new X509Certificate(Buffer.from(der, 'base64url')))
  } catch {
    return null
  }
}

export const keyIdOf = (spki: Buffer): string => createHash('sha256').update(spki).digest('hex')
