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
interface Node { tagNumber: number, body: Buffer, end: number }

const read = (b: Buffer, at: number): Node => {
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
  return { tagNumber, body: b.subarray(cursor, cursor + length), end: cursor + length }
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
}

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
  return {
    attestationVersion: asNumber(fields[0] as Node),
    attestationLevel: level(fields[1], 'attestationSecurityLevel'),
    keyMintLevel: level(fields[3], 'keyMintSecurityLevel'),
    rootOfTrust
  }
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
    return { proven: 'none', failures: ['attestation is not a chain of DER certificates'] }
  }
  if (certs.length === 0) return { proven: 'none', failures: ['attestation chain is empty'] }
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

  const outside = walked.findIndex((c) => !validAt(c, at))
  let expiredSince: string | undefined
  if (outside !== -1) failures.push(`certificate ${outside} was not valid at ${at.toISOString()}`)
  else {
    const lapsed = walked.filter((c) => !validAt(c, clock)).map((c) => new Date(c.validTo).getTime())
    if (lapsed.length > 0) expiredSince = new Date(Math.min(...lapsed)).toISOString()
  }

  const extension = keyDescriptionOf(leaf)
  if (!extension) return { proven: 'none', failures: [...failures, 'leaf carries no key attestation extension'], expiredSince }
  let description: KeyDescription
  try {
    description = parseKeyDescription(extension)
  } catch (e) {
    return { proven: 'none', failures: [...failures, `key attestation extension unreadable: ${(e as Error).message}`], expiredSince }
  }
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
    bootState: description.rootOfTrust,
    expiredSince
  }
}

export interface ChainOutcome {
  proven: 'strongbox' | 'tee' | 'none'
  failures: string[]
  bootState?: { locked: boolean, state: string }
  expiredSince?: string
}

/** DER of an OBJECT IDENTIFIER, header included. Encoded rather than written
 * out as bytes: the second subidentifier of this OID is 11129, whose base-128
 * form is easy to get wrong by hand and impossible to notice afterwards. */
const encodeOid = (oid: string): Buffer => {
  const parts = oid.split('.').map(Number)
  const body: number[] = [40 * (parts[0] as number) + (parts[1] as number)]
  for (const part of parts.slice(2)) {
    const septets: number[] = []
    let value = part
    do { septets.unshift(value & 0x7f); value >>>= 7 } while (value > 0)
    for (let i = 0; i < septets.length - 1; i++) septets[i] = (septets[i] as number) | 0x80
    body.push(...septets)
  }
  return Buffer.from([0x06, body.length, ...body])
}

const KEY_DESCRIPTION_OID_DER = encodeOid(KEY_DESCRIPTION_OID)

/** The raw extension body, unwrapped from its OCTET STRING. */
const keyDescriptionOf = (cert: X509Certificate): Buffer | null => {
  // Node exposes no extension accessor, so the certificate's DER is searched
  // for the extension by its OID. Reading it out of the structure beats
  // re-encoding the certificate to get at it.
  const der = cert.raw
  const at = der.indexOf(KEY_DESCRIPTION_OID_DER)
  if (at === -1) return null
  const after = read(der, at + KEY_DESCRIPTION_OID_DER.length)
  // extnValue is an OCTET STRING; the optional critical BOOLEAN sits between.
  const value = after.tagNumber === 1 ? read(der, after.end) : after
  return Buffer.from(value.body)
}

export const keyIdOf = (spki: Buffer): string => createHash('sha256').update(spki).digest('hex')
