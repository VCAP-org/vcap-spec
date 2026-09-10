import { X509Certificate } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * What a verifier trusts, as the corpus ships it: `vectors/_trust/`.
 *
 * A verdict is only ever "green against these anchors". Writing them down as
 * files a verifier loads — instead of compiling them into the reference
 * implementation — is what lets a second implementation reproduce a vector's
 * verdict, and what makes the substitution visible: the attestation root here
 * is a test root standing in for a pinned Google root (see the bundle's
 * README), so these vectors prove the logic of §7, not that anyone can walk a
 * real Google chain.
 */
export interface TrustedLog { log_id: string, spki: string }

export interface TrustBundle {
  attestationRoots: X509Certificate[]
  logs: TrustedLog[]
  /** The TSA roots a verifier pins; none means *trusted time not evaluated*. */
  tsaRoots: X509Certificate[]
}

export const EMPTY_TRUST: TrustBundle = { attestationRoots: [], logs: [], tsaRoots: [] }

const pemCertificates = (pem: string): X509Certificate[] =>
  (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((block) => new X509Certificate(block))

/** Loads the bundle from a directory; a missing bundle is an empty one. */
export const loadTrust = (directory: string): TrustBundle => {
  const rootsFile = join(directory, 'attestation-roots.pem')
  const logsFile = join(directory, 'logs.json')
  const tsaFile = join(directory, 'tsa-roots.pem')
  return {
    attestationRoots: existsSync(rootsFile) ? pemCertificates(readFileSync(rootsFile, 'utf8')) : [],
    logs: existsSync(logsFile) ? (JSON.parse(readFileSync(logsFile, 'utf8')) as { logs: TrustedLog[] }).logs : [],
    tsaRoots: existsSync(tsaFile) ? pemCertificates(readFileSync(tsaFile, 'utf8')) : []
  }
}
