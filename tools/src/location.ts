import { type Json, jcs } from './jcs.js'
import { publicKeyFromSpki, verifyEs256 } from './core.js'
import { type TrustedLog } from './trust.js'

/**
 * §7.1, the position level. Three levels a proof can reach and one for no
 * claim at all — and the level is **orthogonal to the verdict**: it never
 * turns a verdict green or red, it only says how much the coordinates in the
 * core are worth.
 *
 * - `none`: the core declares no position.
 * - `declared`: the device signed coordinates. The device says so; nothing
 *   else does.
 * - `corroborated`: a `location_corroboration` attachment, signed by a
 *   registry key this verifier trusts and bound to this core hash, relays an
 *   operator-side check that agreed with the declared position.
 * - `authenticated`: reserved. No evidence kind a v1.0 verifier implements
 *   reaches it (§7.1), so this module never returns it.
 */
export const LOCATION_LEVELS = new Set(['declared', 'corroborated', 'authenticated'])
export const LOCATION_RANK: Record<string, number> = { none: 0, declared: 1, corroborated: 2, authenticated: 3 }

const LOCATION_SEPARATOR = Buffer.from('vcap/1.0/location', 'ascii')

/** The §6.2 methods, each a CAMARA API the registry may have called. Extensible (§9). */
export const CORROBORATION_METHODS = new Set(['camara-location-verification', 'camara-number-verification', 'camara-sim-swap'])
/** Not extensible: a result outside this set under a valid signature is evidence that does not parse. */
export const CORROBORATION_RESULTS = new Set(['match', 'no-match', 'unknown'])

export interface LocationCorroboration {
  method: string
  result: string
  radius_m?: number
  at: number
  operator_ref?: string
  sig: string
}

/**
 * The message the registry signs: `"vcap/1.0/location" ‖ core_hash ‖ JCS(A \ sig)`,
 * where A is the attachment. JCS of the whole body rather than a fixed-length
 * layout, so a later minor can add a field and a v1.0 verifier — which
 * canonicalizes every member it sees, known or not — still verifies the
 * signature. The result is inside the message: a `no-match` cannot be
 * relabelled `match`, which is the one thing the signature is for.
 */
export const corroborationMessage = (coreHash: Buffer, attachment: { [key: string]: Json }): Buffer => {
  const { sig: _sig, ...body } = attachment
  return Buffer.concat([LOCATION_SEPARATOR, coreHash, jcs(body)])
}

export type CorroborationOutcome =
  | { ok: true, method: string, result: string, radiusM: number | null }
  /**
   * Three ways to fail, kept apart because §8 keeps them apart:
   * `evaluated: false` is evidence this verifier cannot read (no log key held,
   * a method it does not know) — *not evaluated*; `trusted: false` is a
   * signature no trusted key made — *not verified*, which covers both a
   * signer nobody follows and a statement about another proof, since the two
   * are the same bytes to a verifier; `trusted: true` is a verified signature
   * over content that means nothing — *evidence invalid*.
   */
  | { ok: false, reason: string, evaluated: boolean, trusted: boolean }

export const verifyLocationCorroboration = (
  attachment: { [key: string]: Json }, coreHash: Buffer, logs: readonly TrustedLog[]
): CorroborationOutcome => {
  if (logs.length === 0) return { ok: false, reason: 'no trusted registry key held', evaluated: false, trusted: false }
  if (typeof attachment.method !== 'string' || !CORROBORATION_METHODS.has(attachment.method)) {
    // A method from a later minor (§9): read as evidence this version cannot
    // evaluate, never as evidence that failed.
    return { ok: false, reason: `unknown method ${String(attachment.method)}`, evaluated: false, trusted: false }
  }
  let signature: Buffer
  try {
    signature = Buffer.from(attachment.sig as string, 'base64url')
  } catch {
    return { ok: false, reason: 'the signature is not base64url', evaluated: true, trusted: false }
  }
  const message = corroborationMessage(coreHash, attachment)
  const signed = logs.some((log) => {
    const key = publicKeyFromSpki(Buffer.from(log.spki, 'base64'))
    return key !== null && verifyEs256(message, signature, key)
  })
  if (!signed) return { ok: false, reason: 'no trusted registry key signed this corroboration over this core', evaluated: true, trusted: false }

  // From here the registry really said this; the question is whether it parses.
  const { method, result } = attachment
  if (typeof result !== 'string' || !CORROBORATION_RESULTS.has(result)) {
    return { ok: false, reason: `unknown result ${String(result)}`, evaluated: true, trusted: true }
  }
  if (!Number.isInteger(attachment.at)) return { ok: false, reason: 'at is not an integer', evaluated: true, trusted: true }
  const radius = attachment.radius_m
  if (method === 'camara-location-verification' && (!Number.isInteger(radius) || (radius as number) < 1)) {
    // A zone check without its zone corroborates nothing anyone can read.
    return { ok: false, reason: 'camara-location-verification without radius_m', evaluated: true, trusted: true }
  }
  return { ok: true, method, result, radiusM: Number.isInteger(radius) ? radius as number : null }
}
