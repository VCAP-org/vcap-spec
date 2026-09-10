import { createHash } from 'node:crypto'
import { jcs, type Json } from './jcs.js'
import { publicKeyFromSpki, verifyEs256 } from './core.js'
import { type TrustedLog } from './trust.js'

/**
 * §6.2 `registry`: the evidence that a signing key was in the transparency log
 * when a tree head was signed — checked **offline**, because the proof carries
 * the evidence rather than a reference to be resolved.
 *
 * Written from the spec, like everything else in this directory, and
 * deliberately not from `vcap-verifier`'s `registry.ts`: two implementations
 * of the same paragraph agreeing is the only evidence the paragraph is
 * unambiguous, and one implementation copied twice is no evidence at all.
 *
 * The one thing worth knowing before reading the code: **nothing in a Merkle
 * tree proves a leaf does not exist.** An inclusion proof is why "the key is
 * in the log" is checkable here; "the key has not been revoked" is not, and
 * §6.2 makes it a signed statement fetched online instead.
 */
const LEAF_PREFIX = Buffer.from([0x00])
const NODE_PREFIX = Buffer.from([0x01])
const STH_SEPARATOR = Buffer.from('vcap/1.0/sth', 'ascii')

const sha256 = (...parts: Buffer[]): Buffer =>
  parts.reduce((h, part) => h.update(part), createHash('sha256')).digest()

/** RFC 6962 leaf hash: `SHA-256(0x00 ‖ bytes)`. */
export const leafHash = (bytes: Buffer): Buffer => sha256(LEAF_PREFIX, bytes)

/** RFC 6962 node hash: `SHA-256(0x01 ‖ left ‖ right)`. */
export const nodeHash = (left: Buffer, right: Buffer): Buffer => sha256(NODE_PREFIX, left, right)

const u64be = (value: number): Buffer => {
  const out = Buffer.alloc(8)
  out.writeBigUInt64BE(BigInt(value))
  return out
}

/**
 * The fixed-length message a log signs a tree head over (§6.2).
 *
 * Fixed-length and separated, for the reason every message in this format is:
 * a size and a timestamp concatenated without widths could be re-split, and a
 * signature over an ambiguous message proves whichever reading the attacker
 * prefers.
 */
export const treeHeadMessage = (treeSize: number, timestamp: number, root: Buffer): Buffer =>
  Buffer.concat([STH_SEPARATOR, u64be(treeSize), u64be(timestamp), root])

/**
 * RFC 6962 §2.1.1 inclusion-proof verification.
 *
 * The index and the tree size drive the walk: at each step the parity of the
 * *remaining* index says whether the sibling is on the left or the right, and
 * the last incomplete level is skipped rather than padded. A verifier that
 * ignored `tree_size` and just hashed the path bottom-up would accept a proof
 * for the same leaf at a different position, which is exactly what a log
 * rewriting history would hand it.
 */
export const verifyInclusion = (
  leaf: Buffer, index: number, treeSize: number, path: Buffer[], root: Buffer
): boolean => {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize)) return false
  if (index < 0 || treeSize <= 0 || index >= treeSize) return false

  let hash = leaf
  let position = index
  let size = treeSize
  let step = 0
  while (size > 1) {
    if (step >= path.length) return false
    if (position % 2 === 1 || position + 1 < size) {
      const sibling = path[step] as Buffer
      hash = position % 2 === 1 ? nodeHash(sibling, hash) : nodeHash(hash, sibling)
      step += 1
    }
    position = Math.floor(position / 2)
    size = Math.ceil(size / 2)
  }
  // A path with hashes left over is not this proof: accepting the prefix would
  // let anyone append junk to a valid proof and have it still verify.
  return step === path.length && hash.equals(root)
}

export interface RegistryLeaf {
  type: string
  key_id: string
  public_key: string
  secure_hw: string
  attestation_digest: string
  registered_at: number
}

export interface RegistryAttachment {
  log_id: string
  leaf_index: number
  leaf: RegistryLeaf
  inclusion_path: string[]
  tree_head: { tree_size: number, timestamp: number, root_hash: string, signature: string }
}

export type RegistryOutcome =
  | { ok: true, secureHw: string, registeredAt: number, treeHeadTimestamp: number }
  /** `trusted: false` is "nobody I trust runs that log", which is weaker
   *  evidence rather than broken evidence — the distinction §8 keeps between
   *  an absent field and an invalid one. */
  | { ok: false, reason: string, trusted: boolean }

/**
 * The checks of §6.2, **in the order the spec gives them**: the tree head
 * signature, then inclusion, then the leaf's binding to this key.
 *
 * Order matters for what a failure means. An unverified tree head makes the
 * root untrusted, so an inclusion proof against it proves nothing — reporting
 * "not included" there would blame the path for a bad signature.
 */
/**
 * The same digest as `device.key_id`, in the encoding the log's leaf records
 * it in.
 *
 * The two are not the same string: `device.key_id` is base64url (§6.1) and the
 * leaf is 64 hex characters (the schema). It is one value in two encodings,
 * and comparing the strings would fail on every honest proof — which is
 * exactly what the first version of these vectors did, and how the mismatch
 * between §6.2's prose and the schema surfaced at all.
 */
export const leafKeyId = (deviceKeyId: string): string | null => {
  try {
    const bytes = Buffer.from(deviceKeyId, 'base64url')
    return bytes.length === 32 ? bytes.toString('hex') : null
  } catch {
    return null
  }
}

export const verifyRegistry = (
  attachment: RegistryAttachment,
  expected: { keyId: string, sigPub: Buffer },
  logs: readonly TrustedLog[]
): RegistryOutcome => {
  const log = logs.find((candidate) => candidate.log_id === attachment.log_id)
  if (!log) return { ok: false, reason: `log ${attachment.log_id} is not trusted`, trusted: false }
  const key = publicKeyFromSpki(Buffer.from(log.spki, 'base64'))
  if (!key) return { ok: false, reason: 'the trusted log key is unusable', trusted: false }

  let root: Buffer, signature: Buffer, path: Buffer[]
  try {
    root = Buffer.from(attachment.tree_head.root_hash, 'base64url')
    signature = Buffer.from(attachment.tree_head.signature, 'base64url')
    path = attachment.inclusion_path.map((hash) => Buffer.from(hash, 'base64url'))
  } catch {
    return { ok: false, reason: 'the attachment is not base64url', trusted: true }
  }
  if (root.length !== 32) return { ok: false, reason: 'root_hash is not 32 bytes', trusted: true }
  if (path.some((hash) => hash.length !== 32)) return { ok: false, reason: 'an inclusion path hash is not 32 bytes', trusted: true }

  const head = treeHeadMessage(attachment.tree_head.tree_size, attachment.tree_head.timestamp, root)
  if (!verifyEs256(head, signature, key)) return { ok: false, reason: 'the tree head signature does not verify', trusted: true }

  const leaf = leafHash(jcs(attachment.leaf as unknown as Json))
  if (!verifyInclusion(leaf, attachment.leaf_index, attachment.tree_head.tree_size, path, root)) {
    return { ok: false, reason: 'the leaf is not included in the signed tree', trusted: true }
  }

  if (attachment.leaf.type !== 'key') return { ok: false, reason: `leaf.type is ${attachment.leaf.type}`, trusted: true }
  const wanted = leafKeyId(expected.keyId)
  if (wanted === null) return { ok: false, reason: 'device.key_id is not 32 base64url bytes', trusted: true }
  if (attachment.leaf.key_id !== wanted) {
    return { ok: false, reason: 'the leaf names another key', trusted: true }
  }
  // The public key too, and not only the id: an id is a hash of the key, so a
  // leaf whose `public_key` did not match its own `key_id` would be a leaf the
  // log should never have accepted, and taking the id alone would let it pass.
  let leafKey: Buffer
  try {
    leafKey = Buffer.from(attachment.leaf.public_key, 'base64')
  } catch {
    return { ok: false, reason: 'leaf.public_key is not base64', trusted: true }
  }
  if (!leafKey.equals(expected.sigPub)) return { ok: false, reason: 'the leaf carries another public key', trusted: true }

  return {
    ok: true,
    secureHw: attachment.leaf.secure_hw,
    registeredAt: attachment.leaf.registered_at,
    treeHeadTimestamp: attachment.tree_head.timestamp
  }
}

/**
 * §6.2 "Revocation, online": the key's standing in the log **at the instant
 * the capture is validated at**.
 *
 * The `registry` attachment proves the key was in the log when a tree head was
 * signed. It cannot prove the key was not revoked afterwards, because a
 * revocation is a *later* leaf and nothing in a Merkle tree proves a leaf's
 * absence. So the answer is a statement the log signs over a fixed-length
 * message, and it answers for one instant only — the log applies the temporal
 * rule before it signs.
 *
 * A verifier with no network gets no statement, and §7 requires it to say so:
 * *revocation not checked*, amber. It is the one check green cannot be reached
 * without, and that is deliberate — green never means less than it says.
 */
export type KeyStatusCode = 0 | 1 | 2

export interface KeyStatusStatement {
  log_id: string
  /** ms, the instant the status is asserted for: the verifier's question, echoed. */
  at: number
  tree_size: number
  status: number
  signature: string
}

const STATUS_SEPARATOR = Buffer.from('vcap/1.0/status', 'ascii')

export const keyStatusMessage = (keyId: Buffer, at: number, treeSize: number, status: KeyStatusCode): Buffer =>
  Buffer.concat([STATUS_SEPARATOR, keyId, u64be(at), u64be(treeSize), Buffer.from([status])])

export type KeyStatusOutcome =
  | { ok: true, status: number }
  | { ok: false, reason: string }

/**
 * Checks a statement is about **this key, this instant** and signed by the
 * trusted log.
 *
 * The instant is checked and not just carried: a statement about last week
 * signed by the right key is a valid statement to the wrong question, and a
 * verifier that accepted it would report a revocation that had not happened
 * yet, or miss one that had.
 */
export const verifyKeyStatus = (
  statement: KeyStatusStatement, keyId: Buffer, at: Date, logs: readonly TrustedLog[]
): KeyStatusOutcome => {
  const log = logs.find((candidate) => candidate.log_id === statement.log_id)
  if (!log) return { ok: false, reason: `log ${statement.log_id} is not trusted` }
  const key = publicKeyFromSpki(Buffer.from(log.spki, 'base64'))
  if (!key) return { ok: false, reason: 'the trusted log key is unusable' }
  if (statement.at !== at.getTime()) return { ok: false, reason: 'the statement answers another instant' }
  if (statement.status !== 0 && statement.status !== 1 && statement.status !== 2) {
    return { ok: false, reason: `unknown status byte ${statement.status}` }
  }
  let signature: Buffer
  try {
    signature = Buffer.from(statement.signature, 'base64url')
  } catch {
    return { ok: false, reason: 'the signature is not base64url' }
  }
  const message = keyStatusMessage(keyId, statement.at, statement.tree_size, statement.status as KeyStatusCode)
  if (!verifyEs256(message, signature, key)) return { ok: false, reason: 'the status signature does not verify' }
  return { ok: true, status: statement.status }
}
