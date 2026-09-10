import { leafHash, verifyInclusion } from './registry.js'

/**
 * §6.2 `anchor`: existence before a block, verifiable against the chain and
 * nothing of ours.
 *
 * The leaves are `SHA-256(0x00 ‖ core_hash)` and the nodes
 * `SHA-256(0x01 ‖ left ‖ right)` — the same tree as the transparency log, on
 * purpose, so a verifier carries one Merkle implementation and not two. That
 * is why this module imports from `registry.ts` instead of restating it.
 *
 * Two halves, and only one of them is offline. Recomputing the batch root from
 * `core_hash`, `index`, `tree_size` and `merkle_path` needs nothing but the
 * proof. Comparing that root with what the contract recorded needs a chain
 * read, and without one the honest answer is *anchoring not verified* — amber,
 * never red, because a verifier with no network has learned nothing bad.
 */
export interface AnchorAttachment {
  chain: string
  tx: string
  block: number
  anchor_id: number
  index: number
  tree_size: number
  root: string
  merkle_path: string[]
}

/**
 * What the contract recorded for `anchor_id`, as a caller read it.
 *
 * `block_time` is optional because a light client reading only the contract's
 * storage does not have it — and it is the field that matters most: §7 makes
 * the block's timestamp the proven instant of the capture when no timestamp
 * token is present, which is the difference between an instant the device
 * asserts and one nobody can move.
 */
export interface ChainRead {
  root: string
  tree_size: number
  block_time?: number
}

export type AnchorOutcome =
  | { ok: true, onChain: boolean, blockTime: number | null }
  | { ok: false, reason: string }

export const verifyAnchor = (
  attachment: AnchorAttachment, coreHash: Buffer, read: ChainRead | undefined
): AnchorOutcome => {
  let root: Buffer, path: Buffer[]
  try {
    root = Buffer.from(attachment.root, 'base64url')
    path = attachment.merkle_path.map((hash) => Buffer.from(hash, 'base64url'))
  } catch {
    return { ok: false, reason: 'the attachment is not base64url' }
  }
  if (root.length !== 32) return { ok: false, reason: 'root is not 32 bytes' }
  if (path.some((hash) => hash.length !== 32)) return { ok: false, reason: 'a merkle path hash is not 32 bytes' }

  if (!verifyInclusion(leafHash(coreHash), attachment.index, attachment.tree_size, path, root)) {
    return { ok: false, reason: 'the merkle path does not reach the anchored root' }
  }
  if (!read) return { ok: true, onChain: false, blockTime: null }

  let recorded: Buffer
  try {
    recorded = Buffer.from(read.root, 'base64url')
  } catch {
    return { ok: false, reason: 'the chain read is not base64url' }
  }
  // Both, and not just the root: two batches of different sizes can share a
  // root only if one is a prefix of the other, and a verifier that checked the
  // root alone would accept a proof about a different batch that happens to
  // hash the same way.
  if (read.tree_size !== attachment.tree_size || !recorded.equals(root)) {
    return { ok: false, reason: 'the anchored root differs from what the chain recorded' }
  }
  return { ok: true, onChain: true, blockTime: read.block_time ?? null }
}
