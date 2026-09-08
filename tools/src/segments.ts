import { type KeyObject, createHash } from 'node:crypto'
import { signEs256, verifyEs256 } from './core.js'

/** §5 segment messages and chain. */
export const SEPARATOR = Buffer.from('vcap/1.0/seg', 'ascii')
export const ZERO_LINK = Buffer.alloc(32)

export const segmentMessage = (captureId: Buffer, index: number, contentHash: Buffer, prevLink: Buffer, separator = SEPARATOR): Buffer => {
  if (captureId.length !== 16 || contentHash.length !== 32 || prevLink.length !== 32) throw new Error('segment message: bad field length')
  const n = Buffer.alloc(4)
  n.writeUInt32BE(index, 0)
  const message = Buffer.concat([separator, captureId, n, contentHash, prevLink])
  if (message.length !== 96) throw new Error('segment message: must be 96 bytes')
  return message
}

export const linkOf = (previousMessage: Buffer): Buffer => createHash('sha256').update(previousMessage).digest()

export interface SegmentEntry {
  gop: number
  // content_hash(n), base64url
  hash: string
  // prev_link(n), base64url — redundant when segment n−1 is present
  prev: string
  // sig(n), base64url P1363
  sig: string
}

/** Signs a full chain from content hashes: the writer's side. */
export const signChain = (captureId: Buffer, contentHashes: Buffer[], privateKey: KeyObject): SegmentEntry[] => {
  const entries: SegmentEntry[] = []
  let prev: Buffer = ZERO_LINK
  contentHashes.forEach((hash, index) => {
    const message = segmentMessage(captureId, index, hash, prev)
    entries.push({ gop: index, hash: hash.toString('base64url'), prev: prev.toString('base64url'), sig: signEs256(message, privateKey).toString('base64url') })
    prev = linkOf(message)
  })
  return entries
}

export type ChainStatus = 'complete' | 'clip' | 'tampered'

export interface ChainResult {
  status: ChainStatus
  verified: number[]
  reason?: string
}

/**
 * Verifier's side. Each present segment is verified over the message rebuilt
 * from its own fields; where segment n−1 is present, the stored prev_link must
 * equal SHA-256(message(n−1)) — a mismatch is a chain broken where the file
 * claims contiguity. Where n−1 is absent, the stored prev_link is taken as is
 * and the segment verifies on its own: a clip from the middle is verifiable,
 * and detectably a clip.
 */
export const verifyChain = (captureId: Buffer, segmentCount: number, segments: SegmentEntry[], publicKey: KeyObject): ChainResult => {
  const byIndex = new Map(segments.map((s) => [s.gop, s]))
  const messages = new Map<number, Buffer>()
  const verified: number[] = []

  for (const index of [...byIndex.keys()].sort((a, b) => a - b)) {
    const entry = byIndex.get(index) as SegmentEntry
    const hash = Buffer.from(entry.hash, 'base64url')
    const storedPrev = Buffer.from(entry.prev, 'base64url')
    const previous = messages.get(index - 1)
    const expectedPrev = index === 0 ? ZERO_LINK : previous ? linkOf(previous) : storedPrev
    if (!storedPrev.equals(expectedPrev)) return { status: 'tampered', verified, reason: `segment ${index}: chain broken` }

    let message: Buffer
    try {
      message = segmentMessage(captureId, index, hash, storedPrev)
    } catch {
      return { status: 'tampered', verified, reason: `segment ${index}: malformed` }
    }
    if (!verifyEs256(message, Buffer.from(entry.sig, 'base64url'), publicKey)) {
      return { status: 'tampered', verified, reason: `segment ${index}: signature invalid` }
    }
    messages.set(index, message)
    verified.push(index)
  }

  const complete = verified.length === segmentCount && verified.every((v, i) => v === i)
  return { status: complete ? 'complete' : 'clip', verified }
}
