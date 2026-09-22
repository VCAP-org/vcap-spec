import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'

/**
 * `vectors/_watermark/layouts.json`, recomputed.
 *
 * The layout vectors are hand-written, which is the right way round — they are
 * the statement of the layout, not an output of it — but a hand-written vector
 * with a typo in it is a vector every implementation will faithfully reproduce
 * the wrong answer for. So the corpus is checked for internal consistency here:
 * the message must follow from the id, and the id from the capture id.
 */
const WATERMARK = join(import.meta.dirname, '..', '..', 'vectors', '_watermark')
const layouts = JSON.parse(readFileSync(join(WATERMARK, 'layouts.json'), 'utf8'))
const floorVectors = JSON.parse(readFileSync(join(WATERMARK, 'agreement-floor.json'), 'utf8'))
const clipVectors = JSON.parse(readFileSync(join(WATERMARK, 'clip-reading.json'), 'utf8'))

const crc8 = (id: number): number => {
  let crc = 0
  for (const shift of [16, 8, 0]) {
    crc ^= (id >>> shift) & 0xff
    for (let bit = 0; bit < 8; bit++) crc = (crc & 0x80) !== 0 ? ((crc << 1) ^ 0x07) & 0xff : (crc << 1) & 0xff
  }
  return crc
}

describe('video-rep-v1', () => {
  const layout = layouts['video-rep-v1']

  for (const c of layout.cases as { mark_id: number, crc8: number, message: string }[]) {
    it(`mark_id ${c.mark_id}: the block is the id and its CRC, eight times`, () => {
      expect(crc8(c.mark_id)).toBe(c.crc8)
      const block = ((BigInt(c.mark_id) << 8n) | BigInt(c.crc8)).toString(16).padStart(8, '0')
      expect(c.message).toBe(block.repeat(8))
      expect(c.message.length * 4).toBe(layouts.message_bits)
    })
  }

  for (const c of layout.derivation.cases as { capture_id: string, sha256: string, mark_id: number }[]) {
    it(`capture ${c.capture_id.slice(0, 8)}…: the id is the digest's first three bytes`, () => {
      const digest = createHash('sha256').update(Buffer.from(c.capture_id, 'hex')).digest()
      expect(digest.toString('hex')).toBe(c.sha256)
      const derived = digest.readUIntBE(0, 3)
      // 0 is reserved as "no id", so it is the one value the derivation may
      // not produce — and one committed case reaches that branch.
      expect(c.mark_id).toBe(derived === 0 ? 1 : derived)
      expect(c.mark_id).toBeGreaterThan(0)
      expect(c.mark_id).toBeLessThan(1 << 24)
    })
  }

  it('reaches the reserved-value branch, which is why that case was searched for', () => {
    const reserved = (layout.derivation.cases as { sha256: string }[])
      .filter((c) => c.sha256.startsWith('000000'))
    expect(reserved).toHaveLength(1)
  })
})

/**
 * `spec/watermark-layouts-1.0.md` *The agreement floor*, as the one line of
 * code it is: a `video-rep-v1` decode is an id only when the checksum passes
 * **and** the copies agreed enough to be believed.
 *
 * It lives here rather than in a numbered vector because no verifier in this
 * repository carries a detector — there are no pixels in the corpus to decode
 * — so the rule is checked where the rest of the layout's arithmetic is.
 */
const FLOOR = 0.85
const resolvesId = (agreement: number, crcPasses: boolean): boolean => crcPasses && agreement >= FLOOR

describe('video-rep-v1 agreement floor', () => {
  it('pins the constant the specification states', () => {
    expect(floorVectors.floor).toBe(FLOOR)
    expect(floorVectors.layout).toBe('video-rep-v1')
  })

  for (const c of floorVectors.cases as Array<{ agreement: number, crc_passes: boolean, resolves: boolean, origin: string }>) {
    it(`${c.agreement} with the CRC ${c.crc_passes ? 'passing' : 'failing'} (${c.origin}): ${c.resolves ? 'an id' : 'no id'}`, () => {
      expect(resolvesId(c.agreement, c.crc_passes)).toBe(c.resolves)
    })
  }

  it('refuses no agreement that any chain was measured to recover at', () => {
    // The floor's upper bound is the worst measured recovery (0.87, int8 at
    // crf 36): a floor above it would refuse a chain the curve says works.
    expect(FLOOR).toBeLessThanOrEqual(0.87)
    // And its lower bound is the highest wrong id observed on a device (0.789),
    // which the code's own correction radius (~0.80, what it can recover
    // rather than what may be reported) clears by only 0.011.
    expect(FLOOR).toBeGreaterThan(0.80)
  })
})

/**
 * `vcap-proof-1.0.md` §8 *For a clip*, which is three answers and not one: the
 * id, the count of sampled frames that carried it, and the agreement figure
 * shown beside them. The two readings of a clip disagree by construction —
 * averaging is what lets a mark survive a chain no single frame survives, and
 * decoding frames separately is the only thing that sees a splice — so which
 * reading owns which answer is the whole content of these cases.
 */
interface Decode { agreement: number, crc_passes: boolean, mark_id: number | null }

/** The clip's one id: the aggregate decode, under the layout's floor. */
const clipId = (clip: Decode): number | null =>
  clip.crc_passes && clip.agreement >= FLOOR ? clip.mark_id : null

/**
 * The count. A frame carries the id when its own decode checks out and lands
 * on that id — the floor is not applied a second time, because the count names
 * no id and equality against an already-floored one is the discriminator the
 * floor would otherwise supply.
 */
const framesWithId = (clip: Decode, frames: Decode[]): number | null =>
  clipId(clip) === null ? null : frames.filter((f) => f.crc_passes && f.mark_id === clipId(clip)).length

describe('video-rep-v1 clip reading', () => {
  it('pins the layout and the floor the aggregate is judged by', () => {
    expect(clipVectors.floor).toBe(FLOOR)
    expect(clipVectors.layout).toBe('video-rep-v1')
  })

  for (const c of clipVectors.cases as Array<{ name: string, clip: Decode, frames: Decode[], reported: { mark_id: number | null, frames_with_id: number | null, sampled: number, agreement: number } }>) {
    it(`${c.name}: ${c.reported.frames_with_id ?? 'no'} of ${c.reported.sampled} at ${c.reported.agreement}`, () => {
      expect(c.frames).toHaveLength(c.reported.sampled)
      expect(clipId(c.clip)).toBe(c.reported.mark_id)
      expect(framesWithId(c.clip, c.frames)).toBe(c.reported.frames_with_id)
      // The figure is the aggregate's own, never recomputed over the frames
      // that carried the id: it is the number the floor was applied to, and a
      // mean over a self-selected subset rises as fewer frames qualify.
      expect(c.reported.agreement).toBe(c.clip.agreement)
    })
  }

  it('ranks a marked clip above a splice, which is what the count is for', () => {
    const named = (name: string) => (clipVectors.cases as Array<{ name: string, reported: { frames_with_id: number | null } }>).find((c) => c.name.includes(name))!
    expect(named('wholly marked').reported.frames_with_id).toBeGreaterThan(named('spliced').reported.frames_with_id!)
  })
})

describe('photo-bch-v3', () => {
  for (const c of layouts['photo-bch-v3'].cases as { capture_id: string, message: string }[]) {
    it(`capture ${c.capture_id.slice(0, 8)}…: the message opens with the capture id`, () => {
      // The systematic half is checkable without a BCH encoder; the parity
      // half is what the layout doc pins and an implementation reproduces.
      expect(c.message.slice(0, 32)).toBe(c.capture_id)
      expect(c.message.length * 4).toBe(layouts.message_bits)
    })
  }
})
