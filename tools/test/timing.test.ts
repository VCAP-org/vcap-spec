import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readContainer } from '../src/container.js'
import { convertTiming, editTrims, timingRecord, timingRoot } from '../src/timing.js'

// §5 *Timing*, pinned at the byte level: the layout a sealer and a verifier
// port, the exact timescale conversion, and the media-edit rule's slack.
describe('timing(n)', () => {
  it('lays out counts, then fixed-width big-endian values', () => {
    const record = timingRecord({ videoDts: [0n, 3000n], videoCts: [0n, -1n], videoEnd: 6001n, audioDts: [0n], audioDur: [1024n] })
    expect(record.toString('hex')).toBe([
      '00000002', // v
      '0000000000000000', '0000000000000000', // dts_0 − dts_0, cts_0
      '0000000000000bb8', 'ffffffffffffffff', // dts_1 − dts_0, cts_1 (signed)
      '0000000000001771', // end_n − dts_0
      '00000001', // a
      '0000000000000000', '00000400' // adts_0 − adts_0, adur_0
    ].join(''))
  })

  it('converts exactly or not at all', () => {
    const t = { videoDts: [0n, 3000n], videoCts: [0n, 0n], videoEnd: 6000n, audioDts: [], audioDur: [] }
    // A finer timescale with every value doubled maps back exactly.
    expect(convertTiming({ ...t, videoDts: [0n, 6000n], videoEnd: 12000n }, { video: 180000n, audio: null }, { video: 90000n, audio: null })).toEqual(t)
    // 3001 ticks at 180 kHz is 1500.5 at 90 kHz: not representable, so it differs.
    expect(convertTiming({ ...t, videoDts: [0n, 3001n] }, { video: 180000n, audio: null }, { video: 90000n, audio: null })).toBeNull()
    // Audio frames with no signed audio timescale cannot be converted.
    expect(convertTiming({ ...t, audioDts: [0n], audioDur: [1024n] }, { video: 90000n, audio: 48000n }, { video: 90000n, audio: null })).toBeNull()
  })

  it('gives a media edit one movie tick of slack at the end, none at the start', () => {
    const edit = { mediaTime: 0n, movieTimescale: 10000n, mediaTimescale: 90000n }
    // 218 178 media ticks are 24 242.0 movie ticks: rounded down, no trim.
    expect(editTrims({ ...edit, duration: 24242n }, { start: 0n, end: 218178n })).toBe(false)
    expect(editTrims({ ...edit, duration: 24241n }, { start: 0n, end: 218178n })).toBe(true)
    expect(editTrims({ ...edit, mediaTime: 1n, duration: 24242n }, { start: 0n, end: 218178n })).toBe(true)
  })

  it('reads back the records vector 175 publishes', () => {
    const dir = join(import.meta.dirname, '..', '..', 'vectors', '175-mp4-timing-original')
    const debug = (JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8')) as { debug: { timing_records_hex: string[], root_hex: string } }).debug
    const reading = readContainer(readFileSync(join(dir, 'input.mp4')))
    if (reading.kind !== 'gops') throw new Error('vector 175 is not a readable video')
    const records = [0, 1, 2].map((n) => timingRecord((reading.gops.find((g) => g.index === n) as { timing: Parameters<typeof timingRecord>[0] }).timing))
    expect(records.map((r) => r.toString('hex'))).toEqual(debug.timing_records_hex)
    expect(timingRoot(records.map((r) => createHash('sha256').update(r).digest())).toString('hex')).toBe(debug.root_hex)
  })
})
