import { type Box, boxes, children, codecOf, find, samplesOf } from './container.js'

/**
 * Edits the sample tables of a progressive ISO-BMFF file, for the container
 * vectors that need a file **cut, reordered or duplicated at GOP level**.
 *
 * Why this exists: until now the corpus could only express those edits at
 * message level (vectors 26-28), where the hashes are given and no GOP has to
 * be found in a file. A verifier that binds nothing to the file passed every
 * one of them. These edits are what a real tool does to a real recording —
 * drop, move or repeat whole GOPs — so the binding rule of §5 meets them on
 * the device's own bytes and the device's own signatures.
 *
 * What it does, deliberately little: the `mdat` bytes before `moov` are kept
 * as they are, and only the tables of the tracks named in the plan are
 * rewritten — one sample per chunk, offsets pointing back into the original
 * `mdat`. Replaced samples go to a second `mdat` appended after `moov`. The
 * movie timescale may be changed so that a cut can keep every surviving sample
 * at its original instant exactly: §5's audio rule is a comparison of
 * instants, and a cut that moved them by a rounding error would test rounding.
 *
 * It refuses a file whose `moov` precedes its media: rewriting `moov` would
 * move every sample, and nothing in these vectors needs that case.
 */
export interface TrackPlan {
  /** Original sample indexes (0-based) in the new decode order; repeats allowed. */
  samples: number[]
  /** Empty-edit delay on the movie timeline, in new movie ticks; 0 writes no edit list. */
  delay?: bigint
  /** Replacement bytes for original sample indexes, stored in an appended `mdat`. */
  replace?: Map<number, Buffer>
  /** `stss`: keep the sync flags of the original samples, or mark every sample. */
  sync?: 'keep' | 'all'
}

export interface Plan {
  movieTimescale?: number
  video?: TrackPlan
  audio?: TrackPlan
}

const u32 = (value: number | bigint): Buffer => {
  const out = Buffer.alloc(4)
  out.writeUInt32BE(Number(value))
  return out
}

const box = (type: string, ...parts: Buffer[]): Buffer => {
  const payload = Buffer.concat(parts)
  return Buffer.concat([u32(8 + payload.length), Buffer.from(type, 'latin1'), payload])
}

const fullBox = (type: string, ...parts: Buffer[]): Buffer => box(type, Buffer.alloc(4), ...parts)

/** Per-sample durations from `stts`, in media ticks. */
const durationsOf = (file: Buffer, stbl: Box): number[] => {
  const stts = find(children(file, stbl), 'stts') as Box
  const out: number[] = []
  const runs = file.readUInt32BE(stts.payload + 4)
  for (let i = 0; i < runs; i++) {
    const at = stts.payload + 8 + i * 8
    for (let n = 0; n < file.readUInt32BE(at); n++) out.push(file.readUInt32BE(at + 4))
  }
  return out
}

const syncOf = (file: Buffer, stbl: Box, count: number): Set<number> => {
  const stss = find(children(file, stbl), 'stss')
  if (!stss) return new Set(Array.from({ length: count }, (_, i) => i))
  const out = new Set<number>()
  for (let i = 0; i < file.readUInt32BE(stss.payload + 4); i++) out.add(file.readUInt32BE(stss.payload + 8 + i * 4) - 1)
  return out
}

/** The new `stbl` of one track: `stsd` kept, every other table written from the plan. */
const tablesFor = (file: Buffer, stbl: Box, plan: TrackPlan, offsets: number[]): Buffer => {
  const kids = children(file, stbl)
  const samples = samplesOf(file, stbl)
  const durations = durationsOf(file, stbl)
  const sync = syncOf(file, stbl, samples.length)
  const sizes = plan.samples.map((i) => plan.replace?.get(i)?.length ?? (samples[i] as { size: number }).size)

  const runs: [number, number][] = []
  for (const i of plan.samples) {
    const delta = durations[i] as number
    const last = runs[runs.length - 1]
    if (last && last[1] === delta) last[0]++
    else runs.push([1, delta])
  }
  const stts = fullBox('stts', u32(runs.length), ...runs.flatMap(([count, delta]) => [u32(count), u32(delta)]))
  const stsz = fullBox('stsz', u32(0), u32(sizes.length), ...sizes.map(u32))
  const stsc = fullBox('stsc', u32(1), u32(1), u32(1), u32(1))
  const co64 = fullBox('co64', u32(offsets.length), ...offsets.map((o) => {
    const b = Buffer.alloc(8)
    b.writeBigUInt64BE(BigInt(o))
    return b
  }))
  const synced = plan.samples.map((i, n) => (plan.sync === 'all' || sync.has(i)) ? n + 1 : 0).filter((n) => n > 0)
  const stss = find(kids, 'stss') || plan.sync === 'all' ? [fullBox('stss', u32(synced.length), ...synced.map(u32))] : []
  const stsd = find(kids, 'stsd') as Box
  return box('stbl', file.subarray(stsd.start, stsd.end), stts, ...stss, stsz, stsc, co64)
}

const elstFor = (delay: bigint, duration: bigint): Buffer =>
  box('edts', fullBox('elst', u32(2), u32(delay), Buffer.from([0xff, 0xff, 0xff, 0xff]), u32(0x00010000), u32(duration), u32(0), u32(0x00010000)))

export const remux = (file: Buffer, plan: Plan): Buffer => {
  const top = boxes(file, 0, file.length)
  const moov = find(top, 'moov')
  if (!moov) throw new Error('remux: no moov')
  if (top.some((b) => b.type === 'mdat' && b.start > moov.start)) throw new Error('remux: media after moov is not supported')
  const head = file.subarray(0, moov.start)

  const mvhd = find(children(file, moov), 'mvhd') as Box
  if (file[mvhd.payload] !== 0) throw new Error('remux: only version 0 mvhd')
  const oldScale = file.readUInt32BE(mvhd.payload + 12)
  const newScale = plan.movieTimescale ?? oldScale

  // Appended samples live after moov, whose size does not depend on their
  // offsets: lay the tables out once with the offsets they will have.
  const extra: Buffer[] = []
  const layout = (stbl: Box, trackPlan: TrackPlan, moovSize: number): number[] => {
    const samples = samplesOf(file, stbl)
    let appended = head.length + moovSize + 8 + extra.reduce((n, b) => n + b.length, 0)
    return trackPlan.samples.map((i) => {
      const replacement = trackPlan.replace?.get(i)
      if (!replacement) return (samples[i] as { offset: number }).offset
      extra.push(replacement)
      const at = appended
      appended += replacement.length
      return at
    })
  }

  const build = (moovSize: number): Buffer => {
    extra.length = 0
    const rebuilt = (container: Box, trackPlan: TrackPlan | undefined, kind: 'video' | 'audio' | null): Buffer => {
      const parts: Buffer[] = []
      for (const child of children(file, container)) {
        if (child.type === 'mvhd' && newScale !== oldScale) {
          const copy = Buffer.from(file.subarray(child.start, child.end))
          copy.writeUInt32BE(newScale, 8 + 12)
          copy.writeUInt32BE(Math.round(copy.readUInt32BE(8 + 16) * newScale / oldScale), 8 + 16)
          parts.push(copy)
        } else if (child.type === 'trak') {
          const stbl = find(children(file, find(children(file, find(children(file, child), 'mdia') as Box), 'minf') as Box), 'stbl') as Box
          const trackKind = codecOf(file, find(children(file, stbl), 'stsd') as Box).kind
          const own = trackKind === 'video' ? plan.video : trackKind === 'audio' ? plan.audio : undefined
          parts.push(rebuiltTrak(child, own, trackKind === 'other' ? null : trackKind))
        } else if (child.type === 'stbl' && trackPlan && kind) {
          parts.push(tablesFor(file, child, trackPlan, layout(child, trackPlan, moovSize)))
        } else if (child.type === 'minf') {
          parts.push(box('minf', rebuilt(child, trackPlan, kind)))
        } else {
          parts.push(file.subarray(child.start, child.end))
        }
      }
      return Buffer.concat(parts)
    }
    const rebuiltTrak = (trak: Box, trackPlan: TrackPlan | undefined, kind: 'video' | 'audio' | null): Buffer => {
      const parts: Buffer[] = []
      const mdhd = find(children(file, find(children(file, trak), 'mdia') as Box), 'mdhd') as Box
      const mediaScale = BigInt(file.readUInt32BE(mdhd.payload + 12))
      for (const child of children(file, trak)) {
        if (child.type === 'edts') {
          // Replaced when the plan says where the track starts; otherwise
          // rescaled to the new movie timescale, which must stay exact.
          if (trackPlan) continue
          if (newScale !== oldScale) throw new Error('remux: rescaling an untouched edit list is not supported')
          parts.push(file.subarray(child.start, child.end))
          continue
        }
        if (child.type === 'mdia') {
          if (trackPlan && kind) {
            const stbl = find(children(file, find(children(file, child), 'minf') as Box), 'stbl') as Box
            const durations = durationsOf(file, stbl)
            const media = trackPlan.samples.reduce((n, i) => n + BigInt(durations[i] as number), 0n)
            // The delay has to be exact; the duration of the edit that follows
            // it is informative (§5 reads where a track starts, not how long
            // the edit claims it lasts), so it is rounded down.
            if ((trackPlan.delay ?? 0n) > 0n) parts.push(elstFor(trackPlan.delay as bigint, media * BigInt(newScale) / mediaScale))
          }
          parts.push(box('mdia', rebuilt(child, trackPlan, kind)))
          continue
        }
        parts.push(file.subarray(child.start, child.end))
      }
      return box('trak', ...parts)
    }
    return box('moov', rebuilt(moov, undefined, null))
  }

  // Two passes: the first learns moov's size, the second writes the offsets.
  const sized = build(0)
  const written = build(sized.length)
  if (written.length !== sized.length) throw new Error('remux: moov size moved between passes')
  const tail = extra.length > 0 ? [box('mdat', ...extra)] : []
  return Buffer.concat([head, written, ...tail])
}
