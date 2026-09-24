import { createHash } from 'node:crypto'

/**
 * §5 from the container side: given an ISO-BMFF file, recompute
 * `content_hash(n)` for every segment out of the video NAL units and the audio
 * frames, the way a verifier that received only the file must.
 *
 * Everything else in this repository verifies the chain at message level — the
 * hashes are read from the proof and taken as given. That layer proves the
 * message format and the chain; it cannot prove that the rule for producing a
 * hash is reproducible by anyone but its author. This module is the other half,
 * and it is deliberately written from §5 rather than from the Android
 * implementation that produced the vectors.
 *
 * It reads sample tables only: no fragmented MP4 (`moof`). The captures the
 * format cares about are progressive files written by a muxer at the end of a
 * recording, and a vector that needed `moof` would need a writer that emits it
 * first. Edit lists it does read — see `editsOf`, and vector 36 for the file
 * that made them necessary.
 */

/** The vcap SEI UUID: SHA-256("vcap/1.0/sei")[0:16] (§5). */
const SEI_UUID = Buffer.from('caa653d1ed1763c7af388aea76527336', 'hex')

export interface Segment {
  /**
   * The index the vcap SEI claims for this GOP, or null when no SEI names it.
   *
   * Null and not the GOP's position in the file. Position is the index only in
   * a file nobody cut, and that is precisely the assumption a clip breaks: drop
   * the first GOP and the file's first GOP is segment 1, so a verifier that
   * counted from zero would check its bytes against segment 0's signature and
   * call an authentic clip forged. §5 lets the SEI locate a segment and gives a
   * verifier nothing else to locate it with, so where the SEI is absent the
   * honest answer is that this GOP is unidentified.
   */
  index: number | null
  /** The `capture_id` the same SEI names, or null with `index`. */
  captureId: Buffer | null
  /** How many vcap SEI NAL units the GOP carries: §5 allows exactly one. */
  seiCount: number
  /** False only for samples ahead of the first IDR, which no segment covers. */
  opensWithIdr: boolean
  /** A vcap SEI in a shape §5 does not allow, or null. */
  problem: string | null
  contentHash: Buffer
  /** Byte range of the GOP's video samples, for humans reading a vector. */
  range: { start: number, end: number }
  /** True when a vcap SEI named this GOP, so `index` is not a guess. */
  located: boolean
  /**
   * What went into the hash, for a vector's `debug` block and for the moment
   * two implementations disagree — which is the moment these numbers save a
   * day, because they say *where* they disagree.
   */
  hashed: { videoBytes: number, audioBytes: number, audioFrames: number }
}

export interface Box { type: string, start: number, end: number, payload: number }

export interface Sample { offset: number, size: number, dts: bigint }

/**
 * A time on the movie's presentation timeline, kept as an exact fraction of a
 * second. Two tracks have two timescales and, once an edit list is involved, an
 * offset each; comparing them in floating point is how a boundary lands one
 * audio frame off, which changes a hash and proves nothing about the frame.
 */
interface Instant { num: bigint, den: bigint }

const before = (a: Instant, b: Instant): boolean => a.num * b.den < b.num * a.den

interface Track {
  kind: 'video' | 'audio' | 'other'
  timescale: bigint
  /**
   * The track's edit list, reduced to what §5 needs: how long the track is
   * delayed on the movie timeline, and where its media starts.
   *
   * `MediaMuxer` writes an empty edit (`media_time = -1`) on the video track
   * whenever the first audio sample precedes the first video sample, which is
   * the normal case for a recording that starts its microphone first. Ignore it
   * and both tracks appear to start at zero: the audio frames that really
   * belong before the first IDR are pulled into segment 0, and every segment
   * hash after it is wrong. Measured on a real file: a 473 ms empty edit, 23
   * audio frames, and three mismatching hashes.
   */
  delay: { num: bigint, den: bigint }
  mediaStart: bigint
  /** NAL length prefix width from avcC/hvcC; 0 for audio. */
  lengthSize: number
  /** H.265 rather than H.264: the NAL header is two bytes. */
  hevc: boolean
  samples: Sample[]
}

const u32 = (b: Buffer, at: number): number => b.readUInt32BE(at)

/** Walks the boxes directly inside [start, end). */
export const boxes = (file: Buffer, start: number, end: number): Box[] => {
  const found: Box[] = []
  let at = start
  while (at + 8 <= end) {
    let size = u32(file, at)
    const type = file.toString('latin1', at + 4, at + 8)
    let payload = at + 8
    if (size === 1) {
      // 64-bit size: the real size follows the type.
      size = Number(file.readBigUInt64BE(at + 8))
      payload = at + 16
    } else if (size === 0) {
      size = end - at
    }
    if (size < 8 || at + size > end) break
    found.push({ type, start: at, end: at + size, payload })
    at += size
  }
  return found
}

export const find = (list: Box[], type: string): Box | undefined => list.find((b) => b.type === type)

/**
 * The leading delay and the media start of a track, from `edts/elst`.
 *
 * Only the shape that matters here is read: leading empty edits are a delay,
 * and the first real edit says which media time the track starts at. Rate
 * changes and multi-segment edits are not something a capture pipeline writes,
 * and a vector that needed them would need a writer that emits them first.
 */
const editsOf = (file: Buffer, trak: Box, movieTimescale: bigint): { delay: { num: bigint, den: bigint }, mediaStart: bigint } => {
  const none = { delay: { num: 0n, den: 1n }, mediaStart: 0n }
  const edts = find(children(file, trak), 'edts')
  if (!edts) return none
  const elst = find(children(file, edts), 'elst')
  if (!elst) return none
  const version = file[elst.payload]
  const count = u32(file, elst.payload + 4)
  const entrySize = version === 1 ? 20 : 12
  let delayTicks = 0n
  for (let i = 0; i < count; i++) {
    const at = elst.payload + 8 + i * entrySize
    const duration = version === 1 ? file.readBigUInt64BE(at) : BigInt(u32(file, at))
    const mediaTime = version === 1 ? file.readBigInt64BE(at + 8) : BigInt(file.readInt32BE(at + 4))
    if (mediaTime < 0n) {
      // An empty edit: this much of the movie timeline with nothing in it.
      delayTicks += duration
      continue
    }
    return { delay: { num: delayTicks, den: movieTimescale }, mediaStart: mediaTime }
  }
  return { delay: { num: delayTicks, den: movieTimescale }, mediaStart: 0n }
}

export const children = (file: Buffer, box: Box): Box[] => boxes(file, box.payload, box.end)

/**
 * `stsd` says which codec, and the codec's configuration box says how wide the
 * NAL length prefix is. Without that width the samples cannot be split, and
 * assuming 4 works until it does not.
 */
export const codecOf = (file: Buffer, stsd: Box): { kind: Track['kind'], lengthSize: number, hevc: boolean } => {
  // stsd: version/flags (4) + entry count (4), then the sample entries.
  const entries = boxes(file, stsd.payload + 8, stsd.end)
  for (const entry of entries) {
    if (entry.type === 'avc1' || entry.type === 'avc3') {
      // Visual sample entry: 78 bytes before the extension boxes.
      const avcC = find(boxes(file, entry.payload + 78, entry.end), 'avcC')
      if (!avcC) continue
      const width = file[avcC.payload + 4]
      if (width === undefined) continue
      // avcC: configurationVersion, profile, compat, level, then
      // 111111 + lengthSizeMinusOne (2 bits).
      return { kind: 'video', lengthSize: (width & 0x03) + 1, hevc: false }
    }
    if (entry.type === 'hvc1' || entry.type === 'hev1') {
      const hvcC = find(boxes(file, entry.payload + 78, entry.end), 'hvcC')
      if (!hvcC) continue
      const width = file[hvcC.payload + 21]
      if (width === undefined) continue
      // hvcC: 21 fixed bytes, then 111111 + lengthSizeMinusOne (2 bits).
      return { kind: 'video', lengthSize: (width & 0x03) + 1, hevc: true }
    }
    if (entry.type === 'mp4a' || entry.type === 'ac-3' || entry.type === 'Opus') {
      return { kind: 'audio', lengthSize: 0, hevc: false }
    }
  }
  return { kind: 'other', lengthSize: 0, hevc: false }
}

/** Sample offsets come from the chunk table; sizes and deltas from their own. */
export const samplesOf = (file: Buffer, stbl: Box): Sample[] => {
  const kids = children(file, stbl)
  const stsz = find(kids, 'stsz')
  const stsc = find(kids, 'stsc')
  const stco = find(kids, 'stco')
  const co64 = find(kids, 'co64')
  const stts = find(kids, 'stts')
  if (!stsz || !stsc || !(stco || co64) || !stts) throw new ContainerMalformed('stbl is missing a required table')

  const sampleCount = u32(file, stsz.payload + 8)
  const uniform = u32(file, stsz.payload + 4)
  const sizes: number[] = []
  for (let i = 0; i < sampleCount; i++) {
    sizes.push(uniform !== 0 ? uniform : u32(file, stsz.payload + 12 + i * 4))
  }

  const chunkOffsets: number[] = []
  if (co64) {
    const count = u32(file, co64.payload + 4)
    for (let i = 0; i < count; i++) chunkOffsets.push(Number(file.readBigUInt64BE(co64.payload + 8 + i * 8)))
  } else {
    const count = u32(file, (stco as Box).payload + 4)
    for (let i = 0; i < count; i++) chunkOffsets.push(u32(file, (stco as Box).payload + 8 + i * 4))
  }

  // stsc maps chunks to "how many samples each chunk holds", run-length coded.
  const runs: { firstChunk: number, perChunk: number }[] = []
  const runCount = u32(file, stsc.payload + 4)
  for (let i = 0; i < runCount; i++) {
    const at = stsc.payload + 8 + i * 12
    runs.push({ firstChunk: u32(file, at), perChunk: u32(file, at + 4) })
  }

  // stts gives decode deltas, also run-length coded.
  const deltas: number[] = []
  const deltaRuns = u32(file, stts.payload + 4)
  for (let i = 0; i < deltaRuns; i++) {
    const at = stts.payload + 8 + i * 8
    const count = u32(file, at)
    const delta = u32(file, at + 4)
    for (let n = 0; n < count; n++) deltas.push(delta)
  }

  const samples: Sample[] = []
  let sample = 0
  let dts = 0n
  for (let chunk = 0; chunk < chunkOffsets.length && sample < sampleCount; chunk++) {
    const run = [...runs].reverse().find((r) => r.firstChunk <= chunk + 1)
    const perChunk = run ? run.perChunk : 0
    let offset = chunkOffsets[chunk] ?? 0
    for (let i = 0; i < perChunk && sample < sampleCount; i++) {
      const size = sizes[sample] ?? 0
      samples.push({ offset, size, dts })
      dts += BigInt(deltas[sample] ?? deltas[deltas.length - 1] ?? 0)
      offset += size
      sample++
    }
  }

  if (samples.length !== sampleCount) throw new ContainerMalformed(`the chunk table places ${samples.length} of ${sampleCount} samples`)
  return samples
}

const tracksOf = (file: Buffer): Track[] => {
  const moov = find(boxes(file, 0, file.length), 'moov')
  if (!moov) throw new Error('no moov: not a progressive ISO-BMFF file')
  const mvhd = find(children(file, moov), 'mvhd')
  if (!mvhd) throw new Error('no mvhd: no movie timescale to align tracks on')
  const movieTimescale = BigInt(file[mvhd.payload] === 1 ? u32(file, mvhd.payload + 20) : u32(file, mvhd.payload + 12))
  const tracks: Track[] = []
  for (const trak of children(file, moov).filter((b) => b.type === 'trak')) {
    const mdia = find(children(file, trak), 'mdia')
    if (!mdia) continue
    const mdhd = find(children(file, mdia), 'mdhd')
    const minf = find(children(file, mdia), 'minf')
    if (!mdhd || !minf) continue
    const version = file[mdhd.payload]
    const timescale = BigInt(version === 1 ? u32(file, mdhd.payload + 20) : u32(file, mdhd.payload + 12))
    const stbl = find(children(file, minf), 'stbl')
    if (!stbl) continue
    const stsd = find(children(file, stbl), 'stsd')
    if (!stsd) continue
    const codec = codecOf(file, stsd)
    const samples = samplesOf(file, stbl)
    tracks.push({ ...codec, timescale, ...editsOf(file, trak, movieTimescale), samples })
  }
  return tracks
}

/**
 * A container that is ISO-BMFF and whose tables or samples do not hold
 * together. Distinct from "no GOP can be located": a verifier that meets one
 * has bytes inside a signed file that no rule of §5 accounts for, which is
 * *tampered*, while a file it cannot read as a video at all simply gives it
 * nothing to compare (§5, *Locating segments*).
 */
export class ContainerMalformed extends Error {}

/**
 * Splits one AVCC/HVCC sample into its NAL units, prefixes discarded (§5).
 *
 * The units MUST tile the sample exactly. Stopping at the first length that
 * does not fit — what this function used to do — leaves the rest of the sample
 * out of every hash while the sample still sits inside a "verified" GOP, and a
 * writer that wanted unsigned bytes in a signed segment would need nothing
 * more than one bad length prefix.
 */
const nalsOf = (sample: Buffer, lengthSize: number): Buffer[] => {
  const nals: Buffer[] = []
  let at = 0
  while (at < sample.length) {
    if (at + lengthSize > sample.length) throw new ContainerMalformed(`a NAL length prefix is cut short at byte ${at} of a ${sample.length}-byte sample`)
    let size = 0
    for (let i = 0; i < lengthSize; i++) size = size * 256 + (sample[at + i] as number)
    at += lengthSize
    if (size === 0) throw new ContainerMalformed(`a zero-length NAL unit at byte ${at - lengthSize} of a sample`)
    if (at + size > sample.length) throw new ContainerMalformed(`a NAL unit of ${size} bytes overruns its ${sample.length}-byte sample`)
    nals.push(sample.subarray(at, at + size))
    at += size
  }
  return nals
}

/**
 * Undoes emulation prevention (H.264 §7.4.1, H.265 §7.4.2): an
 * `emulation_prevention_three_byte` 0x03 that follows two zero bytes is
 * dropped, and the zero count restarts after it. The SEI header and payload
 * are read from this RBSP; `content_hash` excludes the NAL as stored.
 */
const rbsp = (nal: Buffer): Buffer => {
  const out: number[] = []
  let zeros = 0
  for (const byte of nal) {
    if (zeros >= 2 && byte === 0x03) { zeros = 0; continue }
    out.push(byte)
    zeros = byte === 0x00 ? zeros + 1 : 0
  }
  return Buffer.from(out)
}

type VcapSei = { captureId: Buffer, index: number }

/**
 * The vcap SEI payload of a NAL, null when this is not one, or a reason when
 * the NAL carries the vcap UUID in a shape §5 does not allow.
 *
 * Recognition is by payload UUID and not by NAL type, exactly as §5 requires:
 * every other SEI is content and stays in the hash. And a vcap SEI NAL carries
 * **one message and nothing else**: excluding a whole NAL because one of its
 * messages is ours would leave every other message in it unsigned inside a
 * segment a verifier calls verified.
 */
const vcapSei = (nal: Buffer, hevc: boolean): VcapSei | string | null => {
  const header = nal[0] ?? 0
  const type = hevc ? (header >> 1) & 0x3f : header & 0x1f
  const isSei = hevc ? type === 39 || type === 40 : type === 6
  if (!isSei) return null
  const body = rbsp(nal.subarray(hevc ? 2 : 1))
  let at = 0
  let messages = 0
  let found: VcapSei | string | null = null
  // sei_message() until only rbsp_trailing_bits remain.
  while (at < body.length && !(body[at] === 0x80 && body.subarray(at + 1).every((b) => b === 0))) {
    let payloadType = 0
    while (at < body.length && body[at] === 0xff) { payloadType += 255; at++ }
    if (at >= body.length) break
    payloadType += body[at++] as number
    let size = 0
    while (at < body.length && body[at] === 0xff) { size += 255; at++ }
    if (at >= body.length) break
    size += body[at++] as number
    if (at + size > body.length) break
    messages++
    // 5 is user_data_unregistered: 16 bytes of UUID, then the payload.
    if (payloadType === 5 && size >= 16 && body.subarray(at, at + 16).equals(SEI_UUID)) {
      found = size === 36
        ? { captureId: Buffer.from(body.subarray(at + 16, at + 32)), index: body.readUInt32BE(at + 32) }
        : `a vcap SEI message whose payloadSize is ${size}, not 36`
    }
    at += size
  }
  if (found === null) return null
  if (messages !== 1) return `a vcap SEI NAL unit carrying ${messages} SEI messages instead of one`
  // What follows the one message must be rbsp_trailing_bits: 0x80, then only
  // the zero bytes §5 counts as part of the unit.
  if (!(body[at] === 0x80 && body.subarray(at + 1).every((b) => b === 0))) return 'a vcap SEI NAL unit with bytes after its message'
  return found
}

/** IDR access units: H.264 type 5, H.265 IDR_W_RADL (19) and IDR_N_LP (20). */
const isIdr = (nal: Buffer, hevc: boolean): boolean => {
  const header = nal[0] ?? 0
  const type = hevc ? (header >> 1) & 0x3f : header & 0x1f
  return hevc ? type === 19 || type === 20 : type === 5
}

/** Where a sample sits on the movie timeline: delay + (dts − media start). */
const instantOf = (track: Track, dts: bigint): Instant => {
  const media = { num: dts - track.mediaStart, den: track.timescale }
  return {
    num: track.delay.num * media.den + media.num * track.delay.den,
    den: track.delay.den * media.den
  }
}

/**
 * What a verifier can read out of the received file for §5:
 * `unreadable` when there is no video to compare — not ISO-BMFF, no `moov`, no
 * H.264/H.265 track — and otherwise every GOP in decode order.
 */
export type ContainerReading =
  | { kind: 'unreadable', reason: string }
  | { kind: 'gops', gops: Segment[] }

const isBmff = (file: Buffer): boolean => file.length >= 8 && file.toString('latin1', 4, 8) === 'ftyp'

/**
 * Splits the video track into GOPs and recomputes each one's `content_hash`.
 *
 * The boundaries are **IDR access units**, read from the NAL types, and not
 * the sync sample table. `stss` marks random-access points, which in H.265
 * include CRA pictures that are not IDRs: a verifier cutting there would cut
 * a writer's segment in two and check half of it against the whole one's
 * signature. Samples before the first IDR form a GOP of their own that no SEI
 * can name — §5 has no segment for them, and the binding rule in `verify.ts`
 * decides what they mean.
 *
 * Each GOP's index and capture come from its vcap SEI, when it has one. §5
 * lets the SEI locate a segment and nothing else: the binding is decided by
 * the caller, which holds the proof.
 */
export const readContainer = (file: Buffer): ContainerReading => {
  if (!isBmff(file)) return { kind: 'unreadable', reason: 'not an ISO-BMFF file' }
  const top = boxes(file, 0, file.length)
  if (!find(top, 'moov')) return { kind: 'unreadable', reason: 'no moov: not a progressive ISO-BMFF file' }
  let tracks: Track[]
  try {
    tracks = tracksOf(file)
  } catch (e) {
    if (e instanceof ContainerMalformed) throw e
    // A table that reads past its box is a malformed file, not an unreadable one.
    throw new ContainerMalformed((e as Error).message)
  }
  const video = tracks.find((t) => t.kind === 'video')
  if (!video) return { kind: 'unreadable', reason: 'no H.264 or H.265 video track' }
  const audio = tracks.find((t) => t.kind === 'audio')

  // One pass over the video samples: split into NAL units, find the IDRs.
  const units = video.samples.map((sample) => {
    if (sample.offset + sample.size > file.length) throw new ContainerMalformed('a video sample lies beyond the end of the file')
    const nals = nalsOf(file.subarray(sample.offset, sample.offset + sample.size), video.lengthSize)
    return { sample, nals, idr: nals.some((nal) => isIdr(nal, video.hevc)) }
  })
  const starts: number[] = []
  units.forEach((unit, i) => { if (unit.idr || i === 0) starts.push(i) })

  return {
    kind: 'gops',
    gops: starts.map((from, gop): Segment => {
      const to = starts[gop + 1] ?? units.length
      const hash = createHash('sha256')
      const seis: VcapSei[] = []
      let problem: string | null = null
      let start = Number.MAX_SAFE_INTEGER
      let end = 0
      let videoBytes = 0
      let audioBytes = 0
      let audioFrames = 0

      for (let i = from; i < to; i++) {
        const { sample, nals } = units[i] as (typeof units)[number]
        start = Math.min(start, sample.offset)
        end = Math.max(end, sample.offset + sample.size)
        for (const nal of nals) {
          const sei = vcapSei(nal, video.hevc)
          if (typeof sei === 'string') { problem ??= sei; continue }
          if (sei) {
            seis.push(sei)
            continue // a signature cannot cover the bytes that carry it
          }
          hash.update(nal)
          videoBytes += nal.length
        }
      }

      if (audio) {
        // The half-open interval of §5, on the presentation timeline both
        // tracks share: [ DTS(IDR n), DTS(IDR n+1) ), and to the end of the
        // track for the last segment.
        const fromInstant = instantOf(video, (units[from] as (typeof units)[number]).sample.dts)
        const next = units[to]
        const toInstant = next ? instantOf(video, next.sample.dts) : null
        for (const sample of audio.samples) {
          const at = instantOf(audio, sample.dts)
          if (before(at, fromInstant)) continue
          if (toInstant && !before(at, toInstant)) continue
          if (sample.offset + sample.size > file.length) throw new ContainerMalformed('an audio sample lies beyond the end of the file')
          hash.update(file.subarray(sample.offset, sample.offset + sample.size))
          audioBytes += sample.size
          audioFrames++
        }
      }

      const first = seis[0]
      return {
        index: first ? first.index : null,
        captureId: first ? first.captureId : null,
        seiCount: seis.length,
        opensWithIdr: (units[from] as (typeof units)[number]).idr,
        problem,
        contentHash: hash.digest(),
        range: { start, end },
        located: first !== undefined,
        hashed: { videoBytes, audioBytes, audioFrames }
      }
    })
  }
}

/**
 * Every GOP of a file the caller already knows to be a readable video: the
 * derivation scripts use it on device captures, where an unreadable file is a
 * broken input and not a verdict.
 */
export const containerSegments = (file: Buffer): Segment[] => {
  const reading = readContainer(file)
  if (reading.kind === 'unreadable') throw new Error(reading.reason)
  return reading.gops
}
