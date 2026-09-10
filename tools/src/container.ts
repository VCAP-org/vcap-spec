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

interface Box { type: string, start: number, end: number, payload: number }

interface Sample { offset: number, size: number, dts: bigint }

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
  /** 1-based sample numbers that are sync samples (IDR); empty means all are. */
  syncSamples: number[]
}

const u32 = (b: Buffer, at: number): number => b.readUInt32BE(at)

/** Walks the boxes directly inside [start, end). */
const boxes = (file: Buffer, start: number, end: number): Box[] => {
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

const find = (list: Box[], type: string): Box | undefined => list.find((b) => b.type === type)

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

const children = (file: Buffer, box: Box): Box[] => boxes(file, box.payload, box.end)

/**
 * `stsd` says which codec, and the codec's configuration box says how wide the
 * NAL length prefix is. Without that width the samples cannot be split, and
 * assuming 4 works until it does not.
 */
const codecOf = (file: Buffer, stsd: Box): { kind: Track['kind'], lengthSize: number, hevc: boolean } => {
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
const samplesOf = (file: Buffer, stbl: Box): { samples: Sample[], syncSamples: number[] } => {
  const kids = children(file, stbl)
  const stsz = find(kids, 'stsz')
  const stsc = find(kids, 'stsc')
  const stco = find(kids, 'stco')
  const co64 = find(kids, 'co64')
  const stts = find(kids, 'stts')
  const stss = find(kids, 'stss')
  if (!stsz || !stsc || !(stco || co64) || !stts) throw new Error('stbl is missing a required table')

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

  const syncSamples: number[] = []
  if (stss) {
    const count = u32(file, stss.payload + 4)
    for (let i = 0; i < count; i++) syncSamples.push(u32(file, stss.payload + 8 + i * 4))
  }
  return { samples, syncSamples }
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
    const { samples, syncSamples } = samplesOf(file, stbl)
    tracks.push({ ...codec, timescale, ...editsOf(file, trak, movieTimescale), samples, syncSamples })
  }
  return tracks
}

/** Splits one AVCC/HVCC sample into its NAL units, prefixes discarded (§5). */
const nalsOf = (sample: Buffer, lengthSize: number): Buffer[] => {
  const nals: Buffer[] = []
  let at = 0
  while (at + lengthSize <= sample.length) {
    let size = 0
    for (let i = 0; i < lengthSize; i++) size = (size << 8) | (sample[at + i] ?? 0)
    at += lengthSize
    if (size <= 0 || at + size > sample.length) break
    nals.push(sample.subarray(at, at + size))
    at += size
  }
  return nals
}

/** Undoes emulation prevention, so an SEI header can be read as written. */
const rbsp = (nal: Buffer): Buffer => {
  const out: number[] = []
  for (let i = 0; i < nal.length; i++) {
    const byte = nal[i] as number
    if (i >= 2 && byte === 0x03 && nal[i - 1] === 0x00 && nal[i - 2] === 0x00) continue
    out.push(byte)
  }
  return Buffer.from(out)
}

/**
 * The vcap SEI payload of a NAL, or null when this is not one.
 *
 * Recognition is by payload UUID and not by NAL type, exactly as §5 requires:
 * every other SEI is content and stays in the hash. Getting this backwards
 * leaves unsigned bytes inside a segment that a verifier calls verified.
 */
const vcapSei = (nal: Buffer, hevc: boolean): { captureId: Buffer, index: number } | null => {
  const header = nal[0] ?? 0
  const type = hevc ? (header >> 1) & 0x3f : header & 0x1f
  const isSei = hevc ? type === 39 || type === 40 : type === 6
  if (!isSei) return null
  const body = rbsp(nal.subarray(hevc ? 2 : 1))
  let at = 0
  while (at < body.length) {
    let payloadType = 0
    while (at < body.length && body[at] === 0xff) { payloadType += 255; at++ }
    if (at >= body.length) return null
    payloadType += body[at++] as number
    let size = 0
    while (at < body.length && body[at] === 0xff) { size += 255; at++ }
    if (at >= body.length) return null
    size += body[at++] as number
    if (at + size > body.length) return null
    // 5 is user_data_unregistered: 16 bytes of UUID, then the payload.
    if (payloadType === 5 && size >= 36 && body.subarray(at, at + 16).equals(SEI_UUID)) {
      return { captureId: body.subarray(at + 16, at + 32), index: body.readUInt32BE(at + 32) }
    }
    at += size
  }
  return null
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
 * Recomputes every segment of a sealed file.
 *
 * The GOP boundaries come from the sync sample table, and each GOP's index from
 * its vcap SEI where one is present. §5 allows exactly that — the SEI locates,
 * it does not prove — and a GOP no SEI names comes back with `index: null`
 * rather than with its position: with the first GOP gone, position in the file
 * is no longer the index, and a verifier that assumed it would validate segment
 * 1's bytes against segment 0's signature and call an authentic clip forged.
 *
 * Refusing to guess costs a verifier nothing it can use. A file whose SEIs were
 * stripped no longer matches `media.hash` either, so its ceiling is already
 * amber; skipping the comparison cannot turn that into green.
 */
export const containerSegments = (file: Buffer): Segment[] => {
  const tracks = tracksOf(file)
  const video = tracks.find((t) => t.kind === 'video')
  if (!video) throw new Error('no video track')
  const audio = tracks.find((t) => t.kind === 'audio')

  const syncs: number[] = video.syncSamples.length > 0
    ? video.syncSamples
    : video.samples.map((_, i) => i + 1)

  return syncs.map((firstSample, gop): Segment => {
    const from = firstSample - 1
    const next = syncs[gop + 1]
    const to = next !== undefined ? next - 1 : video.samples.length
    const hash = createHash('sha256')
    let located: { index: number } | null = null
    let start = Number.MAX_SAFE_INTEGER
    let end = 0
    let videoBytes = 0
    let audioBytes = 0
    let audioFrames = 0

    for (let i = from; i < to; i++) {
      const sample = video.samples[i]
      if (!sample) break
      start = Math.min(start, sample.offset)
      end = Math.max(end, sample.offset + sample.size)
      const bytes = file.subarray(sample.offset, sample.offset + sample.size)
      for (const nal of nalsOf(bytes, video.lengthSize)) {
        const sei = vcapSei(nal, video.hevc)
        if (sei) {
          located ??= { index: sei.index }
          continue // a signature cannot cover the bytes that carry it
        }
        hash.update(nal)
        videoBytes += nal.length
      }
    }

    if (audio) {
      // The half-open interval of §5, on the presentation timeline both tracks
      // share: [ DTS(IDR n), DTS(IDR n+1) ), and to the end of the track for
      // the last segment.
      const fromInstant = instantOf(video, video.samples[from]?.dts ?? 0n)
      const nextSample = video.samples[to]
      const toInstant = nextSample ? instantOf(video, nextSample.dts) : null
      for (const sample of audio.samples) {
        const at = instantOf(audio, sample.dts)
        if (before(at, fromInstant)) continue
        if (toInstant && !before(at, toInstant)) continue
        hash.update(file.subarray(sample.offset, sample.offset + sample.size))
        audioBytes += sample.size
        audioFrames++
      }
    }

    return {
      index: located ? located.index : null,
      contentHash: hash.digest(),
      range: { start, end },
      located: located !== null,
      hashed: { videoBytes, audioBytes, audioFrames }
    }
  })
}
