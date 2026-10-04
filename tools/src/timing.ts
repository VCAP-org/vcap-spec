import { createHash } from 'node:crypto'

/**
 * §5 *Timing*: the timing record of one segment, `timing(n)`, and what a
 * verifier does with it. This is the reference the sealers and the verifiers
 * port, so it is written to be read: every rule here is a sentence of §5.
 *
 * Why it exists. A segment's `content_hash` covers NAL units and audio frame
 * bytes, and `media.presentation` covers how a player is told to show them;
 * neither covers *when* each frame is shown. For an original, `media.hash`
 * covers the timing tables with every other byte; for a clip nothing did, so a
 * re-mux could freeze a frame (`stts`), reorder frames inside a GOP (`ctts`),
 * rescale a track (`mdhd`) or trim a located segment (`elst`) and still read
 * *verified clip*. The sealer now hashes this record per segment and signs the
 * root of those hashes in the core (`media.timing`).
 *
 * What this module does NOT do: read a container. `container.ts` walks the
 * sample tables, splits GOPs and assigns audio frames by §5's DTS rule, and
 * hands each GOP's values to `timingRecord`. Keeping the two apart means the
 * byte layout below can be ported and tested on its own.
 */

/**
 * The values of one segment's record, exactly as §5 lists them, each an
 * integer in the media timescale of its own track. All "relative" values are
 * measured from the segment's own first sample, so the record does not depend
 * on where the segment sits in the file — a clip that cut the segments before
 * it has the same record as the original.
 */
export interface TimingValues {
  /** dts_i − dts_0 for each video sample of the segment, in decode order (the first is 0). */
  videoDts: bigint[]
  /** cts_i, the sample's composition offset from `ctts`; 0 when the track has no `ctts`. */
  videoCts: bigint[]
  /**
   * end_n − dts_0: the DTS of the segment's last video sample plus that
   * sample's `stts` duration. In a sample table this is the DTS of the next
   * sample (IDR n+1) when there is one; for the last segment it is the only
   * definition, and it is what binds the last frame's duration.
   */
  videoEnd: bigint
  /** adts_j − adts_0 for each audio frame §5 assigns to the segment, in decode order. */
  audioDts: bigint[]
  /** adur_j, each audio frame's `stts` duration. */
  audioDur: bigint[]
}

/** The timescales a record's values are expressed in: the `mdhd` timescale of each track. */
export interface Timescales { video: bigint, audio: bigint | null }

const INT64_MIN = -(1n << 63n)
const INT64_MAX = (1n << 63n) - 1n
const UINT64_MAX = (1n << 64n) - 1n
const UINT32_MAX = (1n << 32n) - 1n

/** Thrown when a value does not fit its field: a record that cannot be encoded is a timing that differs. */
export class TimingUnencodable extends Error {}

const int64 = (value: bigint): Buffer => {
  if (value < INT64_MIN || value > INT64_MAX) throw new TimingUnencodable(`${value} does not fit int64`)
  const out = Buffer.alloc(8)
  out.writeBigInt64BE(value)
  return out
}

const uint64 = (value: bigint): Buffer => {
  if (value < 0n || value > UINT64_MAX) throw new TimingUnencodable(`${value} does not fit uint64`)
  const out = Buffer.alloc(8)
  out.writeBigUInt64BE(value)
  return out
}

const uint32 = (value: bigint | number): Buffer => {
  const v = BigInt(value)
  if (v < 0n || v > UINT32_MAX) throw new TimingUnencodable(`${v} does not fit uint32`)
  const out = Buffer.alloc(4)
  out.writeUInt32BE(Number(v))
  return out
}

/**
 * The record's bytes (§5):
 *
 * ```
 * timing(n) = uint32 BE v
 *             ‖ ( int64 BE (dts_i − dts_0) ‖ int64 BE cts_i ) × v
 *             ‖ uint64 BE (end_n − dts_0)
 *             ‖ uint32 BE a
 *             ‖ ( int64 BE (adts_j − adts_0) ‖ uint32 BE adur_j ) × a
 * ```
 *
 * Every field is fixed-length and the counts come first, so nothing can shift
 * between the video and the audio half.
 */
export const timingRecord = (t: TimingValues): Buffer => {
  if (t.videoDts.length !== t.videoCts.length) throw new Error('timing: one composition offset per video sample')
  if (t.audioDts.length !== t.audioDur.length) throw new Error('timing: one duration per audio frame')
  return Buffer.concat([
    uint32(t.videoDts.length),
    ...t.videoDts.flatMap((dts, i) => [int64(dts), int64(t.videoCts[i] as bigint)]),
    uint64(t.videoEnd),
    uint32(t.audioDts.length),
    ...t.audioDts.flatMap((dts, j) => [int64(dts), uint32(t.audioDur[j] as bigint)])
  ])
}

const sha256 = (bytes: Buffer): Buffer => createHash('sha256').update(bytes).digest()

/** `segments[n].timing`: SHA-256 of the record, 32 bytes (base64url in the proof). */
export const timingHash = (t: TimingValues): Buffer => sha256(timingRecord(t))

/**
 * `media.timing.root`: SHA-256 over the timing hashes of segments 0 to
 * `segment_count − 1`, 32 bytes each, in index order. Not a Merkle tree: a
 * clip's proof carries every entry, so a verifier always has all of them, and
 * the flat hash is the one two implementations cannot build differently.
 */
export const timingRoot = (hashes: Buffer[]): Buffer => {
  if (hashes.some((h) => h.length !== 32)) throw new Error('timing root: every hash is 32 bytes')
  return sha256(Buffer.concat(hashes))
}

/**
 * Expresses received ticks in the timescale the sealer signed:
 * `t_signed = t_received × ts_signed / ts_received`, which must be an integer
 * for **every** value, or the timing differs and this returns null.
 *
 * Exact on purpose. A re-mux that keeps a timescale, or multiplies it, maps
 * every instant back exactly and verifies; one that moved to a timescale
 * unable to represent the original instants has moved them — by at most a
 * tick, but moved — and a hash admits no tolerance, which is the point: a
 * tolerance would be the thing to argue about.
 *
 * Audio values need both audio timescales; when a segment has audio frames
 * and either side has no audio timescale, there is nothing to convert with.
 */
export const convertTiming = (t: TimingValues, received: Timescales, signed: Timescales): TimingValues | null => {
  const scale = (from: bigint | null, to: bigint | null) => (value: bigint): bigint | null => {
    if (from === null || to === null || from <= 0n || to <= 0n) return null
    const product = value * to
    return product % from === 0n ? product / from : null
  }
  const video = scale(received.video, signed.video)
  const audio = scale(received.audio, signed.audio)
  const all = (values: bigint[], f: (v: bigint) => bigint | null): bigint[] | null => {
    const out: bigint[] = []
    for (const value of values) {
      const converted = f(value)
      if (converted === null) return null
      out.push(converted)
    }
    return out
  }
  const videoDts = all(t.videoDts, video)
  const videoCts = all(t.videoCts, video)
  const videoEnd = video(t.videoEnd)
  const audioDts = all(t.audioDts, audio)
  const audioDur = all(t.audioDur, audio)
  if (videoDts === null || videoCts === null || videoEnd === null || audioDts === null || audioDur === null) return null
  return { videoDts, videoCts, videoEnd, audioDts, audioDur }
}

/**
 * The hash of a record read from a received file, in the signed timescales,
 * or null when the values cannot be expressed in them (or encoded at all):
 * both mean the timing differs.
 */
export const receivedTimingHash = (t: TimingValues, received: Timescales, signed: Timescales): Buffer | null => {
  const converted = convertTiming(t, received, signed)
  if (converted === null) return null
  try {
    return timingHash(converted)
  } catch (e) {
    if (e instanceof TimingUnencodable) return null
    throw e
  }
}

/**
 * The span of media time a segment occupies on one track, in that track's
 * media ticks: from the earliest composition instant of its samples to the
 * latest instant one of them ends. Audio has no composition offsets, so its
 * span is from its first frame's DTS to its last frame's DTS plus duration.
 */
export interface Extent { start: bigint, end: bigint }

/** The single media edit §5 models: where the track's media starts, and for how long it is shown. */
export interface MediaEdit {
  /** `media_time`, in the track's media ticks. */
  mediaTime: bigint
  /** `segment_duration`, in movie ticks. */
  duration: bigint
  movieTimescale: bigint
  mediaTimescale: bigint
}

/**
 * Whether the single media edit trims inside a segment's extent on one track
 * (§5 *Timing*, clips only). The edit shows media from `media_time` for
 * `segment_duration` movie ticks; a segment whose span starts before
 * `media_time`, or ends one movie tick or more after the edit does, is shown
 * in part — a subset of the signed frames, under a timing nobody signed.
 *
 * The end gets one movie tick of slack because a muxer has to round the
 * edit's duration into the movie timescale, which is usually coarser than the
 * media's: `(d + 1) × T ≤ (e − m) × M` is "the edit ends a whole movie tick or
 * more before the segment does", in integers.
 */
export const editTrims = (edit: MediaEdit, extent: Extent): boolean => {
  if (edit.mediaTime > extent.start) return true
  return (edit.duration + 1n) * edit.mediaTimescale <= (extent.end - edit.mediaTime) * edit.movieTimescale
}

/** The video span of a segment from its record: earliest composition instant to the latest end. */
export const videoExtent = (t: TimingValues, dts0: bigint): Extent => {
  let start: bigint | null = null
  let end: bigint | null = null
  t.videoDts.forEach((dts, i) => {
    const next = t.videoDts[i + 1] ?? t.videoEnd
    const shown = dts + (t.videoCts[i] as bigint)
    const until = shown + (next - dts)
    if (start === null || shown < start) start = shown
    if (end === null || until > end) end = until
  })
  return { start: dts0 + (start ?? 0n), end: dts0 + (end ?? t.videoEnd) }
}

/** The audio span of a segment from its record, or null when it has no audio frame. */
export const audioExtent = (t: TimingValues, adts0: bigint): Extent | null => {
  const last = t.audioDts.length - 1
  if (last < 0) return null
  return { start: adts0, end: adts0 + (t.audioDts[last] as bigint) + (t.audioDur[last] as bigint) }
}
