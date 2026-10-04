# Design note — binding a clip's timing

Status: **accepted** 4 October 2026, **implemented** in corpus 7.0.0:
`vcap-proof-1.0.md` §5 *Timing* and §6.1 `media.timing` are normative, and
vectors 175–187 pin them. Proposed 3 October 2026. The text below is the
proposal as accepted and is not normative; where the spec settles a detail,
the spec is authoritative. What the spec settled beyond this note: `end_n` is
always the last sample's DTS plus its duration (equal to the next IDR's DTS
in a sample table, and never the `mdhd` duration); `audio_timescale` is
absent — never `null` or 0 — on a file without an audio track; the root is
recomputed only when every entry is present, and a clip whose proof lacks one
reads *timing differs* (vector 186); an entry without `timing` is not well
formed (vector 187); the media edit rule gives one movie tick of slack at the
end and applies to clips only; vector 4 below became an end cut (178),
because vector 89 itself now carries the timing-kept case. Written because an
audit found that a clip can be re-timed and still read *verified clip*, and
asked whether a verifier-only rule could close it. It cannot; this note says
why and what the sealers would have to sign.

## The gap

For an original, `media.hash` covers every byte, timing tables included. For a
clip nothing does. A segment's `content_hash` covers NAL units and audio frame
bytes; `media.presentation` covers the decoder configuration, the `tkhd`
matrix and display size, and the track layout. Not covered:

| Container data | What a re-mux can do with it while every GOP still hashes |
|---|---|
| `stts` sample durations | freeze a frame (one long duration), slow or speed a passage, drop the gaps that showed time passing |
| `ctts` composition offsets | reorder the presented frames inside a GOP |
| `mdhd` timescale | scale a whole track; scaled on both tracks, the whole clip plays slower or faster in sync |
| the single media edit's `segment_duration`, `media_time` | trim inside a located segment (shows a subset of it) or hold the last frame |
| the audio sample entry (`esds` / AudioSpecificConfig) | declare another sample rate: the same coded frames play pitched and re-timed |

What binds timing today, by accident: audio frames are assigned to segments by
DTS (§5), so moving an IDR's DTS relative to the audio moves frames between
segments and the hashes break. That covers only re-timing that crosses a
segment boundary on a file with audio; a uniform rescale of both tracks, any
change inside a GOP, and every silent file pass.

## Why a verifier-only rule cannot close it

What the sealers sign holds no timing. The segment message is 96 fixed bytes
with no time in it; the core's only time values are `media.duration_ms`
(the original's) and `time.device_clock`. Checked against the two sealers
that write video (the web SDK refuses video):

- **SPS VUI `timing_info`** is inside `presentation.config`, but neither
  sealer's encoder sets it, and it would not describe a variable frame rate
  if it did.
- **Picture order count** in the slice headers is signed (it is inside the
  NAL units) and would let a verifier check `ctts` reordering against the
  coded order. It closes reordering only, needs an H.264 and an H.265
  slice-header parser in every verifier, and both sealers disable B-frames
  (iOS always; Android from API 29), so on their files there is no reordering
  to check.
- **Audio duration against video duration** needs the audio sample rate,
  which is in the unsigned audio sample entry, and passes a uniform rescale.

Durations — the freeze and the slow-down — are in no signed byte at all. A
binding needs the sealer to sign new data.

## Proposal

Sign each segment's timing, without touching the segment message.

**`timing(n)`**, the timing record of segment `n`, read from the finished
container on the presentation timeline §5 already defines (leading empty
edits, one media edit at rate 1), every value an integer in the **media
timescale of its own track as the sealer wrote it**:

```
timing(n) = uint32 BE v || ( int64 BE dts_i − dts_0 || int64 BE cts_i ) × v
            || uint64 BE end_n − dts_0
            || uint32 BE a || ( int64 BE adts_j − adts_0 || uint32 BE adur_j ) × a

  v, i        video samples of segment n in decode order; dts_0 is the IDR's DTS
  cts_i       the sample's composition offset (ctts; 0 when there is none)
  end_n       DTS of IDR n+1, or, for the last segment, the last sample's DTS
              plus its duration — so the last frame's duration is bound
  a, j        audio frames §5 assigns to segment n, in decode order
  adur_j      the frame's duration (stts)
```

**Where it goes.** Two places, neither of them the 96-byte message:

- each `segments[]` entry gains `timing`: base64url `SHA-256(timing(n))`;
- the core gains `media.timing`: `{ "video_timescale", "audio_timescale",
  "root" }`, `root` being base64url `SHA-256(timing hash 0 ‖ … ‖ timing hash
  segment_count − 1)`, the timescales the `mdhd` values the sealer wrote.
  Required wherever `segments` is, like `media.presentation`.

A clip's proof carries every `segments[]` entry, so a verifier recomputes
`root` from the entries and compares it with the signed one — a mismatch is a
binding the proof makes that does not hold, **tampered** — then, for each
located segment, reads `timing(n)` back from the received file and compares
its hash with the entry's.

**Timescale changes.** A verifier converts the received ticks into the signed
timescale: `t_signed = t_received × ts_signed / ts_received`, which must be an
integer for every value, else the timing differs. A re-mux that keeps the
timescale, or multiplies it, verifies exactly; one that moves to a timescale
that cannot represent the original instants has moved them, by at most a
tick, and reads *timing differs* — amber, never red. Hashing makes a
tolerance impossible, and a tolerance would be the thing to argue about.

**Audio configuration.** `presentation.config`'s `X` gains the audio sample
entry's `esds` box (whole, as stored), so the sample rate is bound with the
rest of what a player is told.

**Verdict.** A located segment whose timing reads back different is
presented under a timing nobody signed: **frames not compared**, no segment
credited, label *timing differs* — the reasoning of *presentation differs*
(§5): re-timing is not an accusation, and it is not a verified clip either.
On an original, `timing` that does not describe it is the writer's false
claim: *timing differs*, amber at best. A single media edit that trims inside
a located segment is a timing that differs.

## Impact on the sealers

Both video sealers already read the finished MP4 back after `stop()` —
`stts`, `ctts` and `elst` included — to reconcile segment hashes and compute
`media.presentation`, and both sign the core after that read-back.

- **Android** (`MediaMuxer`): compute `timing(n)` in the read-back, write the
  entry's `timing` and the core's `media.timing`, add `esds` to `config`. The
  segment messages do not change, so **no segment is re-signed** and the
  live signing budget is untouched. `MediaMuxer` chooses the timescales and
  edit list, which is why the record is read back and never predicted; on
  API 28, where B-frames cannot be disabled, `ctts` is covered by the same
  record.
- **iOS** (`AVAssetWriter`, video timescale fixed at 90 000, no frame
  reordering): the same three changes in its read-back. Its AAC priming trim
  produces an audio edit, which the presentation timeline already models.
- **Web**: seals photos only; nothing.

The rejected alternative put a timing hash inside the segment message (128
bytes, new separator). It needs the muxer's final values at signing time,
which neither sealer has live — muxer rounding, AAC priming and edit offsets
land only in the finished file — so every recording would re-sign its whole
chain at stop: 15–21 ms per segment in the Android TEE. Signing live with
pre-mux microseconds and a tolerance was rejected for the reason above.

## Vectors needed

1. An original with `media.timing` → *authentic* (from vector 166's container,
   re-signed).
2. Its proof without `media.timing` → *no proof found*.
3. A `segments[].timing` that does not hash to `root` → *tampered*.
4. Vector 89's clip, timing kept → *verified clip* 1–2 of 3.
5. The clip with one `stts` duration lengthened (a freeze) → *frames not
   compared*, *timing differs*.
6. The clip with two `ctts` offsets swapped → the same.
7. The clip with both tracks' `mdhd` timescales doubled and every duration
   kept → the same.
8. The clip with every timing value and both timescales multiplied by the
   same integer → *verified clip* (an exact re-mux).
9. The clip with the audio `esds` sample rate changed → *presentation
   differs*.
10. The clip with its media edit's `segment_duration` cut inside segment 2 →
    *timing differs*.
11. An original whose `media.timing` does not describe it → *authentic*,
    amber, *timing differs*.

Corpus impact: a major bump (vector 166's family re-signed, every video proof
gains a required field), recorded as breaking in `CHANGELOG.md`.
