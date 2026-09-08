# Implementability review of the vcap/1.0 draft on Android

**Step 3 of the work order** (`Doc/06-fase1-avvio.md` §3), mobile half. Reviews
`spec/vcap-proof-1.0.md` as of 8 September 2026, after the cryptographic review
(step 2). Question asked: *what does the device actually produce, and what does
it cost?*

Severity: **BLOCKING** — the format must change, or a `TODO` must be filled,
before the freeze · **SHOULD** — change now, cheap, avoids a v1.1 · **NOTE** —
no format change, text or implementation guidance.

Verdict of the review: **the format is implementable as written on a TEE-class
Android device, and the costs are small.** Per-segment signing is affordable
(2 % of the recording's wall time at a one-second GOP), the trailer appends in
place without re-muxing, a vcap SEI survives `MediaMuxer` untouched, and files
sealed by the phone verify green-eligible in the reference verifier on the
first try. Three things must change before the freeze: the SEI UUID is still a
`TODO` (M4), §5 does not say which clock its audio DTS rule reads (M8), and §8
does not say how a verifier decides a file is video (M15). Nothing found here
requires reopening one of the six format decisions.

Every number below comes from a run on the device described in *Method*. Where
something could not be measured it says so; nothing is estimated.

---

## Method

**Device.** moto g75 5G, Android 16 (SDK 36), security patch July 2026, not
rooted, bootloader locked. KeyMint 300, **TEE only — no StrongBox**. Same unit
as the attestation fixture of 8 September 2026.

**Instrument.** `vcap-sdk-android/tools/capture-probe`, a Gradle/Kotlin project
of instrumented tests, no UI. Each probe writes one JSON file read back with
`adb shell run-as`; the raw outputs are the source of every figure here. Its
JVM tests keep the SEI builder and the SEI recogniser each other's inverse,
which is what caught the one probe bug that would otherwise have been reported
as a `MediaMuxer` failure.

**Video path.** CameraX `Preview` bound to a `MediaCodec` input surface at
1920×1080, 30 fps, 12 Mbit/s requested, `KEY_I_FRAME_INTERVAL` 1 s or 2 s,
`MediaMuxer` to MP4. Hashing, SEI splicing and signing all run on the encoder's
drain thread on purpose: the open question is whether that is viable. The
camera's AE target range is pinned to (30, 30) — see M1 for why that matters.
H.264 encoder `c2.qti.avc.encoder`, HEVC `c2.qti.hevc.encoder`, both hardware.

**Photo path.** CameraX `ImageCapture`, highest available resolution
(4096×3072, 12.6 MP), `CAPTURE_MODE_MINIMIZE_LATENCY`.

**Sealing.** The probe hashes the media, builds the §6.1 core, canonicalizes it
with a 12-line JCS for the core's subset, signs it with a Keystore EC P-256 key
(ES256, P1363, low `s`), and appends the §3 trailer in place with
`RandomAccessFile`. Sealed files were pulled off the device and put through the
reference verifier `vcap-verifier/core` unchanged.

**Percentiles** are nearest-rank on the sorted samples; `n` is given for each.

---

## What the numbers are

### Secure hardware

| Operation | n | p50 | p95 | max |
|---|---|---|---|---|
| ES256 over the 96 B segment message, idle | 200 | 15.2 ms | 18.6 ms | 24.0 ms |
| ES256 over a 768 B core-sized message, idle | 200 | 15.8 ms | 17.8 ms | 28.7 ms |
| `NONEwithECDSA` over a 32 B digest, idle | 200 | 14.5 ms | 17.6 ms | 19.9 ms |
| ES256 per segment, **while the camera and encoder run** | 100 | 20.5 ms | 25.6 ms | 35.9 ms |
| ES256 per segment, **camera, encoder and audio track** | 40 | 30.2 ms | 40.1 ms | 42.5 ms |
| Key generation with an attestation challenge | 10 | 81.8 ms | 199 ms | 199 ms |
| Key generation without attestation | 10 | 31.5 ms | 39.8 ms | 39.8 ms |

Sustained rate: **69 signatures/s with one thread, 73 with two, 75 with four.**
The TEE serializes; concurrency buys nothing. Attestation chain: 5 certificates,
3261 bytes DER.

### Hashing

SHA-256 in the platform provider: 1096 MiB/s over 64 KiB, 1136 MiB/s over
512 KiB, 1228 MiB/s over 2 MiB. Streamed from disk over the 31.7 MB clip:
48.2 ms, ≈ 660 MB/s. A 2.6 MB JPEG: 2.36 ms in memory, 3.4 ms streamed.

### Video, per second of recording

Drain-thread work, 1080p30, hardware encoder, measured over a 100 s clip
(2990 frames, 100 segments) and a 40 s clip for the other rows:

| Configuration | hash | SEI | sign | all drain-thread work |
|---|---|---|---|---|
| H.264, 1 s GOP | 0.078 ms/s | 0.162 ms/s | 20.7 ms/s | **53.4 ms/s** |
| H.264, 2 s GOP | 0.015 ms/s | 0.123 ms/s | 10.2 ms/s | **36.2 ms/s** |
| HEVC, 1 s GOP | 0.062 ms/s | 0.134 ms/s | 19.7 ms/s | **53.8 ms/s** |
| H.264, 1 s GOP, with audio | 0.051 ms/s | 0.352 ms/s | 29.2 ms/s | **78.7 ms/s** |

Per access unit (the whole NAL split, digest update, SEI splice, and on IDRs
the segment close): p50 0.795 ms, p95 3.74 ms, p99 24.0 ms, **max 134 ms**
(HEVC max 306 ms). No frames were lost in any run — 2990 encoded, 2990 muxed,
2990 decoded — but see M6.

Segment sizes at 1 s GOP: mean 317 KB (H.264), 218 KB (HEVC). The encoder
undershot the requested 12 Mbit/s on a static scene, delivering ≈ 2.5 Mbit/s,
so these are a floor; at 1.2 GB/s the hash does not care.

### Photo and trailer

| | |
|---|---|
| `ImageCapture` latency (5 shots, first included) | p50 1.45 s, min 0.93 s |
| JPEG written | 4096×3072, 2.6 MB, one APP segment: `APP1/Exif` |
| §4.1 marker scan | 0.116 ms |
| §4.1 scan and rebuild the canonical bytes | 5.2 ms |
| Trailer size, JPEG / MP4 | 604 B / 638–639 B (core 330–365 B, payload 580–615 B) |
| Append in place | 0.12–0.23 ms, no re-mux |

### ONNX Runtime

Session creation 2.6 ms warm, 12.2 ms cold. Inference on a 143k-parameter
strided CNN over a 1×3×256×256 input: **13.4 ms p50** with one intra-op thread,
**5.7 ms p50** with four. The stock `onnxruntime-android` artifact carries
17.6 MB of native library for arm64 alone.

---

## Findings

### M1 · NOTE — a GOP is a frame count, not a duration

`KEY_I_FRAME_INTERVAL` is expressed in seconds and the encoder turns it into
`interval × KEY_FRAME_RATE` frames. With the camera's AE target range pinned to
(30, 30), IDRs came exactly every 30 frames and every 0.999 s, for a hundred
consecutive segments. Without pinning it, indoor light dropped the sensor to
≈ 17.3 fps, the encoder still emitted an IDR every 30 frames, and the same
configuration produced **1.73-second segments**.

This does not change the format — `media.segment_count` and the chain describe
whatever the encoder did — but it changes the arithmetic in §5's own review
note. "A 2-second GOP on a 10-minute clip is 300 signatures" holds only if the
capture rate holds; on a variable-rate capture the count is
`frames / (interval × configured fps)`, and the wall-clock spacing drifts.
Implementation guidance for C1, not a spec change: **pin the capture frame
rate, and derive the expected segment count from frames, not from seconds.**

Second observation in the same area: the encoder emitted **two IDRs 63 ms
apart at the start** of every run, so segment 0 contained a single frame. §5
must tolerate a one-frame segment, and a verifier must not treat a very short
segment 0 as evidence of anything. Worth one sentence in §5.

### M2 · NOTE — this encoder emits no SEI of its own

Across 5368 access units on both codecs, **zero SEI NAL units** came out of
`c2.qti.avc.encoder` or `c2.qti.hevc.encoder`. Codec-specific data is SPS+PPS
(NAL types 7, 8) for H.264 and VPS+SPS+PPS (32, 33, 34) for HEVC — 32 and 85
bytes respectively.

So §5's rule that *every SEI other than a vcap SEI is content and is hashed*
costs nothing on this device. Keep it: other vendors emit picture-timing and
buffering-period SEI, and the rule is what stops those bytes from being
silently unsigned.

### M3 · NOTE — the vcap SEI survives `MediaMuxer`; no custom muxing needed

A prefix SEI NAL (type 6 for H.264, 39 for HEVC) with a
`user_data_unregistered` payload was built per GOP and spliced in front of the
IDR in the same access unit, then handed to `MediaMuxer` as one sample.

- **Preserved: 100 of 100 samples (H.264), 40 of 40 (HEVC).** The muxer
  rewrote the Annex-B access unit into length-prefixed form and kept both NAL
  units.
- **Decoders ignore it cleanly.** Re-reading the file with `MediaExtractor` and
  decoding every sample through `MediaCodec`: 2990 of 2990 frames decoded, no
  error, on both codecs.
- Size: 45 bytes (H.264) / 46 bytes (HEVC) per GOP, including emulation
  prevention. At a one-second GOP that is 45 B/s against ≈ 2.5 Mbit/s —
  0.0014 % of the stream.
- Building and splicing it: 0.12 ms p50.

**`MediaExtractor` returns samples in Annex-B form, not AVCC**, even though the
file stores length-prefixed NAL units. An implementation that assumes the
stored form when re-reading its own output finds one-byte NAL units and
concludes the SEI was dropped. This is the probe bug the JVM tests caught; it
is worth a sentence of implementation guidance somewhere in C1, because every
verifier that recomputes `content_hash` from a received MP4 will meet it.

### M4 · BLOCKING — the vcap SEI UUID is still a `TODO`

§5: *"whose 16-byte UUID is the vcap UUID: `TODO — register and write the 16
bytes here`"*. This is the one field that stops the elementary-stream side from
being written, and it is already on the freeze checklist as `TODO (LEAD)`.

`user_data_unregistered` UUIDs are unregistered by definition — H.264 §D.2.6
requires only that they be unlikely to collide — so nothing has to be applied
for. Proposal, used by the probe throughout:

```
vcap SEI UUID = SHA-256("vcap/1.0/sei")[0:16]
              = ca a6 53 d1 ed 17 63 c7 af 38 8a ea 76 52 73 36
```

Nothing up the sleeve, recomputable by anyone from one ASCII string, and it
carries no brand (P8). A future layout takes a new separator string exactly as
§5's segment message does.

### M5 · SHOULD — say what the vcap SEI carries, or say it carries nothing

§5 defines what a vcap SEI *is*, for the sole purpose of excluding it from
`content_hash`. It never says a writer must emit one, and never says what the
payload after the UUID contains. Two implementations will disagree, and a
verifier re-deriving segment boundaries from a demuxed stream has nothing to
read.

The probe wrote `capture_id (16 B) ‖ uint32 BE segment index`, which is enough
for a stripped elementary stream to say which capture and which segment a GOP
belongs to, and costs 20 bytes.

Either fix works, but one of them is needed:

1. Specify the payload as `capture_id ‖ uint32 BE n` and say a writer SHOULD
   emit one prefix SEI per segment, immediately before the IDR; or
2. Say the SEI is optional, that its payload is not normative in v1.0, and that
   a verifier MUST NOT read anything from it — the exclusion rule stands on its
   own.

Option 1 costs 45 bytes per GOP and buys segment identity in a re-muxed stream.
The review recommends option 1; the decision is the spec owner's.

### M6 · NOTE — signing must not run on the encoder's drain thread

The measurement was taken with hash and signature deliberately inline. The
signature spikes dominate: p50 for a whole access unit is 0.795 ms and p95 is
3.74 ms, but the **maximum is 134 ms (H.264) and 306 ms (HEVC)** — four to nine
frame periods at 30 fps. Nothing was dropped, because `MediaCodec`'s output
queue absorbed it, but that is luck about queue depth, not a margin to design
on.

Guidance for C1, not a spec change: **hash on the drain thread, sign on a
single offload thread.** Single, because the TEE serializes anyway (69 vs 75
signatures/s from one to four threads) — a pool would add contention and no
throughput. The chain in §5 is sequential by construction, so a single-consumer
queue is also the natural shape.

### M7 · NOTE — §5's per-segment signing cost is affordable on a TEE; StrongBox is still unmeasured

§5 asks: *"a 2-second GOP on a 10-minute clip is 300 signatures. Confirm the
per-signature cost in StrongBox (the slow path) and, if it is prohibitive,
propose a segment = N GOPs grouping with the chain kept."*

Half-answered:

- **On this TEE**, 300 signatures at 20.5 ms p50 is 6.1 s of signing spread over
  600 s of recording — a 1 % duty cycle. At a one-second GOP, 600 signatures is
  12.3 s over 600 s, 2 %. Add hashing and the whole per-second drain-thread
  budget is 53 ms/s, 5.3 % of one core. **Not prohibitive.** No grouping is
  needed for TEE devices.
- **StrongBox could not be measured**: this device has none
  (`setIsStrongBoxBacked(true)` is refused). The question §5 asks is
  specifically about the slow path and it stays open until a Pixel or Samsung
  unit is available. It is a checklist item, not a format decision: if
  StrongBox turns out to be prohibitive, the escape is an implementation
  choice (fall back to a TEE key for the segment chain and keep StrongBox for
  the core signature) before it is a format change.

Recommendation: **keep "segment = one GOP" in v1.0**, do not add a grouping
mechanism speculatively, and record in §5 that the TEE figure is measured and
the StrongBox figure is not.

### M8 · BLOCKING (for the video vectors) — §5's audio DTS rule does not name a clock

The rule works. With a second interleaved AAC track: 940 frames over 40 s, at
most 24 frames and 8217 bytes belonging to any one-second segment, and hashing
them into the segment digest cost 0.465 ms p50. §5's *"memory and latency
budget of hashing two interleaved tracks"* question is answered: **8 KB and
half a millisecond per segment.** Nothing to change there.

What is missing is the timebase. §5 says the interval is
`DTS(IDR_n) <= DTS < DTS(IDR_n+1)`, but a writer and a verifier read different
numbers:

- the writer sees the encoder's presentation timestamps — for video, the
  camera surface timestamp on a boot-based monotonic clock; for audio,
  whatever clock the recorder thread stamps;
- the verifier sees the container's sample decode timestamps in the track
  timescale, after the muxer has rewritten them.

Two implementations picking different clocks disagree about which audio frames
fall in the boundary segment, and the disagreement is invisible until a
`content_hash` mismatch. §5 must say which one is normative. The only one both
sides can see is the container's: **the sample's decode timestamp in its track,
converted to a common timescale, as read from the received file.** Proposed
sentence for §5, after the audio paragraph:

> The DTS of the rule is the decode timestamp the container records for the
> sample, in the media timescale of the received file, not any clock internal
> to the capture pipeline. A writer that computes segment boundaries before
> muxing MUST use the timestamps it will write.

This is what makes the container-level video vectors (checklist item
`REVIEW (mobile)`) reproducible; without it they are not.

### M9 · SHOULD — say what happens to audio before the first IDR

Seven AAC frames of the run were older than the segment window open when it
closed: audio recorded before the first IDR, plus the occasional frame that
reaches the hasher after its own window has been sealed. §5's rule starts the
first interval at `DTS(IDR_0)`, so those frames are in the file and in
`media.hash`, and in **no segment hash**. The same hole appears at the start of
any clip cut from the middle of an original.

That is the right behaviour — a segment cannot cover bytes that precede it —
but the spec should say it, because a verifier author will otherwise treat the
gap as missing evidence:

> Audio frames whose DTS precedes the first IDR are covered by `media.hash` and
> by no segment hash. A verifier MUST NOT report them as missing.

### M10 · NOTE — §4.2's pre-hash fast path needs the key to permit `DIGEST_NONE`

§4.2 says an implementation may stream `core_bytes` into the signer or pre-hash
and sign the digest with `NONEwithECDSA`. On Android the second form fails with
`InvalidKeyException: Keystore operation failed` unless the key was generated
with `setDigests(DIGEST_SHA256, DIGEST_NONE)` — a property of the key, fixed at
generation, not of the signature call.

And it buys nothing: 14.5 ms p50 against 15.2 ms for the streaming form. The
cost is the Keystore IPC round trip, not the data — signing 768 bytes costs the
same as signing 96. §4.2's "it is its business" is correct; a footnote saying
the fast path is not free on Android would save the next implementer an hour.

### M11 · NOTE — §4.1 for JPEG is proven end to end, including the C2PA ordering rule

What `ImageCapture` writes at 12.6 MP: exactly one APP segment, `APP1/Exif`
(1315 bytes), then the quantization and Huffman tables and SOS. **No APP11 at
all**, no XMP, no ICC. So on this device the §4.1 JPEG rule removes nothing and
the canonical bytes are the file bytes; the scan costs 0.116 ms, and rebuilding
the buffer 5.2 ms (memcpy-bound, and skippable when the scan found nothing).

§4's `REVIEW (mobile)` asks whether the manifest writer can be ordered after
sealing for photos. Tested directly on a JPEG the phone sealed: inserting a
2 KB JUMBF `APP11` after SOI and re-running the reference verifier gives
**`authentic`, unchanged `core_hash`**. Inserting a *non*-JUMBF `APP11` of the
same size gives **`tampered`**, which is exactly what §4.1's "and only those"
requires. The photo half of that review item is closed: **no re-encode, no
resealing, the manifest is a pure append-after.**

The video half is **not measured** — no C2PA writer was exercised on an MP4.
Structurally it is a build-order requirement rather than a format problem: the
manifest must be inside the file before the trailer is appended, and the MP4
tolerated appended bytes after `mdat` (M13). It should stay on the checklist
until a real manifest writer runs.

### M12 · NOTE — HEIC is not reachable from the CameraX capture path on this device

Two hardware HEIC image encoders are present (`c2.qti.heic.encoder`,
`OMX.qcom.video.encoder.heic`), but **neither camera advertises
`ImageFormat.HEIC`** in its stream configuration map, and CameraX 1.4
`ImageCapture` has no HEIC output format. A HEIC original would mean a second
encode from YUV through `HeifWriter`.

§4.1 already treats HEIC as ISO-BMFF and needs no change. The consequence is
for the vectors: the HEIC conformance file cannot come from this device's
capture path, and the C1 decision "which container for photos" has one fewer
option than the hardware inventory suggests.

### M13 · NOTE — §3 works exactly as designed, on both containers

Appending the trailer with `RandomAccessFile.seek(length); write` — no re-mux,
no rewrite, 604 B on a JPEG and 638–639 B on an MP4 — took 0.12 to 0.23 ms.
After the append:

| Check | Result |
|---|---|
| `MediaExtractor` on the sealed MP4 | same 1 track, 2990 samples, 100 key frames as before sealing |
| `MediaMetadataRetriever` | duration read (99638 ms), frame at 1 s decoded |
| `BitmapFactory` on the sealed JPEG | 4096×3072 decoded |
| `ExifInterface` on the sealed JPEG | Model and DateTime still readable |
| MediaStore insert + `loadThumbnail` | thumbnail returned for both; **indexed size equals the sealed size**, so the scanner did not rewrite the file |
| `vcap-verifier/core` on the phone's own files | `authentic` for the JPEG, the HEVC MP4 and the H.264 MP4 |

The verifier's verdict on all three: `outcome: authentic`, `level: { claimed:
tee, proven: none, ceiling: amber }`, labels *origin not hardware-attested*,
*key not in transparency log*, *no trusted time*, *not anchored*, *no
watermark*, *integrity unevaluated* — correct, since the probe's proof carries
no attachments.

MediaStore is the closest an instrumented test gets to "the gallery opens it":
it is the same index and the same decoder path. A human check on the gallery
app was not performed.

### M14 · NOTE — §6.1's restriction to integers and enums pays for itself

A JCS serializer for the core's subset is **12 lines of Kotlin**: sorted keys,
integers, and strings that need only the two mandatory escapes. No ECMAScript
number algorithm, no UTF-16 collation problem. The core the phone built and the
core the TypeScript verifier rebuilt from the received JSON hashed to the same
value on the first attempt, with no debugging in between.

This is the strongest evidence in the review that a rule earns its keep. Keep
§6.1 exactly as written, including "no floating-point numbers" and "no
free-text strings".

### M15 · SHOULD — §8 says `segments` is required for video and never says what "video" is

The probe sealed an MP4 with `media.mime: "video/mp4"`, `media.segment_count`
present and **no `segments` array**. Both reference verifiers —
`vcap-spec/tools` and `vcap-verifier/core` — return **`authentic`**. They branch
on the presence of `segments`, not on the media being video, and they are not
wrong to: §8 says *"Required … and for video `media.segment_count` and
`segments`"* without ever defining how a verifier decides a file is video.

Candidates: `media.mime` starting with `video/`, `media.duration_ms` present,
or sniffing the container. They disagree — an animated HEIC, an MP4 holding a
single still, a proof whose `mime` says `image/jpeg` over an MP4 body.

Pick one, write it in §8, and add a vector: *video proof with `segment_count`
and no `segments` → no proof found*. Today the rule has no test and no
implementation, which by the repo's own working rule makes it a comment.

### M16 · NOTE — key generation with attestation costs 82 ms and 3.3 KB

Per-capture keys are out of scope for v1.0 (§6.2), and the measurement supports
leaving it there — but not for cost reasons. Generating an attested EC P-256
key takes 81.8 ms p50 (199 ms p95) and yields a 5-certificate, 3261-byte chain;
without a challenge, 31.5 ms. A per-capture key is affordable for photography
and would roughly triple the proof size. The reasons to keep it out of v1.0
remain the registry and revocation semantics, not the hardware.

### M17 · ML half — the runtime is cheap, the artifact is not, the detector does not exist

The watermark model is spike S2 and does not exist, so **no number in this
review says anything about detection cost or quality**. What was measured is
the runtime underneath it, with a stand-in model of a plausible shape (a 143k
parameter strided CNN, 1×3×256×256 input, 572 KB):

- `OrtSession` creation: 12.2 ms cold, 2.6 ms warm.
- Inference: 13.4 ms p50 single-threaded, 5.7 ms p50 with four intra-op
  threads. Sessions are reusable and cheap to keep alive.
- **The stock `onnxruntime-android` artifact adds 17.6 MB of native library for
  arm64 alone**, before any model. That is the number that matters for C3
  packaging: the SDK cannot ship it as-is, and `vcap-sdk-android/AGENTS.md`
  already anticipates a runtime download or a reduced build.

Open for S2, and untouched by this review: `watermark.layout` values, what the
detector reports when a layout is declared but the payload does not decode, and
the 24-bit `mark_id` collision question. Those three checklist items stay
unticked — no measurement here bears on them.

---

## Verdict by section

| § | Verdict | Why |
|---|---|---|
| 3 — trailer and footer | **fine** | Appends in place in 0.2 ms, 604–639 B; `MediaExtractor`, `MediaMetadataRetriever`, `BitmapFactory`, EXIF and MediaStore all unaffected (M13) |
| 4.1 — canonical bytes | **fine** | 0.116 ms to scan a 12.6 MP JPEG; the C2PA-after-sealing property proven on a device file, both positively and negatively (M11). HEIC untested from capture (M12) |
| 4.2 — the signature | **fine**, one footnote proposed | Costs measured; the pre-hash path needs `DIGEST_NONE` on the key and saves nothing (M10) |
| 5 — segment granularity | **change proposed** | UUID must be filled (M4, BLOCKING); DTS timebase must be named (M8, BLOCKING for vectors); audio before the first IDR (M9); SEI payload (M5); one-frame first segment (M1). Cost itself is fine (M7) |
| 6.1 — the core | **fine** | The integer/enum restriction made a 12-line canonicalizer agree with the reference verifier first time (M14) |
| 6.2 — attachments | **not evaluated** | Only `sig` was exercised; `attestation` was covered by the 8 September attestation work, the rest wait on C6–C8 |
| 7 — proof level | **not evaluated here** | The probe's proofs carry no attestation attachment; the level table was exercised by the real-chain fixture instead |
| 8 — optional vs invalidating | **underspecified** | "Required for video" has no definition of video, no implementation and no vector (M15) |
| 9 — compatibility | **not evaluated** | No version-skew case was produced on device |

---

## Recommendation for the freeze

1. **Fill the SEI UUID in §5** with `SHA-256("vcap/1.0/sei")[0:16]` =
   `caa653d1ed1763c7af388aea76527336`, or with any other 16 bytes — but fill
   it. It is the last blocking `TODO` on the video path (M4).
2. **Name the clock in §5's audio rule**: the DTS is the container's, in the
   received file's track timescale. Without it the container-level video
   vectors are not reproducible across two encoders (M8).
3. **Add two sentences to §5**: audio before the first IDR is covered by
   `media.hash` and by no segment hash (M9); a segment may contain a single
   frame (M1).
4. **Decide what the vcap SEI carries** — `capture_id ‖ uint32 BE n`, or
   explicitly nothing normative (M5).
5. **Define "video" in §8** and add the vector for a video proof with no
   `segments` (M15).
6. **Freeze §3, §4 and §6.1 as they stand.** They were implemented from the
   text alone, on real hardware, and the phone's output verified in the
   reference verifier without a single amendment.
7. Keep "segment = one GOP": affordable on TEE at 2 % duty for a ten-minute
   clip. Record that the StrongBox figure §5 asks for is **still unmeasured**,
   and that no grouping mechanism should be added before it is (M7).

## What could not be measured, and why

- **Anything on StrongBox.** The only device available is TEE-only; the §5
  review question about the slow path is unanswered.
- **iOS / VideoToolbox.** Spike S1; no Apple hardware.
- **A real C2PA manifest on video** (the second half of §4's review item): no
  manifest writer was exercised on an MP4.
- **Watermark embedding and detection cost.** The S2 model does not exist; the
  ONNX figures are for a stand-in and say nothing about the detector.
- **Battery and thermal behaviour.** The longest run was 100 seconds, far too
  short to show throttling. No number is offered rather than an estimate.
- **HEIC capture**, unsupported on this device's camera path (M12).
- **Key generation during capture**: attested keygen was measured idle only.
- **The gallery application itself**: MediaStore indexing and `loadThumbnail`
  were used as the proxy (M13).
