# vcap watermark robustness 1.0

Companion to `watermark-layouts-1.0.md`, which defines the payload layouts.
This document says **what the watermark is worth**: where the payload comes
back, where it stops coming back, and with how much margin in between.

Status: **informative**. Nothing here is normative and no implementation has to
reproduce a number in it. It exists because `watermark-layouts-1.0.md` §
*Versioning* rule 6 says every published model ships its robustness curve, and
because a verifier's confidence language is worth nothing if the numbers behind
it are not readable by the person deciding whether to trust the verdict.

## Read this before any number below

1. **A recovered watermark is never a green verdict.** The proof format's rule
   outranks everything here: a valid signature makes a file authentic with no
   watermark at all, and a watermark without a valid signature is *origin
   traced*, never *authentic*. Nothing in this document changes that, and a
   table showing 3/3 recoveries is not evidence that a file is genuine.
2. **The failures are in the same tables as the successes,** at the same
   weight. A curve that stopped at the last row that worked would be an
   advertisement.
3. **Every number carries the corpus it came from,** and the corpora here are
   small — three images, one clip. They are measurements, not statistics. The
   section *Corpus, and how small it is* is not a footnote; read it before
   quoting anything.
4. **What is missing is listed,** in *Not measured, and not estimated*. Several
   questions a reader will reasonably have — the false-positive rate above all
   — have no answer here, and the honest answer to those is that they were not
   measured, not a plausible-sounding figure.

## What was measured

| | |
|---|---|
| Model version | `videoseal-y256b-1` (the string a proof carries in `watermark.algo`) |
| Detector graph | ConvNeXt-tiny trunk + pixel decoder, 33.4 M parameters, 256-bit message + 1 detection logit |
| Input handling | the graph resizes its input to a fixed 256 px working size before the trunk, so input resolution barely changes cost or result |
| Layouts | `photo-bch-v3` at strength 1.5, `video-rep-v1` at strength 2.0 — the defaults of `watermark-layouts-1.0.md` |
| Builds | fp32 (133.6 MB), fp16 (66.9 MB), int8 dynamic quantization (34.2 MB), same graph |
| Hardware | Apple M4, 10 cores, 16 GB |
| Runtime | onnxruntime 1.28 (native), onnxruntime-web 1.29 (browser), Chromium 152, ffmpeg/libx264 for the video chains |

The weights, the exported graphs and their digests are not in this repository:
a layout is a wire contract and can be implemented against, a model is an
artifact fetched by digest. What is published here is the behaviour.

**The curves are deterministic.** Re-running the int8 measurement on the same
machine reproduced the report byte for byte, which is what makes a diff in
these numbers worth reading.

## Corpus, and how small it is

Stated first, because every number below inherits it.

- **Photo**: 3 images — one still image plus two frames taken 1 s and 3 s into
  one clip, all three from a single pinned upstream asset set. Each chain is
  run over all three, and the tables report the **mean and the worst** of the
  three, plus how many of the three recovered. "3/3 recovered" means three
  images, not a rate.
- **Video**: **one** clip, built by embedding the mark into **one** frame and
  repeating that marked frame 24 times at 24 fps. Every frame therefore carries
  identical content: the only thing that varies frame to frame is what the
  encoder does with it. This isolates the codec, which is what the measurement
  wanted, and it means the video numbers say nothing about motion, scene
  changes, or a dropped frame.
- **The chain names are proxies, not the apps they name.** `whatsapp-photo` is
  a resize and a JPEG quality chosen to resemble what that kind of sharing does;
  no file in these measurements has been through any messaging service. A chain
  is a re-encode recipe, spelled out in full in the tables, and should be read
  as that recipe and nothing more.

## Photo: `photo-bch-v3`, strength 1.5

BCH(255,131) corrects up to 18 **byte** errors. Bit errors out of 256, mean and
worst over the 3 images, and how many of the 3 recovered the full 128-bit
capture id.

| Chain | What the chain does | fp32 mean / worst | fp32 recovered | int8 mean / worst | int8 recovered |
|---|---|---|---|---|---|
| as-sealed | JPEG q98 | 0.0 / 0 | 3/3 | 0.0 / 0 | 3/3 |
| whatsapp-photo | scale to 1600 px wide, JPEG q65 | 0.0 / 0 | 3/3 | 0.0 / 0 | 3/3 |
| instagram-feed | scale to 1080 px, JPEG q60 | 0.0 / 0 | 3/3 | 0.3 / 1 | 3/3 |
| telegram-compressed | scale to 1280 px, JPEG q55 | 0.0 / 0 | 3/3 | 0.7 / 1 | 3/3 |
| screenshot-then-share | scale to 1080 px, JPEG q75, crop 4 % per edge, JPEG q60 | 2.0 / 3 | 3/3 | 2.7 / 5 | 3/3 |
| heavy-recompress | scale to 720 px, JPEG q40, JPEG q40 again | 3.3 / 7 | 3/3 | 8.3 / 12 | 3/3 |
| **thumbnail-q30** | **scale to 480 px, JPEG q30** | **30.0 / 40** | **0/3** | **35.3 / 43** | **0/3** |
| thumbnail-q20-crop | scale to 480 px, JPEG q20, crop 10 % per edge, JPEG q40 | 115.7 / 132 | 0/3 | 100.0 / 123 | 0/3 |
| destroyed | scale to 320 px, JPEG q15, upscale to 640 px, JPEG q30 | 97.3 / 105 | 0/3 | 111.3 / 115 | 0/3 |

**Where it breaks.** Recovery is total through `heavy-recompress` and **zero**
from `thumbnail-q30` onward, on every build. The break is not gradual: the last
chain that works costs 3.3 bit errors on average and the first that fails costs
30, because BCH has no partial answer — a corrected block either checks out or
does not exist. A thumbnail at 480 px and JPEG quality 30 has no readable mark,
and neither does anything past it: an aggressive crop with a heavy re-encode
(115 bit errors, near half the message) or a 320 px round trip at quality 15.

The practical reading: **a photo that has been reduced to a thumbnail carries
no watermark evidence.** A verifier meeting one says *watermark not recovered*
and produces its verdict from the signature alone — which, for a file whose
bytes were re-encoded, is *no proof found* or *tampered*. The watermark does
not rescue that case, and this document is the place that says so.

## Video: `video-rep-v1`, strength 2.0

24 frames, H.264 (libx264), one intra period per clip, `yuv420p`, decoded and
averaged over all 24 frames as a verifier does. Bit errors out of 256, and the
decoder's *agreement* figure — the fraction of the 8 repetitions that matched
the majority, which stays meaningful when the CRC fails and is what a verifier
shows instead of a verdict.

| Chain | crf | width | fp32 errors / agreement | fp32 recovered | int8 errors / agreement | int8 recovered |
|---|---|---|---|---|---|---|
| as-sealed | 18 | 1280 | 0 / 1.00 | yes | 0 / 1.00 | yes |
| whatsapp-ish | 28 | 848 | 0 / 1.00 | yes | 0 / 1.00 | yes |
| telegram-ish | 30 | 1280 | 0 / 1.00 | yes | 0 / 1.00 | yes |
| story-ish | 32 | 720 | 4 / 0.98 | yes | 4 / 0.98 | yes |
| worst-case | 36 | 640 | 25 / 0.90 | yes | 34 / 0.87 | yes |
| **past-worst** | **40** | **480** | **93 / 0.67** | **no** | **95 / 0.65** | **no** |
| destroyed | 45 | 360 | 133 / 0.58 | no | 144 / 0.60 | no |

**Where it breaks.** Recovery holds to crf 36 at 640 px and is **gone** at
crf 40 at 480 px, on every build. The layout's own self-test places the
correction floor near 51 flipped positions out of 256 — roughly 0.80 agreement
— and the crf 40 row is at 93 errors and 0.67: not marginal, well past it.
Between the two lies the one row where the margin is visibly thin, crf 36 at
0.87–0.90 agreement, and a real clip that is harder than this synthetic one in
any respect will be worse there.

`agreement` below the correction floor is the number a verifier shows when it
has nothing else: it means *some structure was found and it did not decode*,
and it must not be rendered as a partial match or a percentage of confidence.

## Build precision: what quantization costs

The browser verifier ships the int8 build, so the difference matters.

| Build | Size | CPU p50 at 720p (M4, native onnxruntime) |
|---|---|---|
| fp32 | 133.6 MB | 32 ms |
| fp16 | 66.9 MB | 35 ms |
| int8 dynamic | 34.2 MB | 121 ms |

- **The break point does not move.** Photo fails at `thumbnail-q30` and video
  at crf 40 for all three builds. Quantization does not create a new failure
  mode; it eats into the margin of the one the full model already has.
- **What it costs is margin, on the rows already under stress**: 8.3 bit errors
  against 3.3 on `heavy-recompress` (against a budget of 18 byte errors), and
  34 against 25 on the crf 36 clip, agreement 0.87 against 0.90. On the lighter
  chains the difference is under one bit.
- **fp16 is the fp32 curve**, within one bit on every row measured.
- int8 is 3.8× slower than fp32 on a CPU provider, not faster: dynamic
  quantization inserts a quantize step ahead of every convolution, and the
  depthwise convolutions gain nothing from integer arithmetic. The build is
  chosen for its size, not its speed.

## How many frames a verifier has to read

Measured by aggregating N of the 24 frames, for N from 1 to 24, under two
sampling policies (`first` N frames, and N evenly spaced).

- On every chain that recovers at all, it **already recovers at N = 1**, and
  the outcome never flips going up to N = 24.
- On every chain that does not recover, **more frames do not help**: `past-worst`
  and `destroyed` never recover at any N. Frame count is not a substitute for
  the model's bit-error budget once a chain is past it.
- The two sampling policies give the same recovered/not-recovered outcome
  everywhere, differing by 1–2 bit errors.
- The one place more frames buy real margin is the int8 build on the crf 36
  clip: 39 bit errors at N = 1, settling to 33–35 by N = 8 and not improving
  materially past it.

**This does not mean a verifier should read one frame.** The corpus has zero
motion — 24 re-encodes of one image — so it structurally cannot show what a
moving clip does, and cross-frame redundancy is the cheap defence against
exactly the failure modes it cannot produce. A reasonable policy is **8 evenly
spaced frames**: a third of a second at 24 fps, the point where the one
measurable margin gain stops, and conservative with respect to a corpus that
cannot justify anything smaller.

## What the detector costs in a browser

onnxruntime-web on the same M4, Chromium 152, p50 per detector call. Load times
are dominated by a one-time WASM bootstrap, not by model size.

| Build | Backend | 720p | 1080p |
|---|---|---|---|
| int8 (34.2 MB) | WASM SIMD, 1 thread | 456 ms | 460 ms |
| int8 | WASM SIMD, 10 threads, cross-origin isolated | 221 ms | 210 ms |
| int8 | WebGPU | 1016 ms | 1146 ms |
| fp16 (66.9 MB) | WASM SIMD, 10 threads | 308 ms | 330 ms |
| fp16 | WebGPU | 23 ms | 31 ms |
| fp32 (133.6 MB) | WASM SIMD, 10 threads | 103 ms | 100 ms |
| fp32 | WebGPU | 37 ms | 44 ms |

Three findings worth carrying out of that table:

- **int8 on WebGPU is the worst result measured**, slower than int8 on WASM and
  slower than int8 on a native CPU: this graph has no integer GPU kernels, so
  the quantized nodes fall back across the CPU boundary. An implementation that
  lets a backend picker choose WebGPU for the int8 build has made it slower, not
  faster.
- **Multi-threaded WASM needs cross-origin isolation** (COOP/COEP). Without
  those headers the runtime silently drops to one thread and the cost roughly
  doubles — which is the default situation for a verifier embedded in someone
  else's page.
- **Resolution barely matters**, because the graph resizes to a fixed working
  size before the expensive part.

A photo is 1–2 calls: 0.2–0.9 s on this desktop with the shipped int8 build. A
clip at 8 frames is ≈ 1.8 s (int8, multi-threaded WASM), ≈ 3.7 s single-threaded,
and ≈ 0.2 s for fp16 on WebGPU where that is available. Those clip figures are
**arithmetic**, per-frame latency multiplied by the frame count, with no
batching — not a measured end-to-end run.

## Not measured, and not estimated

Each of these is a question a reader will have. None of them has a number here,
and a number that was not measured is not published in its place.

- **False-positive rate — the most important absence.** The detector emits a
  detection logit alongside the 256 message bits. **No measurement exists of
  what it does on unmarked content**: how often unmarked footage yields a
  payload that passes BCH or the CRC, and on what volume of content that was
  checked. Every number in this document is a *true-positive* measurement on
  content known to carry a mark. Until the complementary measurement exists,
  no claim can be made about what a recovered `mark_id` implies on its own,
  and the layouts' own rule stands in for it: a `mark_id` is a lookup hint that
  returns a candidate set, never an identifier
  (`watermark-layouts-1.0.md`, *`mark_id` is a lookup hint*).
- **Anything on a phone.** Every latency here was measured on one desktop
  machine. No device was available, and desktop figures are not extrapolated
  into device figures.
- **Perceptual quality of the mark.** No PSNR or SSIM figure is published. One
  exists in an internal capture experiment, but the device and the content it
  was measured on were not recorded precisely enough for the number to carry
  its own conditions, and a number whose conditions are lost gets quoted
  without them.
- **Real sharing services.** No file measured here has been through any
  messaging or social platform. The chains are re-encode recipes chosen to
  resemble them; the recipes are published in full so that they can be judged
  as recipes.
- **Motion, and more than one clip.** The entire video curve is one embed into
  one still frame. Scene changes, camera motion, dropped frames and
  variable-rate encoding are absent by construction.
- **Key-frame-aligned frame sampling.** The measured clips carry one intra
  frame each, so this policy could not be distinguished from "the first N
  frames" and was not measured rather than half-measured.
- **Geometric attacks beyond the two chains that include a centre crop.**
  Rotation, perspective, and heavy cropping were not swept, and the correction
  radius of BCH(255,131) was not probed at its boundary — there is no watermark
  decoder in this repository to hand a marred payload to.
- **Deliberate removal or forgery of a mark by a motivated adversary.** That is
  a threat-model question, not a robustness curve; see `threat-model.md`. These
  measurements describe an unaware channel, not an attacker.

## Reproducing

The curves come from the model repository, which is not public. What is public
is the recipe: the chains are fully specified above, the layouts are specified
normatively in `watermark-layouts-1.0.md`, and
`vectors/_watermark/layouts.json` pins the worked payload cases bit for bit.
An independent party with the same detector build can rebuild every table here
from those three; the numbers in it are exactly as strong as that, and no
stronger.
