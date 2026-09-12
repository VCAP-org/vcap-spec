# vcap watermark robustness 1.0

Companion to `watermark-layouts-1.0.md`, which defines the payload layouts.
This document says **what the watermark is worth**: where the payload comes
back, where it stops coming back, with how much margin in between, what
comes back from content that was never marked at all, and what an adversary
who is trying can remove or plant.

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
   small — three images and one clip for the recovery curve, 481 frames of
   which 49 natural for the false-positive section. They are measurements, not
   statistics. The sections *Corpus, and how small it is* and *False positives:
   what a recovered payload implies* are not footnotes; read them before
   quoting anything.
4. **The curve has three parts, and all three are here.** The recovery tables
   are *true-positive* measurements, on content known to carry a mark; *False
   positives* is what the same detector does on content that was never marked;
   *Adversarial removal and forgery* is what happens when somebody is trying.
   A decoder that returned a payload for anything would score 3/3 on every row
   above, so the first part cannot be read without the second — and the
   successful attacks in the third are in the same tables as the failed ones.
5. **What is still missing is listed,** in *Not measured, and not estimated*.
   Several questions a reader will reasonably have have no answer here, and the
   honest answer to those is that they were not measured, not a
   plausible-sounding figure.

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

## False positives: what a recovered payload implies

Every table above is a true-positive measurement, on content known to carry a
mark. This section is the complement, and it is the measurement this document
used to list first among its absences: what the detector does on content that
was never marked.

**Corpus and conditions, first.** 481 frames from eleven sources, each run down
the same nine photo chains as the photo table above — **4 329 decodes**, read
under both layouts from the same 256 soft bits, so the photo and video trial
counts are equal by construction and not independent of one another. Of the 481
frames, **49 are natural photographic content** (one still and one ten-second
scene, from the pinned asset set the curve above marks) and 432 are synthetic:
flat gradients from this repository's own container vectors, and a stripe
pattern from an internal capture spike. That is content with little texture for
a detector to misread, which is the easy direction for a false positive, so
these rates are better read as a floor than as a ceiling. A frame is admitted
as unmarked **by provenance** — because its source never met the embedder,
never because the detector was quiet on it; historic demo material that was
available was excluded for that reason, its origin no longer being arguable,
and screening it found frames carrying one and the same real mark. Neighbouring
frames of one scene are near-identical detector inputs, so the decodes are
**correlated**: the 15 passes below are 7 distinct ids. Same machine and
runtime as the rest of this document (Apple M4, onnxruntime 1.28, CPU
provider), fp32 and int8 builds, against a reference of 24 of the same frames
marked at capture strength (24/24 recovered). Nothing here has been through a
sharing service and nothing here is ordinary phone footage of the world.

### The detection logit is not a usable gate

The detector emits a detection logit alongside the 256 message bits. A verifier
could reach for it as a gate before trusting a payload; on this corpus it does
not work.

| fp32 | min | p50 | p95 | max |
|---|---|---|---|---|
| unmarked, 4 329 decodes | 0.052 | 0.134 | 0.146 | 0.181 |
| marked `photo-bch-v3` (strength 1.5), 24 frames | 0.007 | 0.082 | 0.170 | 0.177 |
| marked `video-rep-v1` (strength 2.0), 24 frames | 0.127 | 0.203 | 0.266 | 0.297 |

- **On the photo layout it points the wrong way.** A frame marked at photo
  strength scores *lower* than an unmarked one: AUC 0.208 on fp32 and 0.129 on
  int8, where 0.5 is a coin flip. A gate of the form "logit above X" would
  reject the marks it is there to find.
- **On the video layout there is signal, measured where it is easiest.** AUC
  0.931 (int8: 0.903), best cut 0.149 separating 0.875 of marked frames from
  0.030 of unmarked ones — but that is on *clean* frames marked at full
  strength. Every row of the tables above is harder than that case, and none of
  them was measured against this logit.
- The two marked distributions sit on **opposite sides** of the unmarked one,
  which is what a quantity tracking mark *energy* rather than mark *presence*
  looks like. Pooling the two layouts gives AUC 0.569, and that pooled figure
  is the one not to quote.

**Consequence.** For the model this document describes there is **no detection
threshold to publish**, and this document publishes none: the detector cannot
be asked "is this content marked?". The layouts' integrity checks are not the
last check before a verifier speaks — on this evidence they are the only one.

### `photo-bch-v3`: 0 ids from 4 329 unmarked decodes

Zero on the fp32 build and zero on the int8 build. The 95 % upper bound this
corpus supports is **0.09 %**, which is as far as 4 329 decodes can go; the
code puts the real figure below what any corpus of this size could resolve. A
(252,128) shortened BCH(255,131) with t = 18 admits a word with no structure in
it with probability **7.2 × 10⁻¹¹**, about one in fourteen billion. That figure
rests on the detector's bit decisions on unmarked content being balanced, and
this measurement is what shows the assumption held rather than assuming it:
median exactly 0.500 ones out of 256 over the 4 329 decodes, mean 0.502 (int8:
0.500 / 0.498).

A pass would then still have to yield one of the capture ids **actually
issued** — the id that comes out is a uniform 128-bit value, so 2⁻¹²⁸ on top of
the above. On this corpus and by the code behind it, **a recovered
`capture_id` is not something that happens by accident.**

### `video-rep-v1`: 15 ids from the same 4 329 decodes

**0.35 %, one unmarked frame in 289** (95 % CI 0.21–0.57 %, 7 distinct ids).
The int8 build measured 12 in 4 329 = 0.28 % (CI 0.16–0.48 %): the intervals
overlap and quantization moves neither figure.

**That rate is the CRC and not the model.** Eight bits of checksum over a
24-bit id admit one word in 256 — 0.39 %, minus the reserved id — the
measured bit decisions are balanced as above, and the measurement lands on the
analytic figure. Nothing about the detector is being characterised here: a
check with one byte of redundancy passes at about that rate on any unstructured
word.

And every pass is a **plausible** `mark_id` by construction, because every
non-reserved 24-bit value is legal. There is no filter between "CRC passed" and
"resolve this id against the registry", which is what makes this the case that
matters rather than a curiosity.

The clip-level measurement — 8 unmarked clips down the 7 video chains, frames
averaged and decoded once as a verifier decodes a clip — saw **0 passes in 56**.
That is consistent with 1/256 (0.2 expected) and too small to say more: the
upper bound 56 trials support is 6.4 %. Averaging frames of one unmarked scene
does not decorrelate anything, so **1/256 is the figure to carry for clips
too**, and 0/56 is not evidence of anything better.

Where the passes fall across the nine chains carries no readable structure: 1.9
passes per chain is what a flat 1/256 predicts, the fp32 and int8 counts
scatter around it in different places, and repeated ids across consecutive
frames of one synthetic clip account for much of the rest. On this corpus no
chain is safer than another.

### `agreement` separates the false ids from the real ones, statistically

The 15 false ids came out at agreement **0.59–0.63** (int8: 0.55–0.63). Every
chain in the video table above that recovers sits at **0.87–1.00**, the worst
chain that still works at 0.90, and the layout's correction floor is near 0.80.

That gap is why `video-rep-v1` returns an agreement figure at all, and why a
verifier reporting a `mark_id` without it has discarded the only discriminator
there is. It is an **observation on a small corpus, not a threshold**: it was
not swept for a cut, the layout does not require one, and this document does
not turn it into a rule.

### The rate is per decode, not per file

All of the above counts one decode of one frame. How many decodes a verifier
runs on one file is a policy the verifier sets, and running more multiplies the
exposure: at the **8 evenly spaced frames** suggested above, the chance that at
least one frame of an unmarked clip yields a `mark_id` is
1 − (255/256)⁸ ≈ **3 %**. For anyone sampling frames, that is the number that
matters, and it is arithmetic on the per-decode rate rather than a measured
per-file rate.

### What this licenses, and what it does not

- A `capture_id` recovered under `photo-bch-v3` is, on this evidence, **not
  noise**: 0 in 4 329 measured, ~10⁻¹⁰ by the code, and 2⁻¹²⁸ before it names
  anything issued.
- A `mark_id` recovered under `video-rep-v1`, on its own, is **weak evidence**.
  It is a lookup hint returning a candidate set — which is what
  `watermark-layouts-1.0.md` already requires — now with a number behind the
  rule rather than a design intuition.
- Neither result softens the proof format's rule, and it outranks both: a
  watermark without a valid signature is *origin traced*, never *authentic*.
- Nothing here supports a claim about **real photographic content at volume**:
  90 % of this corpus is synthetic and the one natural scene is ten seconds
  long. Nor about an **adversary** — this is unmarked content nobody shaped,
  and a party trying to manufacture a mark id is a threat-model question
  (`threat-model.md`).

## Adversarial removal and forgery

Every table above measures something nobody intended: degradation from a
channel, or a payload read out of content nobody marked. This section is the
third case, and the only one with an adversary in it — someone who wants the
mark gone, or wants a mark that was never issued.

**65 attacks** on the same corpus as the recovery tables, three images and one
clip, run on the fp32 and the int8 builds. Each attack carries what the
adversary has, and each is labelled by whether it *removed* a payload or made
the detector emit a **chosen** one. Those are not the same finding and this
document does not pool them: a removal makes a verdict *weaker*, which the
proof format already allows for, while a forgery makes the system **assert**
something false.

| | |
|---|---|
| Model version | `videoseal-y256b-1`, builds fp32 and int8 (both reported) |
| Corpus | the recovery tables' corpus: three images, one synthetic clip of 24 frames |
| Layouts | `photo-bch-v3` at strength 1.5, `video-rep-v1` at strength 2.0 |
| Container | JPEG q98 after every photo attack, crf 18 after every video attack, so the container does no attack's work |
| Hardware and runtime | as *What was measured*: Apple M4, onnxruntime 1.28, CPU provider |
| Video decoding policy | frames averaged and decoded once, which is the policy the video table above uses |

| Outcome | fp32 | int8 |
|---|---|---|
| Attacks | 65 | 65 |
| Survived — the attack failed | 40 | 37 |
| Removed the payload | 13 | 17 |
| Partial — worked on some of the three images, which on three images is a break point being crossed | 5 | 4 |
| **Forged — the detector emitted a payload the adversary chose** | **7** | **7** |

Both builds' runs reproduce exactly on a re-run, outcome labels included.

**What the adversary has.** *A0* holds consumer tools only: rotate, crop, blur,
denoise, recompress, re-cut a clip. *A1* adds these published layouts and one
marked file. *A2* holds the **embedder** — which is not a hypothesis, because
the model this document describes is an export of a publicly downloadable
upstream checkpoint, so anyone willing to fetch it has A2. *A3* adds the
unmarked original of the file attacked, which for a sealed capture does not
exist outside the device; it is measured as a ceiling, not as a realistic
adversary.

**Quote the build you run.** Against geometric attacks the two builds differ by
a whole break point, which the *Build precision* section above does not
predict — there, quantization eats margin on rows already under stress and
moves no break point. Both columns are below; the fp32 figure alone overstates
what a verifier running int8 resists.

### Removal by filtering does not work

Gaussian blur to 2 px, a 3×3 and a 5×5 median, and posterising to 5 bits each
cost **0.0 to 4.3 bit errors out of 256** and recover 3/3 on both builds. So
does the standard blind removal available to A1: estimating the mark as the
residual against a median-filtered copy and subtracting it leaves **0.0 bit
errors** at gain 1.0 and at gain 1.5, on both builds. An adversary who knows
what they are looking for and subtracts their best estimate of it removes
nothing. The mark is not a fragile high-frequency dither, and that is a
robustness result worth as much as the failures next to it.

Two non-geometric attacks do remove the payload, and both cost visible damage:
additive noise at σ = 12 (39.3 bit errors, 0/3, PSNR 29.5 dB) and JPEG q10
(37.7, 0/3, 31.5 dB). Their neighbours hold — σ = 4 and JPEG q20 recover 3/3 —
and at 29–31 dB the file looks like what it is. The A3 ceiling behaves as a
ceiling: subtracting the exactly known mark delta returns the original and the
mark is gone (129.3 errors), while subtracting *half* of it leaves the payload
fully readable (0.3 errors), so even that adversary has to be exact.

### Removal by geometry works, and it costs the attacker nothing

| Attack | fp32 errors / recovered | int8 errors / recovered |
|---|---|---|
| rotate 5° | 0.0 / 3/3 | 1.3 / 3/3 |
| rotate 8° | 1.3 / 3/3 | **19.7 / 1/3** |
| rotate 10° | 2.3 / 3/3 | **30.3 / 0/3** |
| rotate 12° | **22.0 / 1/3** | 50.3 / 0/3 |
| rotate 15° | **63.0 / 0/3** | 66.7 / 0/3 |
| crop 25 % | 2.7 / 3/3 | 6.0 / 3/3 |
| crop 35 % | **22.3 / 1/3** | **61.7 / 0/3** |
| crop 50 % | **129.7 / 0/3** | 121.7 / 0/3 |
| rotate 90°, horizontal flip, 8 px shift, rescale 50 % and 125 % | 0.0 / 3/3 | 0.0–0.3 / 3/3 |

On fp32 the payload survives rotation to 10°, is at its break point at 12° and
is **gone at 15°**; on **int8 it is at its break point at 8° and gone at 10°**.
Centre crop likewise: fp32 survives 25 %, breaks at 35 % and is gone at 50 %;
int8 is already **gone at 35 %**. `psnr_db` is not quoted for these rows —
where pixels move there is no correspondence to compare, and a low figure would
say the image moved, not that it degraded.

**Why it breaks there.** The detector resizes whatever it is given to a fixed
256 px working view and the mark was embedded on that same grid. A uniform
rescale produces an identical working view and costs nothing; an 8 px shift on
a multi-megapixel image is a fraction of one cell of that grid and also costs
nothing; 90° and a flip map the grid onto itself up to a permutation of axes
and recover with 0.0 errors. A crop changes *which* region is squashed onto the
working view and a rotation turns the grid relative to it, and **neither layout
in `watermark-layouts-1.0.md` carries a synchronisation pattern**, so nothing
resynchronises before decoding. What fails is registration, not signal
strength — which is also why int8's narrower margin matters here and not on the
compression rows: a recompressed frame is still registered and merely weaker,
a rotated one produces a different answer rather than a degraded one.

**Straightening and reframing are not damage.** Unlike the thumbnail row that
breaks the photo chain above, a picture rotated 15° or cropped to half its area
is a normal edit, not a degraded file, so the attacker pays nothing a viewer
would notice. This document therefore does not support describing the watermark
as surviving ordinary *editing*; what it survives is ordinary
*re-compression*.

### Forgery is cheap, because the embedder is public

| Attack | A | bit errors | PSNR dB | planted | outcome |
|---|---|---|---|---|---|
| embed a chosen `capture_id` in unmarked content | A2 | 142.0 | 42.5 | 3/3 | **forged** |
| overwrite an existing mark, same strength | A2 | 142.0 | 42.0 | 3/3 | **forged** |
| overwrite an existing mark, 2× strength | A2 | 149.0 | 36.6 | 3/3 | **forged** |
| collude: average 2 differently marked copies | A2 | 69.7 | 45.0 | 0/3 | removed |
| collude: average 3 differently marked copies | A2 | 62.0 | 44.5 | 0/3 | removed |
| transplant the exact mark delta onto another image | A3 | 107.7 | 42.5 | 0/3 | removed |
| transplant a high-pass estimate onto another image | A1 | 124.7 | 41.7 | 0/3 | removed |

Identical outcomes on int8; the three forgeries succeed 3/3 on both builds.
`psnr_db` is the planted file against the content the adversary started from;
no perceptual study was run, so "invisible" is an inference from 42 dB and not
a measurement of its own.

Writing a chosen `capture_id` into content that was never captured succeeds
3/3, and overwriting a real one with the attacker's succeeds 3/3 at the *same*
strength, leaving no readable trace of the original. There is no key in a
watermark: **the embedder is not a secret and the mark is not a signature.**

Two routes are closed, and only one of them usefully. Collusion — averaging two
or three copies marked with different ids — removes all of them at 45 dB, which
is a working invisible removal, but it needs A2, and an A2 adversary would
overwrite rather than erase. Transplanting a mark field onto another image
fails with the exact delta (A3) and with a blind estimate (A1), because the
mark is attenuated per pixel by a perceptual mask derived from the content and
does not detach from the image it was made for. That is a genuine defence
against A1, and it is pointless against A2, which does the same thing better.

An adversary with **no** model reaches a *legal* `mark_id` by random search
alone: 15 passes in 4 000 detector calls on fp32, 18 in 4 000 on int8. That is
the same event the previous section measures as a rate, read as a cost, and it
buys a legal id rather than a chosen one — a specific 24-bit value costs 2²⁴
times more.

### The severe result needs no model at all

One genuine marked frame spliced into 23 frames of an unrelated scene makes the
clip report the genuine `mark_id` at **agreement 0.996** on fp32 and **0.93**
on int8. For comparison, the video table above reads 1.00 as sealed and
0.90 (int8: 0.87) on its worst chain that still recovers, and the false ids of
the previous section sit at 0.55–0.63. Four genuine frames in 20 foreign ones read 1.00 on both
builds.

**Why, measured rather than asserted.** Mean absolute message logit on a marked
frame is **11.321**, and on an unmarked foreign frame **0.131** (int8: 11.118
against 0.375). An unmarked frame does not vote against the mark, it
**abstains**, so averaging 24 frames of which one is marked leaves the sign of
every bit set by that single frame. The dilution rows are the softer version of
the same mechanism and point the same way: diluting inside the *same* scene
costs more (0.844 agreement at 1 marked frame of 24 on fp32, and a failure on
int8) than splicing a *different* scene in (0.996), because same-scene frames
produce correlated non-zero logits that partly disagree while unrelated content
produces near-nothing.

This is a property of **averaging per-frame logits**, which is the decoding
policy the video table above uses. Decoding frames individually and reporting
how many carried the id would turn "the clip reports `0x5a1234` at agreement
0.996" into "1 of 8 sampled frames carries `0x5a1234`", and *How many frames a
verifier has to read* above found that every chain which recovers already
recovers at N = 1, so per-frame decoding costs no recovery. That is a verifier
policy and not a format change, and no document requires it today;
`threat-model.md` carries it as an open item.

### What this licenses, and what it does not

- A recovered mark is **not** evidence that the file is the capture. The
  supportable statement is that *a frame of that capture appears in this file*.
  The splice rows produce a clip of unrelated footage reporting a genuine
  `mark_id` at the agreement of a clean recovery, with no model and one genuine
  frame.
- **`agreement` is not a forgery detector.** The previous section identified it
  as the only thing separating a false id from a real one, and that remains
  true of *noise*: it reads 0.55–0.63 on ids the detector invented. It reads
  0.996 on a splice. It discriminates noise from signal, not honest from
  hostile, and a verifier's wording should say which of the two it does.
- **The watermark carries no authorship.** The embedder is a public download,
  so a mark says something was marked, never *by whom*. Nothing about a
  recovered payload attributes it to any issuer.
- **The watermark is not a defence against re-framing**, and a cropped or
  straightened copy of a genuine capture is, to the watermark, indistinguishable
  from anything else.
- Nothing here reaches past the proof format's rule, and every result is
  bounded by it. A file whose mark was stripped has a *weaker* verdict, never a
  greener one; a file whose mark was forged is *origin traced* and never
  *authentic*, because authenticity needs an ECDSA signature over the file
  bytes from an attested hardware key, which nothing in this section touches.
  These measurements are the reason that rule is not a formality.
- Nothing here is a rate. A break point located at 12° is located on three
  images, and the adversary models are the ones listed, not every adversary.

## Not measured, and not estimated

Each of these is a question a reader will have. None of them has a number here,
and a number that was not measured is not published in its place.

- **A false-positive rate on real photographic content, at volume — the most
  important absence.** *False positives* above measures unmarked content, but
  **432 of its 481 frames are synthetic** and the natural half is 49 frames
  from a single still and a single ten-second scene. A few thousand frames of
  ordinary phone footage would turn 0.35 % into a rate of its own rather than
  an agreement with an analytic figure, and would say whether texture, faces,
  foliage or sensor noise push the detector's bit decisions off balance —
  which is the assumption the `photo-bch-v3` figure rests on. That corpus does
  not exist here, and nothing was fetched to stand in for it: a corpus whose
  contents are unknown cannot support a claim about unmarked content.
- **A per-*file* false-positive rate.** The measured rates are per decode. The
  ≈ 3 % arrived at for 8 sampled frames is arithmetic on top of them, not a
  measurement, and no frame-sampling policy has been measured against unmarked
  clips.
- **Whether `agreement` can be made a rule.** The separation between the false
  ids (0.55–0.63) and every row that recovers (0.87–1.00) was not swept for a
  threshold, and doing that on a corpus 90 % synthetic would produce a number
  that does not travel.
- **The false-positive behaviour of the fp16 and distilled builds.** fp32 and
  int8 were measured and agree; the argument that the rate is the code rather
  than the model predicts the others land in the same place, and for them the
  prediction is untested.
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
- **Perspective, and geometry in combination with anything else.** Rotation
  and centre crop are now swept in *Adversarial removal and forgery* above, on
  three images; perspective warps were not, and **each row there is one
  attack**. A rotation of 8° with a JPEG q20 recompression — each harmless on
  its own — was not measured, and the geometric break points suggest that
  combination is where a careful adversary would start.
- **Adaptive, gradient-based attacks on the detector — the largest gap here.**
  The model is differentiable and publicly downloadable, so a gradient search
  for the smallest perturbation that flips a payload to a chosen value is the
  strongest attack available to an adversary. It has no number in this
  document. *Adversarial removal and forgery* above measures random search
  only, which bounds the cost from above and nothing more.
- **A real photograph of a real screen.** No camera and no second device were
  available, so the analogue path — display, re-photograph, re-encode — was not
  measured and was not approximated by anything this document would quote.
- **What an adversary does to *moving* footage.** The clip corpus is 24
  identical frames, so the splice result in particular would behave differently
  on real footage, where the foreign frames are not one still image.
- **The red team on the fp16 and distilled builds.** fp32 and int8 were
  attacked. What the threat model accepts, and what it leaves open, is in
  `threat-model.md` § 5.8.

## Reproducing

The curves come from the model repository, which is not public. What is public
is the recipe: the chains are fully specified above, the layouts are specified
normatively in `watermark-layouts-1.0.md`, and
`vectors/_watermark/layouts.json` pins the worked payload cases bit for bit.
An independent party with the same detector build can rebuild every table here
from those three; the numbers in it are exactly as strong as that, and no
stronger.
