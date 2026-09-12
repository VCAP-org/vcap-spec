# vcap watermark payload layouts 1.0

Companion to `vcap-proof-1.0.md`. The proof format declares which layout a
capture used (`watermark.layout`) and does not define the layouts; this
document does, because a verifier that cannot read the payload cannot say
*watermark matched* and a second implementation cannot be written from a field
name.

Status: **draft**, alongside `vcap/1.0`. What is normative here is the bit layout
and the decoder's failure answer. What is not here, and stays out on purpose,
is the model: the weights, the exported graphs and their digests live in
`vcap-ml`, which is not public. A layout is a wire contract and can be
implemented against; a model is an artifact and is fetched by digest.

`vectors/_watermark/layouts.json` pins both layouts with worked cases — a
capture id or a `mark_id` and the 256-bit message it becomes. An implementation
that reproduces those messages agrees bit for bit; one that only reads this
prose probably does not.

## The carrier

Both layouts fill the same carrier: a **256-bit message**, one soft bit per
position out of the detector. Bit order is **MSB-first within each byte**
throughout.

## Why there are two

The two channels are not comparable, and one layout for both would be sized
for the worse of them.

A photo leaves the device as JPEG and comes back re-encoded and resized with a
handful of bits flipped. A video is re-encoded by a messaging app at a fraction
of the bitrate, and about a fifth of the bits flip — past what any block code
of this size can correct. So the photo carries the whole capture id under a
block code, and the video carries a short id many times over and lets the
proof tie it back to the capture id.

## `photo-bch-v3`

| | |
|---|---|
| Payload | 128 bits: the capture id, verbatim |
| ECC | BCH(255,131), t=18, m=8 → 124 parity bits |
| Padding | 4 zero bits |
| Total | 256 |

The parity bits follow the data bits. A BCH implementation that pads its parity
buffer to whole bytes emits more than 124 bits: only the first 124 are code,
the rest is always zero and is **not** transmitted.

The correction radius is 18 **byte** errors, not bit errors. Recovery holds
through every real sharing chain measured so far and fails around 30 flipped
bits — the point where the errors spread over more than 18 bytes.

## `video-rep-v1`

| | |
|---|---|
| Payload | 24 bits: `mark_id` |
| Checksum | CRC-8/ATM (poly `0x07`, init `0x00`) over the three id bytes, MSB first |
| Repetition | the 32-bit block, 8 times |
| Total | 256 |

Copies of one payload bit sit **32 positions apart**, which is the whole design:
a contiguous error burst shorter than a block touches at most one copy of each
bit, and a position decodes wrong only once 4 of its 8 copies flip. Interleaving
this way is what makes repetition beat a block code on a channel that fails in
bursts.

A clip is decoded **once, on the logits averaged over frames**, not frame by
frame and then voted.

### Deriving a `mark_id`

A writer SHOULD derive it from the capture id:

```
mark_id = uint24 BE of SHA-256(capture_id)[0:3]        (1 when that is 0)
```

`0` is reserved as "no id" — it is the value a decoder reports when nothing
decoded — so it is the one output the derivation may not produce.

This is a SHOULD and not a MUST because nothing in verification depends on it:
`mark_id` sits in the signed core, so a verifier reads it and never recomputes
it. What the rule buys is what the alternatives cost. A **counter** needs state
a capture library does not have, and its value leaks how many captures a device
has taken — a number a photographer never agreed to publish, embedded in the
pixels of every frame. A **random** id needs an entropy source at capture time
and gives up reproducibility for nothing, since collisions are already expected
at 24 bits (above). Derivation from the capture id is stateless, discloses only
what the proof already carries, and lets a second implementation check itself
against a vector instead of against its own output.

`vectors/_watermark/layouts.json` pins the rule under
`video-rep-v1.derivation`, including a capture id found by search whose digest
begins `00 00 00` — the reserved-value branch, which no natural corpus reaches
at 2^-24, and a branch no vector reaches is a branch two implementations can
disagree on for years.

The decoder returns an **agreement** figure — the fraction of copies that
matched the majority — and that figure stays meaningful when the CRC fails.
A verifier shows it instead of a verdict.

## Strength

`watermark.strength` is an integer in the proof and the embed path takes a float
multiplier, so the convention is that **the multiplier travels in tenths**: 1.5
is written `15`, 2.0 is `20`.

Defaults are 1.5 for photos and 2.0 for video. A clip is marked harder because
the codec eats the signal; a photo is looked at closely and survives
compression anyway.

A reader needs `strength` only to explain a weak recovery. It never changes how
a decoder reads bits, and it is **not part of the layout** — two files with
different strengths carry the same layout.

## When the payload does not decode

A declared layout that fails to decode is not an error and never a guess. Each
decoder has exactly one failure answer:

- `photo-bch-v3`: beyond the correction radius → **no id**. There is no partial
  answer; a corrected block either checks out or does not exist.
- `video-rep-v1`: CRC mismatch → **no id**, plus the agreement figure.

The verifier reports *watermark not recovered* (§8 of the proof format) and
produces its verdict from the signature alone. The proof format's own rule
outranks everything here: a valid signature makes a file authentic with no
watermark at all, and a watermark without a valid signature is never a green
verdict.

## `mark_id` is a lookup hint, not an identifier

24 bits is 16.7 million values, so collisions are not a corner case:

| Captures | P(at least one collision) | Expected colliding pairs |
|---|---|---|
| 1 000 | 2.9 % | 0.03 |
| 5 800 | 63 % | 1 |
| 100 000 | ~1 | 298 |
| 1 000 000 | ~1 | 29 802 |

These are design constraints, not caveats:

- **A `mark_id` never identifies a capture.** The binding that counts is
  `capture_id` in the signed core; `mark_id` is bound to it by the proof. Two
  proofs claiming the same `mark_id` are both perfectly valid.
- **Origin search returns a candidate set.** A clip with no proof attached
  yields every registered capture sharing that `mark_id`. The answer is "one of
  these, or none", and the caller narrows it with a proof, a time window or a
  tenant.
- **`mark_id` is issued per tenant and per window**, never as a global counter,
  so the candidate set stays small in the case that matters.

Collisions between issued ids are not the only reason the hint is weak. Content
that was never marked also produces one: measured at about one decode in 289,
which is the false-pass rate of the CRC-8 above and not a property of any
model (`watermark-robustness-1.0.md`, *False positives*). That is a robustness
observation, informative like the document it comes from; it changes nothing in
this layout, and the rules above already assumed it.

Widening the id would move the problem, not solve it: the channel is what
limits it to 24 bits, and the proof already carries a 128-bit id. A future model
that carries more bits reliably is a **new layout**, not a change to this one.

## Versioning

A watermark model is a dependency of every file already sealed, so these rules
are about compatibility and not about model quality.

1. **A layout is frozen once a file carries it.** Changing the bit layout
   desynchronizes every sealed file. Add a numbered layout (`photo-bch-v4`) and
   leave the old decoder in place.
2. **A new model that decodes existing marks is a new model version, not a new
   layout.** Verifiers keep both until no traffic asks for the old one.
3. **A new model that cannot decode existing marks is a new layout,** even if
   the bit layout is unchanged. From a verifier's point of view it is a
   different code.
4. **Retiring a decoder is retiring a verdict.** A layout stays supported for as
   long as the retention promise made to whoever sealed the file — in practice
   forever for a browser verifier, which is a static build anyone can keep.
5. **Strength is a capture-time parameter, not a version.**
6. **Every published model ships its robustness curve.** A model change without
   one is not publishable: a verifier's confidence language depends on the
   numbers. The curve of the currently published model, with its corpus, its
   break points and the list of what was not measured, is
   `watermark-robustness-1.0.md`.
7. **A change on the embed side alone is still a new model version, once
   anything is published.** The weights can be identical and the detector
   byte-identical while the graphs a device runs change digest — folding a
   byte/float conversion into the per-frame graph did exactly that. Nothing
   sealed is affected, because marks from either build decode under the same
   detector, but a model version has to name **one** set of digests: an SDK pins
   them, so two builds under one name make the pin meaningless.

An unknown layout is *watermark not evaluated*: a weaker verdict, never an
error — the same rule the proof format applies to any absent field.
