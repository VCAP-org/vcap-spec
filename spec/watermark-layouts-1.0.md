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
of the bitrate and comes back with bit errors in the tens — past what any block
code of this size can correct. So the photo carries the whole capture id under
a block code, and the video carries a short id many times over and lets the
proof tie it back to the capture id.

How far that gets the video channel is a smaller number than the repetition
code alone suggests, and the two must not be confused: the code recovers an id
through roughly 51 random flips of 256, but *The agreement floor* below allows
one to be **reported** only through **38 of 256, a 14.8 % bit error rate**.
Measured budget and margins in `watermark-robustness-1.0.md`, *What may be
reported*.

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

Within one frame, the 8 copies of a bit are decoded **once, on that frame's
logits**, not voted after a per-copy hard decision. Across frames of a clip it
is the opposite: a verifier decodes the sampled frames **individually** and
reports how many of them carried the id (`vcap-proof-1.0.md` §8), because an
unmarked frame abstains rather than dissents, so a decode taken on logits
averaged over frames is set by any single marked one — one genuine frame
spliced into foreign footage reports the real id at the agreement of a clean
recovery (`watermark-robustness-1.0.md`).

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

### The agreement floor

**A `video-rep-v1` decoder MUST NOT report a `mark_id` at an agreement below
0.85.** CRC and floor are one gate, not two answers: below it the decode is
**no id**, plus the agreement figure, exactly as a CRC mismatch is, and a
reader cannot tell the two apart because there is nothing to tell apart —
neither one produced an id worth believing.

The floor exists because the CRC alone does not decide anything. Eight bits of
checksum over a 24-bit id admit one word in 256, every non-reserved 24-bit
value is legal, and there is no other filter between "CRC passed" and "look
this id up". So a block that passes is a block that passes *by chance* about
0.39 % of the time, and the id it carries is a plausible one by construction.
Measured on unmarked content, that is one decode in 289
(`watermark-robustness-1.0.md`, *False positives*). What the floor adds is the
one discriminator the layout has.

**Why 0.85, from the measurements rather than from roundness.** Two populations
are known, and they overlap:

| What | Agreement |
|---|---|
| unmarked content, ids the detector invented (15 cases, synthetic corpus) | 0.55–0.63 |
| unmarked control clips, whole recordings on a device | 0.566–0.664 |
| a **wrong** `mark_id` off genuinely marked content (2 of 38 device recordings) | 0.738, 0.789 |
| a **correct** `mark_id` off the same campaign, at its worst | 0.727 |
| every synthetic chain that recovers at all | 0.87–1.00 |
| the code's correction radius — what it recovers, not what may be reported | ≈ 0.80 |

The device figures are a campaign of 38 recordings on one phone, four scenes,
recorded in `vcap-ml` and summarised in `watermark-robustness-1.0.md`,
*A device campaign*. They are what forced this rule: two of those recordings
resolved an id the pixels were never given, at 0.738 and at 0.789.

0.85 is the value that sits above every wrong id observed anywhere (0.789) and
below every chain measured to recover (0.87), with margin on both sides. The
margin is the point. The code's own correction radius, ≈ 0.80, would also
exclude both wrong ids — by 0.011, while the same campaign found two recordings
of the *same scene* a minute apart differing by as much as 0.20. A threshold
whose margin is a twentieth of the spread of the measurement is a number that
happens to fit this corpus. 0.85 keeps 0.06 above the worst observed false
resolve and 0.02 below the worst measured true one, and that is the whole
justification: it is not derived, it is placed in the gap that the two
measurements leave, as far from the closer edge as the data allows.

**It is a refusal band and not a separator, and it costs true answers.**
0.727 is a *correct* id. Nothing in the numbers above separates right from
wrong — 0.727 correct sits below 0.738 wrong — so no floor can be the rule
"reject the false ones". This floor says something weaker and honest: between
the unmarked baseline and the recovery range there is a band where the decoder
does not know, and in that band it declines to answer. Every correct id below
0.85 is lost with the wrong ones, and on the campaign above that is a real
number of clips, not a corner case.

Three zones follow, and the middle one is new:

| Agreement | CRC | Answer |
|---|---|---|
| ≥ 0.85 | passes | the `mark_id` |
| ≥ 0.85 | fails | no id |
| < 0.85 | either | **no id** — a mark may be present and its id is not resolvable |

The third row is never a contradiction. A proof declaring a different
`mark_id` is not contradicted by a decode that did not happen, so a below-floor
block can no more make a file *tampered* than a failed CRC can
(`vcap-proof-1.0.md` §8, *Invalidating*). Before this rule those two wrong ids
would have been read as evidence against the files that carried them.

**What the floor leaves.** Since agreement is `1 − flips/256` while every
position's majority holds, the rule caps the error budget arithmetically at
**38 flipped bits of 256** (0.8516, reportable) against 39 (0.8477, refused) —
against the ≈ 51 the code can still correct. Inside that ceiling recovery is
probable and not certain, because a position whose eight copies split 4–4 ties
and loses the CRC: about three patterns in four resolve the id at 38 flips, and
the rest answer *no id*. An implementation should expect that shape, and should
expect its failures at the edge to be **refusals**: over a 20 000-pattern sweep
per flip count no pattern returned a wrong id at any flip count. The figures,
their method and what they leave on the shipped browser build are in
`watermark-robustness-1.0.md`, *What may be reported*.

The floor belongs to **this** layout and travels with it. `photo-bch-v3` gets
none: BCH(255,131) with t=18 admits a wrong codeword at about 10⁻¹⁰ by the
code and 0 in 4 329 measured, so there is nothing for a floor to catch, and a
number invented for it would be a rule with no measurement under it. A future
repetition layout states its own floor from its own curve.

Vectors: `vectors/_watermark/agreement-floor.json`, which pins the constant and
the decision for the measured cases above.

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
- `video-rep-v1`: CRC mismatch, **or agreement below 0.85** → **no id**, plus
  the agreement figure. One answer for both, because a decode that is not
  believed and a decode that did not happen license exactly the same claim.

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
model (`watermark-robustness-1.0.md`, *False positives*). That observation is
what *The agreement floor* above is built on: the floor removes the passes that
land below it and leaves the rest, so a hint that survives the floor is still a
hint and still a candidate set.

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
