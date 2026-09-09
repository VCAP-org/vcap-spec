# Changelog

`vcap/1.0` is frozen. Changes after the tag are additive only (spec §9): new
optional keys, new values in fields declared extensible. Every entry names the
section it touches, the vectors it adds and what an older verifier does with it.

## Unreleased

Clarifications for writers, found while implementing the Android core against
`v1.0`. No byte changes: every `v1.0` file verifies the same.

- §4.1: the JPEG walk keeps fill bytes and length-less markers (`TEM`, `RSTn`);
  vector 35 `jpeg-fill-bytes` (a `0xFF` fill byte before a marker, sealed →
  authentic). A reference walker that refused fill bytes is fixed.
- §4.2: what a writer does with a high-`s` signature — replace `s` by `n−s`.
- §5: `media.segment_count` of an original equals the entries written, `gop`
  contiguous from 0.
- §6 sketch: `attestation` is an array of base64url DER certificates, as §6.2
  and the schema already said.
- §7: what a verifier says about a watermark that was declared but does not
  come back — *origin traced*, *watermark not recovered*, *watermark not
  evaluated*, all non-red — and the red case narrowed to a payload that
  **decodes** to an id other than the declared one (`capture_id` for
  `photo-bch-v3`, `watermark.mark_id` for `video-rep-v1`). Before, the rule read
  as if any watermark that did not match were red, which made an undecodable
  payload on a re-compressed clip indistinguishable from a forgery.
- §7 implemented: the reference verifier in `tools/` now emits *watermark not
  evaluated* on every proof that declares `watermark`, because it ships no
  detector, and the 13 vectors with a non-red verdict carry that label in
  `expected.json`. A rule no implementation emitted and no vector covered was
  not a rule.
- §7: a 24-bit `mark_id` is a lookup hint, not an identifier. Collisions are
  expected, two proofs may carry one mark, and origin search from a mark alone
  answers with a candidate set. Layout internals stay out of scope (§1).

## v1.0 — 9 September 2026

First frozen version. Trailer and footer (§3), canonical bytes and core
signature (§4), per-GOP segment chain with the vcap SEI (§5), proof structure
(§6), proof levels (§7), optional versus invalidating (§8), compatibility policy
(§9). 34 conformance vectors, JSON Schema, reference verifier in `tools/`.
Reviews absorbed before the freeze: cryptographic
(`reviews/01-crypto-review-draft-1.0.md`), implementability on Android hardware
(`reviews/implementability-android.md`).
