# Changelog

`vcap/1.0` is frozen. Changes after the tag are additive only (spec §9): new
optional keys, new values in fields declared extensible. Every entry names the
section it touches, the vectors it adds and what an older verifier does with it.

## Unreleased

### The instant a proof is validated at (§6.2, §7, §9)

- §7: every certificate path in a proof — the `attestation` chain, a
  `timestamp` token's TSA chain — is validated at the **proven instant of the
  capture** (token `genTime`, else a verified `anchor`'s block time, else
  `time.device_clock`, which caps the verdict at amber), not at the verifier's
  clock. A chain valid then and expired since is not an error; expired with no
  trusted instant is amber with *attestation chain expired, capture time not
  proven*, never red. Not a new principle: §6.2 already said it for the device
  key's revocation. The measurement that forces it into writing: in the moto
  g75 5G's real chain the RKP intermediate is valid 6–18 September 2026, so
  under verifier-clock validation every capture from that device reads as *not
  hardware-attested* from 19 September on.
- §6.2: new **optional** attachment `attestation_status` — `source` (extensible,
  `googleStatusList`), `fetched_at`, `entries` of `{serial, status, reason?}`,
  and the registry's ES256 signature over `core_hash ‖ JCS(entries) ‖ uint64 BE
  fetched_at`. It exists because the status of an expired certificate is no
  longer published anywhere, so the question the instant rule poses — was the
  chain revoked *at* the capture — is unanswerable later without frozen
  evidence. Google's list carries no signature of its own, hence the registry
  countersignature: evidence, never a verdict signed by us. Revocation is
  temporal, as for the device key: `fetched_at ≤ T` and `revoked` → proven
  `none`, red for the level; `revoked` after `T` → the level at `T` stands,
  shown.
- §9: `attestation_status.source` joins the extensible fields; its fallback is
  to ignore the attachment (*chain revocation not checked*).
- §6.2: **which key** signs `attestation_status` — the one that signs that
  log's tree heads, named by `registry.log_id` when a registry attachment is
  present and otherwise found by trying the trusted logs' keys; no log key held
  means *chain revocation not checked*. The first sentence said "the registry
  signing key" without saying which of several a verifier may trust, which two
  implementations could have resolved differently. No `log_id` inside the
  attachment on purpose: a proof must not point a verifier at a key.
- Schema: `attestation_status` added, `additionalProperties: false` inside it.
  An older verifier reads the key as unknown and lists it *not evaluated* (§9).
- Vectors **41–45**, the attestation slice of the proof-level corpus: a chain
  proving `tee` and one proving `strongbox`, a chain valid at the capture and
  expired by the time the verifier reads it, and the same frozen snapshot
  revoking a certificate before and after the capture — two verdicts from the
  same entries, decided by the instant. With them, `_trust/` (the anchors a
  verifier is assumed to hold, with a test attestation root standing in for a
  pinned Google root) and `_chains/` (the chains, committed because minting a
  certificate again changes its bytes).
- `expected.json` grows `level` and `validated_at`, and `verifier_clock` as an
  *input*: a §7 verdict depends on when the verifier runs, so a vector that
  left the clock to the calendar would change its own answer over time.
- Schema fix: `attestation_status.source` was `$ref: identifier`, whose pattern
  is lowercase-only — it rejected `googleStatusList`, the one value the spec
  names. Found by the generator, which validates every vector it writes.
- **Still to come**: the registry, timestamp and anchor slices of the corpus.

### Clarifications for writers (§4, §5, §6, §7)

Found while implementing the Android core against `v1.0`. No byte changes:
every `v1.0` file verifies the same.

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
