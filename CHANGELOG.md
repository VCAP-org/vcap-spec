# Changelog

`vcap/1.0` is a **draft**: the six format decisions are settled, the wire
contract is not binding yet. The additive-only rule of §9 starts at the first
publication — the first store build, or the first SDK handed to an integrator —
not at the `v1.0` tag, which is a working tag with a pre-release. Until then a
breaking change is allowed and is marked **BREAKING** here. Every entry names
the section it touches, the vectors it adds and what an older verifier does
with it.

## Unreleased

### The watermark payload layouts are public (new document)

- `spec/watermark-layouts-1.0.md` defines `photo-bch-v3` and `video-rep-v1`:
  the 256-bit carrier, the BCH and repetition layouts, bit order, the strength
  convention, each decoder's single failure answer, why `mark_id` collides on
  purpose, and the versioning rules that keep an already-sealed file
  verifiable. `vectors/_watermark/layouts.json` pins both with worked cases.
- Why it moves here: the proof format names a layout in `watermark.layout` and
  a verifier that cannot read the payload cannot say *watermark matched*. The
  layouts existed, written down, in a private repository — which makes them
  documentation and not a contract. §1 said the format "does not define
  watermark internals"; it now separates the layout, which is a wire contract,
  from the model, which is an artifact fetched by digest and stays out.
- No change to the proof format, the schema or any vector verdict.

### The anchor slice, and an instant nobody asserts (vectors 55-58, §6.2, §8)

- The reference verifier now evaluates `anchor`: the batch root recomputed
  from `core_hash`, `index`, `tree_size` and `merkle_path`, with leaves
  `SHA-256(0x00 ‖ core_hash)` — the same tree as the transparency log, so one
  Merkle implementation serves both. Four vectors: the path alone, a forged
  path, the chain read agreeing, and the chain recording another root.
- **Vector 57 is the first vector whose proven instant is not the device's
  word.** `chain_read` is a corpus input, like `key_status`: with it the
  block's timestamp becomes `validated_at`, `source: "anchor"`. It is an upper
  bound — the capture existed *before* that block — and §6.2 now says so, along
  with the fact that an anchor the chain contradicts yields no instant at all.
  Dating a capture by a transaction that does not contain it is worse than
  having no anchor.
- §6.2 also now requires **both** `root` and `tree_size` to match the chain
  read: a batch of a different size can share a root when one is a prefix of
  the other.
- **§8 states one label rule for every attachment**, replacing the
  registry-specific wording added with vectors 49-54: a present attachment that
  does not hold up carries the absent label *and* its own *… evidence invalid*.
  An attachment a verifier cannot *read* — a log outside the trust set, a chain
  it has no client for — is absent evidence instead, and carries one label.
- `expected.schema.json` gains `chain_read`. No change to the wire format.

### The registry slice, and the first green (vectors 49-54, §6.2, §8)

- The reference verifier now evaluates `registry`: RFC 6962 leaf and node
  hashes, inclusion against a signed tree head, and the leaf's binding to
  `device.key_id` and `sig.pub`. Six vectors cover it — verified, a forged
  audit path, a leaf naming another key, a log outside the trust set, a tree
  head signed after the declared capture, and **green**.
- **Vector 54 is the corpus's first green.** It needs one input more than the
  others: `key_status`, §6.2's online answer about the key at the instant the
  capture is validated at. That is a corpus convention, like `verifier_clock`,
  and it has to be — an inclusion proof shows the key was in the log when a
  head was signed and cannot show it was not revoked afterwards, because a
  revocation is a later leaf and nothing in a Merkle tree proves a leaf's
  absence. No file on its own is green, by design.
- **§6.2 clarified, twice, both because two implementations disagreed on the
  vectors.** `leaf.key_id` is the same digest as `device.key_id` in a different
  encoding — 64 hex characters in the leaf, base64url in the core — so a
  verifier compares digests and not strings; comparing the strings fails on
  every honest proof. And a failure of the evidence emits **both** *registry
  evidence invalid* and *key not in transparency log*, while a `log_id` the
  verifier holds no key for emits *log not trusted* alone: evidence that does
  not hold up and evidence this verifier cannot read are different facts, and
  the second is absent evidence rather than a lie.
- §8's label table gains those three rows and *revocation not checked*.
- No change to the wire format or the schema of a proof. `expected.schema.json`
  gains `key_status` as an input.

### The first iOS captures in the corpus (vectors 47-48)

- No spec text changes. Two vectors from an iPhone 11 Pro (S1 spike,
  `vcap-sdk-ios`), and the first evidence in this repository that anything but
  Android can produce or be read at either layer.
- **Vector 47**, a 1600×1200 HEIC the device sealed itself: the corpus's first
  `platform: "ios"`, its first `secure_hw: "secureEnclave"`, and its first
  signature made by a Secure Enclave. The core hash the device computed is the
  one `tools/src/verify.ts` recomputes — which is where a writer's JCS, its
  DER→P1363 conversion and its low-`s` normalization are proven right
  *together*, since any one of them wrong would not land on that number.
- **Vector 48**, a `qt  ` container `AVAssetWriter` wrote, with §5 recomputed
  from it. Until now every demuxed vector came out of Android's `MediaMuxer`, so
  a reader could pass them all while reading one muxer's habits: this file has
  the `qt  ` brand, a `wide` box before `mdat`, `tapt` and `sdtp` where a reader
  must skip what it does not know, a movie timescale of 600, an edit list that
  is present and says nothing — and chunk offsets in **`stco`**, 32-bit, a
  branch no container vector had ever executed. Its `media.mime` is
  `video/quicktime`, the first video here that is not `video/mp4`, which is what
  §8's `video/` prefix rule was written for.
- The chain in 48 is synthesized with the test key and proves nothing about
  iOS: the spike inserted vcap SEIs and never sealed a video. The container and
  its content hashes are the device's. `vectors/README.md` says which vectors
  are which weight of evidence.
- `tools/src/derive-ios-vectors.ts` rebuilds both from the spike's artifacts,
  the way `derive-container-vectors.ts` does for 36-39.

### BREAKING — `media.w` and `media.h` are required (§8, §9, D9)

- §8 requires the pixel dimensions of every proof. They are not evidence —
  nothing is proven by them — but every writer holds them at capture, and a
  reader that cannot say how large the frame is cannot place a watermark
  payload or a segment in it. Missing is malformed: *no proof found*, the same
  shape as an absent `capture_id`, and the signature is never examined because
  the §8 shape check fires first. **Vector 46** pins it.
- Why this is breaking and taken anyway: a proof without them was conformant
  yesterday and is not today. Every vector already carried them and the Android
  core already writes them unconditionally, so nothing in the project changes
  behaviour — but a third-party writer built against the old schema would break,
  which is exactly what §9 forbids once the format is published. It is taken now
  because now is the only time it is free.

### BREAKING — `segments[].range` is deprecated (§5, D9)

- Writers MUST NOT emit it; verifiers MUST ignore it where an older file carries
  it. It was unsigned, a verifier was already forbidden to conclude anything
  from it, and its base was never specified: the offsets are taken before the
  trailer is appended and any clip moves them, so two writers had no obligation
  to agree. A field nobody may trust and everybody may compute differently is an
  invitation to trust it by accident.
- No file is invalidated: `range` is outside the core hash and outside the
  per-segment message, so every already-sealed file verifies unchanged, and no
  vector carried it.

### A verifier that does not recompute segment content says so (§5, §7, D10)

- Recomputing the §5 `content_hash` values from the container stays **optional**
  — a sidecar without a demuxable container, a light library — but a verifier
  that skips it MUST report *segment content not recomputed*. The two answers
  differ: on vector 39 the same file reads *verified_clip* without the
  recomputation and *tampered* with it, so a reader who is not told which one
  ran cannot know what the verdict means. Same shape as the watermark labels.
- **Vector 33** now carries the label; vectors 36–39 (`kind: container`) do not,
  because there the recomputation runs. An older verifier that omits the label
  is not wrong about the file, only silent about its own coverage.

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
- §9 and the schema: `$defs/identifier` now accepts camelCase as well as
  lowercase-hyphen, and §9 says a new value in an extensible field uses one of
  the two spellings the format already uses. The narrow pattern was the cause of
  the fix above, and it was still armed on `location.evidence[].kind` and
  `timestamp.tsa_issuer`, whose values arrive with C15 and D2 — the same
  incident, later, on another field. A pattern there is a gate against free
  text, not a style rule.
- Tooling: the generator signs with **RFC 6979** (deterministic `k`) and the two
  vector inputs built from `randomBytes` now use fixed bytes, so regenerating an
  unchanged corpus produces no diff at all. Signing moved to `tools/src/sign.ts`
  and stays off the verification path — the reference verifier never signs, and
  nothing it loads pulls the signing dependency. The vectors' signature values
  change once, here, and are stable from now on; every verdict is unchanged.
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
