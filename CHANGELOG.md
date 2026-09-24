# Changelog

The format is in development: nothing is frozen and no version of this
specification has been released. `"v": "vcap/1.0"` is the format identifier
carried by every proof, not a release.

**No backward-compatibility burden** (decision of 22 September 2026). No sealed
file is in anybody else's hands, so a breaking change is allowed, is marked
**Breaking** below, and carries no fallback for older files. The additive-only
rule of §9 binds from the first build, SDK or sealed file that reaches somebody
else.

## Unreleased

### Review fixes — corpus 1.3.0 → **2.0.0**

A major corpus bump: existing vectors changed bytes or verdict (33, 38, 44,
45, 54, 64–67 and every attested vector, whose chains were re-minted), which
the bump policy in `vectors/README.md` reserves for a major. 36 vectors are
new (86–121), 121 in all.

**Video binding (§5)**

- **Breaking. A signed segment is verified only where the file has it.**
  *Locating segments*: a segment counts as verified only if exactly one GOP
  of the received file carries a vcap SEI with its index and the proof's
  `capture_id`, and that GOP recomputes to the signed `content_hash`. Once any
  GOP names this capture, every GOP is accounted for in decode order: a GOP
  with no vcap SEI, one naming another capture, an index the proof does not
  sign, a duplicated index, indices not strictly increasing, or more than one
  vcap SEI in a GOP is *tampered*. Before, GOPs without an SEI were skipped
  and a segment verified on its signature alone: a stolen proof next to an
  unrelated clip read *verified clip* (vector 86), and so did a file with one
  SEI index edited (88). Vector 38 — segment 0 dropped from the proof, left in
  the file — changes from *verified clip* to **tampered**; vector 89 is the
  genuine cut clip.
- **Breaking. New outcome `frames_not_compared`**, amber: a video whose
  signatures hold and in which no GOP of the capture can be located, or whose
  verifier did not recompute. Never *verified clip*. `segments.verified` is
  empty whenever nothing was located, so vector 33 (a `file` vector, not
  demuxed) keeps *authentic* on `media.hash` and now reports no verified
  segment. `expected.schema.json` gains the value.
- **Breaking. Segment boundaries are IDR access units** by NAL type, not
  `stss` (vector 94). **Writers MUST emit exactly one vcap SEI per segment**,
  in its IDR access unit.
- **A vcap SEI NAL carries exactly one message**, `payloadSize` exactly 36,
  then only `rbsp_trailing_bits`; any other shape with the vcap UUID is
  *tampered* (vector 93). Emulation prevention is stated: the payload is read
  from the RBSP, the NAL is excluded as stored.
- **The NAL units of a sample tile it exactly**; a bad length prefix is
  *tampered*, not a silent stop (vector 92).
- Container vectors 86–94 are edits of the device captures 36 and 37,
  derived by `npm run generate` through a sample-table remuxer
  (`tools/src/remux.ts`); the device signatures are untouched.

**Time and revocation (§6.2, §7)**

- **Breaking. `time.device_clock` alone caps at amber.** Green needs a valid
  timestamp token or a verified anchor for the proven instant. Vector 54
  changes from green to **amber**; vector 100 is the green, with a token.
- **Breaking. A missing `device_clock` never strengthens a verdict**: new
  label *capture time not declared*, and the registration cannot be placed
  before the capture (vector 101). The reference verifier read it as "before".
- **`tree_head.timestamp` MUST NOT exceed a valid token's `genTime`**: new
  label *registered after the trusted time* (vector 102).
- **Breaking. Chain revocation.** `attestation_status` entries gain optional
  `revoked_at`, the revocation date as the source gives it; `fetched_at` is
  never used as one. A `revoked` chain certificate is red unless a token or a
  verified anchor places the capture before `revoked_at` and the reason is
  not `KEY_COMPROMISE`/`CA_COMPROMISE` (vectors 44, 45, 96, 97). `unknown`, or
  a chain certificate without an entry, is *chain revocation not checked*,
  amber, never red (98, 99). Every certificate but the pinned root needs an
  entry; serials compare with leading zeros stripped.
- **A token must agree with a verified anchor**: `genTime` not after the
  block, and the TSA signer valid at the block time; otherwise both timestamp
  labels and the anchor dates the capture (vectors 103, 104). The residual
  risk of a leaked TSA key is in `threat-model.md` §5.4.
- The online key status is asked at the proven instant, not at the device
  clock when a trusted instant exists.

**Attestation (§7)**

- **Breaking. Android chain MUSTs**: every certificate above the leaf is a CA
  with `keyCertSign`; the key attestation extension is in the leaf only
  (vector 105, a genuine attested key signing a forged "StrongBox" leaf);
  verified boot on a locked device, as the reference verifier already
  enforced. A chain that fails is *origin not hardware-attested* **and** new
  *attestation evidence invalid*.
- **Breaking. `attestationApplicationId`** is compared with the app signing
  digests a trusted log declares (`app_signing_digests` in the trust list,
  `_trust/logs.json`); new labels *attestation app not admitted* and
  *attestation app not checked*, both amber (vectors 106, 107).
- **Attestation leaf ≠ `sig.pub` is *tampered***, as §8 always said; the
  reference verifier used to drop the level silently (vector 108).
- **iOS `secureEnclave`** is reachable only through a verified registry leaf
  that records it, and is labelled *level from registry records* (vector
  110). No offline App Attest binding is defined in this version.
- `vectors/_chains/` re-minted with `keyUsage` on the CAs and an
  `attestationApplicationId` in each leaf; three new chains (`forged-leaf`,
  `other-app`, `no-app-id`).

**Integrity (§6.2, §7)**

- **Breaking. One rule**: a valid `integrity` verdict of `failed` caps the
  ceiling at amber, prominently flagged; nothing else and no absence caps
  (vector 109). The contradicting sentences in §6.2, §8 and the threat model
  are gone.
- **Breaking. The integrity signature** is over
  `"vcap/1.0/integrity" ‖ core_hash ‖ JCS(attachment without sig)`, like
  `location_corroboration`: `source` and `evaluated_at` are now signed, and
  the separator isolates the message. Vectors 64–67 change bytes.
- `integrity.source` and `watermark.layout` are extensible identifiers in the
  schema and read as *not evaluated* when unknown (vectors 95, 121).

**JSON, JCS and the trailer (§3, §4.1, §6.1)**

- **Breaking. Reading the JSON**: no BOM, no duplicate member names at any
  depth, every number an integer literal within ±(2^53 − 1); otherwise *no
  proof found* (vectors 111–114).
- **The reference JCS** wrote integer-like member names in numeric order and
  dropped a `__proto__` member (vector 120).
- **Breaking. A `VCAP` footer with major ≠ 1 is *unsupported format
  version***, not *no proof found* (vector 115). `8 + payload_len + 16` is
  computed without overflow (118); reserved flags are ignored (119).
- **The container is chosen by magic bytes**, never by `media.mime`; a
  malformed JPEG is *no proof found*, never an exception (vector 116); an empty
  file is *no proof found* (117).
- The schema bounds uint32 fields (`w`, `h`, `duration_ms`, `segment_count`,
  `gop`, `acc_cm`, `radius_m`, …) and caps every other integer at 2^53 − 1.

**Documents**

- §8 defines outcome and ceiling and lists the eight outcomes; the labels
  table no longer has prose inside it.
- `watermark-layouts-1.0.md`: the `photo-bch-v3` radius is 18 **bit** errors;
  the repetition code's guaranteed radius is 3 flips and beyond it recovery is
  a curve, not a ≈ 51-flip radius. `watermark-robustness-1.0.md` corrected to
  match, and the photo break point is marked unmeasured between 7 and 30
  flipped bits.
- `c2pa-interop-1.0.md`: the custom assertion label is
  `io.github.vcap-org.vcap.proof`.
- Private references removed from the tools, the trust README, the watermark
  fixtures and the notes of vectors 36–39 and 75.

### Watermark

- **Photo strength default 1.5 → 1.2** (`watermark-layouts-1.0.md` § Strength).
  A capture-time default, not a layout change; no vector moves.
- **Breaking. A clip's frame count is not gated by the agreement floor** (§8).
  A sampled frame counts when its own decode passes the layout's checksum and
  yields the id the clip reported; its own agreement is not tested against
  0.85. The floor governs naming an id, and the aggregate already cleared it;
  equality with that id supplies what the floor would. A per-frame floor made a
  wholly marked clip on a hard chain report 0 of 8 while a one-frame splice
  reported 1 of 8. A frame decoding to another id carries nothing and is not
  evidence against the file.
- **Breaking. A clip's reported agreement is the aggregate decode's own** (§8).
  A verifier MUST NOT substitute a mean over the carrying frames or any other
  subset: that mean rises as fewer frames qualify and would rank a splice above
  a heavily re-compressed genuine clip.
  Vectors for both entries: `vectors/_watermark/clip-reading.json`. Corpus
  1.2.0 → **1.3.0** (fixture added; the 85 numbered vectors are unchanged).
- **Breaking. `video-rep-v1` reports no id below 0.85 agreement** (§8,
  `watermark-layouts-1.0.md`). Below the floor the answer is *no id* plus the
  agreement figure, reported as *watermark not recovered*. The layout's CRC-8
  passes by chance about one word in 256, and a 38-recording device campaign
  found two wrong ids at 0.738 and 0.789; correct ids reach down to 0.727, so
  the floor refuses some true answers by design. §8's invalidating row is
  narrowed accordingly: a below-floor decode is not evidence against the file.
  A verifier that reports a `video-rep-v1` id without its agreement MUST say
  *watermark not evaluated*. `photo-bch-v3` is untouched. Vector:
  `vectors/_watermark/agreement-floor.json`. Corpus 1.1.0 → **1.2.0**.
- **Reportable budget: 38 flipped bits of 256** (informative). The video
  channel was advertised on the repetition code's ≈ 51-bit correction radius;
  under the floor the reportable budget is 38 bits (14.8 % BER). Recovery inside
  it is probabilistic and every failure is a refusal, never a wrong id.
  `watermark-robustness-1.0.md` gains *What may be reported*.
- **Frame count required when a clip's watermark is reported** (§8). A
  verifier that decodes several frames and reports one answer MUST report how
  many sampled frames decoded to that id, and MUST NOT present a confidence
  figure as that answer. Closes the threat model's splice item as a policy.
- **Adversarial removal and forgery** (informative,
  `watermark-robustness-1.0.md`; `threat-model.md` §5.8): 65 attacks. Filtering
  fails to remove the mark; geometry removes it (10° / 35 % crop on the int8
  build); forgery with the public model is cheap; one genuine frame spliced into
  foreign footage reports the real id at 0.996, so `agreement` is not a forgery
  detector. Adaptive gradient attacks lead the *Not measured* list.
- **False positives on unmarked content** (informative): 4 329 decodes of 481
  unmarked frames; `photo-bch-v3` produced 0 ids, `video-rep-v1` one per 289
  decodes (its CRC-8 false-pass rate). No detection threshold is published.
- **Measured robustness curve** (informative, `watermark-robustness-1.0.md`):
  photo and video chains, break points, int8 cost, frames to read, browser cost,
  and what was not measured. Satisfies versioning rule 6 of the layouts document.
- **The payload layouts are public** (`watermark-layouts-1.0.md`):
  `photo-bch-v3` and `video-rep-v1`, bit order, strength convention, each
  decoder's failure answer, versioning rules; pinned by
  `vectors/_watermark/layouts.json`. §1 now separates the layout (a wire
  contract) from the model (an artifact fetched by digest).
- **Editorial**: `watermark-layouts-1.0.md` now uses §8's label *watermark not
  recovered*.

### Proof format

- **§3: replacing a trailer.** A writer may replace its own trailer to add
  §6.2 attachments obtained after sealing: media bytes unchanged, core and
  `sig` byte-identical, old trailer dropped rather than wrapped, a corrupted
  trailer never rewritten. Readers are unaffected.
- **§5: the extent of a NAL unit.** Exactly the bytes the container stores for
  it, trailing zeros and the leading zero of a four-byte start code included; a
  writer that hashes before muxing MUST hash the bytes it hands the muxer.
  Encoders pad slices with trailing zeros on cheap scenes, and a writer that
  trimmed them produced files that verified *tampered*. Still owed: vector
  `mp4-container-nal-trailing-zeros`.
- **§6.1: `policy.retention_ref`** attests no storage, encryption, retention,
  deletion or retrieval right. Clarification only.
- **Position level** (§6.1, §6.2, new §7.1, §8, §9, vectors 74–84).
  `location.level` in the verifier output: `none`, `declared`, `corroborated`,
  `authenticated` (reserved, unreachable). It never moves the proof level.
  `location` gains `alt_cm`, `source`, `at`; new optional attachment
  `location_corroboration` (operator-side CAMARA check countersigned by the
  registry; no phone number ever enters a proof). Every photo vector gains
  *location declared only*. `threat-model.md` §5.7 covers the threats.
- **§6.2: `ebsi` and `ebsi-pilot`** as `anchor.chain` values, read through the
  EBSI Ledger API v4 JSON-RPC gateway. Prose only.
- **C2PA interoperability and the sidecar** (§3.1, §4.1,
  `c2pa-interop-1.0.md`, vectors 68–73). Mapping of the proof onto a C2PA
  custom assertion; co-existence rules for JPEG and ISO-BMFF; a C2PA update
  manifest appended to a sealed file hides the footer. §3.1 makes the sidecar
  normative: payload bytes only, `<filename>.vcap` or caller-supplied, never
  fetched; trailer first, then *corrupted*, then sidecar over the whole file.
- **`integrity` attachment** (§6.2, §8, vectors 64–67): checked, shown as
  `integrity <verdict>`, changes no ceiling.
- **`timestamp` attachment** (§6.2, §8, vectors 59–63): the five RFC 3161
  checks are normative. A token lifts vector 43's expired-chain caveat (63).
- **`anchor` attachment** (§6.2, §8, vectors 55–58): Merkle path to the batch
  root; a chain read gives an upper-bound instant. Both `root` and `tree_size`
  must match. §8 states one label rule for every attachment.
- **`registry` attachment** (§6.2, §8, vectors 49–54): RFC 6962 inclusion and
  key binding. Vector 54 is the first green; it needs the `key_status` input.
  `leaf.key_id` and `device.key_id` are compared as digests, not strings.
- **Breaking. `media.w` and `media.h` are required** (§8, vector 46). Missing
  is *no proof found*.
- **Breaking. `segments[].range` is deprecated** (§5). Writers MUST NOT emit
  it; verifiers MUST ignore it. It is outside every signed message, so no file
  is invalidated.
- **Segment content not recomputed** (§5, §7). Recomputing `content_hash` stays
  optional, but a verifier that skips it MUST say so (vector 33).
- **Validation instant** (§6.2, §7, §9, vectors 41–45). Certificate paths are
  validated at the proven capture instant, not the verifier's clock; expired
  with no trusted instant is amber, never red. New optional attachment
  `attestation_status` freezes revocation evidence at capture. `identifier`
  accepts camelCase. The generator signs with RFC 6979, so regeneration is
  byte-stable.
- **Clarifications for writers** (§4, §5, §6, §7). JPEG fill bytes and
  length-less markers (vector 35); high-`s` normalization; `segment_count`;
  `attestation` as a DER array; a declared watermark that does not come back is
  non-red, red only for a payload decoding to another id; `mark_id` is a lookup
  hint, not an identifier.

### Vectors and tooling

- **`tools/corpus-drift.sh`**: run by consumers that pin this repository as a
  submodule, to learn whether their pin has fallen behind main. Fires only when
  a numbered vector directory moved; no network is a skip, never a failure.
- **Conformance docs checked against the corpus**: `vectors/CONFORMANCE.md` and
  `vectors/README.md` cite corpus 1.3.0 and 85 vectors, and
  `tools/test/conformance-doc.test.ts` fails when they disagree with `VERSION`
  or `MANIFEST.json`.
- **Corpus 1.1.0: vector 85** `mp4-container-ios-sealed`: an MP4 whose segment
  chain and core a Secure Enclave signed (ISO `mp42`, `avc1`). Five of its
  eleven segments are one frame long; this comes from the writer forcing a
  keyframe while also setting a keyframe interval on the same encoder, not
  from the encoder itself. `NOTES.md` in the vector predates this correction
  and stays byte-frozen.
- **Vectors 47–48**: the first iOS captures — a Secure Enclave–signed HEIC, and
  an `AVAssetWriter` QuickTime container (`stco`, `wide`, timescale 600) under a
  synthesized chain.
- **Conformance claims** (`vectors/CONFORMANCE.md`,
  `schema/conformance-report.schema.json`): a claim names corpus version,
  manifest hash and vectors run; zero vectors is a failure. CI checks this
  repository's own report.
- **Corpus version and manifest** (`vectors/VERSION`, `vectors/MANIFEST.json`,
  `npm run manifest:check`) and the edge-case generator
  (`npm run generate:edge-cases`, 46 swept boundary vectors, not versioned).
- **Vector 51 is byte-stable**: its second key is fixed test material.

### Initial draft

Trailer and footer (§3), canonical bytes and core signature (§4), per-GOP
segment chain with the vcap SEI (§5), proof structure (§6), proof levels (§7),
optional versus invalidating (§8), compatibility policy (§9). 34 conformance
vectors, JSON Schema, reference verifier in `tools/`. Reviews absorbed:
cryptographic (`reviews/01-crypto-review-draft-1.0.md`) and implementability
(`reviews/implementability-android.md`).
