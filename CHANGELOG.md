# Changelog

`vcap/1.0` is a **draft**: the six format decisions are settled, the wire
contract is not binding yet. The additive-only rule of §9 starts at the first
publication — the first store build, or the first SDK handed to an integrator —
not at the `v1.0` tag, which is a working tag with a pre-release. Until then a
breaking change is allowed and is marked **BREAKING** here. Every entry names
the section it touches, the vectors it adds and what an older verifier does
with it.

## Unreleased

### The red team: the attacks that worked, next to the ones that did not

No spec or vector change: `vectors/NN-*`, its expected verdicts and the corpus
manifest are untouched. Documentation only, and nothing normative moves.

- **`spec/watermark-robustness-1.0.md`** (informative) gains *Adversarial
  removal and forgery* — 65 deliberate attacks on three images and one clip,
  fp32 and int8, each with its adversary model, split between attacks that
  *removed* a payload and attacks that made the detector emit a **chosen** one.
  Removal by filtering failed everywhere, including the blind high-pass
  subtraction aimed at the mark (0.0 bit errors). Removal by **geometry**
  works and costs the attacker nothing: gone at 15° of rotation and a 50 %
  centre crop on fp32, and already at **10° and 35 % on the int8 build a
  browser verifier ships**, because nothing resynchronises the mark to the
  detector's fixed working grid. **Forgery is cheap**: the model is a public
  download, so a chosen `capture_id` is planted or overwritten 3/3 at 42 dB.
  The worst row needs no model — one genuine frame spliced into 23 foreign
  ones makes the clip report the real `mark_id` at agreement **0.996**,
  because an unmarked frame abstains rather than dissents (mean absolute
  message logit 11.3 against 0.131) — from which it follows that
  **`agreement` is not a forgery detector**, correcting a reading the
  false-positive section left open.
- The *Not measured* list now leads with **adaptive, gradient-based attacks**
  — the model is differentiable and public, and this is the largest gap — then
  a real photograph of a real screen, an adversary against moving footage,
  combined attacks, and the fp16 and distilled builds.
- **`spec/threat-model.md`**: new **§5.8**, threats against the watermark.
  *Watermark removal by re-framing* and *watermark forgery with the public
  model* move out of *Open items* into **accepted and named** — removal only
  weakens a verdict, and forgery is exactly why the watermark alone is never
  green. *Splicing one marked frame into foreign footage* is **open**, with a
  mitigation that is a **verification policy and not a format change**: decode
  the sampled frames individually and report how many carried the id, instead
  of decoding once over the averaged logits. §2 gains the matching
  non-claim: a mark says a frame of that capture appears in the file, and
  carries no authorship.

### The other half of the curve: false positives on unmarked content

No spec or vector change: `vectors/NN-*`, its expected verdicts and the corpus
manifest are untouched. Documentation only, and nothing normative moves.

- **`spec/watermark-robustness-1.0.md`** (informative) gains *False positives:
  what a recovered payload implies* — 4 329 decodes of 481 unmarked frames
  (only 49 of them natural photographic content, the rest synthetic), on the
  fp32 and int8 builds: `photo-bch-v3` produced **0** ids, `video-rep-v1`
  produced one per 289 decodes (0.35 %), which is the false-pass rate of its
  CRC-8 and not a property of the model. The detection logit separates nothing
  usable — below a coin flip on the photo layout — so **no detection threshold
  is published** and the layouts' integrity checks are the only check. The
  per-decode rate becomes ≈ 3 % per file at 8 sampled frames, and `agreement`
  separates false ids from real ones as an observation, not a threshold.
- The *Not measured* list keeps that absence first, reduced to what is still
  true: no false-positive rate on **real photographic content at volume**, no
  per-file rate, no swept `agreement` threshold, and fp16 and the distilled
  build unmeasured.
- **`spec/watermark-layouts-1.0.md`**: one informative sentence under
  *`mark_id` is a lookup hint* pointing at that number. The layout, its bit
  layout and its failure answer are unchanged.

### A checkable conformance claim, and the watermark's published curve (C10)

No spec or vector change: `vectors/NN-*` and its expected verdicts are
untouched.

- **`vectors/CONFORMANCE.md`** and **`schema/conformance-report.schema.json`**:
  what a claim of conformance has to name (corpus version, manifest hash,
  vectors actually run) and the rule that a run of zero vectors is a failure
  and never a pass. `npm run validate -- --report <file>` checks a report,
  including the two arithmetic rules the schema cannot express.
  `vectors/conformance-report.json` is this repository's own claim, written by
  `npm run conformance:report` and gated in CI by `conformance:check`, which
  exits 1 when the run covered fewer vectors than the manifest declares.
- **`tools/src/conformance.ts`**: the per-vector loop, now shared by the
  reference suite and the report so the published claim is about the code CI
  runs; `corpus()` throws on a missing or empty corpus. The suite pins the
  vector count to `MANIFEST.json` instead of flooring it at 30.
- **`spec/watermark-robustness-1.0.md`** (informative): the measured curve of
  the published model — the photo chains and the video chains with their
  recipes, the two break points (a 480 px JPEG-q30 thumbnail; a clip past
  crf 36), what int8 quantization costs in margin, how many frames a verifier
  has to read, and what a detector call costs in a browser. It publishes its
  corpus size next to every table (three images, one synthetic clip) and lists
  what was **not** measured rather than estimating it — the detector's
  false-positive rate on unmarked content first among them. Satisfies
  `watermark-layouts-1.0.md` versioning rule 6, which had no published curve
  behind it.

### Corpus version, manifest and edge-case generator (C19, tooling only)

No spec or vector change: `vectors/NN-*` and its expected verdicts are
untouched. Two additions to the tooling that reads `vectors/`:

- **`vectors/VERSION`** (`1.0.0`) and **`vectors/MANIFEST.json`**: a
  byte-exact inventory of the numbered corpus — name, `kind`, `outcome` and a
  SHA-256 per vector, plus one per shared fixture directory (`_media`,
  `_trust`, `_chains`, `_timestamps`, `_watermark`) — generated by
  `tools/src/manifest.ts` (`npm run manifest`) and checked in CI (`npm run
  manifest:check`). Lets a third-party implementation say "conformant with
  corpus 1.0.0" and a consumer verify it means exactly these 84 vectors' bytes,
  not "some version of vcap-spec's vectors". Additive-only, the same as the
  format itself: the version moves forward only when the vector list grows.
- **`tools/src/generate-edge-cases.ts`** (`npm run generate:edge-cases`):
  writes `vectors/edge-cases/`, 46 vectors produced by sweeping a boundary
  systematically — every trailer-truncation offset, every magic byte flipped
  alone, unsupported major and unknown minor swept instead of asserted once,
  every required field dropped in turn, the JCS corners RFC 8785 pins to
  ECMAScript (negative zero, a supplementary-plane character, control-character
  escaping, UTF-16 code-unit key order), and a JPEG fill-byte run next to a
  stripped JUMBF segment. Deterministic (`--seed`, default 1) and self-checked
  against the reference verifier the same way `generate.ts` checks the
  numbered corpus — a disagreement aborts the run. Not part of the versioned
  manifest above: it is regenerated on demand, not reviewed vector by vector,
  and nothing outside this repository reads it. Does not cover the watermark's
  BCH(255,131) correction radius — no decoder exists anywhere in this
  repository to test it against; that boundary belongs to whichever component
  owns the decoder (`vcap-ml` or an SDK core), not to this proof-format layer.

### Editorial: one label, one spelling (§8, watermark layouts document)

Found while implementing `vcap-verifier` PR #31. `spec/watermark-layouts-1.0.md`
quoted §8's watermark-not-recovered label as *no watermark recovered* — a
paraphrase of the table §8 actually defines, not a second label. §8 of
`spec/vcap-proof-1.0.md` is the normative label table; *watermark not
recovered* is the wording used there, in `spec/c2pa-interop-1.0.md`, and in
the "Clarifications for writers" entry above. `spec/watermark-layouts-1.0.md`
is corrected to match.

No vector, schema entry, or reference-verifier output uses either spelling —
`tools/src/verify.ts` ships no watermark detector and never emits this label,
so no `expected.json` carries it. Nothing here changes an oracle; this is a
documentation-only, non-breaking fix.

### The position level: declared, corroborated, and a reserved third (§6.1, §6.2, §7.1, §8, §9, vectors 74-84)

- **Two levels on two axes.** §7's proof level says how strong the origin
  claim is; the new §7.1 says how much the coordinates in the core are
  worth, as `location.level` in the verifier's output — `none`, `declared`,
  `corroborated`, `authenticated` — and the two never mix: the position
  level moves no ceiling and turns no verdict green or red (vectors 75, 79).
  "Guaranteed" is not a value. Every proof that declares a position now
  carries a label naming its level, so **every photo vector in the corpus
  gains *location declared only*** — the same shape as the day *watermark
  not evaluated* landed on thirteen of them: a level nobody named was not a
  level.
- **§6.1 `location`, additive.** The declared claim gains `alt_cm` (WGS 84
  ellipsoid height, integer centimetres), `source` (`gnss`, `network`,
  `manual`; extensible) and `at` (device clock at the fix, ms). `level` is
  now defined as the level the device **claims**: a writer claims
  `declared`, never `corroborated` (vector 82), and `authenticated` is
  reserved for device-side `evidence[]` kinds a later minor defines (vector
  81). A `location` without both coordinates declares nothing (vector 84).
  Signed by the device means the device says so: the OS is the only thing
  between the app and any coordinates it likes, which is why the level is
  called *declared*.
- **§6.2 `location_corroboration`, a new optional attachment (D12, spike
  S4).** The registry relays an operator-side CAMARA check of the declared
  position — `method` (`camara-location-verification`,
  `camara-number-verification`, `camara-sim-swap`; extensible), `result`
  (`match`, `no-match`, `unknown`; **not** extensible, it decides the level),
  `radius_m` (required for a zone check), `at`, an opaque `operator_ref` —
  signed with the log key over `"vcap/1.0/location" ‖ core_hash ‖ JCS(body)`.
  **No MSISDN enters a proof, ever**, in any form. A valid `match` under a
  trusted key reaches *corroborated*; the verifier MUST show it as *the
  registry attests that the operator confirmed the zone, radius R* — never
  "verified by the operator", because the operator's answer has no
  transportable signature and what travels is our countersignature. Same
  construction and same limit as `integrity`.
- **Failures land on `declared`, each with its §8 label**: *location
  corroboration not evaluated* (unknown method, no log key, nothing to
  corroborate — evidence this verifier cannot read; vectors 78, 84), *not
  verified* (a signature no trusted key made, which covers both an unknown
  signer and a genuine statement about another proof — the same bytes, as for
  `integrity`; vectors 76, 77), *evidence invalid* (a verified signature over
  a `result` outside the enumeration; vector 80, schema-invalid too),
  *location contradicted* (a verified `no-match`; vector 79). Plus *location
  claimed above evidence* and *location evidence not evaluated* for the
  claims a core can make that nothing here supports (81–83).
- **`authenticated` is reserved and unreachable**: no evidence kind is
  defined, no smartphone chipset exposes Galileo OSNMA as of September 2026,
  and a v1.0 verifier says so with the two labels above rather than letting
  *declared* stretch. Listed open in §11.
- `threat-model.md` §5.7: the threats against the declared position — a
  faked fix, a forged or transplanted corroboration, the **false accept with
  the SIM in the corroborated cell and a fabricated file**, the **SIM/device
  decoupling** (tethering, a moved SIM), a stale or coarse answer, a lying
  registry, no phone number in a proof — each with what the verifier says.
- Schema: `location` gains the three members, `location_corroboration` is
  added with `additionalProperties: false`, `expected.schema.json` gains
  `location`. `tools/src/location.ts` is the reference computation. An older
  verifier lists `location_corroboration` as *not evaluated* (§9) and reads
  the extended claim as it always did — the new members are inside the core
  it already hashes, and it never looked inside `location` beyond the keys.
- Vectors 36 and 47, which declare no position, now pin `location.level:
  none` in `expected.json`. Corpus: **84** vectors.

### Housekeeping: vector 51 is byte-stable, §11 catches up with the corpus

- **Vector 51 regenerated identically from now on.** Its registry leaf is
  about *another* key, and the generator minted that key with
  `generateKeyPairSync` on every run — so `npm run generate` rewrote
  `51/proof.json` and `51/input.jpg` each time while every other vector stayed
  still, which is the diff noise RFC 6979 signing was adopted to remove. The
  other key is now fixed test material, `TEST_OTHER_KEY_PKCS8_BASE64` in
  `tools/src/testkey.ts`, public like the two keys beside it: it is nobody's
  key and trusted by nobody, which is all the vector needs of it. The bytes of
  51 change once, here; its verdict and labels do not, and the reference
  verifier agrees with `expected.json` before and after.
- §11 listed the proof-level, `timestamp` and `anchor` vectors as still to
  come; they have existed since 41–45, 49–54, 55–58 and 59–63. The three
  items are ticked with the vector numbers, and no rule changed.

### EBSI as an anchoring chain (§6.2)

- §6.2 now names `ebsi` and `ebsi-pilot` as values of `anchor.chain`, for
  EBSI's Hyperledger Besu ledger, and says how a verifier reads it: through
  the Ledger API gateway `POST /ledger/v4/blockchains/besu`, a JSON-RPC proxy
  that forwards the read methods the anchor check needs — `eth_call`,
  `eth_getTransactionReceipt`, `eth_getLogs` — without any authorisation, plus
  the contract address published for that chain. Source: EBSI Ledger API v4,
  https://hub.ebsi.eu/apis/pilot/ledger/v4/post-blockchains-besu.
- No change to the wire format, the schema (`chain` is already an
  identifier) or any vector. Prose only, so no vector: a v1.0 verifier with
  no client for the chain reads the attachment as *anchoring not verified*,
  exactly as §6.2 already says.

### C2PA interoperability, the sidecar, stripped metadata (§3.1, §4.1, new document, vectors 68-73)

- `spec/c2pa-interop-1.0.md`, informative except where marked: what vcap and
  C2PA each prove that the other does not; the proof as one custom assertion,
  `com.gregoriogalante.vcap.proof`, a JSON box holding the payload bytes; the
  field-by-field mapping (`media.hash` against `c2pa.hash.data` /
  `c2pa.hash.boxes` / `c2pa.hash.bmff.v3`, the watermark against
  `c2pa.soft-binding`, whose algorithm list we are not on); and a table of
  what survives each transformation with the §8 verdict, with and without a
  sidecar. Cited to C2PA 2.4 by clause. We do not sign C2PA claims (R4), and
  the document says so first.
- **Co-existence, analysed against the C2PA text.** JPEG: §4.1's exclusion
  is symmetric — the proof is byte-identical whether the manifest was added
  after sealing (02) or present at it (**68**) — and the C2PA hard binding
  covers every byte to end of file, so once a manifest is written after the
  trailer, **rewriting the trailer breaks the manifest, not the proof**;
  attachments are a rewrite. ISO-BMFF: `c2pa.hash.bmff.v3` covers a trailing
  `free` box unless `/free` is on the exclusion list, which C2PA treats as
  ordinary; §4.1 said "BMFF hashing ignores the trailing `free` box", which
  was true only under that condition, and now says so. A manifest inserted
  into a sealed BMFF file is *tampered* (**73**). A C2PA **update** manifest
  must be the last box of the file, the position the footer needs: appended
  to a sealed file it hides the footer — *no proof found* (**69**), and
  *tampered* with a sidecar because the whole file is then hashed (**70**).
  Writers MUST NOT do either; a reader rule for stepping over such a box is
  listed open in §11.
- **§3.1 The sidecar**, normative, gathering what §3 said in one bullet and
  what the reference verifier already did: content is the payload bytes and
  nothing else; discovery is `<filename>.vcap` beside the file or a sidecar
  the caller supplies, never a search and never a fetch; precedence is
  trailer, then *corrupted* whatever the sidecar says (**72**), then the
  sidecar over the **whole** file, then *no proof found*; and a verdict from a
  sidecar carries no extra label and no less weight, because where a proof
  sat is not evidence (17). A sidecar over changed bytes is *tampered* and
  never "probably the same picture" (**71**, a stripped APP0).
- No change to the wire format, the schema or any existing vector's verdict.
  The reference verifier needed no change: every new vector is a consequence
  of rules it already implemented, which is what the six vectors show.
  `schema/README.md` now lists all six schema-invalid vectors (40 and 67
  were missing).

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

### The integrity slice, the last attachment (vectors 64-67, §6.2, §8)

- The reference verifier now checks `integrity`: the signature over
  `core_hash ‖ UTF-8(verdict)` under a trusted registry key, and that `source`
  and `verdict` are values §6.2 names. A valid attachment reads as
  **`integrity <verdict>`**; §8's table gains that row.
- **It changes no ceiling, and §6.2 now says why.** §7 takes the proven level
  from `attestation`, and the same rooted device that fails an integrity check
  also fails to produce a chain to a hardware root — counting it again would
  count one fact twice. Vector 65 pins `failed` as *authentic, and here is what
  Google said*, which is the vector most likely to be "fixed" by somebody who
  reads it as too lenient.
- **What the signature buys, and what it cannot.** The verdict is inside the
  signed message, so a verdict cannot be *strengthened*. It cannot buy the
  other direction: a relabelled attachment (vector 66) is indistinguishable
  from one signed by a registry the verifier does not follow, and an attacker
  suppressing a `failed` verdict could simply delete the attachment for the
  same answer. Something whose absence and whose invalidity are the same
  answer cannot be load-bearing — which is the reason this attachment has no
  row in §7's table, now written down rather than implied.
- Vector 67 is where *integrity evidence invalid* belongs: a verdict outside
  the enumeration, correctly signed. Present, readable and meaningless, and
  schema-invalid too — the two gates disagreeing about a proof would say the
  schema and the verifier disagree about the format.
- With this every attachment §6.2 defines has vectors behind it.

### The timestamp slice, and the last of §7 (vectors 59-63, §6.2, §8)

- The reference verifier now validates `timestamp.tsr`: CMS SignedData over
  TSTInfo, the imprint against `core_hash`, the `messageDigest` attribute, the
  signature over the attributes re-encoded as a `SET OF`, the signer's chain to
  a pinned TSA root at `genTime`, and the `timeStamping` extended key usage.
  §6.2 now lists those five checks normatively, each with the attack it stops.
- Five vectors: a valid token, a genuine token over **another proof's** core
  hash, one from a TSA nobody pinned, one whose signer has no `timeStamping`
  usage, and **vector 63** — vector 43's expired chain with a token added.
- **Vector 63 is why a timestamp is worth carrying.** Vector 43 shows
  *attestation chain expired, capture time not proven*; with a token the label
  is gone, because §7's table asks for that caveat only while the capture time
  is `time.device_clock` alone. The reference verifier showed it
  unconditionally — its own comment said otherwise — and `vcap-verifier` was
  already right, which is the first time the corpus has settled a disagreement
  in the shipping implementation's favour.
- The tokens and the test TSA root are **committed** (`vectors/_timestamps/`,
  `_trust/tsa-roots.pem`), minted by `tools/src/make-timestamp-tokens.ts`, for
  the reason the attestation chains are: a CMS signature is ECDSA. The
  generator refuses a token whose imprint is not the core hash it just built.
- §8's table gains *trusted time not evaluated*. No change to the wire format.

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
