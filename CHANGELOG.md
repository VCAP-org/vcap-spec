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

### `media.presentation` required — corpus 4.0.0 → **5.0.0**

**Breaking.** §5 *Presentation*, §6.1, §8: `media.presentation` is a
**required** core field of every proof that carries `segments`, so of every
video proof (`media.mime` `video/…` already requires `segments`). Absent →
the proof is not well formed: **no proof found**, the outcome §8 gives any
missing required core field (`media.segment_count`, `segments`, `media.w`),
reached before the signature is read. The schema requires it in both
conditionals (`segments` present, `media.mime` `video/…`).

Before: required of writers and optional to readers. An original without it
read *authentic* and every clip of it *frames not compared*, *presentation
not bound*. A core is signed once and attached to every file cut from it, so a
field a clip depends on cannot be optional to the original; and an optional
field is one a writer can leave out without any verifier noticing on the
file it tests. The **label *presentation not bound* is removed**: no proof
that reaches the clip branch can lack the field. *tracks not bound* and
*presentation differs* are unchanged.

Corpus 5.0.0 (168 vectors). No backward compatibility: the device captures
are not re-signed and carry no fallback.

- **Changed verdicts, bytes kept**: 36, 37, 48, 85 (*authentic* → *no proof
  found*, `schema_valid` false) — device proofs that predate the field; 145,
  147 (*no proof found*, now for the missing field: `core_hash` and
  `frames_name_capture` dropped) and 146 (*tampered* → *no proof found*) — C2PA
  vectors carrying 36's proof. Their notes are corrected in the errata
  (`vectors/README.md`), not in place.
- **Moved bytes, re-signed**: 38, 39, 86–94 and 156, the edits
  `npm run generate` derives from 36 and 37, now under a core and segment
  chain re-signed with the test key over the device's capture id and content
  hashes, with the presentation read back from the device's container. 89
  and 94 go back to **verified clip** (1–2 of 3, and 0–2); every other
  verdict is unchanged. `derive-container-vectors.ts` now writes 36 and 37
  only; 38 and 39 moved to `generate.ts`.
- **Moved bytes, gained the field**: 33 and 34 (verdicts unchanged); 143 and
  144 re-sealed with 33's new proof over their committed Content Credentials
  — the manifests are the same bytes, so `c2pa` and the notes stand.
  `make-c2pa-vectors.ts` gained `--only` for the next run that needs one.
- **New**: 165 (a video proof signed without the field → *no proof found*),
  166–168 (the containers of 36, 48 and 85 under a re-signed core that
  carries it → *authentic*, every segment recomputed).

**What a verifier that predates 5.0.0 does**: it reads 36, 37, 48, 85 and 165
*authentic* and 146 *tampered* — it has not learned the field is required —
fails 89 and 94 (it says *frames not compared*, *presentation not bound*, for
*verified clip*), and fails the moved vectors' `core_hash`.

### Writer requirements: what muxers actually write

Text only, no corpus change. §5 *Presentation* said either muxer "may add
`colr` or `pasp`"; it now says what was measured — `MediaMuxer` writes a
`colr` (`nclx`) and no `pasp`, macOS `AVAssetWriter` writes `fiel`/`chrm` and
neither — and that the writer reads back whichever of `clap`/`pasp`/`colr` are
there. Erratum for vector 158's note (`vectors/README.md`).

### Verdict hardening and presentation binding — corpus 3.1.0 → **4.0.0**

**Breaking.** A major corpus bump: the attestation chains were minted again
(every committed chain lacked `origin`), so the 26 attested vectors moved
bytes and none changed its verdict; vector 54's `key_status` input changed;
`_trust/logs.json` gained a second trusted log; 89, 94 and 145 changed
verdict (below); 152–164 are new (164 in all).
Six verdict rules changed. Five closed a verdict both the reference verifier
and the published one gave too generously; one aligned the two where they
disagreed:

- **§7 rule 6: an imported key proves no level** (vector 152). The
  hardware-enforced `origin` (tag 702) MUST be `GENERATED`; absent,
  `IMPORTED` or `SECURELY_IMPORTED` → proven level `none`, *origin not
  hardware-attested* alone, like an unlocked boot (a genuine chain that
  proves too little, not *evidence invalid*). Before: a key imported into the
  TEE read `tee` with a verified boot, and could reach green while whoever
  imported it kept the private key. `threat-model.md` §5.2 said `origin` was
  checked; nothing checked it.
- **§6.2 *Revocation, online*: the device clock never dates the question**
  (vectors 54, 155). The log is asked about the proven instant only when a
  valid token or a verified anchor proved it; otherwise about the verifier's
  own clock. Revoked there → *key revoked*, **red**. Before: the verifier
  asked about `time.device_clock`, which the holder of a stolen key revoked
  for a non-retroactive reason sets before the revocation, and the verdict
  was amber where it should be red. The same rule `attestation_status`
  already applied to the chain (vector 96). A key valid at the verifier's
  clock was valid at any earlier instant, so vector 54 keeps its verdict.
- **§6.2 `integrity`: a source proves only its own platform** (vector 153).
  `playIntegrity` `hardware` proves device integrity on an `android` proof
  and nothing on any other. Before: a Play Integrity verdict relayed beside an
  iOS proof made it **green**, against "no iOS capture is green in this
  version".
- **§6.2 *Which key*: the log the `registry` attachment names, and no other**
  (vector 154). When a `registry` attachment names a trusted log, its key
  alone verifies `attestation_status`, `integrity`, `location_corroboration`
  and the online key status. Before: the text said so and both
  implementations tried every trusted key, so a second trusted log could
  supply the integrity verdict for a device the first one admitted. A
  `registry` naming a log the verifier does not trust names nothing, and
  every trusted key is tried as before — such a proof is never green (vector
  52 unchanged).
- **§5: an edit list with more than one edit is not recomputed over**
  (vector 156). Leading empty edits and one rate-1 media edit are the
  timeline §5 models; anything after that edit on the video or audio track →
  no segment located, *segment content not recomputed*, *frames not
  compared* over a file that is not the original. Before: only the first
  media edit was read, so a re-mux that reordered presentation with the
  samples untouched read **verified clip**. Originals are unaffected:
  `media.hash` covers the edit list.

- **§7 *Claimed above proven*: a chain that holds and proves `none` is
  evidence** (vector 157). A device claiming `tee` beside a genuine chain
  that proves `none` (unlocked boot, imported key, `software`) is
  *inconsistent claim*, measured against the level before revocation. The
  published verifier did this and the reference verifier did not; the text
  said neither. Vector 152 hid it: its registry leaf raised the same label.
  The same chains now have their revocation and app checked in both
  implementations (§6.2 *Revoked*, vector 164): a revoked certificate is
  evidence against the file, so a chain that proves `none` and is revoked is
  red, where the reference verifier read amber.
- **§5 *Presentation*, §6.1 `media.presentation`: a clip is verified only
  where the core binds how its frames are shown** (vectors 158–163). New core
  member for video, required of writers: `config` (SHA-256 over the decoder
  configuration's parameter sets in NAL-type order, then `clap`, `pasp`,
  `colr`), `matrix` (the video `tkhd` matrix, nine `int32` as stored) and
  `display` (`tkhd` width and height, `uint32` as stored); plus a track
  layout rule — one `vide`, at most one `soun`, one sample description each,
  every other track disabled. A file that is not the original with the field
  absent, the layout broken or a value different → *frames not compared*,
  *presentation not bound* / *tracks not bound* / *presentation differs*, no
  segment credited. On an original a value that differs is the writer's false
  claim: *presentation differs*, amber. Before: a re-mux keeping every sample
  could rotate the matrix, edit the out-of-band SPS (crop, VUI colour) or add
  an enabled track and still read *verified clip*. Photos: nothing, since
  `media.hash` covers every byte.
  - **Changed verdicts**: 89 and 94 (*verified clip* → *frames not
    compared*, *presentation not bound*: their device proofs cannot gain the
    field) and 145 (*verified clip* at depth 1 → *no proof found*,
    `SOURCE_CAPTURE`; its `NOTES.md` is corrected in the errata, not in
    place). Originals 36, 37, 47, 48, 85 are unchanged.
  - **Writers**: compute the field from the file the muxer produced, before
    the trailer (§5 *Writer requirements*). The schema accepts it and does
    not yet require it.

**What a verifier that predates 4.0.0 does**: it passes the 26 moved
vectors once it loads the new `_trust/` (the attestation root changed), and
fails the new ones — 152–154 green, 155 amber, 156 and 160–162 *verified
clip*, 157 without *inconsistent claim*, 164 red where the old reference verifier
read it amber — and 89, 94 and 145, which it reads
as *verified clip*. It ignores `media.presentation`'s meaning but hashes it
with the core (JCS covers every member), so 158–163 still verify their
signatures.

### `location.source: fused` — corpus 3.0.0 → **3.1.0**

A minor corpus bump: vector 151 is new (151 in all), no existing vector
changed a byte.

- **§6.1: `source` gains `fused`** — the OS combined its sources and did not
  say which (Android's fused provider; iOS CoreLocation, always). The other
  values are described: `gnss` satellites, `network` Wi-Fi or cell, `manual`
  typed by a person.
- **Writer rule**: a writer that knows how the fix was obtained SHOULD say so,
  and MUST NOT name a source the OS did not report; `fused` when it combined
  them, absence when it said nothing.
- **Why**: until now iOS never carried a `source` and Android dropped it for
  fused fixes, so most real positions said nothing about how they were taken.
  `acc_cm` already carries the precision the OS reported, approximate
  permissions included (kilometres).
- **What a verifier that predates 3.1.0 does**: `source` is extensible (§9),
  so it reads a declared position exactly as before and shows `fused` as an
  unknown source string. No level or ceiling moves.

### Device integrity is a condition for green — corpus 2.1.0 → **3.0.0**

**Breaking.** A major corpus bump: vector 100 changed bytes, 20 expected
verdicts changed, vector 110 went from green to amber, and 148–150 are new
(150 in all).

**Why.** A registry-signed `integrity: failed` capped the ceiling at amber,
and its absence capped nothing. The attachment is outside the core, so
deleting it leaves every other signature intact: whoever held a copy of a
`failed` capture could turn amber into green by stripping the evidence against
it (vectors 109 and 100 differed in nothing else). The 2026-09-24 review chose
"absence caps nothing" to avoid the server being needed for green; the
registry already is (*key not in transparency log* is amber), so that price
bought nothing and cost the one direction that matters.

**The rule (`vcap-proof-1.0.md` §6.2, §7, §8)**

- **Green requires proven device integrity**: a valid `integrity` attachment
  with `source: playIntegrity` and verdict `hardware`. Absent, unknown
  source, untrusted signer, `basic`, `unevaluated`, `failed`, or any
  `appAttest` verdict → **amber**.
- **New label *integrity not proven***, beside a proven level only (without
  one the verdict is already amber for *origin not hardware-attested*, and a
  revoked chain proves no level). A valid `failed` is still *integrity
  failed*, shown prominently, alongside it.
- **`hardware` is defined**: the source attested the device's software state
  from a hardware root. Play Integrity `MEETS_STRONG_INTEGRITY` → `hardware`;
  `MEETS_DEVICE_INTEGRITY` / `MEETS_BASIC_INTEGRITY` → `basic`; no label →
  `failed`. A registry MUST NOT relay `appAttest` as `hardware` (Apple says
  nothing about a jailbreak): App Store / TestFlight assertion → `basic`.
- **iOS is amber at best**: the `secureEnclave` row of §7 is amber in this
  version. A future iOS device-integrity source arrives as a new `source`
  value with its vectors.
- **Consequence stated**: a capture sealed offline is amber until it is sent
  and the registry relays a `hardware` verdict for it.

**Vectors**

- **100** gains an `integrity` attachment (`playIntegrity`, `hardware`) and
  stays the corpus's green; its bytes moved.
- **148** (new) is the old 100: no `integrity`, amber, *integrity not proven*.
  It is also 109 with the `failed` statement deleted — the case this change
  closes.
- **149** (new): `playIntegrity` `basic` → amber.
- **150** (new): iOS with an `appAttest` statement mislabelled `hardware` →
  amber; the rule is the verifier's, not the registry's good behaviour.
- **110**: green → amber, *integrity not proven*.
- **41–43, 45, 49–54, 63, 98, 99, 101, 102, 106, 107, 109**: expected labels
  gain *integrity not proven*; ceilings unchanged (all amber already).
- Notes that described a vector as "vector 100 with …" and carry no
  integrity now say "vector 148 with …".

**What a verifier that predates 3.0.0 does**: it shows green for a capture
with a proven level and no `hardware` integrity statement (vectors 148, 149,
150, 110), and never shows *integrity not proven*. There is no fallback, under
the no-backward-compatibility decision of 22 September 2026 above.

### Content Credentials as a carrier — corpus 2.0.0 → **2.1.0**

A minor corpus bump: 26 vectors are new (122–147), 147 in all, and no
existing vector changed a byte. `vectors/_trust/` gains `c2pa-test/`, so the
`_trust` fixture hash in `MANIFEST.json` moves.

**Reading the proof (`vcap-proof-1.0.md` §3.1–§3.2)**

- **New, §3.2: a C2PA Manifest Store carries the proof** as the assertion
  `io.github.vcap-org.vcap.proof`. Where the store is (JPEG APP11 groups
  reassembled by `En`/`Z`; ISO-BMFF top-level C2PA `uuid` boxes of purpose
  `manifest`, `original` or `update`, 8-byte offset skipped; a `.c2pa` store
  the caller hands over, only when none is embedded, never fetched); which
  manifests (`c2ma`, `c2um`, legacy `c2md`; `c2cm` not read; the active one is
  the last); which assertion (listed by its own claim, labelled exactly, JSON
  box, toggles `0x03` or `0x13`; `__n` ignored; both redaction forms of C2PA
  6.8 are absence); the chain (the one `parentOf` ingredient, depth 1–16, no
  revisits; `componentOf` and `inputTo` never). More than one embedded store —
  an `original` beside an `update` included — is no carrier (C2PA 15.5.2.1).
  Nothing about the manifest is checked: the proof authenticates itself.
- **Precedence** (§3.1, rewritten in five steps): valid footer and CRC → the
  trailer, with the sidecar compared as bytes and the active manifest's copy
  as `JCS(parse(a)) == JCS(parse(b))`; CRC fails → *corrupted proof*, whatever
  the store; `VCAP` with major ≠ 1 → *unsupported*; no footer → the active
  manifest's proof (depth 0), then the sidecar, then the nearest `parentOf`
  ancestor's proof (depth 1–16).
- **Verdict with a carried proof.** Depth 0 reads exactly as a sidecar. Depth
  ≥ 1 is a source capture's proof: *authentic* and *verified clip* stand,
  and where §4–§8 give *tampered* or *frames not compared* the outcome is
  *no proof found*, reason *Content Credentials carry the proof of a source
  capture*.
- **New label *manifest copy differs***, a warning beside *sidecar differs*.
- **New verdict fields**, diagnostics and never labels: `proof_source`
  (`{kind: "trailer"}`, `{kind: "sidecar"}`, `{kind: "c2pa", manifest,
  depth}`) and `frames_name_capture` (a GOP of the file has a vcap SEI naming
  the capture: a locating hint, not evidence).
- **What a verifier that predates 1.1 does**: it ignores Content Credentials.
  It answers *no proof found* wherever the carrier is the only copy, uses the
  sidecar where there is one, never shows *manifest copy differs*, and
  returns the same verdict wherever the trailer is intact — except on vector
  122, which it reads *authentic* (§4.1 below).

**Canonical bytes (§4.1)**

- **Breaking, narrow. The JPEG exclusion covers the C2PA store only.** A
  JUMBF APP11 segment is removed only when its box is a C2PA Manifest Store
  or its type cannot be read; a JUMBF box of any other type (JPEG 360, JPEG
  Privacy and Security) is content, as C2PA hashes it (15.12.1.2). Before,
  every `JP` segment was removed, so a JPEG 360 box added to a sealed photo
  left it *authentic* while C2PA's binding broke (vector 122). A JPEG sealed
  with such a box present reads *tampered* under 1.1; none exists outside
  this repository. Vectors 02 and 68, whose JUMBF-shaped segment has no
  readable type, keep their verdict. Every canonicalizer changes: the SDKs
  that seal JPEG and every verifier.

**`c2pa-interop-1.0.md` → 1.1** (file name kept: frozen vector notes cite it)

- **§2.1**: the assertion's box (JSON content type
  `6A736F6E-0011-0010-8000-00AA00389B71`, toggles `0x03`/`0x13`), one
  instance, copies compared as JCS because c2pa-rs re-serializes the JSON,
  both redaction forms read as absence. **Normative**: the assertion goes in
  `gathered_assertions` unless the claim generator ran the seal. **Normative
  writer rules**: a vcap writer MUST NOT seal a JPEG that already embeds a
  C2PA store (`VCAP_C2PA_MANIFEST_PRESENT`, vector 131); J1 — a writer that
  replaces the trailer of a JPEG under a store MUST re-issue the manifest or
  strip the store (vector 125).
- **§2.3**: the soft binding's value, informative: the decoded payload (16
  bytes of `capture_id`, or 3 bytes of `mark_id` big-endian), one `alg` per
  layout, no `alg-params`, no `bindingMetadata`, `c2pa.watermarked.unbound`
  until the algorithm is on the list.
- **§3.1 corrected**: 15.12.1.2 says C2PA **hashes** non-C2PA APP11 segments;
  1.0 read it as excluding them.
- **§3.4 corrected**: on video the trailer is a `free` box the C2PA hash
  excludes, not inside it, as §3.2 already said.
- **§6**: any future reader rule for a trailing update box first normalizes
  `box_purpose`, which C2PA rewrites from `manifest` to `original` inside
  `media.hash`.

**Vectors and tooling**

- **122** (generated): a non-C2PA JUMBF box added after sealing → *tampered*.
- **123–147** (minted, committed): real C2PA manifests over sealed and
  unsealed JPEG and MP4 — carrier after sealing, trailer cut, copy differing,
  CRC broken, sidecar beside the carrier, foreign proof at depth 0, edited
  ancestor with and without a sidecar, the writer's refusal, an external
  store, the assertion unsalted, a legacy manifest type, a suffixed label,
  both redaction forms, a compressed manifest, a cycle, a component only, two
  stores, an assertion no claim lists, `/free` excluded and hashed, a clip
  through `parentOf`, a clip with a replaced GOP, a re-encoded clip. Signed by
  a public test credential, *vcap-spec test CA* (`vectors/_trust/c2pa-test/`,
  keys in `tools/src/testc2pakey.ts`), with c2pa-rs 0.91.0 through
  `@contentauth/c2pa-node` 0.9.8, a new devDependency used only to mint them.
  They are committed, not regenerated: c2pa-rs salts every assertion from the
  OS RNG. `tools/src/make-c2pa-vectors.ts` mints them, and refuses to write
  one the reference verifier disagrees with.
- **`expected.json`** gains `proof_source` and `frames_name_capture`
  (compared where present), `writer` (for writer suites: `refuse` with the
  error code, or `not_covered`) and `c2pa` (what c2pa-rs reports; never
  compared). A `*.c2pa` file in a vector directory is the external store
  handed to the verifier.
- **Reference tooling**: the carrier reader (`tools/src/jumbf.ts`,
  `cbor.ts`, `carrier.ts`, `extractProof`), structure only, with hostile-input
  tests (`tools/test/carrier.test.ts`).

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
