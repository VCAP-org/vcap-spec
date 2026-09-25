# Conformance vectors

One directory per case, numbered. Each has `expected.json` and `NOTES.md`, plus
its input:

| `kind` | Input | What it exercises |
|---|---|---|
| `file` | `input.<ext>`, optional `input.<ext>.vcap` sidecar, optional `input.c2pa` external C2PA store, `proof.json` for reading | trailer, canonical bytes, core signature, key binding, version policy, absence labels, Content Credentials as a carrier |
| `container` | `input.mp4` or `input.mov`, optional `input.mp4.vcap` sidecar, optional `input.c2pa`, `proof.json` for reading | everything `file` does **plus** §5: every GOP of the received container located by its vcap SEI and bound to a signed segment (*Locating segments*), and every located segment's `content_hash` recomputed from its NAL units and audio frames |
| `segments` | `segments.json` — `capture_id`, `pub`, `segment_count`, `segments[]` | the §5 chain at message level: content hashes given, no container |
| `jcs` | `core.json` | canonicalization: expected `core_bytes_hex` and `core_hash` |

`_timestamps/` holds the committed RFC 3161 tokens the timestamp vectors carry,
minted by `tools/src/make-timestamp-tokens.ts` — committed for the reason the
attestation chains are, and the generator refuses a token whose imprint is not
the core hash it just built.

The underscore directories are not vectors: `_media/` holds the unsealed
inputs, `_trust/` holds the anchors a verifier is assumed to hold while
checking this corpus (its README says what the substituted attestation root
does and does not prove), `_chains/` holds the committed attestation chains
(see below), and `_watermark/` holds the payload-layout fixtures — the worked
encoder cases, the `video-rep-v1` agreement floor and what a clip reports once
its sampled frames are decoded, which is decoder behaviour no numbered vector
can exercise because this repository ships no detector
(`_watermark/README.md`).

`expected.json` for `file` and `segments` vectors carries the fields a verifier
must reproduce: `outcome` (`authentic`, `verified_clip`, `frames_not_compared`, `tampered`,
`nested_proof`, `corrupted_proof`, `no_proof_found`, `unsupported_format_version`),
`labels` (the §8 labels, sorted), `not_evaluated` (unknown top-level keys,
sorted), `core_hash` (hex, when a core was read) and `segments.verified` (the
indexes that verified). `level` (§7: `claimed`, `proven`, `ceiling`) and `validated_at` (the instant
every certificate path was validated at, and what proved it) appear on the
vectors that carry attestation evidence. `location` (§7.1: `claimed`, the
level the core asks for, and `level`, the one the evidence reaches — `none`,
`declared`, `corroborated`, `authenticated`) appears on the position vectors
(74–84) and on 36 and 47, which declare no position and pin `none`.
`proof_source` (where the proof was read: `trailer`, `sidecar`, or `c2pa` with
the carrying manifest's label and its depth on the `parentOf` chain) and
`frames_name_capture` (whether a GOP of the file names the proof's capture)
appear on the carrier vectors (123–147), and are compared where present.
`debug`, where present, is for humans: intermediate bytes to compare before
touching signatures.

Two fields are **not** a verdict and a reader never compares them. `writer`
is for writer suites: `{"expect": "refuse", "error": "VCAP_C2PA_MANIFEST_PRESENT"}`
on the input a writer must refuse to seal (131), and `{"expect":
"not_covered"}` on every vector whose proof travels in a C2PA manifest, which
no vcap writer produces — a writer suite declares those NOT_COVERED. `c2pa`
is what a C2PA validator (c2pa-rs 0.91.0 through c2pa-node, trusting
`_trust/c2pa-test/root.pem`, OCSP off) reports about the file's Content
Credentials: the validation state and the active manifest's status codes, or
the error it refuses the file with. It is there so that nobody writes a C2PA
promise the library does not keep — c2pa-rs reports
`assertion.bmffHash.additionalExclusionsPresent` for `/free` and `/skip`, and
`signingCredential.ocsp.skipped` on every file — and each vector's `NOTES.md`
adds what c2patool 0.28.0 says.

`key_status`, where present, is also an **input**: §6.2's online revocation
answer, as the corpus declares a verifier is assumed to have fetched it. It has
to be an input, because the proof cannot carry the *absence* of a later
revocation leaf — nothing in a Merkle tree proves a leaf does not exist — so no
file on its own can reach green. A corpus that pretended otherwise would be
testing a verdict no verifier can reach.

`chain_read`, where present, is an **input** too: what a caller read from the
anchoring contract for that `anchor_id`. Absent means the chain was not
consulted, which is *anchoring not verified* — the offline half of an anchor
proves the path, never that the chain recorded it.

`verifier_clock`, where present, is an **input and not an expectation**: the
verifier's own clock in ms. A §7 verdict depends on it, because certificates
expire — an attested capture read a year later is a different question from the
same capture read the next day (vectors 41 and 43 differ in nothing else). A
vector that left the clock to the calendar would change its own answer over
time, which is the one thing a conformance vector must not do.

Expected verdicts are decided in review from the spec and written down first;
`tools/src/generate.ts` then produces the inputs and aborts if the reference
verifier in `tools/src/verify.ts` disagrees. **Never edit an `expected.json` to
make an implementation pass.** Either the implementation is wrong or the spec
is; fix that.

The test key in `tools/src/testkey.ts` is public by design: anyone can
regenerate the vectors. Next to it, `TEST_OTHER_KEY_PKCS8_BASE64` is a key
that is **nobody's** — not the signing key, not a trusted log — for the vectors
that need somebody else's key (51, a registry leaf about another device). Base media in `_media/` (a 16×16 JPEG, its HEIC, a two-frame
H.264 MP4) are the unsealed inputs.

**Regeneration is byte-stable.** `npm run generate` signs with RFC 6979
(deterministic `k`, derived from the key and the message), so a run that changes
nothing produces no diff — which is what makes a diff worth reading. It was not
always so: ECDSA's random `k` rewrote every signature on every run, and two
vector inputs were built from `randomBytes`, so their `media.hash` and
`core_hash` moved too. Forty changed files hide the one that was meant to
change.

**The attestation chains are committed, not generated.** `vectors/_chains/`
holds them and `tools/src/make-attestation-chains.ts` writes them on demand,
outside `npm run generate`. The reason is the one that exempts the container
vectors below: a certificate carries an ECDSA signature, so minting the chains
again produces different bytes and every attested vector would be rewritten on
every run for nothing. Run the script only to change what a chain *says*, and
expect the vectors that use it to change with it.

**The vectors that came off a device are the exception.** `npm run generate`
cannot make them — it has no camera and no device key — and it now owns only the
directories it declares, printing the ones it left alone. It used to delete
every numbered directory before rewriting, which for these was not a rewrite
but a loss. Two scripts rebuild them instead, each pointed at the artifacts a
device produced: `tools/src/derive-container-vectors.ts` for 36-39 (Android) and
`tools/src/derive-ios-vectors.ts` for 47-48 and 85 (iOS). That is what keeps the
edited cases (38, 39) auditable rather than asserted. The later edits of
those captures — 86-94, a stolen proof, a cut clip, reordered and duplicated
GOPs, a relabelled SEI — need no device: `npm run generate` derives them from
the committed 36 and 37 through `tools/src/remux.ts`, which rewrites sample
tables and leaves every device signature as it was.

They are not all the same weight of evidence, and each `NOTES.md` says which it
is. 36-39, 47 and 85 carry a **real device signature**: an implementation that
only ever meets this repository's test key never learns whether it can read a
real one, and 47 and 85 are the proofs here made by a Secure Enclave — 85 is
the only one where a Secure Enclave signed a **segment chain** and not just a
core. In 48 the **container** is the device's and every `content_hash` is
recomputed from it, but the chain over them is synthesized with the test key —
the iOS capture spike inserted vcap SEIs and had not yet sealed a video, so at the time
there was no iOS video signature to carry. 85 is that file, two days later:
same phone, `AVAssetWriter` again, and the chain its own.

## Running them

```
cd tools && npm ci && npm test        # every vector against the reference verifier
npm run generate                       # rewrite the vectors/NN-* it owns; byte-stable, see above
```

## Corpus version and manifest

The numbered corpus (`vectors/NN-*`) has its own version, in `vectors/VERSION`
— separate from `vcap/1.0`, the proof format version. The format version says
what a proof looks like; the corpus version says which exact vectors an
implementation checked itself against, so a third party can claim "conformant
with vcap-spec corpus 2.1.0" and mean something a consumer can check.

`vectors/MANIFEST.json` is that check: for every `vectors/NN-*` directory, its
`kind`, its `outcome`, and a SHA-256 over its files (name and length included,
so a renamed or truncated file changes the hash even if some other file's
bytes happen to collide); plus one hash per shared fixture directory
(`_media`, `_trust`, `_chains`, `_timestamps`, `_watermark`) so a change to an
input every vector depends on is as visible as a change to a vector itself. It
is generated, never hand-edited:

```
npm run manifest         # (re)writes vectors/MANIFEST.json from vectors/ and vectors/VERSION
npm run manifest:check   # exits 1 if the committed file is stale — CI runs this
```

`vectors/CONFORMANCE.md` says what the sentence "conformant with corpus
2.1.0" has to contain to be checkable — corpus version, manifest hash, and
how many vectors actually ran — and why a suite that ran zero vectors must be
red. `vectors/conformance-report.json` is this repository's own claim in that
format, regenerated and checked by CI (`npm run conformance:report` /
`conformance:check`).

**Bump policy**, the same additive-only rule as everywhere else in this
repository: a vector's hash never changes once published (`AGENTS.md`), so
`VERSION` only ever moves forward. Bump the minor version when vectors are
added, the patch version for a manifest-only regeneration triggered by
something outside `vectors/` (there is not expected to be one, since the
manifest is a pure function of the directory and `VERSION`). A major bump
would mean an existing vector's bytes moved — the one thing this corpus does
not do — so seeing one asks the same question a breaking spec change does.
**2.0.0 is one**, and the answer is in `CHANGELOG.md`: the review of
24 September 2026 changed verdicts the format had got wrong (a stolen proof
reading *verified clip*, a device clock reaching green) while the format is
still a draft, which is the one time §9 allows it. 2.1.0 is a minor again:
26 vectors added (122–147), none changed.

`vectors/edge-cases/` (below) is not in the manifest and not part of the
versioned corpus: it is regenerated on demand by its own tool, not hand-curated
and reviewed vector by vector, and nothing outside this repository reads it.

## The edge-case generator

`tools/src/generate-edge-cases.ts` produces `vectors/edge-cases/` — vectors a
review would not think to hand-pick one at a time, because they are the same
question asked at every point along a boundary: every offset a trailer can be
truncated at, every byte its magic can be flipped in, every field §6.1/§8
require that a writer could drop, the JCS corners RFC 8785 pins to
ECMAScript's own serialization (negative zero, a supplementary-plane
character, key sort by UTF-16 code unit), and the JPEG fill-byte run next to a
stripped JUMBF segment that exercises canonical.ts's marker walk one byte at a
time. Every case is deterministic — most are exhaustive sweeps over an
enumerated domain, so a seed changes nothing about them; the one case that
flips a single payload bit at a random offset takes `--seed` and picks the
same offset for the same seed. Every generated vector runs through the
reference verifier before being written, exactly as `generate.ts` does for the
numbered corpus, and the script aborts instead of writing a vector the
verifier disagrees with:

```
npm run generate:edge-cases              # seed 1
npm run generate:edge-cases -- --seed 7  # a different, still reproducible, draw
```

It does not exercise the watermark's BCH(255,131) correction radius: there is
no watermark decoder anywhere in this repository (`tools/src/verify.ts` ships
none, by design — see its file comment), so there is nothing here to hand a
marred payload to. That boundary belongs to whichever component owns the
decoder.

**The sidecar vectors** (17, 18, 70, 71, 72) carry `input.<ext>.vcap` next to
the input, and a verifier under test is handed both, as `tools/test/vectors.test.ts`
does. They pin §3.1: the trailer wins when it is found and intact (18), a broken
trailer is *corrupted* whatever the sidecar says (72), and a sidecar alone
restores the full verdict over unchanged bytes (17) and nothing over changed
ones (70, 71). **The C2PA co-existence vectors** (02, 03, 04, 68, 69, 73) carry
no C2PA signature — a JUMBF-shaped APP11 or a `uuid` box with the C2PA extended
type is all the vcap layer looks at — and pin §4.1's two orders, one per
container, and the update-manifest case that fits neither
(`spec/c2pa-interop-1.0.md` §3). Vector 122 is §4.1's narrowing in 1.1: a
JUMBF box that is not a C2PA store is content.

**The C2PA carrier vectors** (123–147) carry real Content Credentials:
manifests written by c2pa-rs 0.91.0 through `@contentauth/c2pa-node` 0.9.8 and
signed by *vcap-spec test CA* (`_trust/c2pa-test/`), a public test credential
no trust list carries. They pin `vcap-proof-1.0.md` §3.1–§3.2: where the store
is, which manifest and which assertion carry the proof, the precedence between
the trailer, the active manifest, the sidecar and the `parentOf` chain, and
the verdict at each depth. Some are edits no claim generator would make — a
salt removed, a type relabelled, a redacted box put back, a reference turned
into a cycle, a second store — so that a reader that cut the corner reaches a
different verdict; their `c2pa` block says how C2PA takes the edit.

They are **committed, not regenerated**, and `npm run generate` leaves them
alone. Everything `tools/src/make-c2pa-vectors.ts` controls is fixed: the vcap
proofs (the test key, RFC 6979), the C2PA signing key and certificate (keys in
`tools/src/testc2pakey.ts`), the claim signature (RFC 6979 through c2pa-node's
callback signer, so it is a function of the claim), the manifest labels and
instance IDs, no thumbnail and no time-stamp — no TSA is called, so nothing in
a manifest depends on a clock. What it cannot fix is the salt: c2pa-rs draws
16 random bytes per assertion from the OS (C2PA 8.4.2.3 asks for random
salts) and offers no hook, and each salt changes the claim and its
signature. Run the script only to change what a vector says, and expect all
of them to change with it; it writes nothing unless the reference verifier
agrees with every vector:

```
npm run generate:c2pa                                  # from tools/
C2PATOOL=/path/to/c2patool npm run generate:c2pa       # and record c2patool's answer in NOTES.md
npm run generate:c2pa -- --mint-ca                     # re-mint _trust/c2pa-test/ first
```

An implementation passes conformance when, for every directory, it produces
the same `outcome`, `labels`, `not_evaluated`, `core_hash`, `segments.verified`
and, where present, `level`, `validated_at`, `location`, `proof_source` and
`frames_name_capture` as `expected.json`, and the same `core_bytes_hex` for
`jcs` vectors. A runner hands the verifier every input the directory holds:
the sidecar, and a `*.c2pa` file as the caller-supplied C2PA store.

## Errata

A vector's bytes never change once it is published, `NOTES.md` included — its
digest is in `MANIFEST.json`, and five runners pin that manifest. So a note that
turns out to be wrong is corrected here, not in place.

- **85 · `85-mp4-container-ios-sealed`** — its note explains the five one-frame
  segments as VideoToolbox answering a forced keyframe with two IDRs. That is
  not what happened. The writer that produced this file forced a keyframe **and**
  left the encoder's own `MaxKeyFrameInterval` set on the same session, so the
  encoder's timer emitted a second keyframe one frame later, unaware that one had
  just been forced out of band. Measured against a four-minute recording: 229
  duplicated keyframes over 240 s, 465 segments where one-second groups predict
  about 236. The vector stays exactly as it is — a file shaped like this exists,
  and a reader has to handle it — but the cause belongs to that writer's
  configuration, not to Apple's encoder.

## Not here yet, and why

Every attachment §6.2 defines now has vectors: `attestation`,
`attestation_status`, `registry` with the online key status, `anchor`,
`timestamp`, `integrity` and `location_corroboration` (74–84, the position
level of §7.1: the full declared claim, a corroboration under the test log
key, one under nobody's key, one lifted from another proof, an unknown
method, a `no-match`, a result outside the enumeration, a claim of
`authenticated` with an evidence kind nobody implements, a claim of
`corroborated` with nothing behind it, an unknown claimed level, and a
corroboration of a `location` with no coordinates).

- **A position that reaches `authenticated`**: no evidence kind exists yet
  (§7.1, §11); the vector arrives with the first one.

- **Watermark-only match, cropped photo beyond the correction budget**:
  detector vectors, ML review.
- **A video trimmed by a third-party remuxer, with its proof in a sidecar**:
  the trailer is gone, the NAL units and vcap SEIs survive, and §5 reads
  *verified clip* over the whole received file. Vector 89 is the same cut made
  by this repository's own sample-table rewrite with the proof in the
  trailer; the case with another tool's output, whose `moov` and interleaving
  are its own, still wants that tool's file.
- **A C2PA manifest signed by a credential on the C2PA trust list**: the
  carrier vectors are *Trusted* only against the test root, and a trust-listed
  signer needs a legal entity (`spec/c2pa-interop-1.0.md`, *We do not sign*).
