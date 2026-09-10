# Conformance vectors

One directory per case, numbered. Each has `expected.json` and `NOTES.md`, plus
its input:

| `kind` | Input | What it exercises |
|---|---|---|
| `file` | `input.<ext>`, optional `input.<ext>.vcap` sidecar, `proof.json` for reading | trailer, canonical bytes, core signature, key binding, version policy, absence labels |
| `container` | `input.mp4` or `input.mov`, `proof.json` for reading | everything `file` does **plus** §5: every present segment's `content_hash` recomputed from the NAL units and audio frames of the received container |
| `segments` | `segments.json` — `capture_id`, `pub`, `segment_count`, `segments[]` | the §5 chain at message level: content hashes given, no container |
| `jcs` | `core.json` | canonicalization: expected `core_bytes_hex` and `core_hash` |

Two directories are not vectors: `_media/` holds the unsealed inputs, and
`_trust/` holds the anchors a verifier is assumed to hold while checking this
corpus (its README says what the substituted attestation root does and does not
prove). `_chains/` holds the committed attestation chains — see below.

`expected.json` for `file` and `segments` vectors carries the fields a verifier
must reproduce: `outcome` (`authentic`, `verified_clip`, `tampered`,
`nested_proof`, `corrupted_proof`, `no_proof_found`, `unsupported_format_version`),
`labels` (the §8 labels, sorted), `not_evaluated` (unknown top-level keys,
sorted), `core_hash` (hex, when a core was read) and `segments.verified` (the
indexes that verified). `level` (§7: `claimed`, `proven`, `ceiling`) and `validated_at` (the instant
every certificate path was validated at, and what proved it) appear on the
vectors that carry attestation evidence. `debug`, where present, is for humans:
intermediate bytes to compare before touching signatures.

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
regenerate the vectors. Base media in `_media/` (a 16×16 JPEG, its HEIC, a two-frame
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
`tools/src/derive-ios-vectors.ts` for 47-48 (iOS). That is what keeps the edited
cases (38, 39) auditable rather than asserted.

They are not all the same weight of evidence, and each `NOTES.md` says which it
is. 36-39 and 47 carry a **real device signature**: an implementation that only
ever meets this repository's test key never learns whether it can read a real
one, and 47 is the only proof here made by a Secure Enclave. In 48 the
**container** is the device's and every `content_hash` is recomputed from it,
but the chain over them is synthesized with the test key — the S1 spike inserted
vcap SEIs and never sealed a video, so there was no iOS video signature to
carry.

## Running them

```
cd tools && npm ci && npm test        # every vector against the reference verifier
npm run generate                       # rewrite vectors/NN-* (signatures change: ECDSA is randomized)
```

An implementation passes conformance when, for every directory, it produces
the same `outcome`, `labels`, `not_evaluated`, `core_hash` and `segments.verified`
as `expected.json`, and the same `core_bytes_hex` for `jcs` vectors.

## Not here yet, and why

- **`timestamp` attachments**: after C8. The `anchor` slice is here (55-58).
- **Watermark-only match, cropped photo beyond the correction budget**:
  detector vectors, ML review.
