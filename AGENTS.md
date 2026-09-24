# Agent instructions — vcap-spec

Normative format specification. Changes here propagate to every implementation,
so treat every edit as a breaking change and record it as one in `CHANGELOG.md`.
The format is **not frozen** and no version has been released (`vcap/1.0` is
the format identifier, not a release): the additive-only rule of §9 binds at
the first build, SDK or sealed file that reaches somebody else. `CHANGELOG.md` is the authority.

## What lives here

- `spec/threat-model.md` — what the format defends against,
  what it does not, and the residual risk of each threat. Public. Every
  mitigation it names points at a spec section or a component; every accepted
  risk must be something the verifier UI says.
- `spec/vcap-proof-1.0.md` — the normative document. The six format decisions
  are settled; §11 lists the follow-ups that remain, each of them evidence to
  collect or a value in a field §9 declares extensible.
- `spec/watermark-layouts-1.0.md` — the payload layouts `watermark.layout`
  names; normative for the bit layout and the decoder's failure answer.
- `spec/watermark-robustness-1.0.md` — the measured curve of the published
  model: where the payload comes back, where it stops, what quantization
  costs, what a browser pays per frame, what the detector returns from content
  that was never marked, and an explicit list of what was not measured (a
  false-positive rate on real photographic content at volume above all).
  Informative. Every number
  carries its corpus; a number without its conditions does not go in.
- `spec/c2pa-interop-1.0.md` — what vcap and C2PA each prove, the mapping onto
  C2PA assertions, how the two bindings co-exist in one file, the sidecar's
  rationale and what survives each transformation. Informative except where
  marked, and every marked sentence has a vector.
- `spec/vcap-vault-1.md` — separate encrypted storage envelope draft, not a
  proof-format revision. Offline decoder in `tools/src/vault/`; public test-only
  keys and deterministic interoperability vectors in `tools/test/vault-vectors/`.
  Decryption never establishes a proof verdict.
- `reviews/` — historical review notes (cryptographic, implementability).
  Findings are graded BLOCKING / SHOULD / NOTE; the spec absorbed them and is
  authoritative. Do not update a review to match the spec.
- `schema/` — JSON Schema plus a validator runnable from CI, including the
  shape of a published conformance report.
- `vectors/` — one directory per case, each with the input, the proof and the
  expected verdict in `expected.json`. Format and rules in `vectors/README.md`.
- `tools/` — the reference verifier and the vector generator. The verifier is
  written from the spec to prove the vectors consistent; it is not the
  implementation others copy. When it disagrees with an expected verdict, the
  review decides which one is wrong — the generator refuses to write a vector
  the verifier fails.
  `tools/corpus-drift.sh` is the one exception to "tooling that runs here": it
  runs in the **consumers**, delivered by the submodule, and tells them when
  their pin has fallen behind this repository's main. It lives here because
  three copies of a drift detector are three things that can drift. Nothing in
  this repository runs it, and inside a development checkout of vcap-spec it
  finds no `conformance-pin.json` and skips.

## Working rules

- Never change an existing vector's expected verdict to make an implementation
  pass. Either the implementation is wrong, or the spec is — fix that instead.
- Every normative statement needs a vector. A rule with no vector is a comment.
- Canonicalization (JCS) and the canonical-bytes rule are the two places where
  independent implementations diverge first: they need a vector per container
  format (JPEG, HEIC, MP4, MOV).
- Once the format reaches somebody else (first build, first SDK, first sealed
  file out of our hands): additive changes only, minor version bump, and a
  changelog entry saying what a verifier that predates a new field does when
  it meets it.
  Before that a breaking change is allowed, and `CHANGELOG.md` says it broke.

## Commands

Node 22 (`.nvmrc`), from `tools/`. CI (`.github/workflows/ci.yml`) runs, in order:

```
npm ci
npm run typecheck
npm test                     # vitest: vectors, vault, watermark layouts, conformance docs vs corpus
npm run validate             # every vector's proof.json / expected.json against the schema
npm run manifest:check       # vectors/MANIFEST.json matches vectors/
npm run conformance:check    # conformance report: corpus version, manifest hash, vector count
npm run generate:edge-cases  # edge-case generator still agrees with the reference verifier
```

## Project rules

Product invariants, naming, definition of done, language and license are in
`README.md`; they bind here too.

## Public repository

Never name private repositories, internal decision codes or internal document
paths. Frozen vector notes, and `tools/src/derive-ios-vectors.ts` that
reproduces them byte for byte, are the only exception and are not edited.
