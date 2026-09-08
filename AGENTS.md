# Agent instructions — vcap-spec

Normative format specification. Changes here propagate to every implementation:
treat every edit as a breaking change until `vcap/1.0` is tagged.

## What lives here

- `spec/vcap-proof-1.0.md` — the normative document. Sections marked `TODO` are
  the six format decisions still open (see the work order in
  `Doc/06-fase1-avvio.md` section 3).
- `schema/` — JSON Schema plus a validator runnable from CI.
- `vectors/` — one directory per case, each with the input, the proof and the
  expected verdict in `expected.json`.

## Working rules

- Never change an existing vector's expected verdict to make an implementation
  pass. Either the implementation is wrong, or the spec is — fix that instead.
- Every normative statement needs a vector. A rule with no vector is a comment.
- Canonicalization (JCS) and the canonical-bytes rule are the two places where
  independent implementations diverge first: they need a vector per container
  format (JPEG, HEIC, MP4, MOV).
- After the freeze: additive changes only, minor version bump, and a changelog
  entry saying what a v1.0 verifier does when it meets the new field.

## Product invariants

These hold for every line of code in every repository:

- **The verification path never contains one of our servers.** If a component
  becomes necessary to produce a verdict, that is a design error.
- **Server registration is always optional**: capturing and verifying work with
  no account and no network.
- **A watermark alone is never a green verdict**: without a valid signature it is
  "origin traced", not "authentic".
- **A missing field yields a weaker verdict, not an error**: no timestamp means
  "no trusted time", and the verifier says so.
- Failures are published alongside successes.
- Location is never "guaranteed": the reached level is declared
  (declared, corroborated, authenticated).

## Naming

`vcap` (verified capture) is the internal codename and the only name allowed in
identifiers: package names, bundle ids, trailer magic, proof version string,
database schemas, log prefixes. The product brand is provisional and must never
appear in anything expensive to rename — it lives only in UI strings (single
localization file) and store metadata. Full table in the workspace `AGENT.md`.

## Definition of done

In main, tested, conformance vectors passing in CI, and documented where the next
person needs it. Not "works on my branch".

## Language

Code, comments, README and commit messages in English. Project documentation in
`Doc/` is in Italian.
