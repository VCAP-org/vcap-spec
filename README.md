# vcap-spec

Normative specification of the **vcap proof format**, plus the conformance test
vectors and the JSON Schema validator every implementation runs in CI.

This repository blocks every other one: two native sealing cores, a React Native
bridge, a web capture SDK and four verifiers must agree byte for byte.

## Status

Phase 1. **`vcap/1.0` is frozen** — tag `v1.0`, 9 September 2026. From here the
format only ever grows by addition (spec §9); every change lands through
`CHANGELOG.md` with its vectors and the fallback for an older verifier.

## Layout

```
spec/      the specification document (normative), the watermark payload
           layouts (normative), the measured watermark robustness curve
           (informative: where the mark holds, where it breaks, what was not
           measured), the C2PA interoperability and sidecar companion
           (informative, with the writer rules it pins) and the public threat model
reviews/   review notes on the draft (crypto, implementability), numbered; the spec absorbs them, they stay as record
schema/    JSON Schema of the proof + validator
vectors/   conformance vectors: sealed files, broken signatures, edge cases (see vectors/README.md),
           the versioned corpus manifest and how to claim conformance against it (vectors/CONFORMANCE.md)
tools/     reference tooling (Node 22, TypeScript): JCS, trailer, canonical bytes, core signature,
           segment chain, the vector generator and the reference verifier CI runs over vectors/
```

## Rules

- **Test vectors are written before the code that produces them.** A vector
  carries its expected verdict, decided in review, not derived from an
  implementation's output.
- An independent implementation must be writable from the spec alone. If someone
  has to ask the author, the spec is not finished.
- No product brand anywhere in the format: trailer magic is
  `"VCAP" + uint8 major + uint8 minor + uint16 flags`, version string is
  `vcap/1.0`, sidecar extension is `.vcap`. Sealed files are immutable; the brand
  is provisional.

## Project documentation

This repository is code only. Plan, specification, decisions and market context
live in the project workspace, outside this repo:

- `Doc/01-piattaforma-build-spec.md` — components, epics, estimates, sequence
- `Doc/05-decisioni.md` — decision log (read before proposing an architectural change)
- `Doc/06-fase1-avvio.md` — phase 1 work order
- `AGENT.md` — workspace rules, naming conventions, product invariants
- `CHECKLIST.md` — the single work list; tick your line in the same commit

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

## License

MIT, for everything in this repository: the specification text, the threat
model, the schema, the vectors and the tools (`LICENSE`). A specification is
worth what it can be implemented into, and the conformance vectors are meant to
live inside other people's test suites. The copyright holder is "the vcap
authors" until decision D1 names the legal entity.

