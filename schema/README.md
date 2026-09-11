# Schema and validator

`vcap-proof-1.0.schema.json` (JSON Schema 2020-12) is the structural definition
of a `vcap/1.0` proof. It **gates writers**: a proof that fails it is not a
vcap/1.0 proof. It does not decide verdicts — a schema-valid proof can still be
tampered — and it does not model a verifier's tolerance of newer minors (§9):
unknown top-level keys pass, unknown keys inside known objects do not, because
a 1.0 writer has no business emitting them.

What it pins, beyond types: base64url lengths (16-byte ids, 32-byte hashes,
64-byte P1363 signatures, 91-byte P-256 SPKI), integer-only numbers in the
core, enum values of `platform`, `secure_hw`, `layout`, `level`, `source`,
`verdict`, and `media.segment_count` required whenever `segments` is present.

`expected.schema.json` is the shape of a vector's `expected.json`.

## Running it

From an implementation repository, in CI, over the proofs it produced:

```
cd <vcap-spec>/tools && npm ci
npm run validate -- path/to/proof.json [more.json …]     # exit 1 on the first invalid
```

Without arguments, `npm run validate` walks `vectors/`: every `expected.json`
must be well formed, and every `proof.json` must be schema-valid exactly when
its vector says so (`schema_valid`). Six vectors are schema-invalid on
purpose — DER signature (13), major 2 (16), missing `capture_id` (21), a float
in the core (22), an unknown `secure_hw` (40), an `integrity.verdict` outside
the enumeration (67) — and the generator refuses to write a vector whose review
verdict and schema verdict disagree.

Programmatic use: `validateProof(json)` in `tools/src/schema.ts` returns
`{ valid, errors }` with JSON pointers and messages, never values.
