# 137-jpeg-c2pa-assertion-redacted-uuid-box

Vector 136 with the second form of redaction C2PA 6.8 allows: the labelled assertion box is kept and its content replaced by a single UUID content box carrying the C2PA Redaction UUID (CAA98EEE-9D4D-F80E-86AD-4DFFCA263973) and zeros. No JSON content box, no proof: **no proof found**. Both forms read as absence (§3.2).

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): refused the file — `Error: required JUMBF box not found`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
