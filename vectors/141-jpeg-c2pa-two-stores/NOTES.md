# 141-jpeg-c2pa-two-stores

Vector 124 with its C2PA Manifest Store embedded twice, as two JUMBF APP11 boxes with different `En`. C2PA 15.5.2.1: with more than one embedded store, all are invalid and validation proceeds as if none were found. The reader does the same — no carrier (§3.2) — and with no footer and no sidecar the verdict is **no proof found**. A reader that took the first store would say *authentic*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): refused the file — `Error: more than one manifest store detected`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
