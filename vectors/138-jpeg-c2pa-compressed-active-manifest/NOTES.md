# 138-jpeg-c2pa-compressed-active-manifest

Vector 124 with its active manifest typed `c2cm` — a compressed manifest (C2PA 11.2.4), whose content is a Brotli `brob` box. It is not one here: the type was relabelled over an uncompressed manifest so that a reader that ignored the type would find the proof. A compressed manifest is not read in this version (§3.2): no proof in it, no chain through it. **No proof found**.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): refused the file — `Error: C2PA provenance not found in XMP`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
