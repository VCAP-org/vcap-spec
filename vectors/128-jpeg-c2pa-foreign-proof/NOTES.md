# 128-jpeg-c2pa-foreign-proof

A photo that is not vector 01's — one byte of entropy-coded data changed — with a manifest that carries vector 01's proof in its **active** manifest. Depth 0 reads like a sidecar (§3.2): the manifest presents the proof as this file's, the canonical bytes are not the ones the key sealed, and on a photo that is **tampered** (§8), the verdict of vector 71. The C2PA side is valid — its signer vouches for these bytes, not for the proof inside.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
