# 130-jpeg-c2pa-ancestor-edited-sidecar

Vector 129 with vector 01's proof in a sidecar. The sidecar outranks the `parentOf` chain (§3.1, step 4): it is presented as **this** file's proof, and this file is not the one the key sealed — **tampered**, as vector 71. Beside vector 129 it pins the order: a reader that consulted the chain before the sidecar would say *no proof found*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
