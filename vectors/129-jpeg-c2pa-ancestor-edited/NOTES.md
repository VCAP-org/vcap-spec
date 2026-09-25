# 129-jpeg-c2pa-ancestor-edited

An edit of vector 123, declared: its active manifest opens vector 123 as `parentOf`, records `c2pa.edited`, and carries no proof of its own; vector 123's manifest travels in the store as the ingredient's. No footer, no proof at depth 0, no sidecar: the proof is found one step up the `parentOf` chain (§3.2, depth 1), and it is the proof of the **source** capture.

The pixels are not the source's, and nothing locates the source in them, so the outcome is **no proof found**, reason *Content Credentials carry the proof of a source capture*, with `proof_source` at depth 1 — **never tampered**: a modification declared in C2PA is not an accusation the proof can make. Vector 130 is the same file with the proof beside it.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
