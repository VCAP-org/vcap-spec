# 170-jpeg-c2pa-foreign-proof-sidecar-no-better

Vector 128 — a photo that is not vector 01's, with vector 01's proof in its active manifest — next to a sidecar that holds vector 59's proof: the same core with a time-stamp token, so it differs from the manifest's copy as JCS and binds the same pixels. Both proofs read *tampered* over these bytes. §3.1 step 4 lets a sidecar decide only when its outcome ranks **above** the manifest proof's; this one ties, so the depth-0 proof stands, with `proof_source` naming the manifest: **tampered**, vector 128's verdict. A red outcome carries no labels, *sidecar differs* included (§8).

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.27.16 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: none; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
