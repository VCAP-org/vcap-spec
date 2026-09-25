# 126-jpeg-c2pa-carrier-footer-crc-mismatch

Vector 06 — a structurally valid footer whose CRC does not match — with Content Credentials written over it that carry an intact copy of the proof. **Corrupted proof**, whatever the store holds (§3.1, step 2), exactly as vector 72 is with an intact sidecar: the carrier is a fallback for a trailer that is absent, never a substitute for one that was found and is broken.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
