# 131-jpeg-c2pa-store-refused-for-sealing

An unsealed photo that already carries Content Credentials, with no proof in them. A **reader** finds no footer, no proof in the active manifest, nothing up the chain: **no proof found**.

A **writer** asked to seal it MUST refuse, error `VCAP_C2PA_MANIFEST_PRESENT` (`spec/c2pa-interop-1.0.md` §2.1): the store's `c2pa.hash.data` covers every byte after EOI, so appending a trailer breaks somebody else's signature. `expected.json` says so in `writer`. The pipeline that wants both seals first and writes the manifest afterwards (vector 123).

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
