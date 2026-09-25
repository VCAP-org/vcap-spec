# 127-jpeg-c2pa-carrier-sidecar-differs

Vector 124 with a sidecar that holds vector 59's proof. With no footer the active manifest's proof outranks the sidecar (§3.1, step 4): it travelled inside the bytes it binds, as C2PA's embedded store outranks a remote one (15.5.2.1). The sidecar is compared with it as JCS and differs: **authentic** on the manifest's proof — vector 01's verdict — with *sidecar differs*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Invalid**; success: `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: `assertion.dataHash.mismatch`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
