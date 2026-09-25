# 140-jpeg-c2pa-component-only

The unsealed photo with Content Credentials whose active manifest has vector 123 as a `componentOf` ingredient — placed into this asset, not the asset it was made from — and a `parentOf` ingredient with no manifest (the photo itself, opened). `componentOf` and `inputTo` are never followed (§3.2): a component's proof is about a part, and a reader that followed it would attribute a capture to a composite. **No proof found**; a reader that followed it would read vector 01's proof over bytes it happens to match, and say *authentic*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
