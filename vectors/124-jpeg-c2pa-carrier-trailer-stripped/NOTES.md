# 124-jpeg-c2pa-carrier-trailer-stripped

Vector 123 cut at EOI: the trailer is gone, the Content Credentials are not — what a tool that truncates a JPEG at its end marker leaves. No footer, so the proof is read from the active manifest (§3.1, step 4; §3.2, depth 0), and the canonical bytes are the whole received file minus the store's APP11 segments (§4.1), which are the canonical bytes of vector 01. **Authentic**, with `proof_source` naming the manifest; where the proof sat is diagnostic and never a label.

The C2PA side reads the same file the other way: its data hash covered the trailer, so the manifest no longer matches. Each format is right about the bytes it binds.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Invalid**; success: `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: `assertion.dataHash.mismatch`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
