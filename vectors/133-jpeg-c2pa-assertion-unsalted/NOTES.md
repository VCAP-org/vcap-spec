# 133-jpeg-c2pa-assertion-unsalted

Vector 124 with the proof assertion's description box rewritten without its salt: toggles `0x03` (requestable, label) instead of c2pa-rs's `0x13` (requestable, label, private `c2sh` salt box). A reader accepts both (`spec/c2pa-interop-1.0.md` §2.1): the salt is for redaction (C2PA 6.6, 8.4.2.3) and says nothing about the proof. **Authentic** at depth 0.

The edit is ours, not a claim generator's, so the C2PA side no longer matches the assertion's hash: a JUMBF box a validator recomputes and the vcap reader never does.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Invalid**; success: `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: `assertion.dataHash.mismatch`, `assertion.hashedURI.mismatch`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
