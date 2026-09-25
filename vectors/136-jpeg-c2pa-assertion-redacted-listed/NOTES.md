# 136-jpeg-c2pa-assertion-redacted-listed

The unsealed photo with Content Credentials whose active manifest opens vector 123 as `parentOf` and **redacts** its proof: `self#jumbf=/c2pa/urn:c2pa:76636170-0000-4000-8000-000001230001/c2pa.assertions/io.github.vcap-org.vcap.proof` is in the active claim's `redacted_assertions` (C2PA 6.8). c2pa-rs removed the box; this vector puts it back, intact, so the only thing saying it is gone is the claim. An assertion any claim of the store lists as redacted is absent, whatever box is still there (§3.2): **no proof found**. A reader that ignored the list would find vector 01's proof at depth 1 over bytes it matches, and say *authentic*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Invalid**; success: `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: `assertion.dataHash.mismatch`, `assertion.notRedacted`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
