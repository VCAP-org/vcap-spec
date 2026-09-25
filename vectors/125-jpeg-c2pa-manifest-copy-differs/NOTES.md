# 125-jpeg-c2pa-manifest-copy-differs

Vector 123 after its trailer was replaced (§3, *Replacing the trailer*) to add a time-stamp token that arrived later — vector 59's proof, same core, one more attachment — **without re-issuing the manifest**, which still carries the proof as it was. This is what rule J1 (`spec/c2pa-interop-1.0.md` §2.1) forbids a writer, and the reason is on the C2PA side: the manifest's data hash covered the old trailer and no longer matches.

The reader is unaffected: the trailer wins (§3.1, step 1), the verdict is vector 59's, and the manifest's copy differs from it as JCS, so the verdict carries *manifest copy differs* — a warning on an otherwise valid verdict, like *sidecar differs*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Invalid**; success: `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: `assertion.dataHash.mismatch`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
