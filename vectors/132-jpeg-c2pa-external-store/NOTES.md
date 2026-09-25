# 132-jpeg-c2pa-external-store

The unsealed photo of `_media/`, with its Content Credentials as a separate store, `input.c2pa` (`application/c2pa`, C2PA 11.4), which the caller hands over — the verifier looks nowhere and fetches nothing (§3.2). The file embeds no store, so the external one is read: the proof in its active manifest, depth 0, over the canonical bytes of the whole file. **Authentic**, `proof_source` naming the external store's manifest (kind `c2pa`, as for an embedded store). An embedded store, when there is one, outranks an external store, as C2PA 15.5.2.1 has it.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
