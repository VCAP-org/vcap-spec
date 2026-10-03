# 169-jpeg-c2pa-foreign-proof-sidecar

Vector 01's photo with no trailer — the canonical bytes of vector 01 — next to a sidecar holding vector 01's proof, and with Content Credentials added by somebody else whose active manifest carries **another capture's** proof: a new capture id and the hash of different pixels, validly signed. Anyone can write such a manifest; it sits outside the canonical bytes (§4.1) and nothing authenticates it to a vcap reader.

The depth-0 proof alone reads *tampered* — its `media.hash` is not these bytes — and before corpus 6.1.0 that was the verdict: the manifest outranked the sidecar and a genuine file next to its genuine proof was accused. §3.1 step 4 now judges both when they differ, and the sidecar's verdict stands when its outcome ranks above the manifest proof's: **authentic**, vector 01's verdict, with *manifest copy differs* and `proof_source` the sidecar. Nothing is gained by it that deleting the manifest would not give. Vector 127 is the other direction: the manifest's proof is the good one and the sidecar's is ignored; vector 170 is a sidecar that does no better.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.27.16 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: none; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
