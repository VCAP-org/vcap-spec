# 123-jpeg-c2pa-carrier-after-sealing

Vector 01 — a sealed photo — after a C2PA claim generator wrote Content Credentials over it, carrying the proof as `io.github.vcap-org.vcap.proof` in `gathered_assertions`: the order `spec/c2pa-interop-1.0.md` §3.1 requires for JPEG, and the only one in which both bindings hold. The `c2pa.hash.data` covers every byte after EOI, the trailer included.

The trailer is the proof (§3.1, step 1). The manifest's copy is not byte-identical to the payload — c2pa-rs re-serializes the JSON it is given — and it is the same proof, because copies are compared as `JCS(parse(a)) == JCS(parse(b))`: a reader that compared bytes here would report *manifest copy differs* on a file nobody touched. **Authentic**, the verdict of vector 01; `media.hash` is unchanged because §4.1 removes the C2PA store's APP11 segments.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.dataHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
