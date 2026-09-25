# 143-mp4-c2pa-free-excluded

The two-frame MP4 of `_media/`, given Content Credentials **before** sealing (the order `spec/c2pa-interop-1.0.md` §3.2 requires for ISO-BMFF) with c2pa-rs's default `c2pa.hash.bmff.v3` exclusions — the C2PA `uuid` box, `/ftyp`, `/mfra`, and `/free` and `/skip` — then sealed: the proof of vector 33 with `media.hash` over the file as it now is, manifest box included, and the trailer appended as the last box.

vcap: **authentic**, the manifest is content inside `media.hash` (§4.1), and the chain is checked at message level only, as in vector 33. C2PA: the trailer is a `free` box, excluded, so the BMFF hash still matches — and c2pa-rs reports the informational `assertion.bmffHash.additionalExclusionsPresent` for `/free` and `/skip` all the same, recorded in `expected.json` so no implementation promises otherwise.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `assertion.bmffHash.additionalExclusionsPresent`, `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
