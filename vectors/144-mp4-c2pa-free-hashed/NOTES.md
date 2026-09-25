# 144-mp4-c2pa-free-hashed

Vector 143 signed with `/free` and `/skip` **not** on the exclusion list (`builder.bmff_hash_exclude_free_and_skip_boxes = false`), then sealed. vcap: **authentic**, exactly as 143 — nothing about the C2PA hash reaches `media.hash`. C2PA: the trailer is a box the hash covers and it was appended after signing, so the manifest no longer matches: `assertion.bmffHash.mismatch`. A claim generator that means both bindings to hold excludes `/free` (§3.2); one that does not has its own binding broken by the trailer, and the vcap verifier cannot tell.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Invalid**; success: `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `signingCredential.ocsp.skipped`; failure: `assertion.bmffHash.mismatch`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
