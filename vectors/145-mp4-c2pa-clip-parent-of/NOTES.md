# 145-mp4-c2pa-clip-parent-of

A clip made by a C2PA-aware cutter: vector 89's cut of vector 166 — GOP 0 removed, no re-encoding, the vcap SEIs intact — with no trailer, signed with a manifest that opens the source as `parentOf` and records `c2pa.trimmed`. The source's manifest (generation 0, urn:c2pa:76636170-0000-4000-8000-000001450000) carries vector 166's proof and travels in the clip's store as its ingredient.

No footer, no proof at depth 0, no sidecar: the proof is found at depth 1 (§3.2), the nearest ancestor that carries one. The frames name the capture (`frames_name_capture`, a locating hint), GOPs 1 and 2 are located and recompute under §5, the core binds the presentation the clip still has (§5 *Presentation*), and the outcome is **verified clip**, 1 and 2 of 3 — vector 89's verdict, reached without a trailer. The source is vector 166: the container of vector 36's Android capture (Samsung SM-S908B), its NAL units and vcap SEIs the device's, under a core and segment chain re-signed with the test key so that it carries `media.presentation` (corpus 5.0.0); the clip bytes are vector 89's cut of it, under the same core. Rebuilt in corpus 6.0.0: the 5.0.0 files carried vector 36's device proof, which predates the field and read *no proof found*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.27.16 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: none; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
