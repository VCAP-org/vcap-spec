# 147-mp4-c2pa-clip-reencoded

What a re-encoding editor leaves: new frames with no vcap SEI (the two-frame MP4 of `_media/` stands in for them), signed with a manifest that opens vector 166's capture as `parentOf` and records `c2pa.transcoded`. The proof is found at depth 1 and is well formed; no GOP names the capture (`frames_name_capture` false) and `media.hash` does not match. §5 alone would say *frames not compared*; at depth ≥ 1 that becomes **no proof found**, reason *Content Credentials carry the proof of a source capture* (§3.2) — never *tampered*. A detector may still add *origin traced* from the watermark. The source is vector 166: the container of vector 36's Android capture (Samsung SM-S908B), its NAL units and vcap SEIs the device's, under a core and segment chain re-signed with the test key so that it carries `media.presentation` (corpus 5.0.0) and `media.timing`, with each segment entry's timing hash (corpus 7.0.0); the clip bytes are vector 89's cut of it, under the same core. Rebuilt in corpus 6.0.0, when the 5.0.0 files carried vector 36's device proof, which predates `media.presentation`, and again in 7.0.0 over the core that binds timing.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.27.16 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: none; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
