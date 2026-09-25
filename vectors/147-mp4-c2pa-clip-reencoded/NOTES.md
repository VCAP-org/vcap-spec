# 147-mp4-c2pa-clip-reencoded

What a re-encoding editor leaves: new frames with no vcap SEI (the two-frame MP4 of `_media/` stands in for them), signed with a manifest that opens the capture of vector 36 as `parentOf` and records `c2pa.transcoded`. The proof is found at depth 1; no GOP names the capture (`frames_name_capture` false) and `media.hash` does not match. §5 alone would say *frames not compared*; at depth ≥ 1 that becomes **no proof found**, reason *Content Credentials carry the proof of a source capture* (§3.2) — never *tampered*. A detector may still add *origin traced* from the watermark. The source is the Android capture of vector 36 (Samsung SM-S908B, StrongBox, device signatures untouched); the clip bytes are vector 89's cut.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `assertion.bmffHash.additionalExclusionsPresent`, `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
