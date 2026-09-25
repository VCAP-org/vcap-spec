# 146-mp4-c2pa-clip-gop-replaced

Vector 145's clip with one byte of the last GOP's IDR slice data changed (clip byte 148196), signed by a cutter that opens vector 36 as `parentOf` and carries its proof in **its own** manifest, as the clip's: a GOP whose vcap SEI still names the capture and segment 2, and whose bytes are not the ones segment 2 signs. The cutter's manifest is valid — it vouches for the bytes it saw — and declares a trim, not this.

Depth 0 reads like a sidecar (§3.2): §5 applies, a located segment that does not recompute is **tampered**, with segment 1 verified. Vector 147 is the other side of the rule: at depth ≥ 1 the same failure would read *no proof found*, because a proof found up the chain is the source's and is never held against a derivation. The source is the Android capture of vector 36 (Samsung SM-S908B, StrongBox, device signatures untouched); the clip bytes are vector 89's cut.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: `assertion.bmffHash.additionalExclusionsPresent`, `signingCredential.ocsp.skipped`; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
