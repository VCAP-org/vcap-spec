# 146-mp4-c2pa-clip-gop-replaced

Vector 145's clip with one byte of the last GOP's IDR slice data changed (clip byte 148196), signed by a cutter that opens vector 166 as `parentOf` and carries its proof in **its own** manifest, as the clip's: a GOP whose vcap SEI still names the capture and segment 2, and whose bytes are not the ones segment 2 signs. The cutter's manifest is valid — it vouches for the bytes it saw — and declares a trim, not this.

Depth 0 reads like a sidecar (§3.2): §5 applies, a located segment that does not recompute is **tampered**, with segment 1 verified. The corpus's only video case of a tampered proof inside an active C2PA manifest; vector 128 is the JPEG one. Vector 147 is the other side of the rule: at depth ≥ 1 a failure reads *no proof found*, because a proof found up the chain is the source's and is never held against a derivation. The source is vector 166: the container of vector 36's Android capture (Samsung SM-S908B), its NAL units and vcap SEIs the device's, under a core and segment chain re-signed with the test key so that it carries `media.presentation` (corpus 5.0.0); the clip bytes are vector 89's cut of it, under the same core. Rebuilt in corpus 6.0.0: the 5.0.0 files carried vector 36's device proof, which predates the field and read *no proof found*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.27.16 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: none; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
