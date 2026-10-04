# 171-mp4-c2pa-foreign-proof-sidecar

Vector 89's clip of vector 166 — GOP 0 removed, no trailer — next to a sidecar holding vector 166's proof, with a manifest somebody else added whose active manifest carries **another capture's** video proof: vector 166's core and segment hashes under a new capture id, the core and every segment message re-signed for it. Every signature in that proof holds, and no GOP of the clip names its capture, so on its own it reads *frames not compared* (§5, *Locating segments*) — amber, not an accusation, but a genuine clip reduced to "nothing ties these signatures to these frames" by a manifest anyone can write.

§3.1 step 4 judges both: the sidecar's proof locates GOPs 1 and 2 and recomputes them, **verified clip**, 1 and 2 of 3 — vector 89's verdict — which ranks above *frames not compared*, so it stands, with *manifest copy differs* and `proof_source` the sidecar. The source is vector 166: the container of vector 36's Android capture (Samsung SM-S908B), its NAL units and vcap SEIs the device's, under a core and segment chain re-signed with the test key so that it carries `media.presentation` (corpus 5.0.0) and `media.timing`, with each segment entry's timing hash (corpus 7.0.0); the clip bytes are vector 89's cut of it, under the same core. Rebuilt in corpus 6.0.0, when the 5.0.0 files carried vector 36's device proof, which predates `media.presentation`, and again in 7.0.0 over the core that binds timing.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.27.16 (trust anchor `_trust/c2pa-test/root.pem`): **Trusted**; success: `assertion.bmffHash.match`, `assertion.hashedURI.match`, `claimSignature.insideValidity`, `claimSignature.validated`, `signingCredential.trusted`; informational: none; failure: none.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
