# 189-mp4-container-crc-broken-trailer-sidecar

Vector 173 with the appended trailer's footer CRC broken: vector 89's clip of vector 166, its own trailer stripped, another capture's video proof appended in a structurally valid `free` box whose CRC fails, and vector 166's proof as sidecar. On its own the footer reads *corrupted proof*.

§3.1 (*A sidecar that does better*, unreadable footer): the sidecar is judged over the file without the `free` box the footer declares, which is vector 89's clip without its trailer; it locates GOPs 1 and 2 and recomputes them, **verified clip**, 1 and 2 of 3, which ranks above *corrupted proof*, so it stands, with *trailer unreadable* and `proof_source` the sidecar. A verifier that predates corpus 8.0.0 reads it *corrupted proof*.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation` and `media.timing` (both read back from the device's container), which the device proof predates (corpora 5.0.0 and 7.0.0).
