# 87-mp4-container-proof-over-unmarked-video

The proof of vector 36 as a sidecar over `_media/base.mp4`, a two-frame H.264 file that carries **no vcap SEI at all** — what a re-encoder or an SEI-stripping remuxer leaves behind. No GOP can be located, so nothing is compared and no segment is credited: **frames not compared**. Vector 86 is the same verdict reached through SEIs that name another capture; here there is nothing to read.

A verifier MUST NOT fall back to position — the first GOP of the file is not segment 0 of a proof just because it comes first (§5).

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation` and `media.timing` (both read back from the device's container), which the device proof predates (corpora 5.0.0 and 7.0.0).
