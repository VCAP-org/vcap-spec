# 87-mp4-container-proof-over-unmarked-video

The proof of vector 36 as a sidecar over `_media/base.mp4`, a two-frame H.264 file that carries **no vcap SEI at all** — what a re-encoder or an SEI-stripping remuxer leaves behind. No GOP can be located, so nothing is compared and no segment is credited: **frames not compared**. Vector 86 is the same verdict reached through SEIs that name another capture; here there is nothing to read.

A verifier MUST NOT fall back to position — the first GOP of the file is not segment 0 of a proof just because it comes first (§5).

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
