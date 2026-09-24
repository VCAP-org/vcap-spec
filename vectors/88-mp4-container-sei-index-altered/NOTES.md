# 88-mp4-container-sei-index-altered

Vector 36 with one byte changed: the index in the second GOP's vcap SEI, 1 → 3 (file byte 75738; the stored form is `00 00 03 00 03`, so emulation prevention still holds). A vcap SEI is excluded from `content_hash`, so the GOP's bytes still hash to segment 1's signed value — and segment 1 is no longer located, while a GOP names segment 3, which the proof does not sign.

**Tampered**, with segments 0 and 2 verified: a GOP whose SEI index is not a signed segment is content no signature covers (§5). Before the binding rule this file read *verified clip* with 0, 1 and 2 — segment 1 counted as verified because its signature held, though no GOP of the file was ever compared with it.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
