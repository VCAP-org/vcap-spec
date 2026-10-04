# 39-mp4-container-frame-replaced

Vector 36 with a single bit flipped inside segment 1's video samples: byte 135610 of the file, the last byte of that GOP's range.

Every signature still verifies, because a signature covers the hash a writer declared and not the bytes a reader received. `media.hash` fails, and segment 1's `content_hash` recomputed from the container fails; segments 0 and 2 still match. The verdict is **tampered**, and it names the segments that survived — a clip is missing segments, this is a present segment whose content was replaced inside a range a signature covers.

Without this vector the corpus cannot tell a verifier that recomputes from one that does not: without the recomputation the same file reads *frames not compared*.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation` and `media.timing` (both read back from the device's container), which the device proof predates (corpora 5.0.0 and 7.0.0).
