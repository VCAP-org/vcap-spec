# 39-mp4-container-frame-replaced

Vector 36 with a single bit flipped inside segment 1's video samples: byte 135610 of the file, the last byte of that GOP's range.

Every signature still verifies, because a signature covers the hash a writer declared and not the bytes a reader received. `media.hash` fails, and segment 1's `content_hash` recomputed from the container fails; segments 0 and 2 still match. The verdict is **tampered**, and it names the segments that survived — a clip is missing segments, this is a present segment whose content was replaced inside a range a signature covers.

Without this vector the corpus cannot tell a verifier that recomputes from one that does not: every other container vector passes for both.

Sealed by `SDK-Android` on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox), 640×360 at 30 fps with one-second GOPs, recorded by `VideoPipelineOnDeviceTest`. The signatures are the device's: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts` rebuilds them from the sealed files.
