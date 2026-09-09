# 38-mp4-container-clip

The file of vector 36 with the entry for segment 0 removed from the proof, so `media.segment_count` is 3 and two segments are present: **verified clip** (§5), reporting 1 and 2.

The trap is index mapping. The file still contains all three GOPs, and its first GOP is segment 0 — the one with no entry. A verifier that matched GOPs to entries by position would check GOP 0's bytes against segment 1's signature, fail, and call a clip tampered. The vcap SEI is what says which GOP is which, and §5 allows exactly that use and no more: it locates, it does not prove.

Sealed by `SDK-Android` on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox), 640×360 at 30 fps with one-second GOPs, recorded by `VideoPipelineOnDeviceTest`. The signatures are the device's: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts` rebuilds them from the sealed files.
