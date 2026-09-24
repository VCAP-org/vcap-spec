# 38-mp4-container-clip

The file of vector 36 with the entry for segment 0 removed from the **proof** and GOP 0 left in the **file**: `media.segment_count` is 3, two entries are present, and the file still carries all three GOPs.

**Tampered**, 1 and 2 verified. GOP 0 carries a vcap SEI naming segment 0, and the proof signs no segment 0: that GOP is content no signature covers (§5, *Locating segments*). It is exactly the file an attacker produces by prepending a forged GOP to a genuine clip whose first segment is gone, and before the binding rule it read *verified clip*, 1 and 2, with the unsigned frames on screen. The genuine clip — the GOP cut from the file, the proof whole — is vector 89.

Sealed by the reference Android SDK on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox), 640×360 at 30 fps with one-second GOPs, recorded by its on-device video pipeline test. The signatures are the device's: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts` rebuilds them from the sealed files.
