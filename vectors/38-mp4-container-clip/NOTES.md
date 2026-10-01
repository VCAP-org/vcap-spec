# 38-mp4-container-clip

The file of vector 36 with the entry for segment 0 removed from the **proof** and GOP 0 left in the **file**: `media.segment_count` is 3, two entries are present, and the file still carries all three GOPs.

**Tampered**, 1 and 2 verified. GOP 0 carries a vcap SEI naming segment 0, and the proof signs no segment 0: that GOP is content no signature covers (§5, *Locating segments*). It is exactly the file an attacker produces by prepending a forged GOP to a genuine clip whose first segment is gone, and before the binding rule it read *verified clip*, 1 and 2, with the unsigned frames on screen. The genuine clip — the GOP cut from the file, the proof whole — is vector 89.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation`, which the device proof predates (corpus 5.0.0).
