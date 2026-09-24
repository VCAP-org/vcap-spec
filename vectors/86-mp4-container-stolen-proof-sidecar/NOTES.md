# 86-mp4-container-stolen-proof-sidecar

The proof of vector 36, as a sidecar, next to an unrelated recording — vector 37's frames with its trailer removed. Every signature in the proof holds: the core, the three segments, the chain. None of it is about this file. Each GOP here carries a vcap SEI, and each names **another capture**, so no GOP of this proof's capture can be located (§5, *Locating segments*).

The outcome is **frames not compared**: the signatures hold and nothing ties them to the frames in front of the reader. Never *verified clip* — a clip is frames that were compared — and this is the case that read *verified clip* with segments 0, 1 and 2 before the binding rule existed, because a GOP that no SEI of this capture names was skipped rather than counted against the file.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
