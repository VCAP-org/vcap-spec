# 91-mp4-container-gop-duplicated

Vector 37 with its second GOP played twice: 0, 1, 1, 2. Both copies of segment 1 recompute to its signed hash. A signed segment counts only when **exactly one** GOP of the file carries its index (§5), so segment 1 is not verified, and a duplicated index is **tampered** — a recording in which one second of footage appears twice is not the recording that was signed, however genuine each copy is.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
