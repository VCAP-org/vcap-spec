# 90-mp4-container-gops-reordered

Vector 37 with its last two GOPs swapped in decode order: segment 0, then 2, then 1. Every GOP is located and every one recomputes to its signed `content_hash` — the bytes of each are untouched, which is why `segments.verified` lists all three.

And the file is **tampered**: vcap SEI indices MUST be strictly increasing in decode order (§5). The chain proves the order of the *messages*; only this rule proves the order of the *frames*, and without it a verifier would accept any shuffle of a signed recording as long as each piece was genuine. Vector 26 asked this question at message level, where no file had to be read.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation`, which the device proof predates (corpus 5.0.0).
