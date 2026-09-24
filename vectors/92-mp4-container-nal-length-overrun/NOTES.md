# 92-mp4-container-nal-length-overrun

Vector 37 with the first NAL length prefix of the second sample of GOP 1 increased by one (file byte 53360), so the units no longer tile the sample. The NAL units of a sample MUST cover it exactly (§5): a verifier that stopped at the first length that does not fit — which the reference verifier used to do — would leave the rest of the sample out of every hash and still call the GOP verified. **Tampered**, and no segment is credited: a malformed container is not a partial answer.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
