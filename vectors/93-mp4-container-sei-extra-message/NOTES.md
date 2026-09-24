# 93-mp4-container-sei-extra-message

Vector 36 with the vcap SEI NAL of GOP 1 rebuilt to carry a **second** SEI message after ours: another `user_data_unregistered` with twenty bytes nobody signed. A vcap SEI NAL carries exactly one message, the 36-byte vcap one, followed by `rbsp_trailing_bits` (§5). A verifier that excluded any SEI NAL containing the vcap UUID — the reference verifier did — would hash GOP 1 exactly as the device did and call it verified, with those twenty bytes inside it and outside every hash.

**Tampered**, 0 and 2 verified. The sample is rewritten through `remux.ts` (it grew by twenty-two bytes) and the audio track is untouched.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
