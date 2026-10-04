# 166-mp4-container-h264-presentation

Vector 36's recording under a core that carries `media.presentation` (§6.1): the `avcC` parameter sets, the sample entry's `colr` (`nclx`, the one `MediaMuxer` wrote), the identity matrix and 640×360 in 16.16. The original every H.264 edit below is made from, and the file vector 36 was until its device proof, which predates the field, read *no proof found*.

What only a real file carries is still here: the video track has an **empty edit** (473 ms) because the microphone started before the camera, so a verifier that ignores the edit list pulls 23 audio frames into segment 0 and gets three wrong hashes; and each GOP carries a vcap SEI, excluded from its own hash. **Authentic**, all three segments located and recomputed.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation` and `media.timing` (both read back from the device's container), which the device proof predates (corpora 5.0.0 and 7.0.0).
