# 36-mp4-container-verified

A real H.264 recording with an audio track, three segments, every `content_hash` recomputed from the container: the NAL units of each GOP with the vcap SEI excluded, then the audio frames of the GOP's time range (§5).

Two things only a real file can carry are in here. The video track has an **empty edit** (`elst` with `media_time = -1`, 473 ms) because the microphone started before the camera, so the tracks do not both begin at zero: a verifier that ignores the edit list pulls 23 audio frames into segment 0 and gets three wrong hashes. And each GOP carries a vcap SEI, which is excluded from its own hash — an implementation that hashes it produces three wrong hashes too, in a file that looks perfectly well formed.

Sealed by `SDK-Android` on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox), 640×360 at 30 fps with one-second GOPs, recorded by `VideoPipelineOnDeviceTest`. The signatures are the device's: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts` rebuilds them from the sealed files.
