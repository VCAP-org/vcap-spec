# 37-mp4-container-hevc

The same rule on HEVC, with no audio track: a two-byte NAL header, SEI NAL types 39 and 40 instead of 6, `hvcC` instead of `avcC` for the length prefix width, and segments that close at the next IDR with no audio to select.

No edit list here — with no audio track there is nothing for the muxer to delay the video behind, which is why the H.264 vector is the one that catches that mistake.

Sealed by `SDK-Android` on a Samsung SM-S908B (Exynos 2200, Android 16, StrongBox), 640×360 at 30 fps with one-second GOPs, recorded by `VideoPipelineOnDeviceTest`. The signatures are the device's: `tools/src/generate.ts` cannot make these vectors, and `src/derive-container-vectors.ts` rebuilds them from the sealed files.
