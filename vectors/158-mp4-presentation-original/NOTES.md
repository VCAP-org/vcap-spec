# 158-mp4-presentation-original

Vector 37's file with a core that carries `media.presentation` (§6.1): the SHA-256 of the presentation message over the `hvcC` parameter sets — VPS, SPS, PPS, in NAL type order — and the sample entry's `clap`, `pasp` and `colr` boxes (this file has a `colr`, `nclx`, the one `MediaMuxer` wrote), the video `tkhd` matrix (identity) and its display size, 640×360 in 16.16. **Authentic**: an original is covered whole by `media.hash`, and the presentation and the timing read back from it are the signed ones.

The container is the device capture of vector 37 (a Samsung SM-S908B, HEVC, no audio); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core can carry `media.presentation` and `media.timing` (no audio track, so no `audio_timescale`).
