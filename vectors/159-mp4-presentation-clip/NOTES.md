# 159-mp4-presentation-clip

Vector 158 cut: GOP 0 dropped from the sample tables by `remux.ts`, which copies the track header and the sample description as they were. Both remaining GOPs are located and recompute, and the clip presents them exactly as the core says — the same parameter sets, the same matrix, the same display size, one video track, the same timing records (a silent file: `media.timing` has no `audio_timescale`, and every record has `a = 0`). **Verified clip**, 1 and 2 of 3: the case §5 *Presentation* must leave alone.

The container is the device capture of vector 37 (a Samsung SM-S908B, HEVC, no audio); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core can carry `media.presentation` and `media.timing` (no audio track, so no `audio_timescale`).
