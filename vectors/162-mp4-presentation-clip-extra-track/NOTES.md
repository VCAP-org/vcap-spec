# 162-mp4-presentation-clip-extra-track

Vector 159 with a second enabled video track: a copy of the first, appended to `moov`. A segment hash covers the first video track and the first audio track; a player may show any enabled track, and an attacker's track would be one no signature covers — overlaid text, another picture, another soundtrack. §5 *Presentation*: a clip is bound only when its file has exactly one `vide` track, at most one `soun` track, one sample description each, and every other track disabled. **Frames not compared**, *tracks not bound*, nothing credited.

The container is the device capture of vector 37 (a Samsung SM-S908B, HEVC, no audio); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core can carry `media.presentation` and `media.timing` (no audio track, so no `audio_timescale`).
