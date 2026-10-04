# 161-mp4-presentation-clip-sps-edited

Vector 159 with one bit of the SPS in its `hvcC` flipped (file byte 102213, the last byte of the SPS). Parameter sets carried only in the decoder configuration are in no sample, so no `content_hash` covers them — and they decide the conformance window (the crop), the VUI colour description and how every slice is decoded. The frames' bytes are the signed ones; the decoder that reads them is told something else. The configuration hash read back differs from the signed one: **frames not compared**, *presentation differs*, nothing credited.

The container is the device capture of vector 37 (a Samsung SM-S908B, HEVC, no audio); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core can carry `media.presentation` and `media.timing` (no audio track, so no `audio_timescale`).
