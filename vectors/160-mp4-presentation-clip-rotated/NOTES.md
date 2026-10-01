# 160-mp4-presentation-clip-rotated

Vector 159 with its video track header's matrix turned 90°: every sample untouched, every GOP still located and recomputing, and a player shows the frames on their side. A rotation, a mirror or a translation changes what a reader sees without touching a signed byte, and before `media.presentation` a clip carried no claim it could be held to. The matrix read back differs from the signed one: **frames not compared**, *presentation differs*, and no segment is credited — the signed frames are here, the way they are shown is not what was signed. Not *tampered*: re-muxing a clip is not an accusation, as a `media.hash` that does not match is not one (§5 *Presentation*).

The container is the device capture of vector 37 (a Samsung SM-S908B, HEVC, no audio); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core can carry `media.presentation`.
