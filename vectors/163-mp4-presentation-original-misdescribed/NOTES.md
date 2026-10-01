# 163-mp4-presentation-original-misdescribed

Vector 158 with a core whose signed `media.presentation.matrix` says 90° while the file it seals is not rotated: a writer that computed the field from something other than the file it produced. The bytes are exactly the sealed ones — `media.hash` matches — so the outcome stays **authentic**, and the false claim is the device's: *presentation differs*, amber at best, the way a level claimed above its evidence is *inconsistent claim* and never *tampered* (§7). A writer conformance suite catches this on its first file.

The container is the device capture of vector 37 (a Samsung SM-S908B, HEVC, no audio); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core can carry `media.presentation`.
