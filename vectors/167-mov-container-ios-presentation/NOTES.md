# 167-mov-container-ios-presentation

Vector 48's QuickTime file under a core that carries `media.presentation`: the `avcC` parameter sets and no `clap`, `pasp` or `colr` (the iPhone wrote none), the identity matrix and 1280×720 in 16.16. **Authentic**, three segments recomputed from a container `AVAssetWriter` muxed.

The container is the iPhone capture of vector 48 (an iPhone 11 Pro, iOS 18.6.2, `AVAssetWriter`); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation`, which the proof of vector 48 predates (corpus 5.0.0).
