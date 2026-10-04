# 168-mp4-container-ios-presentation

Vector 85's recording under a core that carries `media.presentation`: the configuration record alone in the sample entry, the identity matrix and 1280×720 in 16.16, and the eleven segments the device wrote — five of them one frame long, which a reader has to handle like any other (`vectors/README.md`, *Errata*). **Authentic**, every segment recomputed. The Secure Enclave signatures are vector 85's and stay there.

The container is the iPhone capture of vector 85 (an iPhone 11 Pro, iOS 18.6.2, `AVAssetWriter`); the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation` and `media.timing`, which the proof of vector 85 predates (corpora 5.0.0 and 7.0.0).
