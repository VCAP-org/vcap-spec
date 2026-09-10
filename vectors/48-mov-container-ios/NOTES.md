# 48-mov-container-ios

The §5 question of vectors 36-39 asked of a container **Apple** wrote. Until this vector every demuxed file in the corpus came out of Android's `MediaMuxer`, so a reader could pass all of them and still be reading one muxer's habits rather than ISO-BMFF:

- `ftyp` says `qt  `, not `mp42`. A reader that gates on brand rejects it outright.
- A `wide` box sits between `ftyp` and `mdat` — a QuickTime pad with no ISO meaning. A box walker that knows a fixed set of top-level types stops here.
- Chunk offsets are in `stco`, 32-bit. Every container vector before this one carried `co64`, so the 32-bit branch of the corpus was **never executed** — the one place a wrong sample offset moves every hash at once.
- Unknown boxes inside the ones that matter: `tapt` in `trak`, `sdtp` in `stbl`.
- The movie timescale is 600, QuickTime's, not 90000 or 1000.
- An edit list is present and says nothing: one entry, `media_time = 0`. Vector 36 proves a reader must not *ignore* an edit; this one proves it must not read a shift into an identity.
- `media.mime` is `video/quicktime`, the corpus's first video that is not `video/mp4`. §8 decides "this is a video" on the `video/` prefix, and a verifier that matched the string `video/mp4` would take this file for a photo and stop requiring segments.

HEVC, no audio track, 1280×720, three one-second GOPs, `hvc1`. Each vcap SEI carries two emulation-prevention bytes rather than one, because this capture id ends in `0x00` and the index that follows it is zero-heavy: the escape straddles the boundary between `capture_id` and `n`, so un-escaping only the index field is not enough. A reader that does not un-escape at all reads index 196608 for all three GOPs — the same wrong answer three times, which looks like a malformed chain and not like a parse bug. That reader is not hypothetical; it is the first checker written for this file.

**The chain here is synthesized.** The spike inserted SEIs and never sealed a video, so the proof carries the repository's test key, and `sig`/`segments` prove nothing about iOS. What is the device's is the container and every `content_hash` recomputed from it. Vector 47 is the one with a real signature on it.

An iPhone 11 Pro (`iPhone12,3`, iOS 18.6.2) during the S1 spike, 10 September 2026 (`vcap-sdk-ios`, `docs/s1-videotoolbox-spike.md`).
