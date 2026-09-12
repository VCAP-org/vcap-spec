# 85-mp4-container-ios-sealed

Vector 48 is a container Apple wrote under a chain this repository synthesized; vector 47 is a real Secure Enclave signature over a photo. This is both halves in one file: an `AVAssetWriter` MP4 in which **every one of the eleven segment signatures, and the core signature over them, came out of a Secure Enclave**, and every `content_hash` is recomputed from the container the same device muxed. Until this vector the corpus could not say whether a writer's §5 boundaries and a reader's survive the same encoder — 48 proved the reader against Apple's bytes, 36-39 proved writer and reader together against Android's.

What only this file has:

- **Five one-frame segments.** VideoToolbox answers a forced keyframe with **two** IDRs 33 ms apart, so the eleven GOPs run 28, 1, 30, 1, 30, 1, 29, 1, 30, 1, 29 frames. §5's "a segment may be one frame" was written from a single observed pair on Android hardware; here it is half the chain. A writer that coalesces the pair, or a reader that treats a one-frame GOP as a parse error, disagrees with this file five times.
- **Apple writing ISO MP4, not QuickTime.** `ftyp` is `mp42` with `isom mp41 mp42` compatible, and the codec is `avc1` H.264 — the `qt  `/`hvc1` pairing of 48 was one of two things `AVAssetWriter` emits, and a reader tuned to that one meets this file as a different muxer. `stco` and a movie timescale of 600 are Apple's either way; `sdtp` is present and `wide` is not.
- **An identity edit list on a video-only track.** One `elst` entry, `media_time = 0`, duration 3679 — no audio to delay the video behind, and still an edit. Vector 36 punishes ignoring an edit, 48 punishes reading a shift into an identity, and this one says the identity is not an artefact of QuickTime.
- **Eleven segments, and a declared watermark on a `container` vector.** The longest chain in the corpus recomputed from a container, against three everywhere else, so an off-by-one in the chain walk has somewhere to show. `watermark` names `video-rep-v1` with `mark_id` 9627292 because the frames really were marked on the device; no verifier here ships a detector, so the label is *watermark not evaluated* and not *no watermark* — the first `container` vector where those two differ.

The frames are a static, out-of-focus surface: this is a fixture, and what it proves is about bytes, not about what the camera was pointed at.

An iPhone 11 Pro (`iPhone12,3`, iOS 18.6.2) during the S1 spike, 12 September 2026 (`vcap-sdk-ios`, `docs/s1-videotoolbox-spike.md`).
