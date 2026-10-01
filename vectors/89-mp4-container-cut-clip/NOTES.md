# 89-mp4-container-cut-clip

Vector 36 **cut**: its first GOP removed from the video track, the audio frames before the cut removed with it, and the full proof — all three segments — still in the trailer. This is what a clip is: the file lacks segment 0, the proof does not.

Every surviving sample keeps its instant on the movie timeline (the movie timescale becomes 90 kHz and each track gets an empty edit for the time that was cut), so §5's audio rule assigns the same frames to segments 1 and 2 as in the original, and both recompute. `remux.ts` copies the decoder configuration, the track header and the track layout as they were, so the clip presents its frames as the core's `media.presentation` says (§5 *Presentation*). **Verified clip**, 1 and 2 of 3. Segment 0 is signed and absent, which is the clip case and never *tampered*; `media.hash` does not match, which is what says this is not the original.

Vector 38 removed segment 0 from the **proof** and left it in the file; under the binding rule that is a GOP no signature covers, and it reads *tampered*.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation`, which the device proof predates (corpus 5.0.0).
