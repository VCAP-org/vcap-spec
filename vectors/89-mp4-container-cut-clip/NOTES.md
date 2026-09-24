# 89-mp4-container-cut-clip

Vector 36 **cut**: its first GOP removed from the video track, the audio frames before the cut removed with it, and the full proof — all three segments — still in the trailer. This is what a clip is: the file lacks segment 0, the proof does not.

Every surviving sample keeps its instant on the movie timeline (the movie timescale becomes 90 kHz and each track gets an empty edit for the time that was cut), so §5's audio rule assigns the same frames to segments 1 and 2 as in the original, and both recompute. **Verified clip**, 1 and 2 of 3. Segment 0 is signed and absent, which is the clip case and never *tampered*; `media.hash` does not match, which is what says this is not the original.

Vector 38, which used to be the corpus's clip, removed segment 0 from the **proof** and left it in the file; under the binding rule that is a GOP no signature covers, and it now reads *tampered*.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
