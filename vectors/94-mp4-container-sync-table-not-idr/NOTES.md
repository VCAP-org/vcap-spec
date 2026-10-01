# 94-mp4-container-sync-table-not-idr

Corpus 4.0.0: **frames not compared**, *presentation not bound*, no segment credited — the device proof predates `media.presentation`, and a file that is not the original is a verified clip only when its core binds how its frames are shown (§5 *Presentation*). The point of the vector is unchanged: the GOPs are found by IDR, not by `stss`, and all three are located and recompute; a verifier that cut at sync samples would call the file tampered instead.

Vector 37 with its sync sample table rewritten to mark **every** sample as a sync sample; the frames are untouched. Segment boundaries are IDR access units, read from the NAL unit types (§5), not `stss`: a verifier that cut at sync samples would find seventy GOPs, sixty-seven of them without a vcap SEI, and call the file tampered. Read by IDR, the three GOPs are where they were and all three recompute. **Verified clip**, not authentic, because the rewritten table is inside the canonical bytes and `media.hash` no longer matches.

The real-world version of this trap is HEVC's CRA picture: a random-access point `stss` lists that is not an IDR.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK); the device signatures are not touched.
