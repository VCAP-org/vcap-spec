# 94-mp4-container-sync-table-not-idr

Vector 37 with its sync sample table rewritten to mark **every** sample as a sync sample; the frames are untouched. Segment boundaries are IDR access units, read from the NAL unit types (§5), not `stss`: a verifier that cut at sync samples would find seventy GOPs, sixty-seven of them without a vcap SEI, and call the file tampered. Read by IDR, the three GOPs are where they were and all three recompute. **Verified clip**, not authentic, because the rewritten table is inside the canonical bytes and `media.hash` no longer matches; the presentation read back is the signed one (§5 *Presentation*).

The real-world version of this trap is HEVC's CRA picture: a random-access point `stss` lists that is not an IDR.

Derived by `tools/src/generate.ts` from the device capture in vector 36 or 37 (a Samsung SM-S908B, Android 16, StrongBox, sealed by the reference Android SDK). The container, its NAL units and its vcap SEIs are the device's; the core and the segment chain are re-signed with the test key in `tools/src/testkey.ts`, over the same capture id and the same content hashes, so that the core carries `media.presentation`, which the device proof predates (corpus 5.0.0).
