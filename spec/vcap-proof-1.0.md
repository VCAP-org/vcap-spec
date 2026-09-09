# vcap proof format, version 1.0

**Status: `vcap/1.0` FROZEN — 9 September 2026, tag `v1.0`.** Written 8
September 2026 as step 1 of the work order in `Doc/06-fase1-avvio.md` §3,
amended the same day after the cryptographic review (step 2,
`reviews/01-crypto-review-draft-1.0.md`) and on 9 September after the
implementability review on real hardware (step 3,
`reviews/implementability-android.md`). The six format decisions below are
final. From this tag the format grows by addition only (§9); §11 lists what is
still being verified and why none of it can change the wire format. Changes
land through `CHANGELOG.md`.

## 1. Scope

This document defines the artefact a capture pipeline produces and a verifier
consumes: its binding to the media file, the byte sequences signatures cover,
the JSON structure, and the verdict semantics of every field.

It does not define transport, registry APIs, or watermark internals. It does
define what a verifier may and may not conclude, because that is the part four
independent implementations must agree on.

## 2. Terminology

- **capture** — one photo or one video clip sealed at the moment of recording.
- **capture id** — 128-bit random identifier, also carried by the watermark.
- **core** — the part of the proof the device signs at capture time (§6.1).
- **core hash** — `SHA-256(JCS(core))`: the identity of a proof. Everything
  added after capture points at it.
- **attachment** — a part of the proof added after capture (timestamp, anchor,
  registry entry, integrity statement), self-authenticating and bound to the
  core hash (§6.2).
- **canonical bytes** — the media byte sequence `media.hash` covers (§4).
- **trailer** — the block appended to the media file carrying the proof (§3).
- **segment** — for video, one GOP (§5).
- **proof level** — how strong the origin claim is, from the hardware root of
  trust down to a browser session key (§7).

Key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

---

## 3. Decision 1 — Trailer magic and header

The proof travels **inside the file** as a trailer that is also a valid ISO-BMFF
`free` box, so muxers and players skip it instead of choking on it. It is found
by seeking from the end, never by scanning.

```
 ┌─ media file bytes, unmodified ────────────────────────────┐
 │ ...                                                       │
 ├─ box header (8 bytes) ────────────────────────────────────┤
 │ box_size : uint32 BE   = 8 + payload_len + 16             │
 │ box_type : "free"      (4 bytes, ASCII)                   │
 ├─ payload (payload_len bytes) ─────────────────────────────┤
 │ proof JSON, UTF-8, no BOM, JCS-canonical (RFC 8785)       │
 ├─ footer (16 bytes, always the last 16 bytes of the file) ─┤
 │ magic       : "VCAP"   (4 bytes, ASCII)                   │
 │ major       : uint8    = 1                                │
 │ minor       : uint8    = 0                                │
 │ flags       : uint16 BE                                   │
 │ payload_len : uint32 BE                                   │
 │ crc32       : uint32 BE, CRC-32 (IEEE 802.3) of payload   │
 └───────────────────────────────────────────────────────────┘
```

- **All integers big-endian**, per ISO-BMFF convention.
- **No padding, no alignment.** BMFF box sizes are byte counts and boxes need no
  alignment; padding would only create a second way to write the same proof.
- **Footer validity.** The last 16 bytes are a *valid footer* when all hold:
  `magic == "VCAP"`, `major == 1`, `8 + payload_len + 16 <= len(F)`, the 8 bytes
  before the payload read `box_size == 8 + payload_len + 16` followed by `"free"`.
  If any of these fails, the file carries no trailer: *no proof found*, not an
  error. If the structure holds and `crc32` does not match the payload, the
  proof is **corrupted**, reported as such and never as *no proof found*. The
  distinction matters: one means the platform stripped the metadata, the other
  means somebody edited the file. The structural checks come first so that
  sixteen unlucky bytes at the end of an unsealed file cannot make it look edited.
- **The CRC has no security role.** It tells corruption from editing; integrity
  comes from the signature over the core (§4). CRC-32 is used because it is in
  every standard library on every target; hardware-accelerated variants buy
  nothing for a payload of a few kilobytes.
- **Nested trailers.** After stripping the trailer, if the remaining bytes end
  in a valid footer, the verifier MUST report *nested proof* and MUST NOT present
  the outer proof as authoritative. Writers MUST refuse to seal a file that
  already carries a trailer. Otherwise a genuine hardware-sealed original can be
  wrapped in a weaker proof that hides it.
- **`flags` are a dispatch hint and never a source of truth.** Bit 0: a sidecar
  exists. Bit 1: segments present (video). Bit 2: pseudonymous capture. Bits
  3–15 reserved, MUST be written as zero. Writers MUST derive bits 1 and 2 from
  the JSON; everything they say is also in the JSON, and the JSON wins on
  disagreement — a verifier MAY warn (*flags disagree*), and an attacker gains
  nothing by flipping them. Bit 0 is not derivable from the JSON and depends on
  what sits next to the file: verifiers MUST NOT check it. Unknown reserved bits
  are ignored, not fatal.
- **Sidecar.** The same JSON, byte-identical, in `<filename>.vcap` next to the
  file. Used when a pipeline cannot append to the container, and always allowed
  as a redundant copy. A sidecar has no footer. When both exist, the trailer is
  authoritative; a sidecar that differs is reported (*sidecar differs*) and not
  used.
- **The magic carries no brand** (decision P8): `VCAP` is the codename, and
  sealed files are immutable while the product name is provisional.

---

## 4. Decision 2 — Canonical bytes and the signature

Two things are hashed and one is signed. **`media.hash`** covers the media file
and nothing else, identically in five implementations. **`sig`** covers the
core — the claims, `media.hash` among them — so the media is covered
transitively and every claim around it is covered directly. This is the first
place independent implementations diverge, so the rule is a procedure, not a
description.

### 4.1 Canonical bytes → `media.hash`

Given the received file `F`:

1. **Strip the trailer.** If the last 16 bytes are a valid footer (§3), let
   `T = 8 + payload_len + 16` and `F' = F[0 : len(F) - T]`. Otherwise `F' = F`.
   If `F'` itself ends in a valid footer: *nested proof*, stop (§3).
2. **Container normalization.**
   - **JPEG**: remove every `APP11` segment (marker `0xFF 0xEB`) whose payload —
     the bytes after the 2-byte segment length — begins with `0x4A 0x50`
     (`"JP"`, the JUMBF common identifier C2PA uses), and only those. Keep every
     other APP11 and every other segment. Concatenate the remaining bytes in
     original order → `C`. The walk stops at `SOS`; fill bytes (`0xFF` padding
     before a marker) and markers without a length field (`TEM`, `RSTn`) are
     kept where they are, like every other byte that is not a JUMBF APP11.
   - **ISO-BMFF** (MP4, MOV, HEIC): `C = F'` unchanged. Nothing is removed.
3. **Hash.** `H = SHA-256(C)`, 32 raw bytes. `media.hash` is `H` in base64url,
   no padding.

The asymmetry between containers is deliberate and follows from where each
standard puts its own hash:

- **Photos embed the C2PA manifest AFTER sealing**, because the JPEG hard binding
  hashes to end-of-file; if the manifest were inside the canonical bytes, adding
  it would invalidate the vcap signature it depends on. So it is excluded — and,
  as a consequence, the C2PA manifest of a sealed photo can be added, replaced or
  removed without touching the vcap verdict. It carries its own signature.
- **Video embeds the manifest BEFORE sealing**, because BMFF hashing ignores the
  trailing `free` box; the manifest is inside the canonical bytes and stays there.

Everything else in the file — EXIF, XMP, ICC, thumbnails, audio — is inside `C`
and therefore covered. A pseudonymous capture (§6, `policy.pseudonymous`) MUST
strip identifying metadata **before** sealing; stripping it afterwards is
editing.

### 4.2 The signature → `sig`

```
core_bytes = JCS(core)                       // RFC 8785 canonical JSON of §6.1
core_hash  = SHA-256(core_bytes)             // 32 bytes, the proof's identity
sig.value  = ECDSA-P256-SHA256(core_bytes)   // ES256 semantics
```

- `sig.alg` is `"ES256"` and is not extensible in v1.
- `sig.value` is the signature in **IEEE P1363 form**: `r ‖ s`, 64 bytes,
  base64url. Not DER. Writers MUST normalize `s` to the low half of the group
  order (`s ≤ n/2`): a signer that returns a high `s` is replaced by `(r, n−s)`,
  which verifies over the same message. Verifiers MUST accept both halves. One
  encoding, one form.
- `sig.pub` is the signing public key as DER SubjectPublicKeyInfo, base64url.
  **Required**, so a verifier works offline without the attestation chain.
- Whether an implementation streams `core_bytes` into the signer or pre-hashes
  and signs the digest (`NONEwithECDSA` over `core_hash`, the StrongBox fast
  path) is its business: the result is identical and one vector proves it.
- **Verifiers recompute.** The bytes in the trailer are not authoritative: the
  verifier parses the JSON, extracts the core keys (§6.1), serializes with JCS,
  and verifies over that. An edit anywhere in the core is *tampered*; an edit in
  an attachment breaks that attachment only, and the verdict says which.
- `sig` is **required for photos and for video**. For video, the segment chain
  (§5) proves the frames; the core signature proves the claims around them.

**Required vectors** (one file each): JPEG with C2PA, JPEG without C2PA, HEIC,
MP4, MOV, MP4 that already contained an unrelated `free` box, JPEG with two
APP11 segments of which one is not JUMBF, file with a footer but truncated
payload, file with valid footer and wrong CRC, double-sealed file (*nested
proof*), signature with high `s` (must verify), signature over a core with one
edited key (must fail), DER-encoded signature (must fail: wrong length).

Verified on Android (`reviews/implementability-android.md`, M11): for photos
the manifest writer runs after sealing, since a JUMBF APP11 added afterwards is
outside the canonical bytes; for video it runs before sealing. iOS confirmation
is a §11 follow-up and cannot change the rule, only confirm it.

---

## 5. Decision 3 — Video signature granularity

One signature per **segment**, where a segment is one GOP: from an IDR access
unit up to, but excluding, the next IDR.

For segment `n`:

```
content_hash(n) = SHA-256( video_nals(n) || audio_frames(n) )

  video_nals(n)   = the NAL units of the segment's video samples, in decode
                    order, each as raw NAL bytes — no Annex-B start code, no
                    AVCC/HVCC length prefix — EXCLUDING vcap SEI NAL units
  audio_frames(n) = the coded audio frames whose decode timestamp DTS satisfies
                    DTS(IDR_n) <= DTS < DTS(IDR_n+1) (for the last segment: to
                    the end of the track), in decode order, raw sample bytes

message(n)      = "vcap/1.0/seg" (12 B) || capture_id (16 B) || uint32 BE n
                                 || content_hash(n) (32 B) || prev_link(n) (32 B)
                  = 96 bytes, every field fixed-length

prev_link(0)    = 32 zero bytes
prev_link(n)    = SHA-256( message(n-1) )

sig(n)          = ECDSA-P256-SHA256( message(n) ), P1363, low s (§4.2)
```

- **A vcap SEI NAL unit** is an SEI NAL (type 6 in H.264, 39 or 40 in H.265)
  carrying a `user_data_unregistered` payload (payloadType 5) whose 16-byte UUID
  is the vcap SEI UUID, `SHA-256("vcap/1.0/sei")[0:16]` =
  `caa653d1ed1763c7af388aea76527336`, and whose `payloadSize` is therefore 36:
  the 16 UUID bytes are inside the payload that size counts, so a parser that
  reads it as 20 over-reads the SEI. Derived, not registered:
  `user_data_unregistered` UUIDs are unregistered by definition (H.264 §D.2.6
  asks only that they be unlikely to collide), and anyone can recompute this
  one from a single ASCII string; a future layout takes a new string, as the
  segment separator does. The payload after the UUID is
  `capture_id (16 B) || uint32 BE n`, 20 bytes. A writer SHOULD emit one vcap
  SEI per segment, as a prefix SEI immediately before the segment's IDR, so a
  demuxed or re-muxed elementary stream still says which capture and which
  segment a GOP belongs to. A verifier MAY use it to locate segments and MUST
  NOT treat it as evidence: `content_hash`, the chain and the signatures are.
  Where no vcap SEI names a GOP, a verifier **MUST NOT infer that GOP's index
  from its position in the file**, and recomputes nothing for it: position is
  the index only in a file nobody cut, which is the one assumption a clip
  breaks. Refusing to guess costs a verifier nothing it can use — a file whose
  SEIs were stripped no longer matches `media.hash` either, so its ceiling is
  amber whatever the segments say — while guessing wrong checks one GOP's bytes
  against another GOP's signature and calls an authentic clip forged. Two
  implementations of §5 disagreed here, one guessing and one refusing, before
  this sentence existed.
  Only vcap SEI NAL units are excluded from `content_hash`: a signature cannot
  cover the bytes that contain it. Every other SEI — registered or not — is
  content and is covered. Excluding by NAL type, as an earlier draft did, would
  have left unsigned bytes inside "verified" segments.
- **Audio is content.** Segment hashes cover the audio frames of the segment's
  time range, so a clip cannot keep verified frames over a replaced soundtrack.
  Audio frames do not align to IDRs: the rule above (by DTS, half-open interval,
  first sample at or after the IDR) is what two encoders must agree on.
- **The DTS is the container's.** The decode timestamp of the rule is the one
  the container records for the sample, in the media timescale of the received
  file and converted to a common timebase across tracks — not any clock
  internal to the capture pipeline. A writer that computes segment boundaries
  before muxing MUST use the timestamps it will write. **The common timebase is
  the presentation timeline the container defines, edit lists included**: in
  ISO-BMFF a leading empty `elst` entry (`media_time = -1`) delays a track, and
  a track's samples start at its first edit's `media_time`. This is not a corner
  case — `MediaMuxer` writes a 473 ms empty edit on the video track of a
  recording whose microphone opened before its camera, which is the ordinary
  case for a capture with audio. Aligning both tracks at zero instead pulls the
  audio frames that precede the first IDR into segment 0 and makes every
  segment hash of the file wrong. Two implementations of this rule, one on the
  device and one from the text, disagreed exactly there until the sentence you
  are reading existed (vector 36). Audio frames whose DTS
  precedes the first IDR are covered by `media.hash` and by no segment hash; a
  verifier MUST NOT report them as missing.
- **A segment may be one frame.** Encoders place IDRs where they choose (two
  IDRs 63 ms apart at the start of a capture were observed on real hardware); a
  one-frame segment is a segment like any other, and a very short segment is
  not evidence of anything.
- **The chain is the point.** `prev_link` makes order and completeness provable:
  a reordered segment breaks the chain, and a clip whose first segment is not
  index 0 is detectably a clip, not an original. Without chaining, per-GOP
  signing would let anyone reassemble a plausible video from genuine pieces.
  The chain runs over **messages, not signatures**: ECDSA signatures are
  malleable (`(r, n−s)` is valid for the same message) and encoding-dependent,
  so hashing them would let anyone break a genuine chain without touching
  content. `message(n-1)` binds `content_hash(n-1)` and, recursively, every
  earlier message; each message is signed.
- **Domain separation.** The 12-byte separator is exactly the ASCII bytes of
  `vcap/1.0/seg`, no terminator, no length prefix; the version in it is the one
  in `v`. A future layout uses a new separator, so a v1.0 verifier fails
  cleanly instead of misparsing. All five fields are fixed-length: nothing can
  shift between `capture_id` and `content_hash`.
- **Each `segments[]` entry carries `gop`, `hash` (`content_hash(n)`), `prev`
  (`prev_link(n)`) and `sig`.** `prev` is redundant when segment n−1 is present
  — the verifier recomputes it and a mismatch is *chain broken* — and is what
  makes a segment verifiable when its predecessor is absent: a clip cut from the
  middle of an original verifies segment by segment, and is detectably a clip
  because it does not start at 0 or does not reach `segment_count`. Nothing in
  `prev` is trusted on its own: it enters the signed message.
- **`media.segment_count`** (core, §6.1) is the number of segments the original
  had: a writer sealing an original MUST set it to the number of `segments[]`
  entries it writes, with `gop` contiguous from 0. A video cut at the end keeps
  index 0, no gaps and an unbroken chain; the
  count is what lets the verifier say *"12 of 300 segments present"*, and the
  full-file `media.hash` (§4.1) is what says it is not the original.
- **Verifier behaviour** on video:
  - `sig` verifies over the core → the claims are authentic (who, which key,
    declared when and where). If `sig` fails → **tampered**, red, stop.
  - `media.hash` matches, every segment verifies, chain unbroken, first index 0,
    `segment_count` segments present → eligible for **green** (subject to §7);
  - `media.hash` does not match, or segments are missing, but every present
    segment verifies and the chain holds wherever two consecutive segments are
    both present → **verified clip**, amber, reporting which segment indexes
    verified out of `segment_count`;
  - a segment signature fails, or a present segment's `prev` differs from
    `SHA-256(message(n−1))` while segment n−1 is present (the chain breaks where
    the file claims contiguity) → **tampered**, red;
  - **a present segment whose `content_hash`, recomputed from the container,
    differs from the signed one → tampered**, red, reporting which segments do
    verify. Recomputation is optional — a verifier without a demuxer verifies
    the signature layer and nothing here changes that — but a verifier that
    holds the file and skips it has checked that somebody signed some hashes,
    not that the frames in front of the reader are those frames. A contradicted
    segment is not a missing one: a clip lacks segments, this file *has* the
    segment and its bytes are not the bytes that were signed, which is
    substitution inside a signed range and never amber (vector 39);
  - `segments[].range` (byte range in the received file) is informational and
    **not signed**: it helps a UI point at a frame, and a verifier MUST NOT
    conclude anything from it.

Photos have no `segments`; their signature is the one in §4.2.

Measured on a TEE device (`reviews/implementability-android.md`, M7, M8): one
segment signature costs 15–21 ms, so 300 segments over ten minutes are about
6 s of TEE time (1 % duty); hashing two interleaved tracks costs 8 KB and
0.5 ms per segment. StrongBox (the slow path) and VideoToolbox are §11
follow-ups. If StrongBox ever proves prohibitive, a `segment = N GOPs` grouping
keeps the chain and arrives as a new separator string (§9), not as a change to
this one.

---

## 6. Proof structure

The proof has two layers. The **core** is signed by the device at capture and
never changes afterwards. **Attachments** are added later (by the sync path,
when there is one), each verifiable on its own and each bound to `core_hash`.

```
{
  // ---- core: signed by the device (§6.1) ----
  "v": "vcap/1.0",
  "capture_id": "base64url, 16 bytes",
  "media":    { "mime", "w", "h", "duration_ms", "hash", "segment_count" },
  "device":   { "platform": "android" | "ios" | "web",
                "secure_hw": "strongbox" | "tee" | "secureEnclave" | "none",
                "key_id" },
  "watermark":{ "algo", "layout": "photo-bch-v3" | "video-rep-v1",
                "payload_bits", "ecc", "strength", "mark_id" },
  "time":     { "device_clock" },
  "location": { "level", "lat_udeg", "lon_udeg", "acc_cm", "evidence": [ ... ] },
  "policy":   { "pseudonymous": true|false, "retention_ref" },

  // ---- signature over the core (§4.2) ----
  "sig":      { "alg": "ES256", "value": "base64url r||s", "pub": "base64url SPKI" },

  // ---- attachments: each self-authenticating, bound to core_hash (§6.2) ----
  "segments":    [ { "gop": 0, "range": [start, end], "hash", "prev", "sig" } ],
  "attestation": [ "base64url DER leaf", "...", "base64url DER root" ],   // omitted on web
  "registry":    { "log_id", "leaf_index", "leaf": { ... }, "inclusion_path": [ ... ],
                   "tree_head": { "tree_size", "timestamp", "root_hash", "signature" } },
  "timestamp":   { "tsr", "tsa_issuer" },
  "anchor":      { "chain", "tx", "block", "anchor_id", "index", "tree_size", "root", "merkle_path" },
  "integrity":   { "source", "verdict", "evaluated_at", "sig" }
}
```

### 6.1 The core

The core is the JSON object made of exactly these top-level keys, when present:
`v`, `capture_id`, `media`, `device`, `watermark`, `time`, `location`, `policy`.
A verifier builds it from the received proof by taking those keys and nothing
else, then serializes it with JCS. Unknown top-level keys are not part of the
core and are listed as *not evaluated* (§9).

**Canonicalization procedure** (normative; vector `32-jcs-core-canonicalization`):

1. Parse the proof JSON. Take the top-level members named above, in whatever
   order they appear; ignore every other member.
2. Serialize the resulting object with JCS (RFC 8785): object members sorted by
   the UTF-16 code units of their names at every level, arrays in place, no
   whitespace, strings escaped as ECMAScript `JSON.stringify` does, numbers as
   plain decimal integers (the core has no other numbers).
3. `core_bytes` is the UTF-8 encoding of that string; `core_hash = SHA-256(core_bytes)`.

A writer MUST store the whole proof in the trailer as JCS of the entire object;
a reader MUST NOT depend on it (vector `20-jpeg-payload-not-canonical`). A
writer MUST produce proofs that validate against
`schema/vcap-proof-1.0.schema.json`; the schema is the structural form of this
section and §6.2, and CI in every implementation repository runs it.

Rules that keep five implementations byte-identical:

- **No floating-point numbers in the core.** Coordinates are integer
  microdegrees (`lat_udeg`, `lon_udeg`, `int32`, ±180 000 000); accuracy is
  integer centimetres (`acc_cm`, `uint32`); durations are integer milliseconds.
  JCS number serialization follows ECMAScript's algorithm, which Kotlin and
  Swift do not have; integers sidestep it.
- **No free-text strings in the core.** Every string is an enum value, a
  base64url value, or a fixed identifier. JCS string escaping and UTF-16 sort
  order then have nothing to bite on.
- `device.key_id = base64url( SHA-256( DER SPKI of sig.pub ) )`. Derived, never
  free; the identifier the registry and the transparency log use.
- `device.secure_hw` is the **claimed** level. The verifier computes the
  **proven** level from the attestation attachment (§7) and uses the proven one.
- `capture_id` MUST come from a cryptographically secure RNG. It is public (the
  watermark carries it); 128 bits are for uniqueness, not secrecy.
- `time.device_clock` is the device's own clock as integer milliseconds since
  the Unix epoch, UTC, signed by the device: a declaration, shown as such.
  Trusted time comes from the `timestamp` attachment.

Field table — type, required, verified against:

| Field | Required | Verified against |
|---|---|---|
| `v` | yes | §9 version policy |
| `capture_id` | yes | watermark payload, segment messages |
| `media.hash` | yes | recomputed canonical bytes (§4.1) |
| `media.segment_count` | yes (video) | segments present (§5) |
| `device.secure_hw` | yes | proven level from `attestation` (§7) |
| `device.key_id` | yes | `sig.pub`, attestation leaf, registry entry |
| `watermark` | no | detector output, if the detector ran |
| `time.device_clock` | no | nothing — declared |
| `location` | no | `location.level` and evidence rules (C15) |
| `policy.pseudonymous` | no | consistency: no device identifiers present |

### 6.2 The signature and the attachments

| Key | Added by | Self-authenticated by | Bound to the core by |
|---|---|---|---|
| `sig` | core, at capture | — it *is* the authentication | covers `JCS(core)` |
| `segments` | core, at capture | each `sig(n)` under `sig.pub` | `capture_id` in every message |
| `attestation` | core, at key creation | chain to a pinned Google root / App Attest | leaf SPKI MUST equal `sig.pub` |
| `attestation_status` | sync, while the chain is current | registry key signature over the entries it saw | signature covers `core_hash` |
| `registry` | sync | inclusion proof against a Signed Tree Head, carried inline | leaf carries `device.key_id` and `sig.pub` |
| `timestamp.tsr` | sync | RFC 3161 token, TSA chain, validated offline | `messageImprint = core_hash` |
| `anchor` | sync | RFC 6962 path from `SHA-256(0x00 ‖ core_hash)` to the root the chain recorded | leaf = `core_hash` |
| `integrity` | sync | registry key signature over `core_hash ‖ verdict` | by construction |

- **`attestation`** — the key attestation certificate chain, leaf first, each
  certificate DER in base64url, `[...]`. Present on Android (required for any
  level above `none`), absent on web; on iOS the App Attest material goes to the
  registry at enrolment and the proof carries the `registry` attachment
  instead. **The leaf's SubjectPublicKeyInfo MUST be byte-equal to `sig.pub`**;
  otherwise *attestation does not match the signing key*, red. The chain MUST
  NOT carry device identifiers (no ID attestation: serial, IMEI, MEID).
- **`attestation_status`** *(optional, added after v1.0)* — the revocation
  status of the certificates in the `attestation` chain, as it stood **while
  the chain was still current**, relayed and countersigned by the registry.
  Without it a verifier reading a proof years later cannot answer the question
  the instant rule (§7) poses: whether the chain was revoked *at* the capture,
  because the status of an expired certificate is no longer published anywhere.
  - `source`: extensible; `googleStatusList` is Android's attestation status
    list. An unknown value → the attachment is ignored and the verdict is the
    one without it (*chain revocation not checked*).
  - `fetched_at`: ms, registry clock, when the status was read.
  - `entries`: one per certificate looked up — `{ "serial": lowercase hex of
    the certificate serial number, "status": "valid" | "revoked" | "unknown",
    "reason": optional string }`.
  - `sig`: the registry signing key's ES256 signature, P1363, over
    `core_hash ‖ JCS(entries) ‖ uint64 BE fetched_at`.

  **Which key.** The signing key is the one that signs that log's tree heads,
  so a verifier needs no key it does not already hold for `registry`. The
  attachment carries no `log_id` of its own: when a `registry` attachment is
  present its `log_id` names the key; otherwise a verifier tries the keys of
  the logs it trusts and the signature identifies the one that made it. A
  verifier holding no log key reports *chain revocation not checked* — the same
  outcome as an absent attachment, because a countersignature it cannot check
  is evidence it does not have. Adding a `log_id` to the attachment would be a
  new optional key and is deliberately not done: it would let a proof point a
  verifier at a key, and the verifier's own trust list must decide that.

  Google's status list is served over TLS and carries no signature of its own,
  so the only thing a proof can carry is the registry's countersignature of
  what the registry saw — the same construction as `integrity`, and with the
  same limit: **evidence, never a verdict**. A verifier that trusted a
  "we checked, it was fine" statement from us would be trusting us, which is
  the property this format exists not to require.

  Revocation of a chain certificate is **temporal**, exactly as in the device
  key's case above. Let `T` be the proven instant of §7. A `revoked` entry with
  `fetched_at ≤ T` means the chain was already revoked when the capture was
  claimed: proven level `none`, *attestation key revoked*, red for the level. A
  `revoked` entry with `fetched_at > T` means it was revoked afterwards: the
  level at `T` stands, shown with *attestation key revoked after the capture* —
  a batch key withdrawn in 2028 does not un-attest a capture from 2026, for the
  same reason a rotated device key does not rewrite the past. `unknown` and a
  missing entry are *chain revocation not checked*, amber.

- **`registry`** — everything a verifier needs to check, **offline**, that the
  signing key was in the transparency log when the tree head was signed. Not a
  reference to be resolved: the proof carries the evidence.
  - `log_id`: SHA-256 of the log's public key (DER SPKI), base64url. The verifier
    ships the public keys of the logs it trusts, keyed by this.
  - `leaf_index`: integer.
  - `leaf`: the log leaf as recorded — `{ "type": "key", "key_id", "public_key",
    "secure_hw", "attestation_digest", "registered_at" }`, integers and
    base64/hex strings only; the verifier serializes it with JCS and hashes
    `SHA-256(0x00 ‖ bytes)` (RFC 6962 leaf hash).
  - `inclusion_path`: the RFC 6962 audit path, base64url hashes, bottom first.
  - `tree_head`: `tree_size`, `timestamp` (ms, log clock), `root_hash`
    (base64url), `signature` — ES256 by the log key in P1363 over the
    fixed-length message `"vcap/1.0/sth" ‖ uint64 BE tree_size ‖ uint64 BE
    timestamp ‖ root_hash`, `SHA-256(0x01 ‖ left ‖ right)` for nodes.

  A verifier MUST check, in this order: the tree head signature under the
  trusted key for `log_id`; the leaf hash's inclusion at `leaf_index` in a tree
  of `tree_size` leaves with root `root_hash`; `leaf.key_id == device.key_id`
  and `leaf.public_key` equal to `sig.pub`. Any failure → *registry evidence
  invalid*, red for the attachment (the core is unaffected: the capture is
  still signed by the key, only "in the log" is not proven). `leaf.secure_hw`
  is the level the log saw proven at registration; it MUST NOT exceed the level
  proven by `attestation` when both are present.

  **Before the capture.** `tree_head.timestamp` is when the log signed a tree
  containing the key. If it exceeds `time.device_clock`, the key was logged
  after the declared capture time: *registered after the declared capture*,
  shown, amber. When a `timestamp` attachment exists, `tree_head.timestamp`
  MUST also not exceed the token's time. Revocation is not visible in this
  attachment — it is a later leaf — and is checked online against the log
  (§7, *revocation not checked* when offline).

  **Revocation, online.** A verifier with network asks the log for the key's
  status **at the capture time** and receives a statement signed by the log
  key over the fixed-length message `"vcap/1.0/status" ‖ key_id (32) ‖ uint64
  BE at ‖ uint64 BE tree_size ‖ status (1 byte: 0x00 unknown, 0x01 valid, 0x02
  revoked)`, together with the tree head of `tree_size` and, when revoked, the
  revocation leaves with their inclusion proofs. Nothing in a Merkle tree
  proves a leaf does *not* exist, which is why the answer is signed.
  Revocation is **temporal**: a revocation leaf carries `effective_from`, and a
  capture at `T` is affected only if `effective_from ≤ T` — a lost or rotated
  key does not rewrite the past — unless the leaf is `retroactive`, which the
  log accepts for the reason `compromise` only: a compromised key vouches for
  nothing it ever signed. The instant a verifier asks about is
  `time.device_clock`, or the `timestamp` token's time when present (the
  trusted bound). *Revoked at the declared capture time* → **red** for the
  key's standing, shown with the reason.
- **`anchor`** — existence before a block, verifiable against the chain and
  nothing of ours. `chain` names the network (`base`, `base-sepolia`);
  `tx` and `block` locate the anchoring transaction; `anchor_id` is the
  contract's sequential id of the batch; `root` (base64url) is the batch root
  the contract recorded with `tree_size` leaves; `index` is this proof's
  position; `merkle_path` is the RFC 6962 audit path, base64url, bottom first.
  Leaves are `SHA-256(0x00 ‖ core_hash)` and nodes `SHA-256(0x01 ‖ left ‖
  right)` — the same tree as the transparency log, so a verifier carries one
  Merkle implementation. A verifier MUST recompute the root from `core_hash`,
  `index`, `tree_size` and `merkle_path`, then read `(root, tree_size)` for
  `anchor_id` from the contract (or a light client) and compare both; the
  block's timestamp is the proven upper bound. Without network: *anchoring not
  verified*, amber, never red.
- **`integrity`** — `source` is `playIntegrity`, `appAttest` or `none`;
  `verdict` is `hardware`, `basic`, `unevaluated` or `failed`; `evaluated_at`
  is the registry's clock; `sig` is the registry signing key's ES256 signature
  over `core_hash ‖ UTF-8(verdict)`, P1363. Integrity verdicts are tokens only
  the developer's server can decrypt, so they cannot live in the core as
  anything but a self-declaration — and a self-declaration by the app is
  worthless against the compromised device it exists to flag. As a
  registry-signed attachment the verdict is Google's or Apple's, relayed and
  signed by a key the verifier already has for tree heads. Absent →
  *integrity unevaluated* (§8). The server *adds* evidence; it is never
  *needed* for a verdict.
- **`timestamp.tsr`** — RFC 3161 TimeStampToken, base64url DER, whose
  `messageImprint` **is `core_hash`** (hash algorithm `sha256`, hashed message =
  the 32 bytes of `core_hash`). A timestamp over `media.hash` would prove the
  pixels existed before T; over `core_hash` it proves the pixels *and the
  claims* did — same cost.

No field carries personal data: the mapping key → organization → operator lives
in the registry, behind access control. `device.key_id` is a **pseudonym** for
the device+app installation, and every capture from it is linkable through it,
whatever `policy.pseudonymous` says: that flag hides the operator, not the
device. Per-capture keys would break the link and are out of scope for v1.0.

---

## 7. Decision 4 — How the proof level is declared

Two things carry it: the **claimed** level in `device.secure_hw`, and the
**proven** level the verifier derives from the attestation attachment. The
verdict is bounded by the proven level, and by the weakest link. This is the
field set that stops the web SDK and iOS from presenting themselves as Android
with StrongBox.

**Proven level.** Android: the weaker of `attestationSecurityLevel` and
`keyMintSecurityLevel` in the attestation extension, with the chain valid to a
pinned Google root and the leaf key equal to `sig.pub`; `software`, an invalid
chain or a key mismatch prove `none`. iOS: `secureEnclave` when the registry
entry records a valid App Attest binding for `device.key_id`. Web: `none`.

| proven level | attestation / binding | key in log before capture | verdict ceiling | label shown |
|---|---|---|---|---|
| `strongbox` | valid to Google hardware root, RKP fresh, revocation checked | yes | **green** | sealed in secure hardware |
| `tee` | valid to Google root, revocation checked | yes | **green** | sealed in the TEE |
| `secureEnclave` | App Attest valid, key bound to app | yes | **green** | sealed in the Secure Enclave (app-attested) |
| any of the above | valid | no (`registry` absent), or its evidence invalid | **amber** | key not in the transparency log |
| any of the above | valid | yes, but `tree_head.timestamp` after the declared capture | **amber** | registered after the declared capture |
| any of the above | valid, log not reachable | any | **amber** | revocation not checked |
| any | key revoked at the declared capture time (signed status, §6.2) | — | **red** | key revoked |
| any | a chain certificate `revoked` at or before the proven instant (`attestation_status`, §6.2) | — | **red** | attestation key revoked |
| any of the above | a chain certificate revoked *after* the proven instant | any | unchanged | attestation key revoked after the capture |
| any of the above | valid at the proven instant of capture, expired since | any | unchanged by the expiry | (nothing: expiry alone says nothing) |
| any of the above | expired, and the capture time is only `time.device_clock` | any | **amber** | attestation chain expired, capture time not proven |
| `none` | session key, or no attestation | n/a | **amber, never green** | origin not hardware-attested |
| any | claimed level above the level the `attestation` attachment proves | — | **amber at best, flagged** | inconsistent claim |
| any | `integrity.verdict` is `failed`, or mock location provider flagged | — | **amber at best, prominently flagged** | device integrity failed |
| any | `sig` invalid, or attestation leaf ≠ `sig.pub` | — | **red** | tampered |

- **Claimed above proven** is flagged and capped at amber, not red: the core is
  signed by the device, so the false claim is the device's, but a firmware that
  misreports its level must not turn a genuine capture into "tampered". Claimed
  below proven: proven wins, nothing shown. The label needs evidence to
  contradict the claim: with no `attestation` attachment the proven level is
  `none` and the only label is *origin not hardware-attested*, whatever the
  claim (vectors 01, 12, 15 claim `tee` with no chain).
- **A self-chosen attestation challenge is allowed.** A device that never
  enrolled produces a genuine chain over a challenge it picked itself; the
  chain still proves the hardware level, and the missing registry entry lands
  the capture in the *key not in the transparency log* row. Offline capture is
  never an error and never green.
- **The instant of validation.** Every certificate path in a proof — the
  `attestation` chain, the TSA chain of a `timestamp` token — MUST be validated
  at the **proven instant of the capture**, not at the moment the verifier
  runs. That instant is, in this order: the `genTime` of a valid `timestamp`
  token; the block time of a verified `anchor`; `time.device_clock`, which is a
  device claim and caps the verdict at amber whatever else holds. A chain that
  was valid at that instant and has expired since is **not** an error. The
  reason is measured, not theoretical: in the real chain of the moto g75 5G the
  RKP-issued intermediate is valid from 6 to 18 September 2026 — twelve days —
  so a verifier that validated at its own clock would report *origin not
  hardware-attested* for every capture from that device from 19 September on,
  and a year-old proof would be indistinguishable from one that never carried a
  chain. Expired with no trusted instant → amber, with
  *attestation chain expired, capture time not proven*; never red, because an
  expired chain says the verifier is late, not that the capture is forged. §6.2
  already states this rule for the device key's revocation — this is the same
  rule, for the same reason, applied to the chain.
- **A verifier MUST name the level.** Collapsing three different roots of trust
  into one green light is the failure mode this table exists to prevent: an
  insurer's expert who later learns that "green" included a browser session key
  stops trusting every green we ever issued.
- `secure_hw` is **not** an extensible enum: adding a value changes the table, so
  it requires a minor version bump, and a v1.0 verifier meeting an unknown value
  MUST treat it as `none`. Treat it, not reject it: non-extensible binds the
  writer, and a reader that refused the file would make a capture from a newer
  minor unverifiable while its core signature is perfectly valid, which is what
  §9 exists to prevent. The same holds for an unrecognised `device.platform`,
  which proves `none` for want of anything to prove it with. A JSON Schema for
  v1.0 rejects such a document and is right to — *"not a v1.0 document"* and
  *"still verifiable"* are different statements (vector 40).

---

## 8. Decision 5 — Optional versus invalidating

**Required.** `v`, `capture_id`, `media`, `device.secure_hw`, `device.key_id`,
`sig`, and for a video proof `media.segment_count` and `segments`. A proof is
a **video proof** when `media.mime` starts with `video/`; nothing else decides
it — not the container, not `duration_ms` — so a video proof without
`segments` is *no proof found*, and a still image carrying `segments` is
verified as §5 says. Missing or unparseable → *no proof found*. Present but
invalid → *tampered*.

**Optional, each with its exact label when absent.** Absence is never an error,
and the verifier states it rather than staying silent. Labels accompany
non-red verdicts only: a red verdict carries its reason and nothing else,
because "no trusted time" on a tampered file is noise.

| Absent | Label | What it means |
|---|---|---|
| `timestamp` | *no trusted time* | only the device clock, shown as declared |
| `anchor` | *not anchored* | existence before a block is not proven |
| `registry` | *key not in transparency log* | the key may be genuine, but nobody can check its registration or revocation |
| `attestation` (Android) | *origin not hardware-attested* | proven level `none` |
| `integrity` | *integrity unevaluated* | no statement about the device's state |
| `watermark` | *no watermark* | the detector did not run, or no mark was looked for |
| `location` | nothing shown | absence is not a claim about place |
| `policy.retention_ref` | nothing shown | no vault involved |

**A declared watermark that does not come back.** `watermark` is the writer
saying a mark was embedded; it is not a promise that a reader will find it, and
a reader that does not find one never guesses. Three outcomes, all non-red:

| Outcome | Label |
|---|---|
| the payload decodes and matches the proof | *watermark matched* |
| the layout is known, the payload does not decode | *watermark not recovered* |
| the layout is not one this verifier implements | *watermark not evaluated* |

*Watermark matched* is a label, not a verdict: the verdict still comes from
`sig`, and the rule at the end of this section is what applies when a mark
matches and no valid signature is there — *origin traced*, never authentic.

*Watermark not recovered* is the normal outcome of heavy re-compression, and a
verifier shows whatever confidence figure the layout defines next to it (for a
repetition layout, the agreement between copies). A layout may define no
partial answer at all — a block code either corrects or does not — and then
there is nothing to show but the label. Neither outcome weakens a signature:
§8 already says an absent field is a weaker verdict, not an error, and a
watermark is not part of what `sig` covers.

**A mark id is not an identifier.** For `video-rep-v1` the payload is
`watermark.mark_id`, a 24-bit value the proof binds to the 128-bit
`capture_id`; it is short because a re-encoded clip cannot carry more, not
because it is unique. Collisions are expected — 24 bits collide with even
odds a few thousand captures in — so two proofs carrying one `mark_id` are
both valid, and origin search from a mark alone answers with a candidate set,
which the caller narrows with a proof, a time window or a tenant. A verifier
that treats a mark id as a key to one capture is wrong, not unlucky.

**Degraded, with its label.** Revocation list unreachable → *revocation not
checked*. A verifier that is offline says so and caps at amber; a server-side
validator with no list fails closed. Same fact, two contexts, both written here.

**Invalidating — red.** `sig` invalid over `JCS(core)`; attestation leaf key
different from `sig.pub`; a present segment whose `content_hash` recomputed from the container
differs from the signed one (§5); a watermark payload that **decodes** to an id other
than the one the proof declares (`capture_id` for `photo-bch-v3`,
`watermark.mark_id` for `video-rep-v1`) — a payload that fails to decode is
*watermark not recovered*, above, and not this; a segment signature invalid, or the chain broken where the file claims
contiguity; footer structurally valid with a CRC mismatch (*corrupted proof*,
distinct from *no proof found*).

**Not red.** `media.hash` not matching the recomputed canonical bytes on a video
whose present segments verify → *verified clip* (§5). On a photo, a `media.hash`
mismatch with a valid `sig` means the file was altered after sealing: **red**.

**The rule that outranks the table.** A watermark match with no valid signature is
**origin traced**, never authentic — and where the original is available, shown
side by side with it.

---

## 9. Decision 6 — Compatibility policy

- `v` is `vcap/MAJOR.MINOR`, and it is inside the signed core: a downgrade is
  signed content and fails the signature.
- **Same major, unknown minor**: verify every field you know, list the unknown
  top-level keys as *not evaluated*, and never fail. Unknown keys are outside
  the core (§6.1), so they do not disturb the signature. A newer capture must
  not be unverifiable by an older verifier.
- **Unknown major**: *unsupported format version*, with the version shown.
- **After the 1.0 tag, additive only**: new optional keys, and new values only in
  fields documented as extensible (`watermark.layout`, `location.evidence[].kind`,
  `timestamp.tsa_issuer`, `integrity.source`, `attestation_status.source`).
  Every extensible field states the fallback for an older verifier. A new value
  in such a field is a short machine name in one of the two spellings the format
  already uses — lowercase-hyphen (`bch-255-131`, `base-sepolia`) or camelCase
  (`secureEnclave`, `playIntegrity`, `googleStatusList`) — and the schema
  accepts both. It once accepted only the first, which made `googleStatusList`
  schema-invalid in the same document that named it. `device.secure_hw`, `sig.alg`, the set of
  core keys and the segment message layout are **not** extensible: changing any
  of them is a new minor with a new separator (§5) or a new major.
- **Never** reuse a key name with a different meaning, never promote an optional
  key to required, never change the meaning of an existing enum value. A layout
  change desynchronizes every already-sealed file: add a version instead.
- The watermark layout is declared in the proof and numbered, so a detector knows
  which decoder to run without guessing.

---

## 10. What this format does not prove

Stated here because a verifier UI must be able to say it, and because an expert
who finds it out later stops trusting the rest:

- **That the scene is real.** Filming a screen produces a genuine recording of a
  fake. Mitigations exist (sensor coherence, depth, temporal consistency) but no
  certainty. `secure_hw` says where the bytes were signed, not what was in front
  of the lens.
- **Who held the device.** The proof binds a key to hardware and, through the
  registry, to an organization — not to a person. And the key is a pseudonym for
  the device, linkable across captures (§6.2).
- **Where it was**, beyond the level `location.level` declares (C15).
- **That the device was not compromised** below the attestation boundary: a
  rooted device with a virtual camera can sign an injected frame. This is why
  `integrity` exists, why it is signed by the registry and not declared by the
  app, and why its failure is prominent.
- **Anything about the C2PA manifest** of a sealed photo. It sits outside the
  canonical bytes (§4.1) and can change without affecting the vcap verdict; it
  is verified by its own signature, separately.

---

## 11. Review status at the freeze

Frozen 9 September 2026. The open items below are follow-ups: each is either
evidence still to collect (measurements, vectors) or a value in a field §9
declares extensible. None of them changes the core keys, the trailer, the
segment message or the meaning of an existing enum value; if one ever needs
to, it arrives as a new minor with a new separator or as a new major, as §9
says.

- [x] `REVIEW (BE)` crc32c availability in Kotlin, Swift, Node — resolved: CRC-32
- [x] `REVIEW (BE)` domain separation of the segment message, no field-shift ambiguity — confirmed, 96 fixed bytes
- [x] `REVIEW (BE)` signature encoding — resolved: P1363, low `s` emitted, both accepted; vector with high `s` and vector with DER
- [x] `REVIEW (BE)` what is signed — resolved: core/attachment split (`reviews/01-crypto-review-draft-1.0.md`)
- [x] `TODO (LEAD)` the vcap SEI UUID — resolved: derived from `"vcap/1.0/sei"`, no registration exists for `user_data_unregistered`; payload defined (`reviews/implementability-android.md`, M4, M5)
- [ ] `REVIEW (mobile)` manifest ordering: after sealing for photos, before for video
- [ ] `REVIEW (mobile)` per-segment signing cost in StrongBox on a long clip
- [~] `REVIEW (mobile)` NAL byte definition and audio DTS rule reproducible on both encoders — the DTS clock is now named (M8) and the timeline with it (edit lists, §5); H.264 and HEVC on Android are reproduced byte for byte by a second implementation written from this text (`tools/src/container.ts`, vectors 36–37), which is what "reproducible" was asking; iOS pending (S1)
- [x] `REVIEW (mobile)` hashing two interleaved tracks during encoding — resolved: 8 KB and 0.5 ms per segment on a TEE device (M8)
- [ ] `REVIEW (mobile)` metadata stripping before sealing for pseudonymous captures
- [x] `REVIEW (ML)` `watermark.layout` values and what the detector reports when
      the layout is declared but the payload does not decode — resolved in §7:
      *origin traced* / *watermark not recovered* / *watermark not evaluated*,
      all non-red, and a decoded mismatch is the only red case
- [x] `REVIEW (ML)` 24-bit `mark_id` collision probability and behaviour on two
      proofs claiming one `mark_id` — resolved in §7: collisions are expected a
      few thousand captures in, both proofs stay valid, and origin search from a
      mark answers with a candidate set
- [x] Vectors for the trailer, canonical bytes, core signature, version policy,
      the segment chain at message level, the §8 video rule, JPEG fill bytes,
      the container-level video cases (36–39) and the §7 proof level (41–45:
      `tee`, `strongbox`, a chain expired since the capture, and a frozen
      revocation snapshot on either side of the instant): **45** in `vectors/`,
      checked by the reference verifier in `tools/` (steps 4–5). The §7 vectors
      trust the anchors in `vectors/_trust/`, whose attestation root is a test
      root: they prove the level logic, not that an implementation can walk a
      real Google chain — for which the real device chains in the two verifier
      repositories exist
- [ ] `REVIEW (BE)` the remaining proof-level vectors: registry inclusion with
      a signed tree head, an RFC 3161 token, an anchor with a recomputed root.
      The reference verifier evaluates none of the three yet, which is why the
      attested vectors top out at amber
- [~] `REVIEW (mobile)` container-level video vectors: real MP4/MOV from each
      encoder, with `content_hash` recomputed from the NAL units and audio
      frames — Android H.264 and HEVC done (vectors 36–39, `kind: container`);
      iOS after S1, and the MOV branch with it
- [ ] `REVIEW (BE)` whether a verifier that cannot recompute segment hashes must
      say so in its labels, the way it says *integrity unevaluated*. Adding a
      label is additive under §9, but it changes the expected labels of every
      video vector, so it is a decision and not an edit
- [ ] Vectors for the proof level (§7): attestation chains, registry entries,
      revocation — after C6 exposes the material
- [ ] Vectors for `timestamp` and `anchor` attachments — after C7/C8
- [x] JSON Schema validates every vector, and rejects each malformed case:
      `schema/vcap-proof-1.0.schema.json`, run by `tools` in CI (step 6)
