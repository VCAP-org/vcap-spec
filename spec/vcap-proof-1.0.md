# vcap proof format, version 1.0

**Status: DRAFT for review — not frozen.** Written 8 September 2026 as step 1 of
the work order in `Doc/06-fase1-avvio.md` §3. The six format decisions below are
**taken, not offered as options**; what remains is the crypto review (step 2, BE)
and the implementability review (step 3, mobile + ML). Each open question is
marked `REVIEW`.

Until the `v1.0` tag: breaking changes expected. After it: additive only.

## 1. Scope

This document defines the artefact a capture pipeline produces and a verifier
consumes: its binding to the media file, the byte sequence signatures cover, the
JSON structure, and the verdict semantics of every field.

It does not define transport, registry APIs, or watermark internals. It does
define what a verifier may and may not conclude, because that is the part four
independent implementations must agree on.

## 2. Terminology

- **capture** — one photo or one video clip sealed at the moment of recording.
- **capture id** — 128-bit random identifier, also carried by the watermark.
- **canonical bytes** — the byte sequence signatures cover (§5).
- **trailer** — the block appended to the media file carrying the proof (§4).
- **segment** — for video, one GOP (§6).
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
 │ crc32c      : uint32 BE, over the payload bytes           │
 └───────────────────────────────────────────────────────────┘
```

- **All integers big-endian**, per ISO-BMFF convention.
- **No padding, no alignment.** BMFF box sizes are byte counts and boxes need no
  alignment; padding would only create a second way to write the same proof.
- **Reading procedure.** Read the last 16 bytes; if `magic != "VCAP"`, the file
  carries no trailer — this is *no proof found*, not an error. Otherwise the
  payload occupies `[len(F) - 16 - payload_len, len(F) - 16)`, and the box header
  the 8 bytes before it. A reader MUST verify that `box_size == 8 + payload_len +
  16` and that `crc32c` matches; a mismatch is **corrupted proof**, reported as
  such and never as *no proof found*. The distinction matters: one means the
  platform stripped the metadata, the other means somebody edited the file.
- **`flags` are a dispatch hint and never a source of truth.** Bit 0: a sidecar
  exists. Bit 1: segments present (video). Bit 2: pseudonymous capture. Bits
  3–15 reserved, MUST be written as zero. Everything the flags say is also in
  the JSON, and the JSON wins on disagreement — so an attacker gains nothing by
  flipping them. Unknown reserved bits are ignored, not fatal.
- **Sidecar.** The same JSON, byte-identical, in `<filename>.vcap` next to the
  file. Used when a pipeline cannot append to the container, and always allowed
  as a redundant copy. A sidecar has no footer.
- **The magic carries no brand** (decision P8): `VCAP` is the codename, and
  sealed files are immutable while the product name is provisional.

`REVIEW (BE)`: crc32c vs crc32 — Castagnoli is hardware-accelerated on both
target platforms; confirm no library friction in Kotlin, Swift and Node.

---

## 4. Decision 2 — Canonical bytes

The signature must cover the media and nothing else, identically in five
implementations. This is the first place independent implementations diverge, so
the rule is a procedure, not a description.

Given the received file `F`:

1. **Strip the trailer.** If the last 16 bytes are a valid footer, let
   `T = 8 + payload_len + 16` and `F' = F[0 : len(F) - T]`. Otherwise `F' = F`.
2. **Container normalization.**
   - **JPEG**: remove every `APP11` segment whose payload begins with the JUMBF
     identifier used by C2PA, and only those. Concatenate the remaining bytes in
     original order → `C`.
   - **ISO-BMFF** (MP4, MOV, HEIC): `C = F'` unchanged. Nothing is removed.
3. **Hash.** `H = SHA-256(C)`, 32 raw bytes. `media.hash` is `H` in base64url.
4. **Sign.** ECDSA P-256 over `H` as a raw 32-byte message digest (`SHA256withECDSA`
   semantics: the implementation hashes `C`, then signs `H`). The signature is
   stored DER-encoded, base64url. A WebCrypto verifier converts DER to P1363.

The asymmetry between containers is deliberate and follows from where each
standard puts its own hash:

- **Photos embed the C2PA manifest AFTER sealing**, because the JPEG hard binding
  hashes to end-of-file; if the manifest were inside the canonical bytes, adding
  it would invalidate the vcap signature it depends on. So it is excluded.
- **Video embeds the manifest BEFORE sealing**, because BMFF hashing ignores the
  trailing `free` box; the manifest is inside the canonical bytes and stays there.

**Required vectors** (one file each): JPEG with C2PA, JPEG without C2PA, HEIC,
MP4, MOV, MP4 that already contained an unrelated `free` box, JPEG with two
APP11 segments of which one is not C2PA, file with a footer but truncated
payload, file with valid footer and wrong crc32c.

`REVIEW (mobile)`: confirm that on both platforms the manifest writer can be
ordered after sealing for photos and before for video without a second full
re-encode.

---

## 5. Decision 3 — Video signature granularity

One signature per **segment**, where a segment is one GOP: from an IDR access
unit up to, but excluding, the next IDR.

For segment `n`:

```
content_hash(n) = SHA-256( concat of the segment's coded sample payloads,
                           in decode order,
                           EXCLUDING every vcap SEI NAL unit,
                           EXCLUDING container box headers and sample tables )

message(n)      = "vcap/1.0/seg" || capture_id (16 B)
                                 || uint32 BE n
                                 || content_hash(n) (32 B)
                                 || prev_link(n) (32 B)

prev_link(0)    = 32 zero bytes
prev_link(n)    = SHA-256( sig(n-1) )

sig(n)          = ECDSA-P256( SHA-256( message(n) ) )
```

- **vcap SEI NAL units are excluded from what they cover.** They are
  `user_data_unregistered` SEIs carrying a registered UUID; a signature cannot
  cover the bytes that contain it, and defining the exclusion by NAL type is the
  only way two encoders agree.
- **The chain is the point.** `prev_link` makes order and completeness provable:
  a reordered segment breaks the chain, and a clip whose first segment is not
  index 0 is detectably a clip, not an original. Without chaining, per-GOP
  signing would let anyone reassemble a plausible video from genuine pieces.
- **Verifier behaviour** on video:
  - every segment present in the file verifies, chain unbroken, first index is 0,
    no gaps → eligible for **green** (subject to §7);
  - segments verify, chain unbroken, but index 0 absent or a gap present →
    **verified clip**, amber, reporting which ranges verified;
  - a segment fails, or the chain breaks where the file claims contiguity →
    **tampered**, red;
  - `segments[].range` (byte range in the received file) is informational and
    **not signed**: it helps a UI point at a frame, and a verifier MUST NOT
    conclude anything from it.

Photos have no `segments`; their signature is the one in §4.

`REVIEW (mobile)`: GOP length in practice — a 2-second GOP on a 10-minute clip is
300 signatures. Confirm the per-signature cost in StrongBox (the slow path) and,
if it is prohibitive, propose a segment = N GOPs grouping *with* the chain kept.
`REVIEW (BE)`: confirm the domain separator string and that no field can be
shifted between `capture_id` and `content_hash` without changing the digest.

---

## 6. Proof structure

```
{
  "v": "vcap/1.0",
  "capture_id": "base64url, 16 bytes",
  "media":    { "mime", "w", "h", "duration_ms", "hash" },
  "sig":      { "alg": "ES256", "value": "base64url DER", "pub": "base64url SPKI" },
  "segments": [ { "gop": 0, "range": [start, end], "hash", "sig" } ],
  "watermark":{ "algo", "layout": "photo-bch-v3" | "video-rep-v1",
                "payload_bits", "ecc", "strength", "mark_id" },
  "device":   { "platform": "android" | "ios" | "web",
                "secure_hw": "strongbox" | "tee" | "secureEnclave" | "none",
                "attestation": "base64url chain, omitted on web",
                "integrity":  { "source", "verdict" },
                "key_id" },
  "registry": { "log_id", "leaf_index", "sth_ref" },
  "time":     { "device_clock", "tsr", "tsa_issuer" },
  "anchor":   { "chain", "tx", "block", "merkle_path" },
  "location": { "level", "lat", "lon", "acc_m", "evidence": [ ... ] },
  "policy":   { "pseudonymous": true|false, "retention_ref" }
}
```

Field table — type, required, producer, verifier:

| Field | Required | Produced by | Verified against |
|---|---|---|---|
| `v` | yes | core | §8 version policy |
| `capture_id` | yes | core | watermark payload, segment messages |
| `media.hash` | yes | core | recomputed from canonical bytes |
| `sig` | yes (photo) | core | `media.hash`, `device.key_id` |
| `segments` | yes (video) | core | §5 |
| `watermark` | no | core | detector output, if the detector ran |
| `device.secure_hw` | yes | core | attestation chain (§7) |
| `device.attestation` | no (yes on android) | core | registry, Google roots |
| `device.integrity` | no | core | §7 |
| `registry` | no | sync | transparency log inclusion proof |
| `time.tsr` | no | sync | RFC 3161 validation, offline |
| `anchor` | no | sync | chain RPC or light client |
| `location` | no | core + sync | §7 of the platform spec (C15) |
| `policy.pseudonymous` | no | core | consistency: no device identifiers present |

`capture_id` is opaque. No field carries personal data: the mapping key →
organization → operator lives in the registry, behind access control.

---

## 7. Decision 4 — How the proof level is declared

Two fields carry it, and the verdict is bounded by the weakest link. This is the
field set that stops the web SDK and iOS from presenting themselves as Android
with StrongBox.

| `secure_hw` | attestation | key in log before capture | verdict ceiling | label shown |
|---|---|---|---|---|
| `strongbox` | valid to Google hardware root, RKP fresh | yes | **green** | sealed in secure hardware |
| `tee` | valid to Google root | yes | **green** | sealed in the TEE |
| `secureEnclave` | App Attest valid, key bound to app | yes | **green** | sealed in the Secure Enclave (app-attested) |
| any of the above | valid | no, or unknown | **amber** | key not in the transparency log |
| `none` | session key only | n/a | **amber, never green** | web-attested origin |
| any | integrity failed, or mock location provider flagged | — | **amber at best, prominently flagged** | device integrity failed |
| any | signature invalid | — | **red** | tampered |

- `device.integrity.source` is `playIntegrity`, `appAttest` or `none`;
  `verdict` is `hardware`, `basic`, `unevaluated` or `failed`.
- **A verifier MUST name the level.** Collapsing three different roots of trust
  into one green light is the failure mode this table exists to prevent: an
  insurer's expert who later learns that "green" included a browser session key
  stops trusting every green we ever issued.
- `secure_hw` is **not** an extensible enum: adding a value changes the table, so
  it requires a minor version bump, and a v1.0 verifier meeting an unknown value
  MUST treat it as `none`.

---

## 8. Decision 5 — Optional versus invalidating

**Required.** `v`, `capture_id`, `media`, `device.secure_hw`, and a signature
(`sig` for photos, `segments` for video). Missing or unparseable → *no proof
found*. Present but invalid → *tampered*.

**Optional, each with its exact label when absent.** Absence is never an error,
and the verifier states it rather than staying silent:

| Absent | Label | What it means |
|---|---|---|
| `time.tsr` | *no trusted time* | only the device clock, shown as declared |
| `anchor` | *not anchored* | existence before a block is not proven |
| `registry` | *key not in transparency log* | the key may be genuine, but nobody can check revocation |
| `watermark` | *no watermark* | a compressed copy cannot be traced back |
| `location` | nothing shown | absence is not a claim about place |
| `policy.retention_ref` | nothing shown | no vault involved |

**Invalidating — red.** Signature present but invalid; recomputed canonical bytes
not matching `media.hash`; `capture_id` in the watermark different from the proof;
segment chain broken where the file claims contiguity; footer present with a
crc32c mismatch (*corrupted proof*, distinct from *no proof found*).

**The rule that outranks the table.** A watermark match with no valid signature is
**origin traced**, never authentic — and where the original is available, shown
side by side with it.

---

## 9. Decision 6 — Compatibility policy

- `v` is `vcap/MAJOR.MINOR`.
- **Same major, unknown minor**: verify every field you know, list the unknown
  top-level keys as *not evaluated*, and never fail. A newer capture must not be
  unverifiable by an older verifier.
- **Unknown major**: *unsupported format version*, with the version shown.
- **After the 1.0 tag, additive only**: new optional keys, and new values only in
  fields documented as extensible (`watermark.layout`, `location.evidence[].kind`,
  `time.tsa_issuer`). Every extensible field states the fallback for an older
  verifier. `device.secure_hw`, `sig.alg` and the segment message layout are
  **not** extensible.
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
  registry, to an organization — not to a person.
- **Where it was**, beyond the level `location.level` declares (C15).
- **That the device was not compromised** below the attestation boundary: a
  rooted device with a virtual camera can sign an injected frame. This is why
  `integrity` exists and why its failure is prominent.

---

## 11. Review checklist before the freeze

- [ ] `REVIEW (BE)` crc32c availability in Kotlin, Swift, Node
- [ ] `REVIEW (BE)` domain separation of the segment message, no field-shift ambiguity
- [ ] `REVIEW (BE)` DER vs P1363 conversion covered by a vector on each side
- [ ] `REVIEW (mobile)` manifest ordering: after sealing for photos, before for video
- [ ] `REVIEW (mobile)` per-segment signing cost in StrongBox on a long clip
- [ ] `REVIEW (mobile)` SEI exclusion by NAL type reproducible on both encoders
- [ ] `REVIEW (ML)` `watermark.layout` values and what the detector reports when
      the layout is declared but the payload does not decode
- [ ] All vectors of §4 exist with an expected verdict written before any code
- [ ] JSON Schema validates every vector, and rejects each malformed case
