# vcap proof format, version 1.0

**Status: `vcap/1.0` DRAFT — the six format decisions are settled, the wire
contract is not yet binding.** There is no `v1.0` tag and no public release:
both were removed on 22 September 2026, because nothing advertises a version
that does not exist yet. Written 8 September 2026, amended the same day after
the cryptographic review (`reviews/01-crypto-review-draft-1.0.md`) and on
9 September after the implementability review on real hardware
(`reviews/implementability-android.md`).

**When the format freezes.** The additive-only rule of §9 starts at the first
publication: the first build, SDK or sealed file that reaches somebody else.
An internal testing track is not one (22 September 2026, `CHANGELOG.md`).
Until then a breaking change is allowed, because the only sealed
files in existence are test vectors and our own devices' output, and we can
re-seal both — so a change need not carry a fallback for older files either.
After it, never — the constraint does not come from our
discipline but from the files we cannot re-sign, in hands that are not ours.
Every breaking change taken while this notice stands is recorded in
`CHANGELOG.md` as such, and the in-file version string stays `vcap/1.0`: a
draft label belongs on a tag, never in bytes that outlive it.

The string `"v": "vcap/1.0"` is therefore already permanent. What is still
open is the shape around it; §11 lists it.

## 1. Scope

This document defines the artefact a capture pipeline produces and a verifier
consumes: its binding to the media file, the byte sequences signatures cover,
the JSON structure, and the verdict semantics of every field.

It does not define transport, registry APIs, or the watermark model. The
**payload layouts** it names in `watermark.layout` are defined in
`watermark-layouts-1.0.md`, next to this file: a verifier that cannot read the
payload cannot say *watermark matched*, and a field name is not enough to write
a second decoder from. The model behind them — weights, exported graphs,
digests — stays outside a wire contract and is fetched by digest.

It does define what a verifier may and may not conclude, because that is the
part four independent implementations must agree on.

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
  The sum is computed without overflow — in 32 bits, `payload_len = 2^32 − 1`
  wraps to 23 and points a reader into the footer (vector 118). If any of
  these fails, the file carries no trailer: *no proof found*, not an error —
  with one exception: `magic == "VCAP"` and `major != 1` is **unsupported
  format version**, with the major shown (vector 115). The magic says a vcap
  trailer is there and the major says it is not one this reader implements;
  a reader does not interpret the rest of a footer of a major it does not
  know, and *no proof found* would tell a reader the proof was stripped. If the structure holds and `crc32` does not match the payload, the
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
- **Replacing the trailer.** A §6.2 attachment is produced *after* the device
  seals — a TSA mints a token, a batcher mines an anchor — so the evidence a
  capture earns arrives minutes later and somewhere else. A writer MAY
  therefore replace the trailer of a sealed file, under all of:
  1. the bytes before the box header are **unchanged**, byte for byte, so
     `media.hash` still covers what it covered (§4.1);
  2. the new payload's **core (§6.1) and `sig` are byte-identical** to the
     ones being replaced, so the device's signature still covers the same core
     hash — this is what makes the edit performable by a party that cannot
     sign, and it is the only thing that does;
  3. the old trailer is **dropped, not wrapped**: appending a second one is
     the *nested proof* case above, and the result would read worse than the
     file that went in;
  4. the trailer being replaced is **intact**. A writer MUST NOT replace a
     trailer whose CRC does not match: *corrupted proof* is the verdict that
     file has earned, and rewriting it would launder somebody's edit into a
     clean proof.

  `flags` and `minor` are carried over from the trailer being replaced. Nothing
  is required of readers: a replaced trailer is indistinguishable from the
  trailer a writer would have written had the attachments existed at sealing
  time, which is the point. A copy of the file that was exported before the
  replacement stays exactly as valid as it was — it simply carries less
  evidence, which §8 already reports as labels and never as an error.

  What this rule forbids is what a reader could not otherwise catch: an edit
  that moves the media bytes, or one that keeps a signature over a core it no
  longer describes. Both reach the verifier as *tampered* on the existing
  vectors; the rule exists so a writer is not the one discovering that.
- **`flags` are a dispatch hint and never a source of truth.** Bit 0: a sidecar
  exists. Bit 1: segments present (video). Bit 2: pseudonymous capture. Bits
  3–15 reserved, MUST be written as zero. Writers MUST derive bits 1 and 2 from
  the JSON; everything they say is also in the JSON, and the JSON wins on
  disagreement — a verifier MAY warn (*flags disagree*), and an attacker gains
  nothing by flipping them. Bit 0 is not derivable from the JSON and depends on
  what sits next to the file: verifiers MUST NOT check it. Unknown reserved bits
  are ignored, not fatal.
- **Sidecar.** The same JSON, byte-identical, in `<filename>.vcap` next to the
  file: §3.1.
- **The magic carries no brand**: `VCAP` is the codename, and
  sealed files are immutable while the product name is provisional.

### 3.1 The sidecar

The detached form of the proof, for a pipeline that cannot append to the
container, for a file whose trailer a platform stripped, and always allowed as
a redundant copy. Normative; the rationale and what a sidecar does and does not
restore are in `c2pa-interop-1.0.md` §4 and §5.

- **Content.** Exactly the bytes a trailer's payload would carry: the proof
  JSON, UTF-8, no BOM, JCS-canonical of the whole object (§6.1). Nothing else —
  no box header, no footer, no CRC. Those exist for discovery from the end of a
  file and for telling corruption from stripping; a separate file has a length
  of its own and cannot be "stripped" without disappearing. A reader parses it
  as it parses a payload and MUST NOT depend on the canonical form (§6.1); a
  sidecar that is not a JSON object with a well-formed `v` is *no proof found*.
- **Discovery.** The sidecar of `F` is the file named `<filename of F>.vcap` —
  the full name, extension included, plus `.vcap` (`IMG_0001.jpg` →
  `IMG_0001.jpg.vcap`) — in the same directory. A verifier MAY also accept a
  sidecar its caller hands it (two files in one upload, two parts of one
  request). It MUST NOT look anywhere else, and MUST NOT fetch one from a
  location the file or the proof names: nothing in the format names one, and
  the verification path contains no server. Served over HTTP the media type is
  `application/json`; there is no registered type.
- **Precedence.** Read the last 16 bytes first (§3), then:
  1. **Valid footer, CRC matches** → the trailer is the proof. A sidecar, if
     present, is compared **byte for byte** with the payload; not equal is
     *sidecar differs*, a label, and the sidecar is not used for anything
     (vector 18). Byte comparison, not semantic: a writer emits canonical bytes
     in both places and the label is a writer bug or a swapped file, either of
     which the reader should say rather than resolve. The copy the file's
     active C2PA manifest carries, if any (§3.2), is compared too, as
     `JCS(parse(copy)) == JCS(parse(payload))` — a claim generator
     re-serializes the JSON it is given, so bytes are not comparable across a
     manifest (vector 123) — and not equal is *manifest copy differs*, a label;
     the copy is not used for anything (vector 125). A copy that is not a
     well-formed proof (§6.1) differs from any other.
  2. **Valid footer, CRC fails** → *corrupted proof*, whatever the sidecar or
     a C2PA store says (vectors 72, 126). The sidecar is a fallback for a
     trailer that is absent, not a substitute for one that was found and is
     broken: somebody edited the file, and showing another copy of the proof
     as the file's would hide it.
  3. **`VCAP` magic, major ≠ 1** → *unsupported format version* (§3, vector
     115), whatever else the file carries.
  4. **No valid footer** → the proof is the first of, in this order: the proof
     in the active manifest of the file's Content Credentials (§3.2, depth 0);
     the sidecar; the proof of the nearest `parentOf` ancestor that carries
     one (§3.2, depth 1–16). The copy inside the bytes outranks the one beside
     them, as C2PA's embedded store outranks a remote one (15.5.2.1), and the
     sidecar, which is presented as this file's proof, outranks a source's
     (vector 130). A sidecar next to a depth-0 proof is compared with it as
     JCS; not equal is *sidecar differs*, and the sidecar is not used
     (vector 127). The canonical bytes are the **whole** received file (§4.1
     step 1, `F' = F`), including whatever a stale or displaced trailer left
     behind (vector 70). The verdict is computed exactly as for an embedded
     proof, and a verifier MUST NOT weaken it or add a label because the proof
     came from a sidecar or a manifest (vectors 17, 124): where the proof sat
     carries no evidence — `sig` over the core and `media.hash` over the bytes
     carry all of it, and both are recomputed in every case. The one exception
     is a proof found at depth ≥ 1, which is not presented as this file's
     (§3.2, *The verdict*).
  5. **None of these** → *no proof found*.
- **Video.** Recomputing §5 content hashes stays optional and, when skipped,
  declared (*segment content not recomputed*); a sidecar next to a demuxable
  container is the case §5 has in mind.
- **Footer flag bit 0** says a sidecar was written and is a hint: verifiers
  MUST NOT check it (§3).

### 3.2 Content Credentials as a carrier

A C2PA Manifest Store (C2PA 2.4, 11.1.4.2 *Manifest Store*) can carry the proof
as the assertion `io.github.vcap-org.vcap.proof` (`c2pa-interop-1.0.md` §2.1):
a platform or an editor that keeps Content Credentials and drops trailing
bytes still delivers the proof, and a derivation's store keeps its source's
manifest, proof included. Normative for readers since 1.1 (vectors 123–147).
A reader authenticates nothing about the store — no COSE signature, no
certificate, no hashed URI: the proof authenticates itself (§4.2), and whether
the manifest is valid is a C2PA validator's question, answered apart and never
merged into the verdict (`c2pa-interop-1.0.md` §1).

- **Where the store is.** Structure only:
  - **JPEG**: the APP11 segments whose payload begins with `JP` (`0x4A 0x50`),
    grouped by box instance number `En`. A group is a store when its packet
    with sequence number `Z` = 1 holds, after `CI`, `En` and `Z`, a JUMBF
    superbox (`LBox`, `TBox` = `jumb`, `XLBox` when `LBox` = 1) whose
    description box (`jumd`) has TYPE `63327061-0011-0010-8000-00AA00389B71`
    (`c2pa`). Its box is reassembled from the group's packets in file order,
    `Z` = 1, 2, 3 …: the first from `LBox` on, every later one without the
    `LBox` and `TBox` (and `XLBox`) it repeats (ISO 19566-5 D.2; C2PA A.3.1
    *Embedding manifests into JPEG*). A broken sequence is a store that cannot
    be read.
  - **ISO-BMFF**: every top-level `uuid` box with extended type
    `D8FEC3D6-1B0E-483C-9297-5828877EC481` and `box_purpose` `manifest`,
    `original` or `update` (C2PA A.5.1, A.5.3) is a store. Its data starts with
    the 8-byte offset A.5.3 defines, which is skipped.
  - In both, the store is the JUMBF superbox at the start of those bytes, and
    whatever follows it is padding.
  - **More than one embedded store is no carrier** (vector 141). C2PA
    15.5.2.1: they are all invalid and validation proceeds as if none were
    found. On ISO-BMFF an `original` store beside an `update` store counts as
    two: the pair is an update manifest, which no writer may add to a sealed
    file (`c2pa-interop-1.0.md` §3.2), and a reader does not merge them. A
    store that cannot be read is no carrier.
  - **An external store.** When the file embeds none, a verifier MAY read a
    store its caller hands over — a `.c2pa` file, `application/c2pa` (C2PA
    11.4) — as it may a sidecar (vector 132). It MUST NOT look anywhere else
    and MUST NOT fetch one, from a URI the file names or otherwise. An
    embedded store, readable or not, outranks it.
- **Which manifests.** The store's children whose description TYPE is `c2ma`
  (`63326D61-0011-0010-8000-00AA00389B71`), `c2um` (`6332756D-…`) or the
  legacy `c2md` (`63326D64-…`, which C2PA 11.2.2 says consumers accept) are
  manifests (vector 134). A compressed manifest, `c2cm` (`6332636D-…`, 11.2.4),
  is not decompressed in this version: it carries no proof a reader sees and
  points nowhere (vector 138). The **active manifest** is the last manifest
  child (15.5.1). Children of any other type are skipped (11.1.2).
- **Which assertion.** An assertion counts only when its own manifest's claim
  lists it (C2PA 6.6, 10.2.2; vector 142): the claim is the manifest's `c2cl`
  box, one CBOR content box, and the lists are `created_assertions` and
  `gathered_assertions` (claim v2) or `assertions` (v1), by relative
  (`self#jumbf=c2pa.assertions/<label>`) or absolute
  (`self#jumbf=/c2pa/<manifest label>/c2pa.assertions/<label>`) URI. The proof
  is the one listed assertion box in the manifest's assertion store (`c2as`)
  labelled exactly `io.github.vcap-org.vcap.proof`, with description TYPE JSON
  (`6A736F6E-0011-0010-8000-00AA00389B71`), toggles `0x03` or `0x13`
  (vector 133), and exactly one `json` content box, whose bytes are read
  exactly as a trailer's payload (§3, §6.1). A `__n` instance (C2PA 6.4) is
  another assertion and is ignored (vector 135); two boxes with the label are
  no proof (8.4.1: an ambiguous reference is unresolved).
- **Redaction reads as absence.** An assertion that any claim of the store
  lists in `redacted_assertions` is absent, whatever box is still there
  (vector 136), and so is one whose content is the single UUID box C2PA 6.8
  defines — `CAA98EEE-9D4D-F80E-86AD-4DFFCA263973` followed by zeros
  (vector 137).
- **The chain.** From a manifest, the next one up is named by its listed
  ingredient assertion (`c2pa.ingredient`, `.v2` or `.v3`, `__n` instances
  included) whose `relationship` is `parentOf`: its `activeManifest` (v3) or
  `c2pa_manifest` (v1, v2) URI, `self#jumbf=/c2pa/<label>`, names a manifest of
  the same store. With no `parentOf` ingredient, with more than one (C2PA
  15.10.1.2 rejects that manifest, `manifest.multipleParents`), or with a URI
  that names no manifest, the chain stops there. `componentOf` and `inputTo`
  are **never** followed (vector 140): a component is a part, and its proof is
  not the proof of what it was placed in. A manifest is never visited twice
  (vector 139), and the chain is read to depth 16 at most — the active
  manifest is depth 0, its parent depth 1. Only the **nearest** ancestor that
  carries a proof is judged, and a reader never looks for a proof off the
  chain.
- **The verdict.** §4–§8 are unchanged, over the canonical bytes of the
  received file.
  - **Depth 0** reads exactly as a sidecar: the manifest presents the proof as
    this file's. *Authentic* when the bytes are the sealed ones (vector 124);
    *verified clip*, *frames not compared* or *tampered* under §5 for a video
    (vector 146); *tampered* for a photo that is not the one sealed
    (vector 128).
  - **Depth ≥ 1** is the proof of a **source** capture, and the file is a
    derivation its Content Credentials declare. It reaches what the proof
    proves of it — *authentic* for the same bytes, *verified clip* for located
    segments that verify (vector 145) — and nothing is held against it: where
    §4–§8 give *tampered* or *frames not compared*, the outcome is **no proof
    found**, and a verifier says *Content Credentials carry the proof of a
    source capture* (vectors 129, 147). A modification declared in C2PA is not
    an accusation the proof can make. An undeclared one gains nothing either:
    a derivation is never *authentic* or *verified clip* unless the source's
    proof covers its bytes or its located segments, and *no proof found* is
    what a file without a proof of its own has.
- **Diagnostics, not labels.** A verdict carries `proof_source`:
  `{kind: "trailer"}`, `{kind: "sidecar"}` or `{kind: "c2pa", manifest,
  depth}`, `manifest` being the label of the manifest that carried the proof
  and `depth` its place on the chain; a proof from an external store is
  `c2pa` too. For a video proof whose container the verifier read, it carries
  `frames_name_capture`: whether any GOP of the received file has a vcap SEI
  naming the proof's `capture_id`. That is a **locating hint** — an SEI is
  never evidence (§5) — and it says why frames were or were not compared.
  Neither field is a label and neither moves an outcome.

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
2. **Container normalization.** The container is decided by the **first
   bytes of `F'`**, never by `media.mime`: `FF D8` is JPEG, `ftyp` at offset 4
   is ISO-BMFF, and anything else is hashed as it is, `C = F'`. The MIME type
   is a claim inside the proof, and letting a claim choose how the bytes it
   describes are hashed would let a writer pick the rule its file passes.
   - **JPEG**: remove the `APP11` segments (marker `0xFF 0xEB`) whose payload
     — the bytes after the 2-byte segment length — begins with `0x4A 0x50`
     (`"JP"`, the JUMBF common identifier), **except** those of a JUMBF box
     whose type can be read and is not the C2PA Manifest Store's. The type is
     read as §3.2 reads it: the segments are grouped by `En`, and the group's
     packet with `Z` = 1 holds `LBox`, `TBox` = `jumb` (`XLBox` when `LBox` =
     1) and a description box `jumd` whose first 16 bytes are the TYPE. A
     group whose TYPE is `63327061-0011-0010-8000-00AA00389B71` (`c2pa`), or
     whose TYPE cannot be read that way — no `En`, no `Z` = 1 packet, too
     short, not `jumb` then `jumd` — is removed (vectors 02, 68); a group with
     any other TYPE — JPEG 360, JPEG Privacy and Security, any JUMBF box that
     is not a C2PA store — is content and stays, because C2PA hashes it
     (15.12.1.2 *Hashing of JPEG 1 files*; vector 122). Keep every other APP11
     and every other segment. Concatenate the remaining bytes in original
     order → `C`. The walk stops at `SOS`; fill bytes (`0xFF` padding
     before a marker) and markers without a length field (`TEM`, `RSTn`) are
     kept where they are, like every other byte that is not a removed JUMBF
     APP11.
     A segment whose length is below 2 or runs past the end of the file makes
     the JPEG malformed: it has no canonical bytes, and the verdict is *no
     proof found* — never an exception (vector 116).
   - **ISO-BMFF** (MP4, MOV, HEIC): `C = F'` unchanged. Nothing is removed.
3. **Hash.** `H = SHA-256(C)`, 32 raw bytes. `media.hash` is `H` in base64url,
   no padding.

The asymmetry between containers is deliberate and follows from where each
standard puts its own hash:

- **JPEG embeds the C2PA manifest AFTER sealing**, because the JPEG hard binding
  (`c2pa.hash.data`) hashes every byte not excluded, EOI to end of file
  included; if the manifest were inside the canonical bytes, adding it would
  invalidate the vcap signature it depends on. So it is excluded — and, as a
  consequence, the C2PA manifest of a sealed photo can be added, replaced or
  removed without touching the vcap verdict, whichever came first (vectors 02
  and 68) — though a writer does not seal a JPEG that already carries one
  (`c2pa-interop-1.0.md` §2.1, vector 131). It carries its own signature, and
  once written after sealing its hard binding covers the trailer: a trailer
  rewritten later breaks the manifest, not the proof (`c2pa-interop-1.0.md`
  §3, vector 125).
- **ISO-BMFF — video and HEIC alike — embeds the manifest BEFORE sealing**:
  the manifest is inside the
  canonical bytes and stays there (a manifest inserted afterwards is
  *tampered*, vector 73, a HEIC photo), and the trailer appended after it is a `free` box,
  which a C2PA claim generator keeps out of `c2pa.hash.bmff.v3` by putting
  `/free` on its exclusion list — the one exclusion, with `/skip`, that C2PA
  15.12.2 does not even flag (c2pa-rs 0.91 flags it all the same, as
  informational: vector 143). Without that entry the trailer breaks the C2PA
  binding, not ours (vector 144). A C2PA *update* manifest, which C2PA requires to be the
  last box of the file, cannot share a file with a trailer at all (vectors
  69–70; `c2pa-interop-1.0.md` §3).

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

- **Segment boundaries are IDR access units**, decided by NAL unit type —
  H.264 `nal_unit_type` 5, H.265 `IDR_W_RADL` (19) and `IDR_N_LP` (20) — and
  **not** by the container's sync sample table. `stss` lists random-access
  points, and in H.265 those include CRA pictures that are not IDRs: a reader
  that cut there would split a writer's segment in two and check half of it
  against the whole one's signature (vector 94). Video samples before the
  first IDR belong to no segment.
- **A vcap SEI NAL unit** is an SEI NAL (type 6 in H.264, 39 or 40 in H.265)
  that carries **exactly one** SEI message: a `user_data_unregistered` payload
  (payloadType 5) whose 16-byte UUID is the vcap SEI UUID,
  `SHA-256("vcap/1.0/sei")[0:16]` = `caa653d1ed1763c7af388aea76527336`, whose
  `payloadSize` is **exactly 36**, and after which the NAL holds nothing but
  `rbsp_trailing_bits` (the byte `0x80`, then only zero bytes). The 16 UUID
  bytes are inside the payload that size counts, so a parser that reads it as
  20 over-reads the SEI. The payload after the UUID is
  `capture_id (16 B) || uint32 BE n`, 20 bytes.
  - **Emulation prevention.** The SEI header and payload are read from the
    RBSP: every `emulation_prevention_three_byte` (a `0x03` that follows two
    zero bytes, H.264 §7.4.1, H.265 §7.4.2) is removed first, and the zero
    count restarts after it. `capture_id` and `n` routinely contain `00 00`,
    so a writer MUST apply emulation prevention to the payload and a reader
    MUST undo it before comparing; `payloadSize` counts RBSP bytes. What
    `content_hash` excludes is the NAL unit **as stored**, emulation
    prevention bytes included.
  - **Shape.** An SEI NAL that carries the vcap UUID in any other shape — a
    second message beside it, a `payloadSize` other than 36, bytes after the
    message — is malformed, and the GOP holding it is *tampered*. Excluding a
    whole NAL because one of its messages is ours would leave every other
    message in it unsigned inside a verified segment (vector 93).
  - **Writers MUST emit exactly one vcap SEI in each segment**, in the
    segment's IDR access unit ahead of its first VCL NAL unit, so a demuxed or
    re-muxed stream still says which capture and which segment a GOP belongs
    to. The UUID is derived, not registered: `user_data_unregistered` UUIDs are
    unregistered by definition (H.264 §D.2.6 asks only that they be unlikely
    to collide), and anyone can recompute this one from a single ASCII
    string; a future layout takes a new string, as the segment separator does.

  Only vcap SEI NAL units are excluded from `content_hash`: a signature cannot
  cover the bytes that contain it. Every other SEI — registered or not — is
  content and is covered. Excluding by NAL type, as an earlier draft did, would
  have left unsigned bytes inside "verified" segments.
- **Locating segments.** The vcap SEI locates a segment and is never evidence
  on its own: `content_hash`, the chain and the signatures are. The binding
  between the proof and the frames of the received file is this rule, and a
  verifier that recomputes applies it whole:

  > A signed segment `n` counts as **verified** only if the container yields
  > exactly one GOP whose vcap SEI carries index `n` and a `capture_id` equal
  > to the proof's, and that GOP's recomputed `content_hash` matches the signed
  > one. Once any GOP of the file carries a vcap SEI naming the proof's
  > `capture_id`, every GOP of the file is accounted for, in decode order: a
  > GOP whose SEI index is not a signed segment of the proof, an index carried
  > by more than one GOP, indices not strictly increasing in decode order, a
  > GOP with no vcap SEI or with one naming another capture, and a GOP with
  > more than one vcap SEI are each **tampered**. If no GOP can be located —
  > no vcap SEI names this capture, the file is not ISO-BMFF or has no
  > H.264/H.265 track, or the verifier did not recompute — there is no segment
  > credit: `segments.verified` is empty, and unless `media.hash` matches, the
  > outcome is **frames not compared** — the signatures hold, the frames were
  > not compared — and it is never *verified clip*.

  A verifier **MUST NOT infer a GOP's index from its position in the file**:
  position is the index only in a file nobody cut, which is the one
  assumption a clip breaks, and guessing wrong checks one GOP's bytes against
  another GOP's signature. And a verifier MUST NOT skip a GOP it cannot
  place: before this rule both of the implementations that existed did, and a
  stolen proof next to an unrelated clip read *verified clip* (vector 86), a
  file with one SEI index edited read *verified clip* with the edited segment
  counted (vector 88), and a genuine clip with a forged GOP prepended read
  *verified clip* too (vector 38). Order, duplication and insertion are
  checked here and not by the chain, because the chain proves the order of
  the *messages*: only the SEI indices in decode order say where the frames
  are (vectors 90, 91).
- **The NAL units of a sample tile it exactly.** In a length-prefixed sample
  each prefix is followed by that many bytes and the next prefix starts where
  they end; the last unit ends at the end of the sample. A prefix that is cut
  short, a zero length, or a unit that overruns the sample makes the container
  malformed and the verdict *tampered*, never a silent stop: stopping would
  leave the rest of the sample out of every hash while the GOP still read as
  verified (vector 92). A sample that lies outside the file is the same case.
- **A NAL unit is exactly the bytes the container stores for it.** In a
  length-prefixed sample it is the `lengthSizeMinusOne + 1`-byte prefix's whole
  extent; in an Annex-B stream it is everything from the end of a three-byte
  start-code prefix `00 00 01` to the beginning of the next one, or to the end
  of the sample. **Trailing zero bytes are inside the unit**, and so is the
  leading zero of a four-byte start code, which falls at the end of the unit
  before it. This is a framing rule, not a bitstream one: `trailing_zero_8bits`
  and `cabac_zero_word` are different things to an H.264 parser and the same
  thing here, because a verifier reading a received file has a length prefix
  and no way to tell which zeros an encoder meant. Trimming them would leave
  bytes physically inside a signed segment covered by nothing, which is what §5
  exists to prevent; it would also make the hash depend on a bitstream reading
  that two implementations perform differently. A writer that hashes before
  muxing therefore **MUST** hash the bytes it hands the muxer, delimited this
  way — and MUST check that against a file it produced, not against the
  platform's documentation. Two implementations disagreed exactly here: an
  encoder pads slices with zeros whenever a scene is too cheap to code, one
  side trimmed them and the other did not, and every recording of a static
  scene verified *tampered* while every recording of a busy one passed.
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
    segment signature verifies, the chain holds wherever two consecutive
    segments are both present, and at least one GOP is located and verified
    under *Locating segments* → **verified clip**, amber, reporting which
    segment indexes verified out of `segment_count`;
  - a segment signature fails, or a present segment's `prev` differs from
    `SHA-256(message(n−1))` while segment n−1 is present (the chain breaks where
    the file claims contiguity) → **tampered**, red;
  - **a located segment whose `content_hash`, recomputed from the container,
    differs from the signed one → tampered**, red, reporting which segments do
    verify; so is every other failure *Locating segments* lists. A contradicted
    segment is not a missing one: a clip lacks segments, this file *has* the
    segment and its bytes are not the bytes that were signed, which is
    substitution inside a signed range and never amber (vector 39);
  - `media.hash` does not match and no GOP is located → **frames not
    compared**, amber: the core and segment signatures hold, and nothing ties
    them to these frames (vectors 86, 87). Recomputation is optional — a
    verifier without a demuxer verifies the signature layer and nothing here
    changes that — but a verifier that skips it has checked that somebody
    signed some hashes, not that the frames in front of the reader are those
    frames. It stays conformant, **MUST** say so with *segment content not
    recomputed* (§7), and never reaches *verified clip*: on vector 39 the same
    file reads *frames not compared* without the recomputation and *tampered*
    with it, and a reader who is not told which one ran cannot know what the
    verdict means;
  - `segments[].range` is **deprecated**: writers MUST NOT emit it, and
    verifiers MUST ignore it where an older file carries it. It was a byte
    range in the received file, unsigned, and a verifier was already forbidden
    to conclude anything from it — so it offered a UI a frame offset that no
    two writers were obliged to compute alike, since the offsets are taken
    before the trailer is appended and any clip moves them. A field nobody may
    trust and everybody may compute differently is an invitation to trust it
    by accident. Removing it invalidates nothing: it is outside the core hash
    and outside the per-segment message, so every file already sealed verifies
    unchanged.

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
never changes afterwards. **Attachments** are added later, by whatever sends
the capture onwards, each verifiable on its own and each bound to `core_hash`.

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
  "location": { "level", "lat_udeg", "lon_udeg", "alt_cm", "acc_cm", "source", "at", "evidence": [ ... ] },
  "policy":   { "pseudonymous": true|false, "retention_ref" },

  // ---- signature over the core (§4.2) ----
  "sig":      { "alg": "ES256", "value": "base64url r||s", "pub": "base64url SPKI" },

  // ---- attachments: each self-authenticating, bound to core_hash (§6.2) ----
  "segments":    [ { "gop": 0, "hash", "prev", "sig" } ],   // "range" is deprecated: writers MUST NOT emit it (§5)
  "attestation": [ "base64url DER leaf", "...", "base64url DER root" ],   // omitted on web
  "registry":    { "log_id", "leaf_index", "leaf": { ... }, "inclusion_path": [ ... ],
                   "tree_head": { "tree_size", "timestamp", "root_hash", "signature" } },
  "timestamp":   { "tsr", "tsa_issuer" },
  "anchor":      { "chain", "tx", "block", "anchor_id", "index", "tree_size", "root", "merkle_path" },
  "integrity":   { "source", "verdict", "evaluated_at", "sig" },
  "location_corroboration": { "method", "result", "radius_m", "at", "operator_ref", "sig" }
}
```

### 6.1 The core

The core is the JSON object made of exactly these top-level keys, when present:
`v`, `capture_id`, `media`, `device`, `watermark`, `time`, `location`, `policy`.
A verifier builds it from the received proof by taking those keys and nothing
else, then serializes it with JCS. Unknown top-level keys are not part of the
core and are listed as *not evaluated* (§9).

**Reading the JSON** (normative). A proof — trailer payload or sidecar — is
read under rules that leave two parsers no room to disagree, and a proof that
breaks one is **not well formed: *no proof found*** (§8):

- UTF-8, **no byte-order mark** (vector 114), and valid UTF-8 throughout.
- **No duplicate member names**, at any depth (vector 111). JSON leaves them
  undefined and parsers split between the first and the last, so one proof
  would read as two.
- **Every number is an integer, written as an integer literal**
  `-?(0|[1-9][0-9]*)` — no fraction, no exponent, not `4032.0`, not `1.25e3`
  (vector 113) — **within ±(2^53 − 1)** (vector 112), the range every JSON
  implementation reads exactly. The format has no other numbers, in the core
  or out of it; a later minor adds none.

**Canonicalization procedure** (normative; vectors `32-jcs-core-canonicalization`
and `120-jcs-integer-like-and-proto-keys`):

1. Parse the proof JSON. Take the top-level members named above, in whatever
   order they appear; ignore every other member.
2. Serialize the resulting object with JCS (RFC 8785): object members sorted by
   the UTF-16 code units of their names at every level, arrays in place, no
   whitespace, strings escaped as ECMAScript `JSON.stringify` does, numbers as
   plain decimal integers (the core has no other numbers). The order is the
   code-unit order of the names **as strings**: `"10"` before `"9"`, and a
   member named `__proto__` is a member like any other. JavaScript objects
   enumerate integer-like names first in numeric order and treat `__proto__`
   as the prototype, so an implementation that builds a sorted object and
   hands it to `JSON.stringify` gets both wrong (vector 120).
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
- `location` is the **declared** position, and every member is optional but
  `level`: `lat_udeg`, `lon_udeg` (integer microdegrees, `int32`, ±90 000 000
  and ±180 000 000), `alt_cm` (height above the WGS 84 ellipsoid, integer
  centimetres, signed), `acc_cm` (the horizontal accuracy the OS reported,
  integer centimetres, `uint32`), `source` — how the fix was obtained: `gnss`,
  `network`, `manual`; extensible (§9), an unknown value is still a declared
  position — and `at`, the device clock when the fix was taken, ms, which may
  precede `time.device_clock` by the age of the fix. A position is two
  coordinates: a `location` without both `lat_udeg` and `lon_udeg` declares
  nothing (vector 84). `level` is the level the device **claims** (§7.1): a
  writer claims `declared`; `authenticated` is reserved for a writer carrying
  device-side `evidence` of a kind a later minor defines (none in this
  version); `corroborated` is never a writer's claim, because corroboration
  happens after the capture and lives in the `location_corroboration`
  attachment (vector 82). The verifier computes the level the evidence
  reaches and the claim never raises it, exactly as `device.secure_hw` never
  does. `evidence[]` is reserved: entries are objects with a `kind` (§9,
  extensible) and a v1.0 verifier lists a non-empty array as *location
  evidence not evaluated* (vector 81). Signed by the device means: the device
  says so. The app obtains the fix from the OS and the OS is the only thing
  between the app and any coordinates it likes — a mock location provider on
  Android, a simulated location on iOS — so a signed position is worth
  exactly *declared* (`threat-model.md` §5.7).

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
| `location` | no | `location_corroboration` and the level rules (§7.1) |
| `policy.pseudonymous` | no | consistency: no device identifiers present |

**Retention reference (informative).** `policy.retention_ref` is reserved and
has no operational meaning in v1.0. Its schema slot is retained for compatibility;
current writers leave it absent. A signed value authenticates only what the
writer declared: it is not evidence that an original was uploaded, retained,
encrypted or deleted, and it is not a URL or an authority to retrieve one.
Vault capabilities, the person's choice to expose an original, retention
settings and deletion receipts belong to the separate storage protocol.
Neither the presence nor the absence of this field changes a proof verdict
or requires a storage service on the verification path (§8). Existing proofs
containing a schema-valid value remain readable under the same rules.

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
| `integrity` | sync | registry key signature over `"vcap/1.0/integrity" ‖ core_hash ‖ JCS(body)` | signature covers `core_hash` |
| `location_corroboration` | sync, after an operator answered | registry key signature over `"vcap/1.0/location" ‖ core_hash ‖ JCS(body)` | signature covers `core_hash`, which covers the declared position |

- **`attestation`** — the key attestation certificate chain, leaf first, each
  certificate DER in base64url, `[...]`. Present on Android (required for any
  level above `none`), absent on web; on iOS the App Attest material goes to the
  registry at enrolment and the proof carries the `registry` attachment
  instead. **The leaf's SubjectPublicKeyInfo MUST be byte-equal to `sig.pub`**;
  otherwise the verdict is *tampered*, red (vector 108): a chain about another
  key next to this signature is a signature swap, not weak evidence. What the
  chain must satisfy to prove a level is in §7. The chain MUST
  NOT carry device identifiers (no ID attestation: serial, IMEI, MEID).
- **`attestation_status`** *(optional)* — the revocation status of the
  certificates in the `attestation` chain, as it stood **while the chain was
  still current**, relayed and countersigned by the registry. Without it a
  verifier reading a proof years later cannot answer the question the instant
  rule (§7) poses: whether the chain was revoked *at* the capture, because the
  status of an expired certificate is no longer published anywhere.
  - `source`: extensible; `googleStatusList` is Android's attestation status
    list. An unknown value → the attachment is ignored and the verdict is the
    one without it (*chain revocation not checked*).
  - `fetched_at`: ms, registry clock, when the status was read. **It is not a
    revocation date** and a verifier MUST NOT use it as one: a list read a
    month after a revocation says nothing about when the revocation happened.
  - `entries`: one per certificate looked up — `{ "serial", "status":
    "valid" | "revoked" | "unknown", "reason": optional string, "revoked_at":
    optional ms }`. `serial` is the certificate serial number in lowercase
    hex; serials compare with leading zeros stripped. `revoked_at` is the
    revocation date **as the source itself gives it**, and is absent when the
    source gives none.
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

  **Coverage.** A snapshot answers for the certificates it names and no
  others. Every certificate of the chain other than the pinned root MUST have
  an entry; a certificate without one, or with `unknown`, leaves the chain's
  revocation unchecked: *chain revocation not checked*, amber, never red
  (vectors 98, 99). `unknown` is the registry not knowing, and reading it as
  revoked would turn silence into an accusation.

  **Revoked.** A `revoked` entry for a certificate of the chain makes the
  proven level `none`, *attestation key revoked*, **red** (vectors 44, 96, 97)
  — unless all of these hold, in which case the level at the proven instant
  stands and is shown with *attestation key revoked after the capture*
  (vector 45):
  1. the proven instant of §7 comes from a **trusted source** — a valid
     `timestamp` token or a verified `anchor` — and not from
     `time.device_clock`. The device clock is set by whoever holds the device
     key, and after a leaked keybox that is exactly who the revocation is
     about: a thief signing today with the clock set to last month would
     otherwise read *revoked after the capture* (vector 96);
  2. the entry carries `revoked_at` and the proven instant is before it.
     `fetched_at` is never that date (vector 97);
  3. the entry's `reason` is not `KEY_COMPROMISE` or `CA_COMPROMISE`. A
     compromised key vouches for nothing it ever signed, so those revocations
     reach back to the key's first use whatever the date says — the rule §6.2
     already applies to a device key revoked for `compromise` (vector 44).

  A batch key withdrawn in 2028 for `SUPERSEDED` does not un-attest a capture
  a time-stamping authority placed in 2026, for the same reason a rotated
  device key does not rewrite the past; a batch key leaked and listed in 2028
  does not keep attesting what its thief signed with a clock set to 2026.

- **`registry`** — everything a verifier needs to check, **offline**, that the
  signing key was in the transparency log when the tree head was signed. Not a
  reference to be resolved: the proof carries the evidence.
  - `log_id`: SHA-256 of the log's public key (DER SPKI), base64url. The verifier
    ships the public keys of the logs it trusts, keyed by this.
  - `leaf_index`: integer.
  - `leaf`: the log leaf as recorded — `{ "type": "key", "key_id", "public_key",
    "secure_hw", "attestation_digest", "registered_at" }`, integers and
    base64/hex strings only; the verifier serializes it with JCS and hashes
    `SHA-256(0x00 ‖ bytes)` (RFC 6962 leaf hash). **`leaf.key_id` is the same
    digest as `device.key_id` in a different encoding**: 64 lowercase hex
    characters here, base64url in the core (§6.1), because a log records
    identifiers in hex and the proof carries bytes in base64url. A verifier
    compares the digests and not the strings — comparing the strings fails on
    every honest proof, which is how this sentence came to exist.
  - `inclusion_path`: the RFC 6962 audit path, base64url hashes, bottom first.
  - `tree_head`: `tree_size`, `timestamp` (ms, log clock), `root_hash`
    (base64url), `signature` — ES256 by the log key in P1363 over the
    fixed-length message `"vcap/1.0/sth" ‖ uint64 BE tree_size ‖ uint64 BE
    timestamp ‖ root_hash`, `SHA-256(0x01 ‖ left ‖ right)` for nodes.

  A verifier MUST check, in this order: the tree head signature under the
  trusted key for `log_id`; the leaf hash's inclusion at `leaf_index` in a tree
  of `tree_size` leaves with root `root_hash`; `leaf.key_id == device.key_id`
  (the same digest, see the encodings above) and `leaf.public_key` equal to
  `sig.pub`. The order is normative: an unverified tree head makes the root
  untrusted, so an inclusion proof against it establishes nothing, and
  reporting "not included" there would blame the path for a bad signature.

  Any failure → **both** *registry evidence invalid* and *key not in
  transparency log*, amber, per §8's rule for a present attachment that does
  not hold up. The core is unaffected: the capture is still signed by the key,
  only "in the log" is not proven.

  A `log_id` the verifier holds no key for is **not** a failure of the
  evidence: it is *log not trusted*, amber, and nothing else. Nobody the
  verifier trusts runs that log, which is the same amount of knowledge as an
  absent attachment. The same bytes are green for a verifier that pins the log
  and amber for one that does not, and both are right: a verdict is only ever
  green against a named set of anchors.

  `leaf.secure_hw` is the level the log saw proven at registration; it MUST NOT
  exceed the level proven by `attestation` when both are present, and a leaf
  that claims more is *inconsistent claim* — the label the format already has
  for a claim above its evidence.

  **Before the capture.** `tree_head.timestamp` is when the log signed a tree
  containing the key. It MUST NOT exceed `time.device_clock`: a key logged
  after the declared capture time is *registered after the declared capture*,
  shown, amber (vector 53). When a valid `timestamp` token exists it MUST NOT
  exceed the token's `genTime` either: *registered after the trusted time*,
  amber (vector 102) — the token is an instant the device does not choose,
  and a key logged after it was not in the log when the capture was stamped.
  A core that declares no `time.device_clock` has no capture time to be early
  against: the key is **not** shown to have been registered before the
  capture, and the verdict says *capture time not declared* (vector 101). An
  absent field is a weaker verdict, never a stronger one. Revocation is not
  visible in this attachment — it is a later leaf — and is checked online
  against the log (§7, *revocation not checked* when offline).

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
  nothing it ever signed. The instant a verifier asks about is the proven
  instant of §7 — the token's `genTime`, else a verified anchor's block time,
  else `time.device_clock`. *Revoked at that instant* → **red** for the key's
  standing, shown with the reason.
- **`anchor`** — existence before a block, verifiable against the chain and
  nothing of ours. `chain` names the network (`base`, `base-sepolia`; `ebsi`,
  `ebsi-pilot` for EBSI's Hyperledger Besu ledger); `tx` and `block` locate
  the anchoring transaction; `anchor_id` is the contract's sequential id of
  the batch; `root` (base64url) is the batch root the contract recorded with
  `tree_size` leaves; `index` is this proof's position; `merkle_path` is the
  RFC 6962 audit path, base64url, bottom first.
  Leaves are `SHA-256(0x00 ‖ core_hash)` and nodes `SHA-256(0x01 ‖ left ‖
  right)` — the same tree as the transparency log, so a verifier carries one
  Merkle implementation. A verifier MUST recompute the root from `core_hash`,
  `index`, `tree_size` and `merkle_path`, then read `(root, tree_size)` for
  `anchor_id` from the contract (or a light client) and compare both; the
  block's timestamp is the proven upper bound. On `ebsi` and `ebsi-pilot`
  that read goes through EBSI's Ledger API gateway,
  `POST /ledger/v4/blockchains/besu`: a JSON-RPC proxy that forwards the
  read methods a verifier needs — `eth_call`, `eth_getTransactionReceipt`,
  `eth_getLogs` — without any authorisation, against the contract address
  published for that chain (EBSI Ledger API v4). Without network: *anchoring
  not verified*, amber, never red — a verifier that could not ask has learned
  nothing bad. A path that does not recompute to `root`, or a chain that
  recorded a different `(root, tree_size)`, is a failure of the evidence and
  carries both labels of §8. **Both** values are compared, not the root alone:
  a batch of a different size can share a root with this one when one is a
  prefix of the other.

  When the chain is read and agrees, the block's timestamp becomes the instant
  the proof is validated at (§7), outranking `time.device_clock` — and it is an
  **upper bound**: the capture existed before that block, which nobody can
  move, and nothing says how long before. An anchor whose root the chain
  contradicts gives no instant at all: dating a capture by a transaction that
  does not contain it would be worse than having no anchor.
- **`integrity`** — `source` is `playIntegrity`, `appAttest` or `none`
  (extensible, §9: a verifier that does not know the value reads the
  attachment as absent, *integrity unevaluated*); `verdict` is `hardware`,
  `basic`, `unevaluated` or `failed` (not extensible: any other value under a
  valid signature is *integrity evidence invalid*); `evaluated_at` is the
  registry's clock; `sig` is the registry signing key's ES256 signature, P1363,
  over `"vcap/1.0/integrity" ‖ core_hash ‖ JCS(A)`, where `A` is the attachment
  without `sig` — the construction of `location_corroboration`, so `source` and
  `evaluated_at` are signed too and the separator keeps the registry's key
  from being read across messages. **Which key**: the one that signs that
  log's tree heads, found as for `attestation_status`. Integrity verdicts are
  tokens only the developer's server can decrypt, so they cannot live in the
  core as anything but a self-declaration — and a self-declaration by the app
  is worthless against the compromised device it exists to flag. As a
  registry-signed attachment the verdict is Google's or Apple's, relayed and
  signed by a key the verifier already has for tree heads. Absent →
  *integrity unevaluated* (§8). The server *adds* evidence; it is never
  *needed* for a verdict.

  A valid attachment is shown as **`integrity <verdict>`**. A valid `failed`
  caps the ceiling at **amber** and is shown prominently (§7, vector 109):
  the chain proves where the key lives, and Google's or Apple's word that the
  device failed its check is a reason not to say green however good the chain
  is. No other verdict moves the ceiling, and neither does absence.

  The cap works in one direction, and the signature is why. The verdict is
  inside the signed message, so a verdict cannot be **strengthened**: `failed`
  cannot become `hardware` without breaking it. It cannot buy the other
  direction. A relabelled attachment is indistinguishable from one signed by a
  registry the verifier does not follow — both are "no key of mine made this
  signature" (vector 66) — and an attacker who wanted to suppress a `failed`
  verdict could delete the attachment for the same result. So no integrity
  verdict is a condition *for* green; a present `failed` is a reason against
  it.
- **`location_corroboration`** *(optional)* — an
  operator-side check of the declared position, relayed and countersigned by
  the registry. The registry, after the capture and with the user's consent
  handled by the operator, calls a CAMARA API about the line in the capturing
  device and maps the answer onto three values. What the proof carries is
  **the registry's word about the operator's answer**, and a verifier MUST say
  so in those terms — *the registry attests that the operator confirmed the
  zone, radius 2000 m* — never "verified by the operator": the operator's
  answer is JSON over TLS with no transportable signature, so nothing but a
  registry countersignature can travel in a file. Same construction, same
  limit as `integrity`: evidence, never a verdict, and trust in the registry,
  stated.
  - `method`: which API was called — `camara-location-verification` (is the
    line inside a circle around the declared position), `camara-number-verification`
    (the line the operator authenticated on the device's own data session is
    the one the registry holds for this device), `camara-sim-swap` (no recent
    SIM change on that line). Extensible (§9): an unknown method is
    *location corroboration not evaluated* (vector 78). How the registry
    combines these into one `result` is the registry's rule and not this
    format's; the method says what was asked so a reader can weigh the answer.
  - `result`: `match`, `no-match` or `unknown`. **Not extensible**, because it
    decides the level: the registry MUST map the operator's raw values
    (`TRUE`, `FALSE`, `PARTIAL`, `UNKNOWN`, an error) onto these three before
    signing, and a verifier reading any other value under a valid signature
    reports *location corroboration evidence invalid* (vector 80).
  - `radius_m`: the circle the operator was asked about, metres, `uint32`.
    Required when `method` is `camara-location-verification`; a zone check
    without its zone is *evidence invalid*. Operators enforce minimum radii of
    one to two kilometres: a `match` corroborates *the same area*, never the
    same point, and a verifier shows the radius.
  - `at`: ms, registry clock, when the operator answered.
  - `operator_ref`: optional, an opaque registry-side reference to the
    operator or aggregator, `[A-Za-z0-9_-]{1,64}`. It MUST NOT be, contain, or
    be derived from a phone number: **no MSISDN enters a proof, ever**, in the
    clear, hashed or truncated. The registry keeps the line-to-key mapping
    behind access control, next to the key-to-organization one.
  - `sig`: the registry signing key's ES256 signature, P1363, over
    `"vcap/1.0/location" ‖ core_hash ‖ JCS(A)` where `A` is the attachment
    object without `sig`. JCS of the body rather than a fixed-length layout,
    so a later minor can add a member and a v1.0 verifier — which
    canonicalizes every member it sees — still verifies; the result is inside
    the message, so `no-match` cannot become `match`. **Which key**: the one
    that signs that log's tree heads, found as for `attestation_status`.

  A verifier MUST check, in this order: that the core declares a position
  (else nothing is corroborated: level `none`, *location corroboration not
  evaluated*, vector 84); that it knows `method`; that the signature verifies
  under a trusted log key over this core hash — a signature no trusted key
  made is *location corroboration not verified*, and it covers both a signer
  this verifier does not follow and a genuine statement about **another**
  proof, because to a verifier those are the same bytes (vectors 76, 77; the
  reasoning of `integrity`); then that `result`, `at` and `radius_m` are what
  this section says. A valid `match` reaches **corroborated** (vector 75); a
  valid `no-match` is *location contradicted*, level `declared`, and it moves
  no ceiling (vector 79) — the file is exactly as authentic as before, what is
  less believable is where it says it was taken; `unknown` is silence, level
  `declared`.

  **What corroborated means, and what it does not.** The operator locates the
  **SIM**, at cell granularity, at the time of the call; it does not locate
  the camera. A SIM in a different device than the one that signed, a
  tethered laptop, a complicit phone in the right cell with a fabricated
  file: none of these is caught here, and `camara-number-verification` over
  the capturing device's own data session is the method that narrows the
  first two. The residual risk is in `threat-model.md` §5.7, and it is the
  reason this level is called *corroborated* and not *verified*.
- **`timestamp.tsr`** — RFC 3161 TimeStampToken, base64url DER, whose
  `messageImprint` **is `core_hash`** (hash algorithm `sha256`, hashed message =
  the 32 bytes of `core_hash`). A timestamp over `media.hash` would prove the
  pixels existed before T; over `core_hash` it proves the pixels *and the
  claims* did — same cost. It is the only instant in a file that the device
  does not assert about itself, and the only one a verifier needs no network
  to check: the evidence travels with the proof.

  A TimeStampToken is CMS SignedData (RFC 5652) carrying a TSTInfo, and a
  verifier MUST check all of:

  1. `messageImprint` names `sha256` and its hashed message equals `core_hash`.
     A token that fails only this is a genuine token **over another proof**,
     and a verifier that read `genTime` without asking what was stamped would
     date this capture by a stamp taken over an unrelated file.
  2. the `messageDigest` signed attribute equals `SHA-256(TSTInfo)`, and the
     signed `contentType` is `id-ct-TSTInfo`.
  3. the signature verifies over the signed attributes **re-encoded as a
     `SET OF`** (RFC 5652 §5.4) rather than over the `[0] IMPLICIT` they appear
     as. One byte, and every CMS implementation gets it wrong once.
  4. the signer certificate chains to a **TSA root the verifier pins** and was
     valid at `genTime`. Anyone can run a TSA and stamp anything with any time,
     so the root is the whole of the trust. The signer is validated at
     `genTime` and not at the verifier's clock for the reason §7 validates an
     attestation chain at the capture: a TSA certificate that expired since
     would otherwise make every token it ever issued worthless.
  5. the signer carries the `timeStamping` extended key usage
     (`1.3.6.1.5.5.7.3.8`). Without this check any certificate under the root
     could stamp, and a TSA root signs more than its own stamping key.

  6. when a verified `anchor` is also present, `genTime` does not exceed the
     anchor's block time, and the signer certificate was still valid at that
     block time (vectors 103, 104). Validating at `genTime` is circular in one
     respect: `genTime` is chosen by whoever holds the TSA key, so a key that
     leaks after its certificate expired can stamp a fresh core with a time
     inside the certificate's life. A block time is chosen by nobody. A core
     first anchored after the certificate expired cannot carry a token that
     honest stamping produced, and a token that postdates the block which
     already anchors its core contradicts the order the evidence was made in.
     Without an anchor nothing bounds a leaked TSA key's backdating; the
     residual risk is in `threat-model.md` §5.4.

  Any failure → both labels of §8, and the instant falls to the next source
  (§7). No pinned TSA root at all is *trusted time not evaluated*: evidence
  this verifier cannot read, not evidence that failed.

  A valid token makes `genTime` the instant the proof is validated at (§7),
  outranking a verified anchor and `time.device_clock` — and it removes
  *attestation chain expired, capture time not proven*, because that caveat
  exists only while nothing but the device places the capture inside the
  chain's validity.

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
`keyMintSecurityLevel` in the attestation extension, when the chain satisfies
every rule below; `software`, or a chain that fails any of them, proves
`none`. iOS: see *The Secure Enclave level* below. Web: `none`.

An Android chain proves a level only when all of these hold — the checks
Google's key attestation guidance asks of a verifier, written as MUSTs so two
verifiers cannot disagree about a chain:

1. **Signatures and anchor.** Each certificate is signed by the next, and the
   last is, or is signed by, a pinned Google attestation root. Every
   certificate is valid at the proven instant (below).
2. **Issuers are CAs.** Every certificate above the leaf carries
   `basicConstraints` with `cA` true and `keyUsage` with `keyCertSign`.
3. **The extension is the leaf's.** The key attestation extension
   (`1.3.6.1.4.1.11129.2.1.17`) is present in the leaf and in **no other**
   certificate of the chain. Rules 2 and 3 are what stop a genuine attested
   key — a leaf, real hardware and all — from signing a "leaf" of its own with
   whatever KeyDescription it likes and having the chain still verify to the
   root (vector 105).
4. **Verified boot.** The hardware-enforced `rootOfTrust` says
   `deviceLocked` true and `verifiedBootState` `Verified`. An unlocked
   bootloader lets anything run above the TEE, so the key's level says nothing
   about what asked it to sign.
5. **The signing key.** The leaf's SubjectPublicKeyInfo equals `sig.pub`;
   otherwise the verdict is *tampered* (§6.2, vector 108).

A chain that fails rule 1, 2, 3 or 5, or cannot be read, is evidence that does
not hold up: *origin not hardware-attested* **and** *attestation evidence
invalid* (§8). A chain that holds and proves too little — rule 4, or a
`software` level — is *origin not hardware-attested* alone: a genuine chain
from an unlocked phone is not a forged one.

**The app that made the key.** The leaf's `attestationApplicationId` names the
signing certificates of the app that created the key (`signature_digests`,
SHA-256). When a `registry` attachment verifies, a verifier compares them with
the app signing digests the log's operator declares for the apps it admits
keys from — shipped with the log's public key in the verifier's trust list
(`app_signing_digests`, `vectors/_trust/logs.json`), so the check needs no
network. None of the leaf's digests declared → *attestation app not admitted*;
no declaration for the log, or no `attestationApplicationId` in the leaf →
*attestation app not checked* (vectors 106, 107). Both are **amber, never
red**: the hardware claim stands and what is missing is the claim that a known
app build made the key, which green asserts (`threat-model.md` §1). Without a
`registry` attachment the check is not made, and the verdict is already amber
for *key not in transparency log*.

| proven level | attestation / binding | key in log before capture | verdict ceiling | label shown |
|---|---|---|---|---|
| `strongbox` | valid to Google hardware root, RKP fresh, revocation checked, app admitted | yes | **green** | sealed in secure hardware |
| `tee` | valid to Google root, revocation checked, app admitted | yes | **green** | sealed in the TEE |
| `secureEnclave` | the registry records an App Attest binding (see below) | yes | **green** | sealed in the Secure Enclave (app-attested) — *our records* |
| any of the above | valid | no (`registry` absent), or its evidence invalid | **amber** | key not in the transparency log |
| any of the above | valid | yes, but `tree_head.timestamp` after the declared capture | **amber** | registered after the declared capture |
| any of the above | valid | yes, but `tree_head.timestamp` after a valid token's `genTime` | **amber** | registered after the trusted time |
| any of the above | valid | the core declares no `time.device_clock` | **amber** | capture time not declared |
| any of the above | valid, log not reachable | any | **amber** | revocation not checked |
| any of the above | valid, and the only instant is `time.device_clock` | any | **amber** | no trusted time |
| any of the above | valid, `attestationApplicationId` not among the log's declared digests | yes | **amber** | attestation app not admitted |
| any of the above | valid, no digests to compare | yes | **amber** | attestation app not checked |
| any | key revoked at the proven instant (signed status, §6.2) | — | **red** | key revoked |
| any | a chain certificate `revoked` (`attestation_status`, §6.2), not shown by a trusted instant to predate the source's revocation date, or revoked for compromise | — | **red** | attestation key revoked |
| any of the above | a chain certificate revoked, and a trusted instant predates the source's revocation date | any | unchanged | attestation key revoked after the capture |
| any of the above | an entry `unknown`, or a certificate of the chain without an entry | any | **amber** | chain revocation not checked |
| any of the above | valid at the proven instant of capture, expired since | any | unchanged by the expiry | (nothing: expiry alone says nothing) |
| any of the above | expired, and the capture time is only `time.device_clock` | any | **amber** | attestation chain expired, capture time not proven |
| `none` | session key, no attestation, or a chain that does not prove a level | n/a | **amber, never green** | origin not hardware-attested |
| any of the above | a video proof whose `content_hash` values were not recomputed from the container (§5) | any | unchanged | segment content not recomputed |
| any | claimed level above the level the `attestation` attachment proves | — | **amber at best, flagged** | inconsistent claim |
| any | a valid `integrity` attachment whose verdict is `failed` (§6.2) | — | **amber at best, prominently flagged** | integrity failed |
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
  token (§6.2, including its agreement with an anchor); the block time of a
  verified `anchor`; `time.device_clock`; and, when the core declares none,
  the verifier's own clock. **Green needs one of the first two.** The device
  clock is a claim, set by whoever holds the device, so every check made "at
  the capture" against it is a check made at a moment the signer chose: it
  caps the verdict at **amber** whatever else holds (vector 54; the green is
  vector 100). The verifier's clock proves nothing about the capture and caps
  it the same way, with *capture time not declared* — a missing
  `time.device_clock` is never a stronger verdict than a present one (vector
  101). A chain that was valid at the proven instant and has expired since is
  **not** an error. The
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

**The Secure Enclave level.** iOS carries no attestation chain in the proof:
App Attest material goes to the registry at enrolment, and what reaches a
verifier is the registry's leaf, whose `secure_hw` says what the registry saw
proven then. This version defines **no offline binding** between a proof and
an App Attest attestation: nothing in the file lets a verifier recompute that
the key lives in a Secure Enclave, and a v1.0 verifier MUST NOT pretend
otherwise. So `secureEnclave` is reachable **only through the registry**: it
is the proven level when a `registry` attachment verifies under a trusted log
and its leaf records `secureEnclave` for this key, and a verifier MUST label it
as evidence of **our records** — the registry's word, like *corroborated* in
§7.1 — never as *checkable without us*. Without such a leaf the level is
`none`, whatever `device.secure_hw` claims. A binding a verifier can check
offline arrives as a new attachment in a later minor, with its vectors.

### 7.1 The position level

A second level, on a second axis. The proof level above says how strong the
**origin** claim is; the position level says how much the **coordinates**
in the core are worth, and the two never mix: the position level MUST NOT
raise a verdict to green or lower it to red, and it MUST NOT change the
ceiling of §7's table (vectors 75, 79). It is `location.level` in the
verifier's output, one of four values, and a verifier MUST name it whenever
the core declares a position — "guaranteed" is not a value and never appears.

| level | what reaches it | label shown |
|---|---|---|
| `none` | no `location` in the core, or one without both coordinates (vector 84) | nothing: absence is not a claim about place |
| `declared` | `lat_udeg` and `lon_udeg` signed by the device (§6.1) | *location declared only* |
| `corroborated` | a `location_corroboration` attachment (§6.2) under a trusted registry key, over this core hash, with `result: match` | *location corroborated* — shown as the registry attesting the operator's answer, with the method and the radius |
| `authenticated` | **reserved** — a device-side `evidence[]` entry of a kind that binds the fix to a signal the device cannot forge, such as a Galileo OSNMA-authenticated GNSS solution attested by the device. No kind is defined in this version and **no v1.0 verifier reaches this level** | — |

Rules:

- **The claim never raises the level.** `location.level` in the core is what
  the device claims (§6.1); the verifier computes the level from the
  evidence. A claim above the computed level is shown as *location claimed
  above evidence* (vectors 81, 82), never applied. A value outside the
  enumeration is read as `declared`, the level any signed position reaches on
  its own (vector 83) — treated, not refused, as §7 says of `secure_hw`.
- **`authenticated` is not reachable in this version**, and a verifier says
  so with what it has: a core claiming it reads *location claimed above
  evidence*, and a non-empty `evidence[]` reads *location evidence not
  evaluated* — both true from where a v1.0 verifier stands, neither an
  accusation, and a later verifier that implements the kind may reach the
  level (vector 81). The level is reserved now so that the word exists in
  every verifier before any device can earn it: as of September 2026 no
  smartphone chipset implements OSNMA, so the level is empty and the format
  says so rather than letting *declared* stretch.
- **Corroborated is the registry's word.** The level says: a registry this
  verifier trusts attests that an operator's check agreed with the declared
  position, to a stated radius and method. A verifier MUST show it in those
  terms (§6.2). It is trust in the registry, and it is optional: without the
  attachment the level is `declared`, a weaker answer and never an error.
- **Every failure of the attachment lands on `declared`**, with the label
  that says why (§8): *not evaluated* for evidence this verifier cannot read,
  *not verified* for a signature no trusted key made, *evidence invalid* for
  a verified signature over content outside §6.2, *contradicted* for a
  verified `no-match`. None is red. None is amber.

---

## 8. Decision 5 — Optional versus invalidating

**Outcome and ceiling.** A verdict answers two questions and keeps them apart.
The **outcome** says what the received bytes are; the **ceiling** (§7) says
what the origin is worth. The outcomes:

| Outcome | Colour | Meaning |
|---|---|---|
| `authentic` | the ceiling's | the file is the one the key sealed; §7 decides green, amber or red |
| `verified_clip` | amber | a video that is not the original, whose present segments are located in the file and verify (§5) |
| `frames_not_compared` | amber | a video whose core and segment signatures hold, and in which no segment could be located or none was recomputed (§5, *Locating segments*) |
| `tampered` | red | a signature, a hash or a binding the proof makes does not hold |
| `corrupted_proof` | red | a structurally valid trailer whose CRC does not match (§3) |
| `nested_proof` | red | the canonical bytes end in another trailer (§3) |
| `no_proof_found` | none | no trailer, no sidecar, no Content Credentials carrying a proof, or a proof that is missing, unparseable or malformed (below); also a proof carried only as a source capture's that nothing in the file matches (§3.2) |
| `unsupported_format_version` | none | a proof or a footer of a major version this verifier does not implement (§9) |

The ceiling is computed for an `authentic` outcome and is red only for a
revocation (§7): the file is intact and the origin is worth nothing, which is
a different statement from *tampered* (vector 44). **Labels accompany every
verdict whose outcome is not red**, a red ceiling included; a red *outcome*
carries its reason and nothing else, because "no trusted time" on a tampered
file is noise. A clip's outcome is amber whatever its ceiling would be.

**Required.** `v`, `capture_id`, `media`, `media.mime`, `media.hash`,
`media.w`, `media.h`, `device.secure_hw`, `device.key_id`, `sig`, and for a
video proof `media.segment_count` and `segments`. The pixel dimensions are
required and are **not** evidence — nothing is proven by them — but every
writer holds them at capture, and a reader that cannot say how large the frame
is cannot place a watermark payload or a segment in it (vector 46). A proof is
a **video proof** when `media.mime` starts with `video/`; nothing else decides
it — not the container, not `duration_ms` — so a video proof without
`segments` is *no proof found*, and a still image carrying `segments` is
verified as §5 says. Missing or unparseable → *no proof found*. Present but
invalid → *tampered*.

**Optional, each with its exact label when absent.** Absence is never an error,
and the verifier states it rather than staying silent.

| Absent, or present and not enough | Label | What it means |
|---|---|---|
| `timestamp` | *no trusted time* | only the device clock, shown as declared |
| `anchor` | *not anchored* | existence before a block is not proven |
| `registry` | *key not in transparency log* | the key may be genuine, but nobody can check its registration or revocation |
| `registry` present, `log_id` unknown to this verifier | *log not trusted* | not evidence that failed: evidence this verifier cannot read |
| the log's signed status, when offline | *revocation not checked* | the key was in the log; whether it still is cannot be established without asking |
| `timestamp` present, no TSA root pinned | *trusted time not evaluated* | evidence this verifier cannot read |
| `integrity` present and valid | *integrity `<verdict>`* | what Google or Apple said about the device, relayed and signed by the registry; `failed` caps the ceiling at amber (§7), every other verdict caps nothing |
| `anchor` present, chain not consulted | *anchoring not verified* | the path reaches the claimed root; nobody checked the chain recorded it |
| `attestation` (Android) | *origin not hardware-attested* | proven level `none` |
| `integrity` | *integrity unevaluated* | no statement about the device's state |
| `watermark` | *no watermark* | the detector did not run, or no mark was looked for |
| `location` | nothing shown | absence is not a claim about place: `location.level` is `none` (§7.1) |
| `location` present, no valid corroboration | *location declared only* | the device signed the coordinates and nothing else vouches for them |
| `location_corroboration` present and valid, `match` | *location corroborated* | the registry attests the operator's answer, to the stated method and radius; the position level is `corroborated` and no ceiling moves |
| `location_corroboration` present and valid, `no-match` | *location contradicted* | the operator's check disagreed with the declared position; shown, level `declared`, no ceiling moves |
| `location_corroboration` present, no trusted key verifies it | *location corroboration not verified* | a signer this verifier does not follow, or a statement about another proof — the same bytes |
| `location_corroboration` present, unknown `method`, no log key held, or no position to corroborate | *location corroboration not evaluated* | evidence this verifier cannot read |
| `location.evidence` non-empty | *location evidence not evaluated* | device-side kinds arrive with a later minor; this version weighs none |
| `location.level` claimed above the level reached | *location claimed above evidence* | the claim is the device's; the level is the evidence's |
| `policy.retention_ref` | nothing shown | reserved; no storage or retention claim (§6.1) |
| `time.device_clock` | *capture time not declared* | nothing in the core dates the capture; the registration cannot be placed before it and the ceiling is amber (§7) |
| `registry` present, tree head after a valid token's `genTime` | *registered after the trusted time* | the key was logged after an instant the device does not choose (§6.2) |
| `attestation` present, not holding up | *attestation evidence invalid* | with *origin not hardware-attested*: a chain that fails a rule of §7 other than verified boot or level |
| `attestation` valid, registry verified, app digests do not match | *attestation app not admitted* | the key was made by an app the log does not declare (§7) |
| `attestation` valid, registry verified, nothing to compare | *attestation app not checked* | the log declares no digests, or the leaf names no app (§7) |
| `attestation_status` absent, unreadable, `unknown` or incomplete | *chain revocation not checked* | the chain's certificates were not all shown valid while the chain was current (§6.2) |
| an iOS level from a registry leaf | *level from registry records* | the registry's word that the key is in a Secure Enclave; nothing in the file shows it (§7) |

**An attachment that is present and does not hold up carries two labels: the
absent label above, and its own *… evidence invalid*.** So a broken `registry`
is *key not in transparency log* **and** *registry evidence invalid*; a broken
`anchor` is *not anchored* **and** *anchor evidence invalid*; a broken
`location_corroboration` is *location declared only* **and** *location
corroboration evidence invalid*. One rule for every
attachment, and the reason is what a reader sees: the absent label is the
statement a user is shown — nobody can confirm this key was registered, nothing
anchors this capture — and a verifier that emitted only the *invalid* label
would leave an interface written against this table saying **nothing at all**
about registration or anchoring in exactly the case that deserves the most
attention. The *invalid* label is the part an operator can act on: somebody
presented evidence that does not hold up.

An attachment a verifier cannot *read* is not that case. A `log_id` outside the
trust set, a chain it has no client for: that is absent evidence, a weaker
verdict and never an error, and it carries the absent label or its own
*not verified* label alone.

**A declared watermark that does not come back.** `watermark` is the writer
saying a mark was embedded; it is not a promise that a reader will find it, and
a reader that does not find one never guesses. Three outcomes, all non-red:

| Outcome | Label |
|---|---|
| the payload decodes and matches the proof | *watermark matched* |
| the layout is known, the payload does not decode — including a decode the layout's own rules refuse | *watermark not recovered* |
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

**What counts as a decode is the layout's to say, and it is not only the
checksum.** `video-rep-v1` requires an agreement of at least **0.85** before
an id may be reported at all (`watermark-layouts-1.0.md`, *The agreement
floor*): its 8-bit CRC passes by chance about one word in 256, and on a
campaign of 38 device recordings two clips resolved an id their pixels had
never carried, at agreement 0.738 and 0.789. Below the floor the only
supportable statement is *a mark may be present and its id is not resolvable*,
which is what *watermark not recovered* already means here — the outcome word
does not change, and a verifier MUST NOT invent a fourth one. What a verifier
adds beside it is the agreement figure the layout defines, and, in its own
plain-language line, that a mark may be there and its id did not resolve.

This has teeth in both directions. A verifier that reports a `video-rep-v1`
id **without** the agreement figure has discarded the only discriminator the
layout has, so it MUST NOT report *watermark matched* on that evidence; the
honest outcome is *watermark not evaluated*, evidence this verifier cannot
read. And a below-floor block is never red, below.

**For a clip, *watermark matched* says how much of it carried the mark.** A
verifier that decodes several frames and reports one answer MUST report the
number of sampled frames whose payload decoded to that id, next to the number
sampled — "3 of 8" — and MUST NOT present a confidence figure as if it
answered that question.

The reason is measured, not theoretical (`watermark-robustness-1.0.md`): an
unmarked frame **abstains** rather than dissenting — mean absolute message
logit 11.3 marked against 0.131 unmarked — so a decode taken over averaged
frames is set by any single marked one. One genuine frame spliced into
unrelated footage reports the real id at the agreement of a clean recovery.
The count is what separates the two, and the robustness curve says it costs
nothing: every chain that recovers at all already recovers at one frame.

A verifier whose detector does not report the count says nothing about frames
rather than inventing one; the recovery is still *watermark matched*, and what
it means is unchanged — **a frame of that capture appears in this file**, never
that the file is that capture.

**Which sampled frames count.** A frame counts when its own decode passes the
layout's checksum and yields the id the clip reported. For `video-rep-v1` the
agreement floor does **not** gate that test: the floor governs an id a verifier
may name, and the count names none — equality against an id the floor already
licensed is the discriminator here, and a second application of the floor would
report a wholly marked clip as *0 of 8* on the build a browser ships while a
single spliced frame reports *1 of 8* (`watermark-layouts-1.0.md`, *The
agreement floor*). A frame that decodes to nothing and a frame that decodes to
another id both count as carrying nothing, and neither is evidence against the
file: *Invalidating* below reads the clip's decode, never one sampled frame's.

**Which agreement is reported.** The figure shown beside a `video-rep-v1` id is
the one produced by the decode that produced the id — the aggregate over the
sampled frames. A verifier MUST NOT substitute a figure computed over the
frames that carried the id, or over any other selected subset. A reader is
shown four things at once — the id, the count, the figure, the outcome word —
and only the aggregate's own figure keeps them consistent: it is the number the
floor was applied to, so it is the reason the id may be named at all, and it is
the population the floor was placed in, every figure behind that constant being
one clip's (`watermark-robustness-1.0.md`, *A device campaign*). A mean over
the frames that carried the id answers the question the count already answers,
and answers it backwards: conditioned on its own selection, it *rises* as fewer
frames qualify, so a clip where one frame of eight carried the mark cleanly
would show a higher figure than one where all eight carried it through heavy
re-compression. Substituting the aggregate when no frame carried the id does
not repair that; it makes one field mean two things a reader cannot tell apart.

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
different from `sig.pub`; a located segment whose `content_hash` recomputed
from the container differs from the signed one, and every other failure of
§5's *Locating segments* — a GOP no signed segment accounts for, a duplicated
or out-of-order index, a malformed vcap SEI — or a container whose NAL units
do not tile its samples (§5); a watermark payload that **decodes** to an id other
than the one the proof declares (`capture_id` for `photo-bch-v3`,
`watermark.mark_id` for `video-rep-v1`) — a payload that fails to decode is
*watermark not recovered*, above, and not this, and **a `video-rep-v1` block
below the layout's agreement floor did not decode**: a decode nobody may report
is not evidence against the file that carried it, and reading one as forgery
would turn a re-compressed clip of a genuine capture into an accusation; a segment signature invalid, or the chain broken where the file claims
contiguity; footer structurally valid with a CRC mismatch (*corrupted proof*,
distinct from *no proof found*).

**Not red.** `media.hash` not matching the recomputed canonical bytes on a video
whose present segments verify and are located in the file → *verified clip*
(§5); on a video in which no segment can be located → *frames not compared*
(§5, *Locating segments*). On a photo, a `media.hash`
mismatch with a valid `sig` means the file was altered after sealing: **red**.
A proof found up a C2PA `parentOf` chain (§3.2, depth ≥ 1) is a source
capture's, and where §4–§8 would give *tampered* or *frames not compared* the
outcome is *no proof found*: the derivation is declared, and the proof is not
presented as this file's.

**Where the proof came from.** *Sidecar differs* and *manifest copy differs*
(§3.1) are warnings on an otherwise valid verdict: a second copy of the proof
that is not the one used. `proof_source` and `frames_name_capture` (§3.2) are
diagnostics and never labels.

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
- **From the first publication, additive only** — see the status notice at the
  top: the rule binds from the first build, SDK or sealed file that reaches
  somebody else, and not from any tag, and while the format is a draft a
  breaking change is allowed and recorded as one in `CHANGELOG.md`. What the
  rule permits once it binds: new optional keys, and new values only in
  fields documented as extensible (`watermark.layout`, `location.evidence[].kind`,
  `location.source`, `location_corroboration.method`, `timestamp.tsa_issuer`,
  `integrity.source`, `attestation_status.source`).
  Every extensible field states the fallback for an older verifier. A new value
  in such a field is a short machine name in one of the two spellings the format
  already uses — lowercase-hyphen (`bch-255-131`, `base-sepolia`) or camelCase
  (`secureEnclave`, `playIntegrity`, `googleStatusList`) — and the schema
  accepts both. It once accepted only the first, which made `googleStatusList`
  schema-invalid in the same document that named it. `device.secure_hw`, `sig.alg`,
  `location.level`, `location_corroboration.result`, the set of
  core keys and the segment message layout are **not** extensible: changing any
  of them is a new minor with a new separator (§5) or a new major.
- **Never**, once the rule binds: reuse a key name with a different meaning,
  promote an optional key to required, or change the meaning of an existing
  enum value. A layout change desynchronizes every already-sealed file: add a
  version instead. `media.w`/`media.h` were promoted to required while this
  format was a draft (§8, vector 46) — that is the kind of change this line
  forbids afterwards, and it is recorded in `CHANGELOG.md` as breaking.
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
- **Where it was**, beyond the position level the verifier reaches (§7.1):
  *declared* is the device's word, *corroborated* is the registry's word
  about an operator's cell-level answer on the SIM, and *authenticated* is a
  word nothing earns yet.
- **That the device was not compromised** below the attestation boundary: a
  rooted device with a virtual camera can sign an injected frame. This is why
  `integrity` exists, why it is signed by the registry and not declared by the
  app, and why its failure is prominent.
- **Anything about the C2PA manifest** of a sealed photo. It sits outside the
  canonical bytes (§4.1) and can change without affecting the vcap verdict; it
  is verified by its own signature, separately. A verifier that reads the proof
  out of Content Credentials (§3.2) still checks nothing about the manifest
  that carried it: who signed it, what it declares and whether its bindings
  hold are a C2PA validator's answer, shown apart. What each format proves
  that the other does not, how a proof maps onto C2PA assertions and what a
  verifier says after a platform strips metadata: `c2pa-interop-1.0.md`.

---

## 11. Review status

Draft as of 10 September 2026 (see the status notice at the top: the additive
rule starts at first publication). The open items below are follow-ups: each is either
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
- [~] `REVIEW (mobile)` manifest ordering: after sealing for photos, before for
      video — confirmed against C2PA 2.4 (`c2pa-interop-1.0.md` §3, vectors
      68 and 73): `c2pa.hash.data` covers to end of file, `c2pa.hash.bmff.v3`
      needs `/free` excluded; executed with a real claim generator (c2pa-rs
      0.91) and a test signing credential in vectors 123–147, whose C2PA
      results `expected.json` records. The on-device check waits for a
      signing certificate of our own
- [ ] `REVIEW (BE)` a C2PA update manifest appended to a sealed ISO-BMFF file
      takes the position the footer needs (vectors 69–70). Forbidden for
      writers; whether a future minor lets a reader step over a trailing C2PA
      `uuid` box before seeking the footer is open, and would be a new reading
      rule, not a change to this one. Any such rule first normalizes
      `box_purpose` in the canonical bytes: appending an update store turns
      the original store's `box_purpose` from `manifest` into `original` in
      place (C2PA A.5.3), inside `media.hash` (`c2pa-interop-1.0.md` §6)
- [ ] `REVIEW (mobile)` per-segment signing cost in StrongBox on a long clip
- [~] `REVIEW (mobile)` NAL byte definition and audio DTS rule reproducible on both encoders — the DTS clock is now named (M8) and the timeline with it (edit lists, §5); H.264 and HEVC on Android are reproduced byte for byte by a second implementation written from this text (`tools/src/container.ts`, vectors 36–37), which is what "reproducible" was asking; on iOS the NAL bytes are reproduced for HEVC in MOV (vector 48) and H.264 in MP4 (vector 85), and the audio DTS rule is not yet exercised: neither clip has an audio track
- [x] `REVIEW (mobile)` hashing two interleaved tracks during encoding — resolved: 8 KB and 0.5 ms per segment on a TEE device (M8)
- [ ] `REVIEW (mobile)` metadata stripping before sealing for pseudonymous captures
- [ ] `REVIEW (LEAD)` the `authenticated` position level (§7.1) is reserved
      and unreachable: the first `location.evidence[].kind` that reaches it
      (Galileo OSNMA attested by the device) waits for a smartphone chipset
      that exposes OSNMA — none does as of September 2026. Arrives as a
      new kind in an extensible field, with its vectors; no change to the core keys
- [ ] `REVIEW (BE)` the registry's mapping from CAMARA raw results (`TRUE`,
      `FALSE`, `PARTIAL` with `matchRate`, `UNKNOWN`) and from
      number-verification plus SIM-swap onto §6.2's `result` — a registry
      rule, to be published with the platform, not a format change
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
      revocation snapshot on either side of the instant): **45** in `vectors/`
      when this item closed, **73** with the registry, anchor, timestamp,
      integrity, iOS, C2PA co-existence and sidecar slices since,
      **84** with the position level (74–84), **85** with the iOS sealed
      clip, and **121** in corpus 2.0.0 with the video binding (86–94), the
      time, revocation and attestation rules (96–110), the JSON reading rules
      (111–120) and the extensible identifiers (95, 121), and **147** in
      corpus 2.1.0 with the JUMBF exclusion narrowed to the C2PA store (122)
      and Content Credentials as a carrier of the proof (123–147),
      checked by the reference verifier in `tools/`. The §7 vectors
      trust the anchors in `vectors/_trust/`, whose attestation root is a test
      root: they prove the level logic, not that an implementation can walk a
      real Google chain — for which the real device chains in the two verifier
      repositories exist
- [x] `REVIEW (BE)` the remaining proof-level vectors: registry inclusion with
      a signed tree head (49–54), an RFC 3161 token (59–63), an anchor with a
      recomputed root (55–58). The reference verifier evaluates all three;
      vector 100 is the corpus's green, and 54 — the same proof with only the
      device clock for an instant — is amber
- [~] `REVIEW (mobile)` container-level video vectors: real MP4/MOV from each
      encoder, with `content_hash` recomputed from the NAL units and audio
      frames — Android H.264 and HEVC done (vectors 36–39, `kind: container`);
      iOS HEVC in MOV (48) and H.264 in MP4 under a Secure Enclave chain (85)
      done, both without audio; an iOS clip with audio is still owed
- [x] Whether a verifier that cannot recompute segment hashes must say so in
      its labels: **yes** — *segment content not recomputed* (§5, §7), decided
      10 September 2026. Recomputation stays optional, declaring it does
      not
- [x] Vectors for the proof level (§7): attestation chains (41–45), registry
      entries and the online revocation answer (49–54) — with test material in
      `_chains/` and `_trust/`, which prove the logic and not a real Google
      chain (see above)
- [x] Vectors for `timestamp` and `anchor` attachments — 59–63 and 55–58,
      with committed tokens in `_timestamps/` and the chain read as an input
- [x] JSON Schema validates every vector, and rejects each malformed case:
      `schema/vcap-proof-1.0.schema.json`, run by `tools` in CI
