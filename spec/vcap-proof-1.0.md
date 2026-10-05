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
     *sidecar differs*, a label, and the sidecar is not used (vector 18) —
     **unless it does better over the same bytes** (*A sidecar that does
     better*, below; vectors 172–174). Byte comparison, not semantic: a writer emits canonical bytes
     in both places and the label is a writer bug or a swapped file, either of
     which the reader should say rather than resolve. The copy the file's
     active C2PA manifest carries, if any (§3.2), is compared too, as
     `JCS(parse(copy)) == JCS(parse(payload))` — a claim generator
     re-serializes the JSON it is given, so bytes are not comparable across a
     manifest (vector 123) — and not equal is *manifest copy differs*, a label;
     the copy is not used for anything (vector 125). It is compared with the
     proof that decides, the sidecar's when the sidecar does. A copy that is
     not a well-formed proof (§6.1) differs from any other.
  2. **Valid footer, CRC fails** → *corrupted proof*, whatever a C2PA store
     says (vectors 06, 126) — **unless a sidecar does better without that
     trailer** (*A sidecar that does better*, below; vectors 72, 188, 189,
     192, 193). No copy found in the file substitutes for a trailer that was
     found and is broken; a sidecar is judged only over the bytes deleting
     that trailer would leave, which is what a reader would find without it.
  3. **`VCAP` magic, major ≠ 1** → *unsupported format version* (§3, vector
     115), with the same exception for a sidecar (vector 190).
  4. **No valid footer** → the proof is the first of, in this order: the proof
     in the active manifest of the file's Content Credentials (§3.2, depth 0);
     the sidecar; the proof of the nearest `parentOf` ancestor that carries
     one (§3.2, depth 1–16). The copy inside the bytes outranks the one beside
     them, as C2PA's embedded store outranks a remote one (15.5.2.1), and the
     sidecar, which is presented as this file's proof, outranks a source's
     (vector 130). A sidecar next to a depth-0 proof is compared with it as
     JCS; not equal is *sidecar differs*, and the sidecar is not used
     (vector 127) — **unless it does better over the same bytes** (*A
     sidecar that does better*, below; vectors 169–171). The same holds for
     a store the caller hands over.
     The canonical bytes are the **whole** received file (§4.1
     step 1, `F' = F`), including whatever a stale or displaced trailer left
     behind (vector 70). The verdict is computed exactly as for an embedded
     proof, and a verifier MUST NOT weaken it or add a label because the proof
     came from a sidecar or a manifest (vectors 17, 124): where the proof sat
     carries no evidence — `sig` over the core and `media.hash` over the bytes
     carry all of it, and both are recomputed in every case. The one exception
     is a proof found at depth ≥ 1, which is not presented as this file's
     (§3.2, *The verdict*).
  5. **None of these** → *no proof found*.
- **A sidecar that does better.** Neither the proof a file carries nor its
  place is authenticated as this file's: a C2PA manifest is not authenticated
  to a reader and, on a JPEG, sits outside the canonical bytes (§4.1), and a
  trailer with a valid CRC can be appended to any trailer-stripped file. So
  anyone can put another capture's proof in either beside a genuine file and
  its genuine sidecar, and a file's proof that always won would turn that into
  an accusation (vectors 169, 172). When a sidecar differs from the proof the
  file carries — the trailer at step 1, the depth-0 proof at step 4 — a
  verifier computes the verdict of each over the same canonical bytes (the
  file without the trailer at step 1, the whole file at step 4), and ranks
  their **outcomes**: *authentic* above *verified clip* above *frames not
  compared* above every other outcome, which rank equal.
  - The sidecar's outcome ranks **strictly above** the file's proof's → the
    sidecar's verdict is the verdict, `proof_source` is `sidecar`, and it
    carries *trailer copy differs* (step 1, vectors 172, 173) or *manifest
    copy differs* (step 4, vectors 169, 171) instead of *sidecar differs*.
    The same ranking decides against an unreadable footer (next item).
  - Otherwise → the file's proof stands with *sidecar differs*, as without
    this rule (vectors 18, 127, 170, 174).

  Only outcomes are ranked, never ceilings: a sidecar stripped of a `revoked`
  `attestation_status` reads amber where the file's complete copy reads red,
  and must not win. Nothing is gained this way that deleting the trailer or
  the manifest would not give — the sidecar, over those bytes, is what a
  reader finds then — and the file's copy can still lower a ceiling on a tie,
  never raise one. A sidecar identical to the trailer, byte for byte, or to
  the depth-0 proof, as JCS, is no second verdict and changes nothing.
  Outside the rule, unchanged: a nested trailer (§3) is *nested proof*, a
  structural verdict no proof of the file is judged for, and deleting the
  outer trailer leaves the inner one to step 1.
- **A sidecar that does better than an unreadable footer.** The same holds
  for a footer a reader cannot use: the last 16 bytes begin with `"VCAP"`
  and are not a valid footer whose CRC matches — the CRC fails (step 2), the
  major is not 1 (step 3), or the size describes no trailer (§3's structure
  fails, which without this rule is step 4 over the whole file). Such a
  footer is no more authenticated as the file's than a valid one, and
  sixteen bytes appended to a stripped genuine file would otherwise accuse
  it beside its genuine sidecar. When a sidecar is present, a verifier also
  judges the sidecar over `F'` = `F` without the **unreadable trailer**,
  defined exactly:
  - let `n` be the footer's `payload_len` (bytes 8–11 of the last 16, read
    at its v1 position whatever the major) and `T = 8 + n + 16`, summed
    without overflow;
  - if `T ≤ len(F)` and the 8 bytes at `len(F) − T` read `box_size == T`
    followed by `"free"`, the unreadable trailer is the last `T` bytes;
  - otherwise it is the last 16 bytes only.

  `F'` is judged as step 4 judges a sidecar: its canonical bytes are the
  whole of `F'` (§4.1 from step 2), whatever `F'` itself ends in — one
  trailer is removed and nothing further is read, so a footer appended
  after an intact trailer is not peeled back to it (vector 193). The
  outcomes rank as above; the sidecar's verdict decides only when it ranks
  **strictly above** the verdict that footer earns without this rule
  (*corrupted proof*, *unsupported format version*, or step 4's verdict over
  the whole file), and then carries *trailer unreadable* (new label) and
  `proof_source` `sidecar` (vectors 72, 188–191). The active manifest's copy
  in `F'`, if any, is compared with the sidecar as at step 1. Without a
  sidecar, or on a tie, the footer's verdict stands unchanged (vectors 06,
  07, 08, 115, 118, 126, 192, 193).

  Why this span and no other. *Authentic* and *verified clip* still need
  `media.hash` or a located segment's `content_hash` to match bytes the
  sealer signed, so trusting the span a broken footer declares cannot make
  forged bytes read genuine: a wrong span removes too much or too little,
  what remains is not what the sealer signed, and the sidecar reads no
  better than those bytes allow — on a photo *tampered*, a tie, and the
  footer's verdict stands. The box
  header is required so that what is removed is a `free` box every ISO-BMFF
  reader skips, or 16 bytes that are no box at all — never a box a player
  presents, which a declared span without that check could reach (vector
  191 is the footer of vector 07, whose declared span holds no box header:
  only the footer is removed). The major is set aside because a reader that
  does not know it reads nothing as a proof there; it takes the length and
  the box header at their v1 positions only to know what to remove. And the
  definition gives one candidate, so two implementations compute the same
  `F'`.
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
manifest, proof included. Normative for readers since 1.1 (vectors 123–147, 169–171).
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
    this file's. Beside a sidecar that differs, the better outcome of the
    two decides (§3.1, step 4). *Authentic* when the bytes are the sealed ones (vector 124);
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
   A sidecar beside a footer that cannot be read is judged once more over
   `F` without that footer's trailer, defined in §3.1 (*A sidecar that does
   better than an unreadable footer*).
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
  a track's samples start at its first edit's `media_time`. That is the whole
  of the timeline §5 models: leading empty edits, then **one** media edit at
  rate 1. An edit list on the video or audio track with anything after that
  edit — a second media edit, an empty edit, a rate other than 1 — trims,
  repeats or reorders what a player presents while every GOP still hashes to
  its signed value, so a verifier MUST NOT recompute segments over it as if
  the extra edits were not there: the container is one it cannot compare, no
  segment is located, and the verdict says *segment content not recomputed* —
  *frames not compared* when `media.hash` does not match, never *verified
  clip* (vector 156). An original is unaffected: `media.hash` covers its edit
  list with every other byte. This is not a corner
  case — `MediaMuxer` writes a 473 ms empty edit on the video track of a
  recording whose microphone opened before its camera, which is the ordinary
  case for a capture with audio. Aligning both tracks at zero instead pulls the
  audio frames that precede the first IDR into segment 0 and makes every
  segment hash of the file wrong. Two implementations of this rule, one on the
  device and one from the text, disagreed exactly there until the sentence you
  are reading existed (vectors 36, 166). Audio frames whose DTS
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
- **Presentation.** A segment hash covers the NAL units in the samples and
  the audio frames, and nothing that tells a player how to show them: the
  parameter sets a decoder configuration record carries out of band (in H.264
  and H.265 the SPS holds the cropping window and the VUI colour description,
  and every slice is decoded under the SPS and PPS it names), the track
  header's matrix (rotation, mirroring, translation) and display size, the
  sample entry's `clap`, `pasp` and `colr` boxes, the audio sample entry's
  `esds` (the sample rate and channel layout a decoder uses), and which tracks
  a player may enable. Parameter sets that travel in band, inside a sample, are NAL units
  of that sample and already inside `content_hash`. For an original,
  `media.hash` covers all of it; for a clip, nothing did, so a re-mux that
  kept every sample could crop, rotate or re-describe the signed frames and
  still read *verified clip*. `media.presentation` (§6.1) binds them into the
  core — it is **required** of every proof that carries `segments`, so of
  every video proof, and a core without it is not well formed: *no proof
  found* (§8, vector 165) — and a verifier reads them back from the received
  file:
  - **The video track** is the one track whose `hdlr` `handler_type` is
    `vide`; its sample description (`stsd`) has exactly one entry, `avc1`,
    `avc3`, `hvc1` or `hev1`, and that entry has its `avcC` or `hvcC`.
  - **`config`** is `SHA-256(P)`, where `P = uint32 BE n ‖ (uint32 BE len_i ‖
    nal_i) × n ‖ X`. The `nal_i` are every NAL unit of the decoder
    configuration record, as stored (no start code, no length prefix): in
    `avcC` the SPS list, the PPS list and, when the record carries it, the
    SPS extension list; in `hvcC` every NAL unit of every array. They are
    ordered by `nal_unit_type` ascending (`nal[0] & 0x1f` in H.264,
    `(nal[0] >> 1) & 0x3f` in H.265), and NAL units of one type keep the order
    the record lists them in. `X` is the concatenation of every child box of
    the video sample entry whose type is `clap`, `pasp` or `colr`, each whole
    — size, type and payload as stored — in file order, followed, when the
    file has a `soun` track, by every `esds` box of that track's sample entry,
    whole, in file order; empty when there is none of either. The child boxes
    of an `mp4a` entry start 28 bytes into its payload (`SampleEntry`, then
    the `AudioSampleEntry` fields); in a QuickTime sound description of
    version 1 or 2 (the `uint16` 8 bytes into the payload) 16 or 36 bytes
    later, and an `esds` inside a `wave` child of the entry counts as the
    entry's. An audio sample entry of another type adds nothing. The
    AudioSpecificConfig in the `esds` says the sample rate: change it and the
    same coded frames play pitched and re-timed while every segment hash and
    every timing record still match (vector 183).
  - **`matrix`** is the nine 32-bit values of the video track's `tkhd` matrix,
    each read as a signed big-endian integer, in stored order (`a, b, u, c,
    d, v, x, y, w`); **`display`** is the `tkhd` width and height, each read
    as an unsigned big-endian 32-bit integer (16.16 fixed point, unconverted).
  - **The track layout** holds when the file has exactly one `vide` track, at
    most one `soun` track, one sample description in each, and the
    `track_enabled` flag (`tkhd` flags `0x000001`) clear on every other track.
    A segment hash covers those two tracks and no other, and a player may
    show any track that is enabled.

  A file that is not the original reaches *verified clip* only when the
  layout holds, `config`, `matrix` and `display` read back equal the
  signed ones (vectors 89, 94, 159), and its timing reads back as signed
  (*Timing*, below). Otherwise the signed frames are in the
  file under a presentation nobody signed: **frames not compared**, no
  segment credited, with *tracks not bound* when the layout does not hold
  (vector 162) and *presentation differs* when a value does not match
  (vectors 160, 161). Not *tampered*: re-muxing a clip is not an
  accusation, as a `media.hash` that does not match is not one. A genuine
  clip that keeps the configuration, the header and the tracks is a verified
  clip (vector 159). On an original the values are compared too: they cannot
  differ without the writer having described some other file, which is the
  writer's false claim about bytes that are exactly the sealed ones —
  *presentation differs*, amber at best, never red (vector 163), the reasoning
  of *inconsistent claim* (§7). A decoder configuration or video track header
  the verifier cannot read is a presentation that does not match, and a track
  whose header it cannot read counts as enabled; neither stops a GOP being
  located, so a file that contradicts its proof is still *tampered*.
- **Writer requirements for `media.presentation`.** A video writer MUST
  include it: a proof without it is *no proof found* over the original as
  over every clip, so a writer that omits it has sealed nothing a verifier
  will read. It MUST compute it from the file it produced, after the muxer
  finalised it and before the trailer is appended — the bytes a verifier will
  read — and never from the encoder's output format, the parameters it asked
  the muxer for or the platform's documentation: a muxer may rewrite the
  configuration record (array order, the `avcC` extension, a `colr` or
  `pasp` of its own) and a matrix it was handed as a rotation hint, and the
  rule is the one §5 already states for NAL units. In practice: Android's
  `MediaMuxer` writes `tkhd` from `setOrientationHint`, and AVFoundation's
  `AVAssetWriter` from the input's `transform`, and what else lands in the
  sample entry is the muxer's choice, not the writer's: measured, `MediaMuxer`
  on a Samsung SM-S908B writes a `colr` (`nclx`) and no `pasp` (vectors 36,
  37), macOS `AVAssetWriter` writes `fiel` and `chrm` and neither of the two,
  and the iPhone files of vectors 48 and 85 carry the configuration record
  alone. Only `clap`, `pasp` and `colr` enter `config`, whichever are there;
  the writer reads them back rather than assuming any. `w` and `h` stay the coded
  frame size; a rotated display is the matrix's business. A writer that
  writes more than the one video and at most one audio track, or leaves an
  extra track enabled, makes every clip of the file *tracks not bound*, and
  its original is still *authentic*. A writer MUST check its output against a
  verifier on a file it produced (vector 158 is one).
- **Timing.** A segment hash covers the bytes of the frames and
  `media.presentation` how a player is told to show them; neither says
  **when**. For an original `media.hash` covers the timing tables with every
  other byte; for a clip nothing did, so a re-mux that kept every sample
  could freeze a frame (`stts`), reorder the frames of a GOP (`ctts`), scale a
  whole track or both (`mdhd`), or trim inside a located segment (the media
  edit), and still read *verified clip*. The audio rule above binds timing
  only by accident, where a change moves an IDR relative to the audio. The
  sealer signs it instead, without touching the segment message: each
  `segments[]` entry carries the hash of its segment's **timing record**, and
  the core carries `media.timing`, whose `root` binds those hashes (§6.1).

  ```
  timing(n)  = uint32 BE v
               || ( int64 BE (dts_i − dts_0) || int64 BE cts_i ) × v
               || uint64 BE (end_n − dts_0)
               || uint32 BE a
               || ( int64 BE (adts_j − adts_0) || uint32 BE adur_j ) × a

    i = 0 … v−1   the video samples of segment n, in decode order: the IDR
                  first, then every sample up to the next IDR, whatever NAL
                  units each holds
    dts_i         the sample's DTS: the sum of the `stts` durations of every
                  sample before it in the track
    dts_0         the DTS of segment n's IDR
    cts_i         the sample's composition offset from `ctts` — version 0
                  unsigned, version 1 signed, as ISO/IEC 14496-12 says —
                  and 0 when the track has no `ctts`
    end_n         the DTS of segment n's last video sample plus that
                  sample's own `stts` duration
    j = 0 … a−1   the audio frames §5 assigns to segment n (those of
                  audio_frames(n)), in decode order; a = 0 when it has none
    adts_j        the frame's DTS in the audio track; adts_0 the first's
    adur_j        the frame's `stts` duration

  segments[n].timing = base64url( SHA-256( timing(n) ) )
  media.timing.root  = base64url( SHA-256( T(0) || T(1) || … || T(segment_count − 1) ) )
                       T(n) = the 32 bytes segments[n].timing decodes to
  ```

  - **Every value is an integer in the media timescale of its own track**,
    the `mdhd` timescale the file states: video values in the video track's,
    audio values in the audio track's. `media.timing.video_timescale` and
    `audio_timescale` are those two timescales; `audio_timescale` is
    **absent** — never `null`, never 0 — when the file has no `soun` track,
    and then every record has `a = 0` (vectors 158, 159). The record is
    measured from the segment's own first sample, so where a segment sits —
    after a cut, behind an empty edit, in a movie timescale a re-muxer chose
    — does not enter it: the edit list enters only through the audio
    assignment and the clip rule below. Every field is fixed-length and each
    count precedes its list; a value that does not fit its field is a record
    that cannot be built.
  - **`end_n` is read from the segment alone.** In a sample table it equals
    the DTS of IDR n+1 when one follows, and for the last segment it is the
    only definition: it is what binds how long the last frame is shown. A
    reader MUST NOT take it from the track's `mdhd` duration or from an edit:
    `MediaMuxer`'s `mdhd` duration counts the leading delay (vector 175), and
    the segment a clip ends on need not be the one its original ended on
    (vector 178).
  - **What the audio half binds.** Which frames a segment has, their spacing
    and their durations. The offset between the tracks is bound only to the
    slack of the assignment rule: shifting the audio by less than the gap
    between each segment boundary and the nearest audio frame moves no frame
    and changes no record — less than one audio frame (21 ms for AAC at
    48 kHz), accepted.
  - **The root, without a demuxer.** When the proof carries an entry for every
    index from 0 to `segment_count − 1`, a verifier recomputes `root` from
    the entries' `timing`; a root that does not match is a binding the proof
    makes that does not hold: **tampered** (vector 177), whatever the file.
    When an entry is missing the root cannot be recomputed, and no entry's
    `timing` is authenticated — they are outside every signature. **A clip's
    proof carries every entry**: a writer, a cutter or any tool that carries
    a proof along with a clip MUST NOT drop the entries of the segments it
    cut (vector 186).
  - **Reading it back** (a file that is not the original). For each located
    segment the verifier builds `timing(n)` from the received file, in the
    received file's timescales, and expresses every value in the signed one:
    `t_signed = t_received × ts_signed / ts_received`, video values with
    `video_timescale`, audio values with `audio_timescale`. Each result MUST
    be an integer; an audio value with no audio timescale on either side, a
    result that is not an integer or one that does not fit its field is a
    timing that differs. The verifier hashes the converted record and
    compares it with the entry's `timing`. A re-mux that keeps a timescale or
    multiplies it, durations with it, verifies exactly (vector 182); one that
    moves to a timescale unable to represent the signed instants has moved
    them — by at most a tick — and reads *timing differs* (vector 181). A
    hash admits no tolerance, and a tolerance would be the thing to argue
    about.
  - **The single media edit** (a file that is not the original). On the
    video track and on the audio track, when the edit list has a media edit
    — `media_time` m in media ticks, `segment_duration` d in movie ticks, the
    track's media timescale T and the movie timescale M — it **trims inside**
    a located segment when `m > s`, or when `(d + 1) × T ≤ (e − m) × M`
    (the edit ends one movie tick or more before the segment does), where
    `[s, e)` is the segment's span on that track in media ticks: for video
    from the least `dts_i + cts_i` to the greatest `dts_i + cts_i + dur_i`
    (`dur_i` is the next sample's DTS minus `dts_i`, `end_n − dts_i` for the
    last), for audio from `adts_0` to the last frame's DTS plus its
    duration. The movie tick of slack is the rounding a muxer cannot avoid
    when M is coarser than T (vector 178). A track with no media edit shows
    all its media and trims nothing. An edit list of any other shape is
    already a container §5 does not compare (*The DTS is the container's*).
  - **Verdict.** A located segment whose timing does not read back as
    signed, whose entry's `timing` the root does not authenticate, or which
    the media edit trims, is in the file under a timing nobody signed:
    **frames not compared**, no segment credited, with *timing differs*
    (vectors 179, 180, 181, 184, 186) — beside *presentation differs* or
    *tracks not bound* when those hold too. Not *tampered*: re-timing a clip
    is not an accusation, and it is not a verified clip either. Changing the
    audio sample rate is *Presentation*'s case, not this one (vector 183).
  - **On the original** the verifier builds the record of every segment
    from the file — each index from 0 to `segment_count − 1` named by
    exactly one GOP — converts them as above, and compares the root they give
    with the signed one. The bytes are the sealed ones, so a root that does
    not match is the writer's false claim: *timing differs*, amber at best,
    never red (vector 185), as for *presentation differs*. The media edit
    rule does not apply to an original: `media.hash` covers its edit list.
  - **Writer requirements for `media.timing`.** A video writer MUST include
    it, and `timing` in every `segments[]` entry: a proof without either is
    *no proof found* (§8, vectors 176, 187). It MUST compute both from the
    file it produced, after the muxer finalised it and before the trailer is
    appended — the sample tables, `mdhd` timescales and edit list a verifier
    will read — and never from the encoder's presentation timestamps, the
    timescale it asked for or the platform's documentation: a muxer chooses
    timescales and edits and rounds every timestamp into them (vector 185
    signs microseconds and describes no file). The segment message does not
    change, so the record is read back after the recording stops and no
    segment is re-signed: only the core, which a writer signs after that
    read-back anyway, and the entries' `timing` change. A writer MUST check
    its output against a verifier on a file it produced (vector 175 lists
    the records byte for byte).
- **Verifier behaviour** on video:
  - `sig` verifies over the core → the claims are authentic (who, which key,
    declared when and where). If `sig` fails → **tampered**, red, stop.
  - `media.hash` matches, every segment verifies, chain unbroken, first index 0,
    `segment_count` segments present → eligible for **green** (subject to §7);
  - `media.hash` does not match, or segments are missing, but every present
    segment signature verifies, the chain holds wherever two consecutive
    segments are both present, at least one GOP is located and verified
    under *Locating segments*, and — when `media.hash` does not match — the
    file presents those GOPs as the core says (*Presentation*) and at the
    instants it binds (*Timing*) → **verified clip**, amber, reporting which
    segment indexes verified out of `segment_count`;
  - a segment signature fails, or a present segment's `prev` differs from
    `SHA-256(message(n−1))` while segment n−1 is present (the chain breaks where
    the file claims contiguity), or every entry is present and their `timing`
    hashes do not recompute `media.timing.root` (*Timing*) → **tampered**, red;
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
  "media":    { "mime", "w", "h", "duration_ms", "hash", "segment_count",
                "presentation": { "config", "matrix": [ 9 ], "display": [ 2 ] },
                "timing": { "video_timescale", "audio_timescale", "root" } },
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
  "segments":    [ { "gop": 0, "hash", "prev", "sig", "timing" } ],   // "range" is deprecated: writers MUST NOT emit it (§5)
  "attestation": [ "base64url DER leaf", "...", "base64url DER root" ],   // omitted on web
  "attestation_status": { "source", "fetched_at", "entries": [ { "serial", "status", "reason", "revoked_at" } ], "sig" },
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
- `media.presentation` (video) — how the signed frames are shown, so that a
  clip cannot crop, rotate or re-describe them (§5 *Presentation*):
  `config`, base64url of 32 bytes, the SHA-256 of the presentation message;
  `matrix`, nine integers, the video `tkhd` matrix as stored, each `int32`;
  `display`, two integers, the `tkhd` width and height as stored, each
  `uint32`. **Required** of every proof that carries `segments`, so of every
  video proof: absent or malformed, the proof is not well formed and reads
  *no proof found* (§8, vector 165), the original as much as any clip of it.
  A core field a clip depends on cannot be optional to the original: the core
  is signed once and has to hold for every file it is attached to. Photos
  carry none: `media.hash` covers every byte of a photo, and a
  photo has no derivation that keeps its signature (a still image that
  carries `segments` anyway carries the field with them, §8).
- `media.timing` (video) — when the signed frames are shown, so that a clip
  cannot freeze, reorder, rescale or trim them (§5 *Timing*):
  `video_timescale`, the video track's `mdhd` timescale as the writer's file
  states it, an integer from 1 to 2^32 − 1; `audio_timescale`, the same for
  the audio track, **absent** when the file has no audio track — never `null`
  or 0; `root`, base64url of 32 bytes, the SHA-256 over the segments' timing
  hashes in index order. Each `segments[]` entry carries `timing`, base64url
  of the 32-byte SHA-256 of its `timing(n)`; it is outside the segment
  message and bound by `root`. **Required**, both, wherever `segments` is,
  for `media.presentation`'s reason: absent or malformed, the proof is not
  well formed and reads *no proof found* (§8, vectors 176, 187).
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
  integer centimetres, `uint32`), `source` — how the fix was obtained: `gnss`
  (satellites), `network` (Wi-Fi or cell), `manual` (typed by a person), or
  `fused` (the OS combined its sources and did not say which: Android's fused
  provider, iOS CoreLocation always); extensible (§9), an unknown value is
  still a declared position. A writer that knows how the fix was obtained
  SHOULD say so, and MUST NOT name a source the OS did not report: `fused` is
  the honest answer when it combined them, and absence when it said nothing
  at all — and `at`, the device clock when the fix was taken, ms, which may
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
| `media.presentation` | yes (video, and wherever `segments` is) | the received container's configuration, `tkhd` and tracks (§5 *Presentation*) |
| `media.timing` | yes (video, and wherever `segments` is) | the entries' `timing` (the root), and each located segment's timing record read back from the received container (§5 *Timing*) |
| `device.secure_hw` | yes | proven level from `attestation` (§7) |
| `device.key_id` | yes | `sig.pub`, attestation leaf, registry entry |
| `watermark` | no | detector output, if the detector ran |
| `time.device_clock` | no | nothing — declared |
| `location` | no | `location_corroboration` and the level rules (§7.1) |
| `policy.pseudonymous` | no | nothing — the writer's declaration that it stripped identifying metadata before sealing (§4.1), which no verifier can check from the file; a trailer whose footer bit 2 says otherwise MAY be reported as *flags disagree* (§3) |

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
| `segments` | core, at capture | each `sig(n)` under `sig.pub`; each entry's `timing` by `media.timing.root` | `capture_id` in every message; `media.timing.root` |
| `attestation` | core, at key creation | chain to a pinned Google root / App Attest | leaf SPKI MUST equal `sig.pub` |
| `attestation_status` | sync, while the chain is current | registry key signature over `"vcap/1.0/attestation-status" ‖ core_hash ‖ JCS(entries) ‖ uint64 BE fetched_at` | signature covers `core_hash` |
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
    `"vcap/1.0/attestation-status" ‖ core_hash ‖ JCS(entries) ‖ uint64 BE
    fetched_at`: the 27 ASCII bytes of the separator, no terminator, no
    length prefix, as every separator in this document; the 32 raw bytes of
    `core_hash`; the JCS bytes of the `entries` array; 8 bytes big-endian.
    Every message the registry key signs — tree heads, key statuses,
    `integrity`, `location_corroboration` and this one — begins with its own
    `"vcap/1.0/…"` string, so no signature over one can be read as another.
    Until corpus 8.0.0 this message had no separator; that was not
    exploitable, because it began with a SHA-256 output nobody chooses where
    every other began with ASCII, but it was the one exception the rule
    should not have had (`CHANGELOG.md`).

  **Which key.** The signing key is the one that signs that log's tree heads,
  so a verifier needs no key it does not already hold for `registry`. The
  attachment carries no `log_id` of its own: when a `registry` attachment
  names a log the verifier trusts, that log's key and **no other** is the
  signing key — a signature under any other trusted key, however valid, is a
  signature no key the proof names made (vector 154). Otherwise — no
  `registry` attachment, or one naming a log the verifier does not trust,
  which is absent evidence (*log not trusted*) and names nothing — a verifier
  tries the keys of the logs it trusts and the signature identifies the one
  that made it; such a proof is never green, because its key is in no log the
  verifier follows. Trying every trusted key whatever the proof names would
  let one trusted log vouch for a device another log admitted, under policies
  the reader never chose to apply to it. A
  verifier holding no log key reports *chain revocation not checked* — the same
  outcome as an absent attachment, because a countersignature it cannot check
  is evidence it does not have. Adding a `log_id` to the attachment would be a
  new optional key and is deliberately not done: it would let a proof point a
  verifier at a key, and the verifier's own trust list must decide that. The
  same rule chooses the key for `integrity`, `location_corroboration` and the
  online key status below.

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
  proven level `none`, *attestation key revoked*, **red** (vectors 44, 96, 97).
  This holds for every chain that holds as evidence (§7 rules 1–3 and 5),
  whatever level it proves: a revoked certificate is evidence against the
  file, not missing evidence, so a chain that proves `none` already — an
  unlocked boot, an imported key — is red when revoked (vector 164); the
  same chains are checked for coverage (*chain revocation not checked*) and,
  with a verified `registry`, for the app that made the key (§7). A
  revocation is red unless all of these hold, in which case the level at the proven instant
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

  **Stripping turns red into amber.** The attachment is outside the core, and
  anyone holding the file can delete it: a proof whose snapshot says
  `revoked` reads red, and the same proof without the snapshot reads amber
  with *chain revocation not checked*. The signature stops a `revoked` entry
  becoming `valid`; nothing in a file can stop evidence leaving it. So an
  amber verdict carrying *chain revocation not checked* is not a statement
  that the chain was not revoked (§8, *What amber does not say*). A verifier
  with network, reading a proof while the chain is still current — every
  certificate within its validity at the verifier's clock — **SHOULD** read
  the source's status list itself and apply this section's rules to what it
  read, as it asks the log for the key's status (below): what it reads
  directly cannot have been stripped. A verifier that does so says which
  source it read and when; one that cannot, or that reads a chain already
  expired — whose status is published nowhere any more — has only what the
  file carries.

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
  instant of §7 when a **trusted source** proved it — the token's `genTime`,
  else a verified anchor's block time — and otherwise the **verifier's own
  clock**, never `time.device_clock`. The device clock is set by whoever holds
  the device key: a thief holding a key revoked for a reason that is not
  retroactive — a lost phone — would set it before `effective_from` and be
  told *valid*, the attack the chain's revocation rule above already refuses
  (vector 96). A revocation is never undone, so a key valid at the verifier's
  clock was valid at any earlier instant (vector 54), and a key revoked at it
  has nothing a third party vouches for placing the capture before the
  revocation (vector 155). *Revoked at the instant asked about* → **red** for
  the key's standing, shown with the reason. The statement is signed by the
  key of the log the `registry` attachment names (*Which key*, above).
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
  block's timestamp is the proven upper bound. **The block time MUST come from
  the chain's own record for `anchor_id`** — the timestamp the contract stored
  with the batch, or the block that emitted the batch's event as the chain
  reports it — and **never** from the proof's `tx` or `block`. Those two are
  unsigned locators, outside the core and outside every signature: anyone can
  rewrite them, so they tell a verifier where to look and nothing it may
  conclude. A verifier that dated a capture by the proof's `block` would let
  whoever holds the file pick the instant. The contract address is the one
  the verifier's trust list publishes for `chain`, never one the proof names
  (it names none). On `ebsi` and `ebsi-pilot`
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
  move once the chain has settled it, and nothing says how long before. An anchor whose root the chain
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
  log's tree heads, found as for `attestation_status` — a statement signed by
  another trusted log is not this log's word (vector 154). Integrity verdicts are
  tokens only the developer's server can decrypt, so they cannot live in the
  core as anything but a self-declaration — and a self-declaration by the app
  is worthless against the compromised device it exists to flag. As a
  registry-signed attachment the verdict is Google's or Apple's, relayed and
  signed by a key the verifier already has for tree heads. Absent →
  *integrity unevaluated* (§8). The server *adds* evidence; a verdict is
  always reached without it, and **green** is not (§7).

  **What `hardware` means.** The source attested the device's software state
  — verified boot, no known tampering — from a hardware root of trust. For
  `playIntegrity` that is `MEETS_STRONG_INTEGRITY`; `MEETS_DEVICE_INTEGRITY`
  and `MEETS_BASIC_INTEGRITY` are `basic`, because a device that hides a root
  from software checks passes them; no label at all is `failed`. `appAttest`
  proves a genuine device running a genuine build and says **nothing** about
  whether the device is jailbroken, so a registry MUST NOT relay an
  `appAttest` verdict as `hardware`: a valid assertion from an App Store or
  TestFlight build is `basic`, a failed one `failed`.

  **What the verdict is bound to** (accepted limit). The app requests a
  `playIntegrity` verdict with `core_hash` as the request's nonce, and the
  registry relays it only when Google's signed answer echoes that nonce and
  names the attested app as the requesting package: the verdict is about
  **this capture**, asked for by the
  app whose key signed it. It is **not** bound to the device that holds the
  key. Play Integrity attests a device and an app, and no key: nothing in its
  answer says which keystore the requester used. Binding the nonce to a fresh
  device-key signature would add nothing, because a signature over the core
  is already public in the proof, and a signature over a fresh challenge is
  something the holder of a compromised key can produce and hand to a clean
  device that asks for the verdict. That the key sits in genuine, locked,
  verified-boot hardware is what the attestation chain's `rootOfTrust` proves
  (§7, rule 4), not this attachment; what this attachment adds is that a
  device running the attested app was intact when the capture was registered.
  The two are evidence about the same capture from two directions, and green
  asks for both. The residual risk is in `threat-model.md` §5.2.

  **Which platform.** A source attests the platform it runs on and no other:
  `playIntegrity` speaks for `device.platform` `android` only. A `hardware`
  verdict from a source that does not attest the proof's own platform proves
  nothing about the device that signed it — a Play Integrity verdict relayed
  beside an iOS proof is about some other device, or about none — and the
  attachment is shown as it is and proves no integrity (vector 153).

  A valid attachment is shown as **`integrity <verdict>`**, and a valid
  `failed` is shown prominently (vector 109). **Green requires proven device
  integrity** (§7): a valid attachment whose `source` is `playIntegrity` and
  whose verdict is `hardware`, on a proof whose `device.platform` is
  `android` (vector 100). Every other case — absent, a source this verifier
  does not know, a signer it does not follow or the proof does not name, a
  verdict of `basic`, `unevaluated` or `failed`, any verdict from
  `appAttest`, a source that does not attest the proof's platform — caps the
  ceiling at **amber** with *integrity not proven* beside the proven level
  (vectors 148, 149, 150, 153, 154). The proven level says where the key lives;
  it does not say that what asked the key to sign was intact, and green
  claims both.

  Why a condition and not only a cap: the signature stops a verdict being
  **strengthened** — `failed` cannot become `hardware` without breaking it —
  and cannot stop it being **deleted**. A relabelled attachment is
  indistinguishable from one signed by a registry the verifier does not
  follow (vector 66), and deleting it leaves a file whose every other
  signature holds. Were absence to cap nothing, whoever held a copy of the
  file could turn a `failed` amber into green by stripping it. With integrity
  a condition for green, stripping evidence leaves the verdict where it was
  or lowers it — never raises it. The price is stated, not hidden: a capture
  is amber until the registry has relayed a `hardware` verdict for it, which
  for a capture sealed offline means until it is sent; and **no iOS capture is
  green in this version**, because no source proves an iOS device intact. A
  source that does arrives as a new `source` value in a later minor, with its
  vectors, and changes the table then.
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
     inside the certificate's life. A block time is not chosen by the holder
     of any key in the proof: the sequencer (Base) or the validators (EBSI's
     Besu network) set it, within the bounds the chain's consensus enforces
     against its parent block, and on `ebsi` the verifier reads it through
     EBSI's gateway, so it trusts that operator not to lie about the record.
     That is a weaker statement than "chosen by nobody" and a different one
     from a TSA's: no party a forger controls sets it, and the contract it is
     read from is the one the verifier's trust list names for the chain. A core
     first anchored after the certificate expired cannot carry a token that
     honest stamping produced, and a token that postdates the block which
     already anchors its core contradicts the order the evidence was made in.
     Without an anchor nothing bounds a leaked TSA key's backdating; the
     residual risk is in `threat-model.md` §5.4.

  These six are the whole check: **no revocation check of the TSA signer is
  required**, and a verifier that skips one is conformant. A token is
  validated offline from what the proof carries, which holds no revocation
  data, and what an online check could conclude about a token issued before
  a revocation is not yet specified (`threat-model.md` §5.4, §6). A verifier
  that stops trusting a TSA removes its root from the roots it pins.

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

The `attestation` chain links further than the key does (accepted, open).
It carries no serial, IMEI or MEID, but it is not anonymous: a Remote Key
Provisioning intermediate is issued to one device and certifies every key
that device creates while it lives, and the leaf's `attestationApplicationId`
names the app's package and signing certificates. Two proofs whose chains
share an intermediate come from the same device even after the device key
rotates, and a chain names the app that sealed the capture. A
`policy.pseudonymous` proof that carries its chain is therefore linkable
across key rotations and names its app. One that leaves `attestation` out is
linkable through `device.key_id` only, and the chain stays with the registry,
whose log leaf commits to it as `attestation_digest` without revealing it —
at the price, on Android, of a proven level of `none`: only the chain proves
an Android level (§7), and a digest in a leaf proves nothing a verifier can
recompute. iOS carries no chain and is unaffected. This version defines no
way to prove an Android level offline without disclosing the chain; a writer
of pseudonymous captures chooses between the two, and per-device
unlinkability is open, with per-capture keys (`threat-model.md` §5.5).

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
6. **Generated, not imported.** The hardware-enforced authorization list
   carries `origin` (tag 702) with the value `GENERATED` (0). A key imported
   into the TEE — `IMPORTED` or `SECURELY_IMPORTED` — carries the TEE's level
   and the device's boot state while it was made somewhere else, and whoever
   made it may hold the private key: the chain says where the key lives, and
   only `GENERATED` says nobody else has it. An `origin` that is absent, or
   present only in `softwareEnforced`, is not `GENERATED` (vector 152).

A chain that fails rule 1, 2, 3 or 5, or cannot be read, is evidence that does
not hold up: *origin not hardware-attested* **and** *attestation evidence
invalid* (§8). A chain that holds and proves too little — rule 4, rule 6, or a
`software` level — is *origin not hardware-attested* without *attestation
evidence invalid*: a genuine chain from an unlocked phone, or of an imported
key, is not a forged one. It is still evidence, so a claim above it is
*inconsistent claim* (below), and its revocation and its app are checked as
for any chain that holds: a revoked certificate in it is *attestation key
revoked*, red (§6.2, vector 164).

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
| `strongbox` | valid to Google hardware root, revocation checked, app admitted, device integrity proven | yes | **green** | sealed in secure hardware |
| `tee` | valid to Google root, revocation checked, app admitted, device integrity proven | yes | **green** | sealed in the TEE |
| `secureEnclave` | the registry records an App Attest binding (see below) | yes | **amber** in this version: no source proves an iOS device intact | integrity not proven — *our records* |
| any of the above | valid, and no valid `integrity` attachment from `playIntegrity` with verdict `hardware` on an `android` proof, signed by the log the proof names (§6.2) | any | **amber** | integrity not proven |
| any of the above | valid | no (`registry` absent), or its evidence invalid | **amber** | key not in the transparency log |
| any of the above | valid | yes, but `tree_head.timestamp` after the declared capture | **amber** | registered after the declared capture |
| any of the above | valid | yes, but `tree_head.timestamp` after a valid token's `genTime` | **amber** | registered after the trusted time |
| any of the above | valid | the core declares no `time.device_clock` | **amber** | capture time not declared |
| any of the above | valid, log not reachable | any | **amber** | revocation not checked |
| any of the above | valid, and the only instant is `time.device_clock` | any | **amber** | no trusted time |
| any of the above | valid, `attestationApplicationId` not among the log's declared digests | yes | **amber** | attestation app not admitted |
| any of the above | valid, no digests to compare | yes | **amber** | attestation app not checked |
| any | key revoked at the trusted proven instant, or — with no trusted instant — at the verifier's clock (signed status, §6.2) | — | **red** | key revoked |
| any | a chain certificate `revoked` (`attestation_status`, §6.2), not shown by a trusted instant to predate the source's revocation date, or revoked for compromise | — | **red** | attestation key revoked |
| any of the above | a chain certificate revoked, and a trusted instant predates the source's revocation date | any | unchanged | attestation key revoked after the capture |
| any of the above | an entry `unknown`, or a certificate of the chain without an entry | any | **amber** | chain revocation not checked |
| any of the above | valid at the proven instant of capture, expired since | any | unchanged by the expiry | (nothing: expiry alone says nothing) |
| any of the above | expired, and the capture time is only `time.device_clock` | any | **amber** | attestation chain expired, capture time not proven |
| `none` | session key, no attestation, or a chain that does not prove a level | n/a | **amber, never green** | origin not hardware-attested |
| any of the above | a video proof whose `content_hash` values were not recomputed from the container (§5) | any | unchanged | segment content not recomputed |
| any | an original whose signed `media.presentation` does not describe it (§5 *Presentation*) | — | **amber at best, flagged** | presentation differs |
| any | an original whose signed `media.timing` does not describe it (§5 *Timing*) | — | **amber at best, flagged** | timing differs |
| any | claimed level above the level the `attestation` attachment proves | — | **amber at best, flagged** | inconsistent claim |
| any | a valid `integrity` attachment whose verdict is `failed` (§6.2) | — | **amber at best, prominently flagged** | integrity failed (and, beside a proven level, integrity not proven) |
| any | `sig` invalid, or attestation leaf ≠ `sig.pub` | — | **red** | tampered |

- **Claimed above proven** is flagged and capped at amber, not red: the core is
  signed by the device, so the false claim is the device's, but a firmware that
  misreports its level must not turn a genuine capture into "tampered". Claimed
  below proven: proven wins, nothing shown. The label needs evidence to
  contradict the claim: with no `attestation` attachment the proven level is
  `none` and the only label is *origin not hardware-attested*, whatever the
  claim (vectors 01, 12, 15 claim `tee` with no chain), and a chain that does
  not hold (rule 1, 2, 3 or 5) is no evidence either. A chain that holds is
  evidence even when it proves `none` — an unlocked boot, an imported key, a
  `software` level — and the claim is measured against the level it proves:
  `tee` claimed beside a chain that holds and proves `none` is *inconsistent
  claim* (vector 157). The measure is the level before revocation: a revoked
  chain retracts a level, it does not contradict the claim.
- **No freshness rule beyond rule 1.** A Remote Key Provisioning
  intermediate lives days, and rule 1 already validates it at the proven
  instant; nothing else about how recent a chain is enters the verdict. How
  fresh a chain was when the key enrolled is the registry's check at
  enrolment (`threat-model.md` §5.2, *Relayed attestation*), which a verifier
  cannot repeat from the file, and the table above asks nothing of it.
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
Whatever the level, an iOS capture is **amber at best** in this version: green
requires proven device integrity, and no source proves an iOS device intact
(§6.2; vectors 110, 150).

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

**What amber does not say.** Attachments are outside the core, and anyone
holding a file can delete one without breaking a signature. The format is
built so that deleting evidence never *raises* a verdict — every condition for
green is a piece of evidence that must be present (§7) — but it can lower one,
and some of what it lowers is red: a proof whose `attestation_status` says
`revoked` is red, and the same proof stripped of that attachment is amber with
*chain revocation not checked*. **An amber verdict may hide a red one.** Its
labels say which evidence is missing, and missing evidence is not evidence
that the answer would have been good. The remedy is to fetch what can be
fetched instead of reading it from the file: the log's signed key status
(§6.2, *Revocation, online*), and, while the attestation chain is still
current, the chain's status list (§6.2, `attestation_status`) — an online
verifier SHOULD do both. What can no longer be fetched — the status of a chain
that has expired — is only ever as good as the copy in the file.

**Required.** `v`, `capture_id`, `media`, `media.mime`, `media.hash`,
`media.w`, `media.h`, `device.secure_hw`, `device.key_id`, `sig`, for a
video proof `segments`, and for a proof carrying `segments`
`media.segment_count`, `media.presentation`, `media.timing` and `timing` in
every `segments[]` entry. The pixel dimensions are
required and are **not** evidence — nothing is proven by them — but every
writer holds them at capture, and a reader that cannot say how large the frame
is cannot place a watermark payload or a segment in it (vector 46). A proof is
a **video proof** when `media.mime` starts with `video/`; nothing else decides
it — not the container, not `duration_ms` — so a video proof without
`segments` is *no proof found* (vector 34), a video proof without
`media.presentation` is *no proof found* (vector 165), one without
`media.timing` or with an entry lacking `timing` is *no proof found*
(vectors 176, 187), and a still image carrying `segments` is verified as §5
says, `media.presentation` and `media.timing` included. Missing or unparseable → *no proof found*. Present but
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
| `integrity` present and valid | *integrity `<verdict>`* | what Google or Apple said about the device, relayed and signed by the registry; only `hardware` from `playIntegrity`, on an `android` proof, proves the device intact (§6.2), and `failed` is shown prominently |
| `anchor` present, chain not consulted | *anchoring not verified* | the path reaches the claimed root; nobody checked the chain recorded it |
| `attestation` (Android) | *origin not hardware-attested* | proven level `none` |
| `integrity` | *integrity unevaluated* | no statement about the device's state |
| a proven level (§7) without proven device integrity | *integrity not proven* | where the key lives is proven, that the device was intact is not: absent, `basic`, `failed`, `appAttest`, a source that does not attest the proof's platform, or evidence this verifier cannot read or the proof's log did not sign; the ceiling is amber (§7) |
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
| `attestation` present, not holding up | *attestation evidence invalid* | with *origin not hardware-attested*: a chain that fails a rule of §7 other than verified boot, origin or level |
| `attestation` valid, registry verified, app digests do not match | *attestation app not admitted* | the key was made by an app the log does not declare (§7) |
| `attestation` valid, registry verified, nothing to compare | *attestation app not checked* | the log declares no digests, or the leaf names no app (§7) |
| `attestation_status` absent, unreadable, `unknown` or incomplete | *chain revocation not checked* | the chain's certificates were not all shown valid while the chain was current (§6.2) |
| a video that is not the original, a track beyond the hashed two enabled, or a second video or audio track or sample description | *tracks not bound* | a player may show what no segment hash covers; *frames not compared* (§5) |
| a video whose configuration, matrix or display size read back differs from `media.presentation` | *presentation differs* | on a clip *frames not compared*; on an original the writer's false claim, amber (§5, §7) |
| a video whose segment timing read back differs from `media.timing`, a clip whose entries' `timing` the root cannot authenticate, or a clip whose media edit trims inside a located segment | *timing differs* | on a clip *frames not compared*; on an original the writer's false claim, amber (§5 *Timing*, §7) |
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

**Where the proof came from.** *Sidecar differs*, *trailer copy differs* and
*manifest copy differs* (§3.1) are warnings on an otherwise valid verdict: a
second copy of the proof that is not the one used. *Trailer unreadable* is a
warning too: the file ends in a vcap footer that could not be read — CRC
failing, an unknown major, or a size that describes no trailer — and the
verdict is the sidecar's over the file without it. Neither a trailer, nor an
unreadable footer, nor a depth-0 proof from Content Credentials makes a
verdict red or broken over a sidecar that does better (§3.1, *A sidecar that
does better*). `proof_source` and `frames_name_capture` (§3.2) are
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
      0.91) and a test signing credential in vectors 123–147 and 169–171, whose C2PA
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
- [x] `REVIEW (BE)` a clip's timing is not bound — resolved in corpus
      7.0.0 (§5 *Timing*): each segment's timing record (`stts`, `ctts`,
      the `mdhd` timescales, the last frame's duration and the audio frames'
      timing) is hashed into its entry and bound by `media.timing.root`, a
      required core field; the media edit may not trim inside a located
      segment; the audio sample entry's `esds` joins `media.presentation`.
      Design in `reviews/design-clip-timing.md`, accepted 4 October 2026;
      vectors 175–187. Still open: a media edit that runs past the end of
      the track (what a player shows there is not defined by ISO-BMFF, and
      nothing binds it), the audio sample entry's own fields beside the
      `esds`, and an `esds` inside a QuickTime `wave` box, which no vector
      exercises (no MOV with audio is in the corpus)
- [~] `REVIEW (mobile)` NAL byte definition and audio DTS rule reproducible on both encoders — the DTS clock is now named (M8) and the timeline with it (edit lists, §5); H.264 and HEVC on Android are reproduced byte for byte by a second implementation written from this text (`tools/src/container.ts`, the containers of vectors 36 and 37, verified under a presentation-bound core in 166 and 158), which is what "reproducible" was asking; on iOS the NAL bytes are reproduced for HEVC in MOV (vector 48's container, 167) and H.264 in MP4 (vector 85's, 168), and the audio DTS rule is not yet exercised: neither clip has an audio track
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
      and Content Credentials as a carrier of the proof (123–147), and
      **168** by corpus 5.0.0 with device integrity (148–150), the fused
      position source (151), the verdict hardening and presentation binding
      (152–164) and `media.presentation` required (165–168), and **171**
      in corpus 6.1.0 with a sidecar no longer overruled by a worse
      depth-0 manifest proof (169–171), and **174** in corpus 6.2.0 with
      the same rule for a trailer (172–174), and **187** in corpus 7.0.0
      with clip timing bound (175–187), and **193** in corpus 8.0.0 with
      the same rule for an unreadable footer (188–193),
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
      done, both without audio; an iOS clip with audio is still owed. The
      device proofs of 36, 37, 48 and 85 predate `media.presentation` and
      read *no proof found* since corpus 5.0.0; their containers are verified
      under a re-signed core that carries it, and `media.timing` since
      corpus 7.0.0, in 166, 158, 167 and 168
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
