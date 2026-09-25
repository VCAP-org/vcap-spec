# vcap and C2PA: interoperability, the sidecar, stripped metadata — 1.1

Companion to `vcap-proof-1.0.md`. It answers three questions the format
leaves to a reader who also knows C2PA: what each of the two proves that the
other does not and how a proof maps onto C2PA assertions (§1–§2); how a vcap
trailer and a C2PA manifest share one file without breaking either binding
(§3); and what a verifier says after a platform strips metadata, with or
without a sidecar (§4–§5).

**Status: informative**, alongside `vcap/1.0` (draft), except the sentences
marked **Normative** — writer rules that follow from the analysis and have a
vector each. The normative text of the sidecar and of the carrier is
`vcap-proof-1.0.md` §3.1–§3.2; here is their rationale. C2PA citations are to **Content Credentials, C2PA Technical
Specification 2.4**, by clause number as the HTML at
`spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html`
numbers them (chapter 6 *Assertions*, 9 *Binding to Content*, 10 *Claims*, 11
*Manifests*, 14 *Trust Model*, 15 *Validation*, 18 *C2PA Standard
Assertions*, Appendix A *Embedding manifests*), and with the clause title
wherever a number alone would not survive a renumbering. Nothing here changes
a byte of the format; the one canonical-bytes change 1.1 needed — §4.1's JUMBF
exclusion narrowed to the C2PA store — is in `vcap-proof-1.0.md`.

**1.1** (25 September 2026): Content Credentials as a carrier of the proof —
the assertion's shape and two writer rules here (§2.1), the reader's rules in
`vcap-proof-1.0.md` §3.2 — the soft binding's value (§2.3), and two
corrections: §3.1 read 15.12.1.2 backwards, and §3.4 put the video trailer
inside the C2PA hash, which §3.2 says it is not. The file keeps its `1.0` name
because the notes of frozen vectors cite it.

We do **not** sign C2PA claims today. A C2PA claim signature needs an X.509
credential meeting the C2PA certificate profile (14.5.1 *Certificate Profiles*),
issued to a legal entity and present on a trust list (14.4.1 *C2PA Signers*)
before a validator reports *Trusted* (14.3.6 *Trusted Manifest*). No legal
entity exists, so no manifest signed by
us exists either. Everything in §3 is therefore about a manifest **somebody
else** writes on a sealed file — an editor, a platform, a camera pipeline that
runs both — and about the day we write one. The corpus does carry real C2PA
manifests (vectors 123–147): they are signed by a public test credential,
*vcap-spec test CA* (`vectors/_trust/c2pa-test/`), which no trust list carries
and which signs nothing but vectors.

---

## 1. What each format proves

The two are not competitors and not a subset of each other. C2PA is a
**provenance envelope**: who signed a statement about an asset, what they said
was done to it, what it was made from. vcap is a **capture proof**: that these
bytes were signed at the moment of recording by a key that lives in a named
class of hardware, that the frames of a video are the frames that were signed,
and that the key was on a public log before the capture.

| Question | vcap | C2PA |
|---|---|---|
| Who signed | a device key, pseudonymous (`device.key_id`), attested by a chain to a hardware root (§6.2 `attestation`, §7) | an organization or product, identified by an X.509 certificate on a trust list (14.2 *Identity of Signers*, 14.4.1) |
| Where the key lives | **proven** level: `strongbox`, `tee`, `secureEnclave`, `none` — a verifier names it (§7) | not modelled. `claim_generator_info` (10.2.3) names software; `c2pa.created` with a `digitalSourceType` of digital capture (18.15.2 *Mandatory presence of at least one actions assertion*) is the signer's **declaration** |
| Bytes covered | `media.hash` over the canonical bytes (§4.1) plus, for video, one signed hash per GOP with a chain (§5) | one hard binding per manifest (9.2 *Hard Bindings*): `c2pa.hash.data` over byte ranges (18.5), `c2pa.hash.boxes` over marker segments (18.7), `c2pa.hash.bmff.v3` over boxes, optionally a Merkle tree over `mdat` chunks (18.6) |
| A cut of a video | *verified clip*: which segments of how many, with the chain saying where it was cut (§5) | a new asset; the cut is an action in a **new** manifest that names the original as an ingredient, if the tool that cut it cooperates (18.15, 18.16). A validator of the clip alone sees a hard-binding mismatch |
| Edit history | none. The core is signed once and never changes (§6) | `c2pa.actions.v2` (18.15), `c2pa.ingredient.v3` (18.16), redaction (6.8 *Redaction of Assertions*), update manifests (11.2.3) |
| Signed metadata | the core: time, location with its level, policy — enums and integers, no free text (§6.1) | `c2pa.metadata` and entity metadata assertions in JSON-LD (18.17), thumbnails, regions of interest |
| Trusted time | RFC 3161 token over `core_hash`, inside the proof, checked offline against a pinned TSA root (§6.2) | RFC 3161 token over the claim signature, inside the COSE structure (10.3.2.5 *Time-stamps*; 15.8 *Validate the Time-Stamp*) |
| Key on a public log | `registry`: RFC 6962 inclusion proof against a signed tree head, carried inline, checked offline (§6.2) | none. Trust is a list of signers (14.4) plus revocation by OCSP (14.5.2, 15.9) |
| Existence before an instant nobody controls | `anchor`: Merkle path to a root recorded on a public chain (§6.2) | none |
| Device state | `integrity`: Play Integrity / App Attest verdict, relayed and signed by the registry; shown, and `failed` caps the ceiling at amber (§6.2, §7) | none |
| Watermark | `watermark`: layout named in the signed core, payload bound to `capture_id` (§6.1, `watermark-layouts-1.0.md`) | `c2pa.soft-binding` naming an algorithm from a public list (18.10, 9.3 *Soft Bindings*) |
| What the verifier says when something is missing | one exact label per absent or unreadable piece of evidence (§8) | status codes (15.2.2 *Standard Status Codes*) and three manifest states, *Well-Formed*, *Valid*, *Trusted* (14.3) |
| Verification without a server | always (invariant) | offline for the signature and binding; the trust list and OCSP are fetched or shipped |

Two consequences a UI must respect. A C2PA *Trusted* manifest says a signer on
a trust list made a statement; it does not say the statement is true, and it
says nothing about hardware — the claim generator's word that it "captured"
the asset is exactly that. A vcap green says the bytes were sealed in a named
class of hardware by a key that was on a log; it says nothing about what was
done to the picture afterwards, because nothing can be done to it without
turning the verdict red (§8). A verifier that shows both MUST NOT collapse
them into one light: §7's "name the level" applies to the pair as it applies
to the three roots of trust inside vcap.

---

## 2. Mapping onto C2PA assertions

### 2.1 The proof as a custom assertion

The whole proof travels as **one custom assertion**, so a C2PA validator that
knows nothing of vcap carries it intact and a vcap verifier finds it whole.
What a reader does with it — where it looks, which copy wins, what the verdict
is — is normative in `vcap-proof-1.0.md` §3.2; this section is its shape and
the writer's side.

- **Label**: `io.github.vcap-org.vcap.proof`. An entity namespace is the
  entity's Internet domain in reverse (6.2.1 *Namespacing*) — ours is
  `vcap-org.github.io`, the domain of the organization that publishes this
  specification — followed by the label components
  (6.2.2 *Label Naming*). The codename, never the brand: a label in a signed
  manifest is as permanent as trailer magic. No version suffix: an unsuffixed
  label is version 1 (6.2.2), a compatible change adds fields without
  changing it, and an incompatible one takes a **new label**, not `.v2`
  (6.3 *Versioning*) — which lines up with §9, where the proof's own `v`
  carries the version and a new major is a new format.
- **Box**: a JUMBF superbox in the manifest's assertion store whose
  description box has TYPE `6A736F6E-0011-0010-8000-00AA00389B71`, the JSON
  content type, the label above, and toggles `0x03` (requestable and label,
  which 11.1.4.1.2 requires) or `0x13` (the same, plus the private `c2sh` box
  that holds the assertion's salt, 8.4.2.3). A reader accepts both (vector
  133); c2pa-rs writes `0x13`. Its one content box is a `json` box holding the
  proof, the whole object, as a trailer's payload or a sidecar would
  (`vcap-proof-1.0.md` §3.1). Not CBOR, not re-keyed: a vcap verifier
  extracts the bytes and runs §6.1 on them, and the two implementations do
  not need to agree on a translation.
- **Bytes are not preserved** across a claim generator: c2pa-rs builds a JSON
  assertion by re-serializing what it is given (serde_json), and the box in
  vector 123 is not its trailer's payload byte for byte. Two copies of a proof
  of which one came through a manifest are therefore compared as
  `JCS(parse(a)) == JCS(parse(b))` — equal in vector 123, not in 125. A
  trailer and a sidecar keep the byte rule of `vcap-proof-1.0.md` §3.1: the
  vcap writer produced both.
- **One instance** per manifest, the unsuffixed label. An `__n` instance
  (6.4 *Multiple Instances*) is another assertion, and a reader ignores it
  (vector 135).
- **Created or gathered. Normative.** A claim generator lists the assertion
  in `gathered_assertions` — it did not produce the proof, and 10.2.2
  attributes every `created_assertions` entry to the signer — and in
  `created_assertions` only when it ran the seal itself, in the same pipeline
  (§3.4). c2pa-rs puts a definition's assertion in `gathered` unless it is
  marked `created`, so the default is the right one for a carrier and the
  wrong one for a capture pipeline that signs. A reader takes the assertion
  from either list and ignores a box no list names (vector 142).
- **Redaction.** A later claim generator may redact the assertion from an
  ingredient's manifest (6.8 *Redaction of Assertions*): the box removed and
  its URI listed in `redacted_assertions`, or the box kept with its content
  replaced by the single Redaction UUID box. Both read as the proof's absence
  (vectors 136, 137). The assertion is readable by anyone who dumps the store,
  position and `key_id` included, so a carrier that must not expose them
  redacts it, or carries only `policy.pseudonymous` proofs.
- **What it does not do.** The claim signature covers the assertion *as data*
  (15.10.3 *Assertion Validation*), so a C2PA validator proves that the signer
  included these bytes, not that they verify. The vcap verdict comes from
  running the vcap verifier over the extracted proof and the asset's canonical
  bytes, and the manifest's hard binding tells the C2PA side nothing about
  whether `media.hash` matches: the two bindings cover different byte sets
  (§3).

**Writing next to a store: two rules for JPEG. Normative.**

- **No seal over a store.** A vcap writer MUST NOT seal a JPEG that already
  embeds a C2PA Manifest Store (`vcap-proof-1.0.md` §3.2 says which APP11
  segments are one); it refuses with `VCAP_C2PA_MANIFEST_PRESENT` (vector
  131). The store's `c2pa.hash.data` covers every byte after EOI (§3.1), so
  the trailer it would append breaks somebody else's signature. The proof can
  still travel as a sidecar, or whoever owns the manifest re-issues it over
  the sealed file.
- **J1: no trailer rewrite under a store.** A writer that replaces the
  trailer of a JPEG embedding a C2PA Manifest Store (`vcap-proof-1.0.md` §3,
  *Replacing the trailer*) MUST afterwards re-issue the manifest — a new
  standard manifest over the file with its new trailer, the previous one as
  its `parentOf` ingredient — or strip the store. A trailer replaced under a
  manifest leaves a file whose C2PA side reads `assertion.dataHash.mismatch`
  and whose vcap side reads *manifest copy differs* (vector 125). An update
  manifest (11.2.3) cannot help: it carries no new hard binding.

### 2.2 Field by field

| vcap | C2PA | Relation |
|---|---|---|
| `media.hash`, canonical bytes (§4.1) | `c2pa.hash.data` (18.5), `c2pa.hash.boxes` (18.7), `c2pa.hash.bmff.v3` (18.6) | same purpose, **different coverage**: vcap excludes the trailer and, on JPEG, the C2PA store's JUMBF APP11 segments; C2PA excludes its own manifest store and whatever its exclusion list names. Neither hash is derivable from the other; each side recomputes its own |
| `segments[]` (§5) | `c2pa.hash.bmff.v3` with `merkle` over `mdat` chunks (18.6) | both hash pieces of the media; C2PA's tree proves a chunk belongs to the signed whole, vcap's chain proves order, completeness and where a cut was made. A C2PA Merkle proof is not a clip verdict |
| `capture_id`, `watermark.layout`, `watermark.mark_id` | `c2pa.soft-binding` (18.10): `alg`, `blocks`, `scope`, `bindingMetadata` | see §2.3 |
| `sig` (ES256 over `JCS(core)`, §4.2) | claim signature: COSE_Sign1 over the claim, detached payload (10.3.2.4 *Signing a Claim*, 13.2.2 *Use of COSE*) | **never the same key.** The device key has an attestation chain, not a certificate meeting 14.5.1; a C2PA signer's certificate names an entity, not a piece of hardware. The proof rides inside the manifest; its signature is checked by a vcap verifier, the manifest's by a C2PA one |
| `device.platform`, `device.secure_hw`, `device.key_id` | — | no equivalent: C2PA has no notion of the signer's hardware. This is the part the custom assertion adds |
| `attestation`, `attestation_status`, `registry`, `anchor`, `integrity` | — | no equivalent; they travel inside the assertion |
| `time.device_clock` | `c2pa.created` action's `when` (18.15.4.3), EXIF `DateTimeOriginal` in `c2pa.metadata` (18.17.3) | same declaration, same weight: a claim by the device. Trusted time is the token on either side |
| `timestamp.tsr` | the manifest's RFC 3161 token (10.3.2.5) | different `messageImprint` — `core_hash` here, the claim signature there — so one token cannot serve both, and each side's TSA trust is its own |
| `location.level`, `lat_udeg`, `lon_udeg`, `acc_cm` | EXIF GPS fields in `c2pa.metadata` (18.17.3 limits the assertion to an enumerated field list) | a declared position can be copied across; `level` has no C2PA field and is lost in the copy. C2PA has no "corroborated" or "authenticated" |
| `policy.pseudonymous` | none; the C2PA analogue is redaction of a metadata assertion (18.17.4) | different mechanism: vcap strips before sealing (§4.1), C2PA redacts after |
| `media.mime`, `media.w`, `media.h`, `duration_ms` | the asset itself; `c2pa.thumbnail`, `dc:format` in ingredients (18.16.5) | descriptive on both sides, evidence on neither |
| `v` | the assertion label's version (6.3) | §9 on one side, a new label on the other |

### 2.3 The watermark and `c2pa.soft-binding`

C2PA calls what our watermark does a **soft binding**: a value computed from
the content rather than its bits, so a manifest can be matched to an asset
whose bytes changed (9.3.1 *General*), and it says in the same clause what §8
says in ours — a soft binding "shall not be used as a hard binding". Its
assertion names an algorithm in `alg`, which "should" be an entry in the
**Soft Binding Algorithm List** (18.10.4), a JSON document C2PA maintains; a
`c2pa.watermarked.bound` action requires one (18.15.5 *Watermarking*).

Our algorithm is not on that list. Registration is a C2PA process and belongs
to the deferred C2PA work. Until
then the `alg` value would be an entity-namespaced string — for example
`io.github.vcap-org.vcap.photo-bch-v3`, one per layout as
`watermark-layouts-1.0.md` numbers them — which a C2PA validator cannot
resolve and treats as an algorithm it does not have. The two carry different
things anyway: a C2PA soft binding is a **value** a resolver looks up; ours is
a **payload** bound to the proof (`capture_id` for photos, `mark_id` for
video), and the binding is the signature over the core, not a lookup.

**The value, when the assertion is written** (informative). One `alg` per
layout, entity-namespaced until the list carries one; one block; and `value`
the decoded payload itself — the 16 bytes of `capture_id` for `photo-bch-v3`,
the 3 bytes of `mark_id`, big-endian, for `video-rep-v1`
(`watermark-layouts-1.0.md`). No `alg-params` and no `bindingMetadata`
(18.10.3.1): the layout fixes everything a decoder needs, and a value any
decoder reproduces from the pixels is what a resolver matches on (18.10.5.1).
The watermarking action is `c2pa.watermarked.unbound` while the algorithm is
not on the list, and `c2pa.watermarked.bound` (18.15.5 *Watermarking*) once it
is. A 24-bit video value is enumerable, and a lookup by it answers with a
candidate set, never with one capture (`watermark-layouts-1.0.md`, *`mark_id`
is a lookup hint, not an identifier*).

---

## 3. Two bindings in one file

The vcap trailer is at the **end** of the file and is found by seeking from
the end (§3). The C2PA manifest store is in the **header**: APP11 marker
segments in a JPEG (Annex A.3.1 *Embedding manifests into JPEG*), a `uuid`
box after `ftyp` and before `moov` and `mdat` in ISO-BMFF (Annex A.5.3 *Box
Containing the Manifest*). In byte order the manifest is always before the
trailer; there is no valid file in which a C2PA manifest store follows a vcap
footer, because the last 16 bytes are the footer or the file carries no
trailer. The order that varies is the order **in time** — which of the two was
written first — and each container has exactly one order in which both
bindings hold.

### 3.1 JPEG: manifest after sealing

**Our side.** §4.1 removes the C2PA Manifest Store's JUMBF APP11 segments from
the canonical bytes, so `media.hash` is the same whether the manifest is absent
(vector 01), added after sealing (vectors 02, 123) or present at sealing
(vector 68): the proof of all of them is byte-identical. A non-JUMBF APP11 is
content and stays (vectors 03, 04), and since 1.1 so is a JUMBF APP11 whose box
is **not** a C2PA store (vector 122). That is what C2PA's own validator does
(15.12.1.2 *Hashing of JPEG 1 files*): APP11 segments used for something other
than C2PA — its examples are JPEG 360 and JPEG Privacy and Security — are "not
included in these calculations", the calculation being the exclusion range,
which counts only the store's segments; so C2PA **hashes** them. 1.0 read the sentence the
other way and removed every JUMBF APP11, which let a JPEG 360 or Privacy and
Security box be added to a sealed photo without touching its verdict while
C2PA's binding broke. A JUMBF segment whose box type cannot be read at all
stays removed, as before (vectors 02, 68, whose JUMBF-shaped segment has none).

**Their side.** A `c2pa.hash.data` hashes **every byte of the asset** except
the exclusion ranges (15.12.1.1 *Validating a data hash*), and a claim
generator may exclude only the manifest store and asset metadata (18.5.1),
with the APP11 marker and length inside the range (18.5.3 *Special
consideration for JPEG 1*). The bytes from EOI to the end of the file are
neither, so **the trailer is inside the C2PA hard binding** whenever the
manifest is written after the trailer exists. With the general box hash that
2.4 recommends for box-like formats such as JPEG (18.5.1, 18.7.1 *General Box
Hash*) the boxes are marker segments, `SOS` carrying the entropy-coded data
that follows it, up to `EOI` (18.7.3.1 *JPEG-specific Handling*); every box
in the asset must be listed, or the manifest is rejected with
`assertion.boxesHash.unknownBox` (15.12.3 *Validating a general box hash*).
The only box that reaches past the last marker segment is `c2pa.after`,
defined for multi-part assets and hashed "from the byte following the last
box until the end of the physical file" (18.7.2 *Special handling of
multi-part assets*); what a validator does with trailing bytes that are not a
marker segment and not listed is not stated. A claim generator that means
both bindings to hold lists the trailer under `c2pa.after`, and is then in
the same position as with a data hash: **the C2PA binding covers the
trailer.**

**Consequences.**

1. *Manifest after sealing* (the order §4.1 requires and
   `reviews/implementability-android.md` M11 verified): both verify. From then
   on the trailer bytes are inside the manifest's binding, and **any rewrite
   of the trailer breaks the C2PA manifest, not the proof**: `assertion.dataHash.mismatch`
   (15.12.1.1) or `assertion.boxesHash.mismatch` (15.12.3), while vcap reads
   the rewritten trailer as it reads any other. Attachments (§6.2) are a
   rewrite. So a pipeline that adds attachments to a JPEG carrying a C2PA
   manifest re-issues the manifest afterwards — a new standard manifest, the
   previous one as ingredient — or writes the manifest only once the proof has
   its final form: rule J1 (§2.1, vector 125). An update manifest (11.2.3)
   cannot help: it carries no new hard binding. Measured with c2pa-rs 0.91:
   the manifest written after sealing is *Trusted* against its signer's root
   (vector 123); the same file cut at EOI is `assertion.dataHash.mismatch`
   (vector 124). A box hash is no way out either: c2pa-rs closes the JPEG box
   map at EOI, so the trailer is simply left uncovered.
2. *Manifest before sealing* (vector 68): the vcap verdict is unchanged; the
   C2PA one is broken by the trailer the moment it is appended, for the reason
   above. Since 1.1 a writer refuses to do it (`VCAP_C2PA_MANIFEST_PRESENT`,
   §2.1, vector 131); a reader still reads such a file as vector 68 does. An exclusion range over the trailer is not a fix: C2PA allows extra
   exclusions only for metadata, a validator flags them
   (`assertion.dataHash.additionalExclusionsPresent`, 15.12.1.1), a range that
   ends past the end of the asset is a mismatch, and a trailer that grows with
   its attachments ends past any range written before it grew.
3. *Anything after the footer* — a second manifest store, a stray copy of the
   trailer, padding — makes the footer not the last 16 bytes: *no proof found*
   (§3, the shape of vector 07). Nothing in C2PA writes after EOI in a
   single-image JPEG, so this is not a co-existence case, only the boundary.

### 3.2 ISO-BMFF (MP4, MOV, HEIC): manifest before sealing

**Our side.** §4.1 removes nothing from a BMFF file. A manifest inserted after
sealing sits inside the canonical bytes and the file is *tampered* (vector
73); a manifest present at sealing is content and is covered like any other
box. So the manifest is written **before** sealing, and the trailer is the
last box.

**Their side.** `c2pa.hash.bmff.v3` hashes every root box as
`offset ‖ data` except the boxes on the exclusion list (18.6.2 *Hash
Computation*). Three exclusions are mandatory — the C2PA `uuid` box, `ftyp`,
`mfra` (Annex A.5.6 *Exclusion List Requirements*) — and `/free` and `/skip`
are the two a validator accepts without even the informational code
(15.12.2 *Validating a BMFF-hash*): the two-pass workflow C2PA describes
reserves space with `free` boxes and hashes with `/free` excluded (18.6.2).
The vcap trailer is a `free` box. **The C2PA binding survives the trailer
exactly when the claim generator put `/free` on its exclusion list**, which
is ordinary practice and costs nothing (vector 143); a claim generator that did
not has its own binding broken by our trailer, and a vcap verifier has no way
to know or say so (vector 144: `assertion.bmffHash.mismatch`, vcap
*authentic*). c2pa-rs 0.91 excludes `/free` and `/skip` by default and then
reports `assertion.bmffHash.additionalExclusionsPresent` for them, an
informational code 15.12.2 says those two do not earn; `expected.json` records
it, so no implementation promises its absence. An offset-bound hash also means a box inserted **anywhere** after the
manifest was signed breaks it — which is the mirror of vector 73 and the
reason both formats agree that in BMFF the manifest comes first and nothing
is inserted afterwards.

**Update manifests cannot co-exist with a trailer.** C2PA puts an update
manifest store in a `uuid` box that "shall exist as the last box of the file"
(Annex A.5.3); the vcap footer must be the last 16 bytes. The two claim the
same position and whoever writes last wins. Appended after the trailer, the
update box hides the footer and the file reads *no proof found* (vector 69);
with a sidecar the proof is read but the canonical bytes are the whole file,
stale trailer and update box included, and the photo is *tampered* (vector
70). The trailer re-appended after the update box would put a box after
C2PA's "last box", violating A.5.3 on their side. **Normative.** A writer
MUST NOT append a C2PA update manifest to a file that carries a vcap trailer
(vectors 69, 70), and a vcap writer MUST NOT seal a BMFF file whose last box
is a C2PA `uuid` box with `box_purpose` `update`: the seal would break the
manifest it was asked to preserve. Whether a future minor lets a **reader**
step over a trailing C2PA update box before seeking the footer is open
(§6); it would be a new reading rule, not a change to this one. As a carrier,
an `original` store beside an `update` store is two stores and no carrier
(`vcap-proof-1.0.md` §3.2).

### 3.3 External manifests on both sides

C2PA's detached form is the manifest store as a file, media type
`application/c2pa` (11.4 *External Manifests*), found by an XMP
`dcterms:provenance` URI (11.5), an HTTP `Link` header, or a file at the
same path with the extension replaced by `.c2pa` (15.5.3.1 *By Reference*).
Ours is `<filename>.vcap`, appended to the full name (§3.1). The
two are independent: neither references the other, a file may have both, and
a JPEG whose manifest is external has no APP11 to exclude, so its canonical
bytes are simply the file minus the trailer. An external store carries a proof
as an embedded one does (vector 132), but only one the caller hands over: a
vcap verifier never looks for a `.c2pa` file, never fetches one, and reads it
only when the file embeds no store (`vcap-proof-1.0.md` §3.2). C2PA's rule
that an embedded store outranks a remote one (15.5.2.1) has the same shape as §3.1's
precedence — the copy inside the bytes wins — and the same reason: it
travelled with what it binds.

### 3.4 When we sign C2PA

The day a signing credential exists, the pipeline is fixed by the above:
seal, then write the manifest with the proof as `io.github.vcap-org.vcap.proof`
in `created_assertions` (the claim generator ran the seal, §2.1), a
`c2pa.created` action with a digital-capture `digitalSourceType`, a
`c2pa.soft-binding` when the algorithm is registered, and the hard binding
covering the trailer in its final form (rule J1). On video the manifest is
written before the seal with `/free` excluded and the proof cannot be inside
it — the proof does not exist yet — so the video manifest carries the soft
binding and the metadata, and the proof stays in the trailer and the sidecar.

That is not a gap, and the two bindings do not mirror each other. On video the
manifest is inside `media.hash` (§3.2), so the proof covers the manifest; the
trailer is a `free` box the C2PA hash **excludes**, so the manifest does not
cover the proof — and need not: the proof authenticates itself, and a C2PA
binding over it would add nothing a verifier could use. (1.0 said the trailer
was inside the C2PA hash, which contradicted §3.2.) A clip made later can carry
the proof in its own manifest, or find it in its source's (`vcap-proof-1.0.md`
§3.2, vectors 145–147).

---

## 4. Why the sidecar is what §3.1 says it is

- **Payload, not trailer bytes.** The box header exists so muxers skip the
  trailer, the footer so a reader finds it from the end and the CRC so a
  reader tells corruption from stripping. A separate file needs none of the
  three: the OS gives its length, nothing can strip it without removing it,
  and a corrupted sidecar fails to parse (*no proof found*) or fails its
  signature (*tampered*) — both already answers. Carrying the framing would
  have made every writer reproduce a box header nobody reads.
- **Byte comparison, not semantic.** Deciding which of two proofs with the
  same core but different attachments "wins" is a merge policy, and five
  implementations would write five. Bytes are equal or not; a writer that
  emits canonical bytes in both places (§6.1) never trips it, and a reader
  shown *sidecar differs* knows something was swapped or rewritten. A copy
  that came through a C2PA manifest is compared as JCS of the parsed JSON —
  still equality, not a merge — because the claim generator re-serialized it
  (§2.1).
- **The trailer wins.** It travelled inside the bytes it binds and cannot be
  replaced without touching the file; a sidecar is whatever sits next to the
  file. Neither can forge a core — the signature is over it — but the
  attachments are where a downgrade would go (a dropped `registry`, a
  dropped `timestamp`), and the copy inside the file is the harder one to
  edit quietly. A broken trailer is not replaced by a sidecar for the same
  reason (vector 72): the CRC failing says the file was edited, and a
  fallback that hid it would answer the question the CRC exists to raise.
- **No label for "from sidecar"**, nor for "from a manifest". The location of
  a proof is not evidence. `sig` over the core and `media.hash` over the
  canonical bytes are checked identically in every case, and a verifier that
  weakened a sidecar verdict would be saying that the box header proves
  something. Vectors 17 and 124 pin the equality. Where the proof sat is
  reported as `proof_source`, a diagnostic, and the one place it changes an
  outcome is a proof found up the `parentOf` chain, which is not presented as
  the file's at all (`vcap-proof-1.0.md` §3.2).
- **Discovery is a filename, not a search.** `<filename>.vcap` in the same
  directory, or a sidecar the caller supplies. A verifier that looked further
  — other names, a parent folder, a URL inside the proof — would be resolving
  a reference, and the invariant is that the verification path resolves
  nothing over a network of ours. Here we are **stricter than C2PA**: its
  by-reference rule (15.5.3.1 *By Reference*) tries an HTTP `Link` header,
  an XMP `dcterms:provenance` URI and a `.c2pa` file at the same path, and
  then says a validator "is not restricted to only the above locations" — a
  child folder is its own example. A vcap verifier has exactly two sources,
  the filename and the caller, because a proof that had to be looked for is
  a proof whose absence a reader could not report with confidence.

---

## 5. What survives a transformation

A verifier's answer after each of the common things that happen to a file
once it leaves the device. *Trailer*, *EXIF/XMP*, *C2PA* and *watermark* say
what the transformation leaves; the two verdict columns are §8 outcomes with
their labels; *watermark* outcomes are what a verifier with a detector adds
(§7, `watermark-layouts-1.0.md`). The one rule that outranks the table: a
watermark match with no valid signature is **origin traced**, never authentic
(§8), so no row below reaches green without an intact `sig` over unchanged
canonical bytes.

| Transformation | Trailer | EXIF / XMP | C2PA store | Watermark | Verdict, no sidecar | Verdict, intact sidecar | Vectors |
|---|---|---|---|---|---|---|---|
| Copy, transfer, rename | kept | kept | kept | kept | as sealed (level per §7) | same; the sidecar is renamed with the file or is not found | 01, 17 |
| Trailer stripped, bytes otherwise intact (a tool that truncates at EOI or drops trailing boxes) | lost | kept | kept, no proof in it | kept | *no proof found* | **full verdict restored**, identical to the embedded one | 05, 17 |
| The same, with Content Credentials that carry the proof | lost | kept | kept | kept | **full verdict restored** from the active manifest (`vcap-proof-1.0.md` §3.2, depth 0) | the same: the manifest's copy outranks the sidecar, which *differs* if it is not the same proof | 124, 127 |
| C2PA manifest added, replaced or removed on a JPEG | kept | kept | changed | kept | unchanged | unchanged | 02, 68 |
| C2PA manifest inserted into a sealed BMFF file | kept | kept | added | kept | *tampered* (§4.1: inside the canonical bytes) | *tampered* | 73 |
| C2PA update manifest appended to a sealed BMFF file | unreachable | kept | changed | kept | *no proof found* | *tampered* (whole file hashed) | 69, 70 |
| EXIF/XMP/APPn stripped or rewritten, pixels intact | kept | lost | — | kept | *tampered* (§8: photo hash mismatch, valid `sig`) | *tampered* | 04, 71 |
| Re-encode by a platform (recompressed, resized, every header dropped) | lost | lost | lost | survives within the layout's budget | *no proof found*; with a detector: *origin traced*, *watermark matched* | *tampered*; with a detector the same *origin traced* | 71 (header), layouts doc (mark) |
| Crop, rotate, filter, screenshot, re-photograph | lost | lost | lost | `photo-bch-v3` may decode within its budget; beyond it *watermark not recovered* | *no proof found* → at most *origin traced* | *tampered* → at most *origin traced* | — |
| Video trimmed or remuxed without re-encoding (NAL units and vcap SEIs intact) | lost | — | lost or kept | kept | *no proof found* | *verified clip*, amber: `media.hash` differs, the segments still in the file are located and verify, the chain says where it was cut (§5) | 89 for the embedded case; the sidecar case is in `vectors/README.md`, *Not here yet* |
| Video re-encoded | lost | lost | lost | `video-rep-v1` usually survives | *no proof found* → *origin traced* | *frames not compared* when no GOP keeps a vcap SEI naming the capture (§5, *Locating segments*): the signature layer holds, nothing ties the frames to it; *tampered* when SEIs survive over re-encoded bytes | 86, 87 |
| Photo edited by a C2PA-aware editor that keeps the source's Content Credentials | lost | — | new manifest, the source's as `parentOf` | may survive | *no proof found*, *Content Credentials carry the proof of a source capture* (§3.2, depth 1) | *tampered*: the sidecar is presented as this file's proof | 129, 130 |
| Video trimmed by a C2PA-aware cutter, no re-encoding, the source's proof in its manifest | lost | — | new manifest, the source's as `parentOf` | kept | *verified clip*, through the chain | *verified clip* | 145 |
| Video re-encoded by a C2PA-aware editor, the source's proof in its manifest | lost | lost | new manifest, the source's as `parentOf` | `video-rep-v1` usually survives | *no proof found*, source capture → *origin traced* | *frames not compared* | 147 |

Reading the table:

- **A sidecar restores exactly one thing**: the proof, when the container
  lost it and nothing else changed. Row 2 is the only one where the two
  verdict columns differ in the sidecar's favour, and it is the case §3.1
  exists for. In every other row the canonical bytes changed, and a sidecar
  turns *no proof found* into *tampered* — a stronger statement, and an
  honest one: the signature is valid and these are not the bytes it vouches
  for. A verifier MUST NOT soften that into "probably the same picture"; the
  format has no such outcome for a photo (§8).
- **Content Credentials restore what a sidecar restores, and name a source.**
  At depth 0 a manifest's proof is read exactly as a sidecar's; up the
  `parentOf` chain it is the proof of the capture the file was made from, and
  it reaches only what it proves of this file — the same bytes, or located
  segments — and otherwise *no proof found* with its reason, never *tampered*
  (`vcap-proof-1.0.md` §3.2). A declared edit is not an accusation.
- **The watermark is the only thing that survives a re-encode**, and it is
  worth exactly *origin traced*: the capture this came from can be found,
  its original shown side by side, and nothing about *these* bytes is proven.
  §7 and §8 say it three times because it is the invariant most tempting to
  relax in a UI.
- **A C2PA manifest and a vcap trailer strip together** under a platform
  re-encode — both are metadata to a pipeline that keeps pixels — and a C2PA
  soft binding is C2PA's answer to that (9.3.1: a removed manifest "may be
  matched using available soft bindings" against a copy kept elsewhere). Ours
  is the same answer at the same strength: a lookup, then *origin traced*.
- **What the verifier must say**, in §8's words, per outcome: *no proof
  found* is not an error and is never *corrupted*; *tampered* carries its
  reason and no absence labels; *verified clip* names the segments verified
  out of `segment_count`; *sidecar differs*, *manifest copy differs* and
  *flags disagree* are warnings on an otherwise valid verdict; a detector result is *watermark matched*,
  *watermark not recovered* or *watermark not evaluated*, and a match without
  a valid signature is *origin traced*.

---

## 6. Open

- Registration of the watermark algorithm on the C2PA Soft Binding Algorithm
  List (18.10.4) — a C2PA process, deferred with the rest of the C2PA track;
  §2.3 fixes the value it would carry.
- A C2PA signing credential. The custom assertion label,
  `io.github.vcap-org.vcap.proof`, and the pipeline order of §3.4 are fixed
  here so that the day does not reopen them. The corpus's manifests are signed
  by a test credential until then.
- A reader rule for a trailing C2PA update box on a sealed BMFF file
  (§3.2, `vcap-proof-1.0.md` §11). **Normalize `box_purpose` first**: when an
  update store is appended, C2PA rewrites the original store's `box_purpose`
  from `manifest` to `original` in place (A.5.3), and that box is inside
  `media.hash`, so any rule that steps over the update box has to state how
  the canonical bytes read `box_purpose` before it can keep a verdict. No such
  rule exists, and until one does the update manifest stays forbidden for
  writers.
- Decompressing a compressed manifest (`c2cm`, 11.2.4) as a carrier: not read
  in this version (`vcap-proof-1.0.md` §3.2, vector 138).
