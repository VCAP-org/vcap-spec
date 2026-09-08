# Cryptographic review of the vcap/1.0 draft

**Step 2 of the work order** (`Doc/06-fase1-avvio.md` §3). Reviews
`spec/vcap-proof-1.0.md` as of 8 September 2026. Question asked: *what is
signed, what is not, and what can an attacker change without invalidating a
signature?*

Severity: **BLOCKING** — the format must change before vectors are written ·
**SHOULD** — change now, cheap, avoids a v1.1 · **NOTE** — no format change,
text or implementation guidance.

Verdict of the review: the six decisions stand. One structural gap (F1) makes
most of the JSON claims unsigned; fixing it changes what `sig` covers and
ripples into F6, F9 and F10. Everything else is precision work.

---

## F1 · BLOCKING — The proof's claims are not signed

§4 signs `H = SHA-256(C)`, the media only. Every other field of §6 is plain
JSON in a trailer anyone can rewrite while the signature stays valid:

| Field an attacker rewrites | Effect on a verifier following the draft |
|---|---|
| `capture_id` | Photo without watermark: no check at all. With watermark: red — but only if the detector runs. |
| `location.*` | Genuine photo, invented coordinates, shown as *declared*. |
| `time.device_clock` | Genuine photo, invented date. |
| `device.integrity.verdict` | `failed` → `hardware`. Nothing catches it. |
| `device.platform`, `media.mime/w/h/duration_ms` | Free. |
| `policy.pseudonymous` | Free. |
| `watermark.mark_id` (video) | Points the detector at a different capture. |
| `device.secure_hw` | Caught only if the verifier derives the level from the attestation chain and ignores the declared value (see F2). |

The trailer's crc32c catches corruption, not editing: the attacker recomputes it.

**Fix.** Split the proof into a **core** the device signs at capture and
**attachments** added later, each self-authenticating and each bound to the
core:

```
core = { v, capture_id, media, device (without attestation), watermark,
         time.device_clock, location, policy }

core_hash = SHA-256( JCS(core) )            // the proof's identity from here on
sig.value = ECDSA-P256-SHA256( JCS(core) )  // ES256 semantics over the canonical bytes of core

attachments (unsigned by the device, verified on their own):
  device.attestation   — certificate chain; its leaf public key MUST equal sig.pub (F2)
  time.tsr             — RFC 3161 token whose messageImprint is core_hash (F9)
  registry             — inclusion proof binding device.key_id, verified against the STH
  anchor               — Merkle path from core_hash to an on-chain root (F9)
```

Consequences:

- `sig` becomes **required for video too** (today only `segments` is). One
  signature at the end of the recording, when the file is final. The per-segment
  chain keeps its role — verifying clips — and the core signature gains a second
  one: proving the claims around the video.
- `media.hash` moves *inside* the signed core. So "media is the complete
  original" (`media.hash` matches the recomputed canonical bytes) and "the
  claims are authentic" (`sig` verifies over `JCS(core)`) become two separate
  facts. This is what §5 needs anyway: a cut video has authentic claims and an
  incomplete medium — *verified clip*, amber — instead of the draft's red for
  `media.hash` mismatch, which contradicts §5's amber.
- The verifier reads the trailer JSON, extracts `core` (the listed keys, in any
  order — JCS sorts), recomputes `JCS(core)`, verifies `sig`. A JSON edit
  anywhere in core is red; an edit in an attachment breaks that attachment only,
  and the verdict says which.
- The device hashes a few kilobytes inside the secure hardware, not the file:
  cheaper than the draft, which streams the media through the signer or relies
  on the `NONEwithECDSA` pre-hash trick (F6).

**Proposed text for §4 step 4:** *"Sign. `sig.value` is an ECDSA P-256 signature
with SHA-256 (ES256) over the canonical JSON of the core, §6. `media.hash` is a
member of the core, so the media is covered transitively. Verifiers recompute
`JCS(core)` from the received JSON: the bytes in the trailer are not
authoritative, the canonical form is."*

## F2 · BLOCKING — Key binding is described, not specified

Three things name the key and the draft does not say they must agree: `sig.pub`
(SPKI), `device.key_id`, and the public key in the attestation leaf. Without
the rule, an attacker attaches a genuine StrongBox chain from any device to a
proof signed with their own key and the table in §7 reads *strongbox*.

**Rules to add:**

1. `device.key_id = base64url( SHA-256( sig.pub as DER SPKI ) )`. Derived, never
   free. This is also the identifier the registry and the transparency log use
   (the data plane's attestation validator already computes exactly this).
2. The attestation leaf's SubjectPublicKeyInfo **MUST be byte-equal** to
   `sig.pub`. Otherwise: *attestation does not match the signing key*, red.
3. `device.secure_hw` is a **claim**; the verifier computes the **proven** level
   from the attestation (Android: `attestationSecurityLevel` and
   `keyMintSecurityLevel`, the weaker; iOS: App Attest valid; web: none) and the
   §7 ceiling uses the proven level only. Claimed above proven → *inconsistent
   claim*, amber at best and shown. Claimed below proven → proven wins, no flag.
   `REVIEW (LEAD)`: decide whether "claimed above proven" is red instead. Argument
   for red: the core is signed by the device, so a false claim is the device
   lying, not a transport error. Argument for amber: a firmware bug that
   misreports the level should not turn a genuine capture into "tampered".
4. `sig.pub` is **required**. The verifier must work offline without the
   attestation chain (web, or iOS where the chain is not in the proof), so the
   key travels with the proof.

## F3 · SHOULD — Chain the segments on messages, not on signatures

§5: `prev_link(n) = SHA-256(sig(n-1))`. Two problems.

- **ECDSA is malleable**: for a valid `(r, s)`, `(r, n − s)` is also valid for
  the same message, and anyone can produce it without the key. Flipping
  `sig(n-1)` keeps segment n−1 valid and breaks the chain at n. Not a forgery
  — but the chain's correctness depends on the exact signature bytes, which is
  fragile, and it lets an attacker turn a genuine original into a "chain
  broken → tampered" file without touching content. A verifier can't tell
  malice from a re-encoder that normalized signatures.
- It ties the chain to the **encoding** of the signature (DER today, F6
  proposes P1363), so changing the encoding changes every chain.

**Fix:** `prev_link(n) = SHA-256( message(n-1) )`, `prev_link(0) = 32 zero bytes`.
Order and completeness are still bound: `message(n-1)` contains
`content_hash(n-1)` and `prev_link(n-1)`, recursively; each message is signed.
Nothing about the signature bytes enters the chain.

**Domain separation, as asked in §5 REVIEW (BE):** `message(n)` is
`"vcap/1.0/seg"` (12 bytes) ‖ `capture_id` (16) ‖ `uint32 n` (4) ‖
`content_hash` (32) ‖ `prev_link` (32) = **96 bytes, every field fixed-length**.
No field can be shifted into another. Confirmed. Two additions:

- The separator MUST be exactly the 12 ASCII bytes, no NUL, no length prefix,
  and the version inside it is the one in `v`. A v1.1 that changes the message
  layout uses `"vcap/1.1/seg"`, so a v1.0 verifier fails rather than misparsing.
- Add a **terminator** to the core: `media.segment_count`. Without it, a video
  cut at the *end* (last GOPs removed, trailer rewritten with fewer segments)
  has index 0, no gaps and an unbroken chain — the draft calls it *eligible for
  green*. With F1 the full-file `media.hash` already fails, so it cannot be
  green; but the verifier should also be able to say *"12 of 300 segments
  present"*, which needs the count in the signed core.

## F4 · BLOCKING — Audio is not covered by the segment chain

`content_hash(n)` hashes *"the segment's coded sample payloads"* of a GOP, a
video-track notion. Audio samples are not in any segment. On a complete original
the full-file `media.hash` (F1) covers them; on a clip, nothing does: the
attacker keeps the verified video segments and replaces the soundtrack, and the
verifier reports *verified clip*.

**Decision needed, `REVIEW (LEAD + mobile)`.** Options, cheapest first:

1. **State it.** *Verified clip* means "these video frames"; the label says
   *audio not verified on clips*. Zero cost, honest, weak for the insurance and
   journalism use cases where the soundtrack is often the evidence.
2. **Include audio in the segment hash**: `content_hash(n)` also covers the
   audio samples whose decode timestamp falls in `[DTS(IDR_n), DTS(IDR_n+1))`,
   after the video samples, in decode order. One chain, one signature per
   segment, no new field. Cost: the encoder pipeline must interleave the hashing
   of two tracks; segment boundaries on audio are approximate by nature (audio
   frames don't align to IDRs), so the rule must say which frame belongs to
   which segment — first sample whose DTS ≥ the GOP start.
3. **A second chain for audio** with its own segmenting. Cleanest separation,
   twice the signatures in StrongBox, more spec.

Recommendation: 2. The rule is one sentence and the alternative is a product
that verifies muted video.

## F5 · SHOULD — Define the SEI exclusion by payload, not by NAL type

§5 excludes "every vcap SEI NAL unit ... by NAL type". `user_data_unregistered`
is payloadType 5 of the SEI NAL (type 6 in H.264, 39/40 in H.265): excluding by
NAL type excludes **every** unregistered SEI, so an attacker can insert arbitrary
SEI NAL units into a verified segment without breaking it. Decoders ignore
unregistered SEIs, so this is not a pixel attack — but it is unsigned bytes
inside "verified" content, which an expert witness will find.

**Fix:** exclude exactly the SEI NAL units that carry payloadType 5 with the
vcap UUID (to be registered and written in the spec as 16 bytes). Everything
else — other SEIs included — is content. And write down what "coded sample
payload" means for the hash: the NAL units of the sample, each as raw NAL bytes
**without** the AVCC/HVCC 4-byte length prefix and without Annex-B start codes,
concatenated in the order the sample lists them. Otherwise the two encoders
(MediaCodec, VideoToolbox) will disagree on the first vector.

## F6 · SHOULD — Signature encoding: P1363, not DER

The draft stores DER and asks the WebCrypto side to convert. Reversed is
better: **store `r ‖ s` as 64 bytes (IEEE P1363)**.

- DER has encoding variants (leading zero bytes, non-minimal lengths) that
  lenient parsers accept; P1363 has one form. With F3 the chain no longer
  depends on it, but "one way to write it" is still the right property.
- JWS ES256 and COSE ES256 both use P1363; the C2PA mapping (C14) will want it.
- Android and iOS return DER; the conversion happens once, at seal time, in
  code we own. WebCrypto verifies P1363 natively; Node accepts `dsaEncoding:
  'ieee-p1363'`.
- Optional: normalize `s` to the low half (`s ≤ n/2`). Not needed for
  verification; document that verifiers MUST accept both, so it never becomes
  an interoperability problem.

The §4 phrasing *"over `H` as a raw 32-byte message digest (`SHA256withECDSA`
semantics)"* conflates two APIs and will be read two ways. After F1 the signed
message is `JCS(core)`, a few kilobytes: write it as plain **ES256 over
`JCS(core)`**. Whether an implementation pre-hashes and calls `NONEwithECDSA`
(StrongBox fast path) or streams the bytes is its business — the result is
identical and one vector proves it.

## F7 · SHOULD — Ban floating point and free text from the core

JCS (RFC 8785) serializes numbers with the ECMAScript `Number.toString`
algorithm. JavaScript has it; Kotlin and Swift do not, and their `Double`
formatting differs in exactly the cases that matter (`0.1 + 0.2`, exponents,
trailing zeros). `location.lat/lon/acc_m` are the only floats in the core.

**Fix:** integers only. `lat`, `lon` as **microdegrees** (`int32`, `±180_000_000`),
`acc_m` in **centimetres** (`uint32`), `duration_ms` already integer. State: *"the
core contains no floating-point numbers and no free-text strings; every string
is an enum, a base64url value or a fixed identifier"*. JCS string escaping and
UTF-16 sorting then have nothing to bite on. Vectors: one with a negative
longitude, one with `acc_m` = 0, one with an unknown top-level key that must be
excluded from the core and listed as *not evaluated*.

## F8 · SHOULD — Nested trailers

Sealing a sealed file is legal by the reading procedure (§3): the inner trailer
becomes part of the outer canonical bytes. So: take a genuine StrongBox
original, append a second trailer signed with a browser session key, and the
verifier sees a valid `none`-level proof and never the inner one. Not a forgery
— the outer level is honest — but a way to *downgrade and hide* provenance,
and a nuisance for the "compare with original" feature.

**Rule:** after stripping the outer trailer, if `C` ends with a valid footer,
the verifier MUST report *nested proof* and MUST NOT evaluate the outer one as
authoritative. Writers MUST refuse to seal a file that already carries a
trailer. Vector: double-sealed file → *nested proof*, not green.

## F9 · SHOULD — Attachments bind to `core_hash`

With F1 the natural imprint for `time.tsr` (RFC 3161 `messageImprint`), the
anchor leaf and the registry entry is **`core_hash`**, not `media.hash`. A
timestamp over `media.hash` proves the pixels existed before T; a timestamp over
`core_hash` proves the pixels *and the claims* — capture id, declared time,
location, key — existed before T. Same cost. Name `core_hash` in §2 and use it
everywhere an attachment needs to point at "this proof".

## F10 · BLOCKING as written, resolved by removing — `device.integrity` cannot be verified offline

Play Integrity verdicts are encrypted tokens decrypted with keys Google gives
to *the app developer's server*. App Attest assertions verify against Apple's
CA, but the assertion covers a client data hash the *server* chose. Neither is
verifiable by a browser with pinned roots. So, as a core field, `integrity.verdict`
is either a **self-declaration by the app** — worthless against the rooted device
it exists to flag — or it silently requires our server, violating the first
invariant.

**Fix:** move integrity out of the core and into an **attachment signed by the
registry**: `integrity = { source, verdict, evaluated_at, sig }` where `sig` is
the registry key's signature over `core_hash ‖ verdict`, verifiable offline
against the registry's published key (the same key that signs tree heads).
Absent → *integrity unevaluated*, per §8's rule. Present and signed → the
verdict Google gave to our server at sync time. This keeps the invariant: the
server *adds* evidence, it is never *needed* for a verdict.

## F11 · NOTE — crc32c vs crc32

Answering §3 REVIEW (BE): crc32c is *less* available than the draft assumes.
`java.util.zip.CRC32C` exists only from Android 14 (API 34); Swift has no
standard CRC-32C; Node's `zlib.crc32` (22.2+) is CRC-32, not Castagnoli. Plain
**CRC-32 (IEEE 802.3)** is in `java.util.zip.CRC32` on every Android, in zlib
on iOS, in `node:zlib`, and in every browser polyfill. Hardware acceleration is
irrelevant for a payload of a few kilobytes, and the CRC has no security role —
the signature covers the core, the CRC only tells *corrupted* from *edited*.
**Recommendation: CRC-32.** If Castagnoli stays, ship a 30-line table
implementation in the spec's reference code so nobody links a library for it.

## F12 · NOTE — Footer detection and ambiguity

- A file with no trailer whose last 16 bytes happen to start with `VCAP`
  yields *corrupted proof* instead of *no proof found*. Probability 2⁻³² by
  chance; deliberately, it lets someone make an unsealed file look edited. Make
  the check stronger before declaring corruption: magic **and** `major == 1`
  **and** `box_size` consistent **and** the 4 bytes at the box header equal
  `"free"`. Only if all hold and the CRC fails is it *corrupted*; if the
  structure does not hold, it is *no proof found*.
- Sidecar and trailer both present: the trailer is authoritative; a sidecar
  that is not byte-identical is reported (*sidecar differs*), not used.
- Reserved `flags` bits: "ignored, not fatal" is right; add that a **writer
  MUST set them from the JSON** and a verifier MAY warn on disagreement, so a
  disagreement is at least visible in conformance testing.

## F13 · NOTE — JPEG canonical rule needs exact bytes

"APP11 segment whose payload begins with the JUMBF identifier used by C2PA":
write the bytes. A C2PA APP11 segment payload begins with the common identifier
`"JP"` (0x4A 0x50), then a 2-byte box instance number and a 4-byte packet
sequence, then the JUMBF superbox. Rule: *remove every APP11 (0xFFEB) segment
whose payload starts with 0x4A50; keep every other APP11*. Vector with an APP11
that is not JUMBF (the draft lists it — good). Two more notes:

- Everything else in the JPEG — EXIF, XMP, ICC, thumbnails — **is signed**.
  Correct for integrity, but EXIF carries device model, serial, GPS. The
  pseudonymous policy (§6 `policy.pseudonymous`) must therefore strip metadata
  **before** sealing; stripping afterwards is tampering. Belongs in the
  implementability review.
- Since JUMBF is excluded from the hash, anyone can add, replace or remove the
  C2PA manifest of a sealed photo without touching the vcap verdict. Intended,
  and the manifest carries its own signature — but say it in §10.

## F14 · NOTE — Attestation freshness and offline revocation

- An attestation chain needs a challenge. Enrolled devices get it from the
  registry (anti-relay, T3); un-enrolled devices, which the product must
  support, choose their own. Both produce a genuine chain to a Google root. The
  spec should say that **a self-chosen challenge is allowed and yields the
  `key not in transparency log` row of §7** — never green, per the table — so
  that offline capture is not an error and not a green light.
- Verifying revocation needs Google's status list, i.e. network. A browser
  offline cannot check it: label *revocation not checked*, verdict amber at
  best. The data plane's validator fails closed (server side, correctly); the
  spec must say the client-side verifier degrades instead. Same fact, two
  contexts, two behaviours — write both down.
- Never request ID attestation (`attestationIdSerial`, `attestationIdImei`):
  the chain would carry hardware identifiers into a proof that claims to carry
  none.

## F15 · NOTE — Linkability under `policy.pseudonymous`

One attested key per app installation means every capture from a device is
linkable through `device.key_id` and the attestation leaf, pseudonymous or not.
That is a pseudonym, not anonymity, and the spec should call it so. Per-capture
keys (Pixel's anonymous per-image certificates) would break the link at the
cost of one attestation per capture; not for v1.0, but the field name should
not promise more than it delivers: consider `policy.unlinkable_operator`
or a comment in §6 — `pseudonymous` hides the operator, not the device.

## F16 · NOTE — Small items

- `v` and `capture_id` are in the core (F1), so a version downgrade or an id
  swap is signed content: good, say it explicitly under §9.
- `watermark.mark_id` (24 bits, video) must be in the core; the ML review
  should state the collision probability and what the detector reports when
  two proofs claim one `mark_id`.
- `capture_id` MUST come from a cryptographically secure RNG; it need not come
  from the secure hardware. 128 bits are enough for uniqueness, not for secrecy
  — it is public in the watermark.
- `segments[].range` unsigned and informational: correct; keep the MUST NOT.

---

## What changes in the draft, summarized

| § | Change | From |
|---|---|---|
| 2 | Define `core`, `core_hash`, attachments | F1, F9 |
| 3 | CRC-32; stricter footer validity; nested trailer rule | F11, F12, F8 |
| 4 | Sign `JCS(core)` with ES256, P1363; exact APP11 bytes; `sig` required for video | F1, F6, F13 |
| 5 | Chain on messages; SEI exclusion by UUID; NAL byte definition; audio in segment hash; `media.segment_count` | F3, F5, F4 |
| 6 | `key_id` derived; `sig.pub` required; integers only; `integrity` becomes a signed attachment | F2, F7, F10 |
| 7 | Proven level wins; claim mismatch rule; self-chosen challenge row | F2, F14 |
| 8 | `media.hash` mismatch on video with a valid chain → *verified clip*, not red; new labels | F1 |
| 10 | Say the C2PA manifest is outside the signature; say pseudonymous ≠ unlinkable | F13, F15 |

## Decisions taken by the spec owner — 8 September 2026

1. **F2.3** — declared level above proven level: **amber, flagged**. A firmware
   that misreports its level must not turn a genuine capture into "tampered".
2. **F4** — audio on clips: **option 2**, audio frames in the segment hash, by
   DTS in the GOP's half-open interval.
3. **F10** — `integrity` **leaves the core** and becomes a registry-signed
   attachment over `core_hash ‖ verdict`. C6 signs one more statement with the
   tree-head key; the sync path returns it to the device.
4. **F11** — **CRC-32.**
5. **F6** — low-`s`: **writers MUST emit, verifiers MUST accept both.**
6. **F12** — footer strictness as proposed.

All amendments are in `spec/vcap-proof-1.0.md`, same day. Step 3
(implementability review) is next; step 4 (canonicalization rule) now has the
core defined and only needs the JCS vectors.

## Addendum — 8 September 2026, from building the log (C6)

**F17 · SHOULD → done.** The draft's `registry` attachment (`log_id`,
`leaf_index`, `sth_ref`) was a reference, not evidence: an offline verifier
could not check it without asking the log, which puts a server in the
verification path. It now carries the leaf, the RFC 6962 inclusion path and
the signed tree head inline, with the checks a verifier MUST run and the
"registered after the declared capture" row in §7. Revocation remains an
online check, said explicitly.

**F18 · SHOULD → done (from building C7).** The `anchor` attachment listed
`chain`, `tx`, `block`, `merkle_path`: a path without the leaf's index and the
tree size cannot be verified (RFC 6962 needs both), and without the root and
the contract's anchor id there is nothing to compare against on-chain. All
four are now in the attachment, with the verification procedure and the
offline label.

