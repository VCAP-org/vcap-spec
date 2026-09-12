# vcap threat model

**Status: DRAFT for review** — written 8 September 2026 as the C18 deliverable
"public threat model"; the technical lead owns it, the backend reviews it. It
is public on purpose: a verifier's expert who cannot read what we defend
against, and what we do not, should not trust our green.

Companion to `vcap-proof-1.0.md`. Where that document says what a field means,
this one says who would want to lie in it, how, and what stops them.

## 1. What the system claims

For a capture that verifies **green**, and only then:

1. The bytes of the media were exactly these when a specific key signed them.
2. That key lives in secure hardware (Android StrongBox or TEE, Apple Secure
   Enclave) of a device whose boot was verified, and was created by a known
   app build — proven by a key attestation chain to Google's or Apple's root,
   not declared.
3. The key was registered in a public, append-only transparency log before the
   capture, by an organization that passed KYB, and was not revoked at capture
   time.
4. The claims around the media — capture id, declared time and place, level,
   watermark parameters — were signed by the same key at the same moment.
5. Optionally: the proof existed before a trusted time (RFC 3161), and before
   an on-chain block.

For a capture that verifies **amber**, one or more of these is not proven, and
the verifier says which.

## 2. What the system does not claim

Stated first, because every threat below that lands here is *accepted*, not
mitigated, and the verifier UI must say so.

- **That the scene is real.** A verified recording of a screen is a verified
  recording. `secure_hw` says where bytes were signed, not what was in front
  of the lens. (Mitigations under research — depth, sensor coherence — are not
  part of v1.)
- **Who held the device.** A key binds to hardware, an app build and an
  organization, never to a person.
- **Where it was**, beyond the position level the verifier reaches
  (`vcap-proof-1.0.md` §7.1): *declared* is the device's word about its own
  coordinates; *corroborated* is the registry's word that an operator's
  cell-level check of the **SIM** agreed with them, to a radius of kilometres;
  *authenticated* is reserved and nothing reaches it yet. The word
  "guaranteed" is not a level. §5.7 has the threats against each.
- **That the device was not compromised below the attestation boundary.** A
  rooted device with a virtual camera can hand genuine hardware a fake frame.
  Attestation and integrity signals raise the cost; they do not make it
  impossible. This is the residual risk that matters most and it is stated on
  every verdict where integrity is not `hardware`.
- **That a watermark identifies a file, or attributes it.** A recovered mark
  says that *a frame of that capture appears in this file*, not that the file
  is that capture — one genuine frame spliced into foreign footage reproduces
  the mark (§5.8). And the marking model is a public download, so a mark
  carries no authorship. A watermark alone is never green: without a valid
  signature it is *origin traced*, never *authentic*.
- **Anything about a C2PA manifest** sitting next to the proof: outside the
  canonical bytes, verified by its own signature, separately.

## 3. Assets and trust boundaries

| Asset | Where | Who must not touch it |
|---|---|---|
| Device signing key | secure hardware of the device | anyone, including the app and the OS |
| Attestation roots (Google, Apple) | pinned in verifier, data plane, SDKs | anyone: changed only by a reviewed commit with a fingerprint test |
| Transparency log | data plane, Postgres, append-only by trigger; mirrors | us — that is the point of the log |
| Log signing key | KMS in production | anyone but the data plane's signing path |
| Registry: key → organization → operator | control plane only | the data plane, the log, the public |
| Revocation list (Google) and App Attest roots | fetched / pinned by the data plane | — |
| Media and proofs | the device, then the customer's systems or the vault | us, unless the customer chooses the vault |
| Challenges | data plane, single-use, hashed | replay from anyone |

Boundaries, each enforced by code and tested:

- **Device ↔ control plane**: TLS, app activation token (identifies a build,
  grants nothing), attestation decides trust.
- **Control plane ↔ data plane**: mTLS with a private CA; an allowlist per
  endpoint on both sides; no personal data crosses, ever
  (`contracts/endpoints.json`, `contracts/boundary.json`).
- **Data plane ↔ public**: the log's read side and signed answers. Everything
  the log serves is verifiable without trusting the server: signed tree
  heads, inclusion and consistency proofs, signed status.
- **Verifier ↔ everything**: a verifier needs no server of ours to reach a
  verdict. The proof carries its evidence (`registry` inline); revocation is
  the one online check and degrades to *revocation not checked*.

## 4. Attackers

| Actor | Capability | Motive |
|---|---|---|
| **Forger** | edits pixels or metadata of a file after capture; re-encodes; splices | pass a manipulated file as authentic |
| **Injector** | controls a device: rooted, virtual camera, hooked frameworks, relayed attestation | make genuine hardware sign a fabricated scene |
| **Impostor** | no device of ours; general crypto and web skills | mint proofs that look like ours, or make ours look like theirs |
| **Insider** | our staff, our infrastructure, our keys | rewrite history, register a fake key, hide a revocation |
| **Log observer / mirror** | reads the log | learn who captures what — the privacy angle |
| **Platform** | Google, Apple, a QTSP, a chain | their root or key is compromised or coerced |

## 5. Threats, mitigations, residual risk

### 5.1 Against the media and the proof

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| Pixel or metadata edit | changes bytes after sealing | `media.hash` over canonical bytes, in the signed core (§4) | none: red |
| Claim edit | changes location, time, level, capture id in the JSON | the core is signed (§4.2); `key_id` derived from `sig.pub`; proven level from attestation, claimed level capped | none: red / flagged |
| Signature swap | re-signs the file with own key and attaches a genuine attestation chain | attestation leaf SPKI must equal `sig.pub` (§6.2) | none: red |
| Proof transplant | moves a genuine trailer onto another file | `media.hash` mismatch; on video, segments do not match | none: red |
| Clip from a genuine video | cuts segments, keeps the trailer | per-segment chain over messages; `segment_count`; `media.hash` mismatch → *verified clip*, amber, ranges shown | accepted and **labelled**: a clip is a clip, never an original |
| Audio replacement on a clip | keeps verified frames, swaps sound | audio frames inside the segment hash (§5) | none on originals and clips |
| Signature malleability | flips `s` to break or forge chains | chain over messages, not signatures; P1363; both `s` halves accepted | none |
| Nested trailer | wraps a hardware-sealed original in a weaker proof | nested trailer detected and reported; writers refuse | none: *nested proof* |
| Metadata stripping by a platform | social network removes the trailer | *no proof found*, distinct from *corrupted*; watermark → *origin traced*, never authentic; sidecar | accepted: provenance lost, origin traceable, never mistaken for tampering |
| Format confusion | crafts a footer to make an unsealed file look edited | structural footer checks before the CRC (§3) | none |
| Canonicalization divergence | exploits differences between implementations | integers only, no free text, JCS, conformance vectors every implementation runs | low; vectors grow with every finding |

### 5.2 Against the key and the device

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| Software key posing as hardware | generates a key outside the TEE, claims StrongBox | attestation chain to Google/Apple root; `attestationSecurityLevel` and `keyMintSecurityLevel`, the weaker; software → `none` | none |
| Relayed attestation | forwards a genuine device's attestation to register an attacker session (Quarkslab 2026) | single-use challenge issued by us, consumed atomically before any check; proof of possession over `"vcap/1.0/pop" ‖ challenge ‖ channel_binding` (Android) / nonce in the App Attest certificate and assertions (iOS); short RKP certificate validity checked; channel binding when the control plane provides one | **medium** until spike S3 confirms against Frida on a rooted device; channel binding without a TLS exporter is weaker and the verdict says so |
| Key extraction | reads the private key out of the device | secure hardware; not our control | accepted: the platform's promise, not ours |
| Compromised app | a modified build of our app, or another app, uses the key | `attestationApplicationId` (package + signing digest) / App ID, per tenant; token rotation stops a leaked build | low; a re-signed app has a different digest |
| Imported key | key created elsewhere, imported into the TEE | `origin` must be `GENERATED` | none |
| Unlocked bootloader / rooted device with virtual camera | genuine hardware signs an injected frame | verified boot state and locked device required in the attestation; integrity statement (Play Integrity / App Attest) signed by the registry as an attachment; both prominent on the verdict | **high and accepted**: see §2. The verdict names it; no green without hardware integrity |
| Cloned Secure Enclave key (theoretical) | two devices with one key | App Attest counter must increase on every assertion; the receipt (future) | low |

### 5.3 Against the registry and the log

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| Insider registers a key without a device | writes a leaf for a key nobody attested | the leaf is public; the attestation digest is in it; a mirror or an auditor asks for the chain; KYB before any leaf | medium: detection, not prevention — this is what "transparency" buys |
| Insider rewrites history | edits or deletes a leaf | Postgres triggers refuse UPDATE/DELETE/TRUNCATE; signed tree heads kept forever; consistency proofs; mirrors | none against a database admin acting alone; a rewrite breaks consistency for every mirror |
| Split view | the log shows different trees to different parties | every head is signed and kept; mirrors compare heads and consistency proofs; gossip between verifiers is future work | medium until mirrors exist (C10) |
| Hidden revocation | the log says "valid" for a revoked key | status is signed by the log key over key, time, tree size, status; revocation leaves have inclusion proofs; anyone can check the revocation leaves for a key | low; a lying log signs the lie, which is evidence |
| Retroactive revocation abuse | an insider revokes a key retroactively to invalidate inconvenient captures | retroactive only for `compromise`, refused otherwise by the log itself; the leaf is public with its reason | low: visible, attributable |
| Log key compromise | attacker signs heads and statuses | key in KMS; rotation with the old key's heads kept; verifiers pin by `log_id` | medium: recovery is a new log id, published |
| Registered after capture | a key logged after the fact | `tree_head.timestamp` vs declared time and vs the RFC 3161 token: *registered after the declared capture*, amber | none on the ordering claim |

### 5.4 Against the platforms we rely on

| Threat | Mitigation | Residual |
|---|---|---|
| Google or Apple attestation root compromised or an attestation key leaked (older provisioning) | pinned roots; Google's revocation list checked, fail closed server-side; RKP preferred | accepted at the platform level; verifiers degrade, never fail silently |
| QTSP compromised | two providers, failover; token chain validated offline | a false time from a compromised QTSP is a false time; the token names the issuer |
| Chain reorganization or censorship | anchoring is optional evidence; *not anchored* is a label | accepted |

### 5.5 Privacy

| Threat | Mitigation | Residual |
|---|---|---|
| Linking captures to a device | `device.key_id` is a pseudonym for device+app; no device identifiers in attestation (no ID attestation) | **accepted and named** in the spec: pseudonymous ≠ unlinkable; per-capture keys are future work |
| Personal data in the public log | leaves carry key identifiers, level, digests, log time — nothing else; the registry mapping stays in the control plane | none by construction, enforced by the plane boundary |
| Personal data leaking through the plane boundary | allowlist per endpoint, both sides; second net over values; tests assert names and VAT never cross | low |
| EXIF in the signed file | signed as content; pseudonymous mode must strip **before** sealing | implementation duty of the SDKs |
| Server learning what is in a capture | the data plane sees hashes and keys; the vault (C9) is envelope-encrypted client-side | none in phase 1; C9 decides for stored media |

### 5.6 Availability and failure behaviour

- The verification path contains none of our servers: an outage cannot turn a
  green into anything. Revocation checks degrade to *revocation not checked*.
- Server-side, every check fails closed: no revocation list, no challenge store,
  no attestation → refused.
- A denial of service against enrolment stops new keys, not existing proofs.

### 5.7 Against the declared position

The position level (`vcap-proof-1.0.md` §7.1) is orthogonal to the verdict:
none of these threats turns a verdict red or green, and each lands on a
level and a label the verifier shows.

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| Faked fix | a mock location provider (Android), a simulated location (iOS), a spoofed GNSS signal: the OS hands the app coordinates of the attacker's choosing and the device signs them | the level is *declared* and the verifier says so; `location.source` names the origin of the fix; a corroboration from the network side (below) does not depend on the device's fix | **accepted and named**: a signed position proves the device said it, nothing more. The mock-provider flag and the integrity verdict raise the cost on a stock device and do nothing on a rooted one |
| Edited coordinates | changes `lat_udeg`/`lon_udeg` after sealing | the core is signed (§4.2) | none: red (vector 10) |
| Forged corroboration | fabricates or relabels a `location_corroboration` | signed by the registry key over `"vcap/1.0/location" ‖ core_hash ‖ JCS(body)`; the result is inside the message; a signature no trusted key made is *not verified* and the level stays *declared* | none on the level; a forgery is indistinguishable from an untrusted signer and reads as absence |
| Transplanted corroboration | lifts a genuine corroboration from another proof | `core_hash` is inside the signed message and covers the declared position | none: *not verified* (vector 77) |
| **False accept, SIM in the cell** | an accomplice — or the attacker — holds the right SIM inside the corroborated cell while a fabricated or replayed file is sealed | none from the operator: the check is about the SIM's cell, one to two kilometres wide, at the time of the call. What catches the fabricated *file* is the rest of the chain: attestation, integrity, watermark, the segment chain | **accepted and named**: *corroborated* means the SIM was in that area, not that the scene was. This is why the level is not called *verified* and why the radius is shown |
| **SIM/device decoupling** | the SIM the operator locates is not in the device that signed: tethering, a hotspot, a SIM moved to another handset, a data-only SIM in a router | `camara-number-verification` over the capturing device's **own** mobile data session binds the line to that session; `camara-sim-swap` flags a recent move; the registry's combination rule decides the `result`; a Wi-Fi-only device has no line and stays *declared* | **medium**: number verification binds the line to a data session, not to the camera; a phone tethering the capturing device passes it. The residual is stated in the verifier's wording — *the registry attests that the operator confirmed the zone* |
| Stale or coarse answer | the operator's location is minutes old or the cell is large | `radius_m` and `at` are in the signed body; the registry asks with a small `maxAge`; a *partial* or *unknown* operator answer maps to `unknown`, which corroborates nothing | accepted: the radius is what a reader is shown, and *same area* is all the level claims |
| Lying or compromised registry | the registry signs a `match` the operator never gave | the level is explicitly the registry's word, stated in those terms by every verifier; the attachment is optional and never a verdict; the log key that signs it is the same key whose tree heads mirrors watch | **accepted and named**: this is trust in us, and the design's job is to keep it out of the verdict and visible in the level |
| Operator wrong or coerced | the network's location is wrong, or an insider at the operator answers falsely | none: a network-side check is worth the network behind it | accepted at the platform level, as for a QTSP (§5.4) |
| Phone number in the proof | the MSISDN, or a hash of it, lands in the attachment for correlation | `operator_ref` is an opaque registry-side reference and the spec forbids anything derived from a number; the line-to-key mapping stays in the control plane behind access control; consent is collected in the app before the call and the operator's three-legged flow decides the rest | none by construction; enforced by the schema's `opaqueRef` pattern and by review |

### 5.8 Against the watermark

The watermark is a lookup hint, never a verdict: `watermark-robustness-1.0.md`
§ *Adversarial removal and forgery* measures 65 deliberate attacks on the
published model, on a corpus of three images and one clip, and publishes the
ones that worked next to the ones that did not. Two of its findings are
accepted and named here; the third is open.

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| **Watermark removal by re-framing** | rotates a sealed photo past ~12°, or crops past ~35 % of the frame — ~8° and ~35 % on the int8 build a browser verifier runs — and the payload no longer decodes | **none from the watermark**: neither layout carries a synchronisation pattern, nothing realigns the mark to the detector's working grid, and straightening or reframing costs the attacker nothing a viewer would read as damage. Filtering-based removal, by contrast, failed on every attempt measured | **accepted and named**: removal makes a verdict *weaker*, never greener. A file whose pixels were rewritten has no valid signature either, so it is already *no proof found* or *tampered*; what is lost is the lookup hint. Break points are measured on three images and are not a rate |
| **Watermark forgery with the public model** | the model is an export of a publicly downloadable upstream checkpoint, so anyone can embed a chosen `capture_id` into content that was never captured, or overwrite an existing one at the same strength — 3/3 in the measurement, at 42 dB | **none in the watermark**: it carries no key and is not a signature, and the mark carries no authorship because anyone can mark. What stops the forged file being believed is the ECDSA **signature** over the file bytes from an attested hardware key, which the adversary cannot produce | **accepted and named**: this is why a watermark alone is never green. A forged mark reaches *origin traced* and never *authentic* — the invariant is load-bearing here, not decorative |
| **Splicing one marked frame into foreign footage** | extracts a single frame from any sealed clip in circulation and splices it into 23 frames of unrelated content; the clip reports that `mark_id` at agreement 0.996 (int8: 0.93), which is the agreement of a clean recovery. No model needed | **a verifier should not decode a clip from frame-averaged logits alone.** An unmarked frame abstains rather than dissents (mean absolute message logit 11.3 marked against 0.131 unmarked), so one marked frame sets every bit. Decoding frames **individually** and reporting how many carried the id turns the claim into "1 of 8 sampled frames carries this id", which is what happened; the robustness curve found that every chain which recovers already recovers at N = 1, so this costs no recovery. `agreement` does not catch this and must not be presented as if it did | **open**: the mitigation is a verification policy, not a format change, and no document requires it yet. See § 6 |

Two wordings follow from the above and hold wherever a verifier speaks about a
watermark: a recovered mark means *a frame of that capture appears in this
file*, never *this file is that capture*; and the mark survives ordinary
re-compression, not ordinary editing.

## 6. Open items

- **Spike S3**: the relay attack reproduced with Frida on a rooted device
  against the deployed mitigations. Until then, "relay" stays *medium*.
- **Channel binding** derivation in the control plane (TLS exporter or session
  hash): today optional; the verdict says when it is absent.
- **Mirrors and gossip** (C10, C11): split-view resistance depends on them.
- **External audit** (D7): commissioned during phase 1, findings folded here.
- **Per-frame clip decoding** (§ 5.8): the splice result — one genuine marked
  frame in 23 foreign ones reporting the real `mark_id` at agreement 0.996 —
  has a mitigation that no document requires yet. Decode the sampled frames
  **individually** and report **how many carried the id**, instead of decoding
  once over the averaged logits; the count is the claim, and a 1-of-8 result
  must not be rendered as a recovery. This is a verification policy and a
  verifier wording change, **not** a format change: no vector, no schema field
  and no bit layout moves. Removal and forgery themselves are no longer open —
  they are measured, and accepted and named in § 5.8.
- **Per-capture keys** for unlinkability: cost and policy, later.
- **Position, corroborated** (§5.7): the residual on SIM/device decoupling
  stays *medium* until the registry's combination rule (number verification
  over the capturing session, SIM swap, local signals) exists and is
  measured; Location Verification is not offered by any Italian operator as
  of September 2026 (D12, spike S4), so the *corroborated* level is
  reachable in production only through the other two methods. The
  *authenticated* level waits for a smartphone chipset with OSNMA.

## 7. Change log

- 2026-09-08 — first draft, from the spec, the crypto review and what phase 1
  built so far.
- 2026-09-12 — §5.8, threats against the watermark, from the 65-attack red
  team published in `watermark-robustness-1.0.md`: removal by re-framing and
  forgery with the public model move out of *Open items* into accepted and
  named; splicing one marked frame into foreign footage is open, with a
  verification-policy mitigation.
- 2026-09-11 — §5.7, threats against the declared position and the
  `location_corroboration` attachment: the false accept with the SIM in the
  cell and the SIM/device decoupling from spike S4 (D12), the registry as
  the asserter, no phone number in a proof.
