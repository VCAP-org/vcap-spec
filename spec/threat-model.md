# vcap threat model

**Status: DRAFT for review** — written 8 September 2026 as the deliverable
"public threat model"; the technical lead owns it, the backend reviews it. It
is public on purpose: a verifier's expert who cannot read what we defend
against, and what we do not, should not trust our green.

Companion to `vcap-proof-1.0.md`. Where that document says what a field means,
this one says who would want to lie in it, how, and what stops them.

## 1. What the system claims

For a capture that verifies **green**, and only then:

1. The bytes of the media were exactly these when a specific key signed them.
2. That key lives in secure hardware (Android StrongBox or TEE) of a device
   whose boot was verified, and was created by a known app build — proven by
   a key attestation chain to Google's root, not declared.
3. Google attested the device's integrity from a hardware root
   (`MEETS_STRONG_INTEGRITY`), relayed and signed by the registry. This is a
   strong signal and not a certainty: attestation keys have leaked before,
   and the check runs when the capture is sent, not when it is taken (§2).
   No source proves an iOS device intact, so **no iOS capture is green** in
   this version.
4. The key was registered in a public, append-only transparency log before the
   capture, by an organization that passed KYB, and was not revoked at capture
   time.
5. The claims around the media — capture id, declared time and place, level,
   watermark parameters — were signed by the same key at the same moment.
6. Optionally: the proof existed before a trusted time (RFC 3161), and before
   an on-chain block.

For a capture that verifies **amber**, one or more of these is not proven, and
the verifier says which. Amber is not a floor under red: evidence that would
make a verdict red can be deleted from a file without breaking a signature —
a revoked `attestation_status` stripped reads *chain revocation not checked* —
so a verifier that can fetch the evidence itself does (`vcap-proof-1.0.md` §8,
*What amber does not say*).

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
  canonical bytes, verified by its own signature, separately — also when it
  carries the proof, which a verifier reads without believing anything the
  manifest says (`vcap-proof-1.0.md` §3.2).

## 3. Assets and trust boundaries

| Asset | Where | Who must not touch it |
|---|---|---|
| Device signing key | secure hardware of the device | anyone, including the app and the OS |
| Attestation roots (Google, Apple) | pinned in verifier, data plane, SDKs | anyone: changed only by a reviewed commit with a fingerprint test |
| Transparency log | data plane, Postgres, append-only by trigger; mirrors | us — that is the point of the log |
| Log signing key | KMS in production | anyone but the data plane's signing path |
| Registry: key → organization → operator | control plane only | the data plane, the log, the public |
| Revocation list (Google) and App Attest roots | fetched / pinned by the data plane | — |
| Media and proofs | the device, then the customer's systems or the vault | us, unless the customer chooses the vault — made precise in §5.9, which says what that choice does and does not take away |
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
  verdict — that is the floor, and it is not negotiable. The signature, the
  chain, the media hash, the segment chain and every attachment the proof
  carries (`registry` inline, the token, the anchor's path) are checked from
  the file alone. Above the floor, some answers only a service can give: the
  log's signed key status (ours), a chain's current status list (Google's),
  an anchor's on-chain record (a public chain, through a node or a gateway).
  Green needs the first, so a fully offline verifier never reaches green, and
  it says so (*revocation not checked*). Each such answer is named as its
  source, signed by it where it can be, and its absence degrades the verdict
  instead of breaking it.

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
| Presentation edit | re-muxes a genuine clip keeping every sample, and rotates the track matrix, edits the out-of-band SPS (crop, colour) or adds an enabled track | `media.presentation` in the core binds the configuration record, `clap`/`pasp`/`colr` and the audio `esds`, the `tkhd` matrix and display size; the track layout rule (§5 *Presentation*, vectors 160–162) | none: *frames not compared*, never *verified clip*; a video proof without the field is not well formed, *no proof found* over the original and every clip (vector 165) |
| Timeline edit | re-muxes a genuine video with an edit list that trims, repeats or reorders what a player shows, every sample untouched | an edit list with more than one edit after the leading delay, or a rate change, is a timeline §5 does not model: no segment is located (§5, vector 156) | none: *frames not compared*, never *verified clip*; an original is covered whole by `media.hash` |
| Clip re-timed | re-muxes a genuine clip keeping every sample and the single-edit timeline, and changes sample durations (`stts`), composition offsets (`ctts`), the `mdhd` timescales, the media edit's extent or the audio sample rate: a frame frozen, a passage slowed, the whole clip sped up in sync, frames reordered within a GOP, part of a segment hidden | each `segments[]` entry carries the hash of its segment's timing record, bound by `media.timing.root` in the signed core; a verifier reads each located segment's record back, converts it to the signed timescales exactly, and refuses a media edit that trims inside a located segment; the audio `esds` is part of `media.presentation` (`vcap-proof-1.0.md` §5 *Timing*, vectors 179–186) | none: *frames not compared* with *timing differs* (*presentation differs* for the sample rate), never *verified clip*; a forged entry hash is *tampered* (vector 177). Accepted: the audio–video offset is bound only to within one audio frame (the assignment rule's slack), and a media edit that runs past the end of the media — what a player shows there is not defined — is not bound. An original is covered by `media.hash` |
| Proof transplant | moves a genuine trailer or sidecar onto another file | `media.hash` mismatch; on video, a signed segment counts only where a GOP of the received file names it and recomputes (§5, *Locating segments*) | none: red on a photo; *frames not compared* on a video whose GOPs name no segment of the proof, never *verified clip* |
| Accusing trailer | strips a genuine file's trailer and appends another capture's valid trailer (CRC correct) beside the genuine sidecar, to have the file accused | beside a differing sidecar whose outcome is better over the same bytes, the sidecar decides, with *trailer copy differs* (`vcap-proof-1.0.md` §3.1, *A sidecar that does better*, vectors 172–173); ties keep the trailer (vector 174) | none with the sidecar present: the file reads as the sidecar says. Without it the appended proof decides, as it would on any file |
| Accusing broken footer | strips a genuine file's trailer and appends a footer a reader cannot use — a trailer whose CRC fails, a footer of another major, sixteen bytes whose size describes no trailer — beside the genuine sidecar, to have the file read *corrupted proof*, *unsupported format version* or *tampered* | beside a sidecar, the sidecar is judged over the file without the unreadable trailer — the `free` box the footer declares when it fits, otherwise the footer alone — and decides when its outcome is better, with *trailer unreadable* (`vcap-proof-1.0.md` §3.1, *A sidecar that does better than an unreadable footer*, vectors 72, 188–191); ties keep the footer's verdict (vectors 192, 193) | none with the sidecar present. A wrong span cannot raise a verdict: what remains must still hash to the signed `media.hash` or recompute a signed segment. Not covered: a broken footer appended after an intact trailer, which is not peeled back (vector 193) |
| Clip from a genuine video | cuts segments, keeps the trailer | per-segment chain over messages; `segment_count`; `media.hash` mismatch → *verified clip*, amber, ranges shown | accepted and **labelled**: a clip is a clip, never an original |
| Reassembled video | reorders, repeats or relabels genuine GOPs, or inserts a foreign one next to them | every GOP of the file is accounted for in decode order: one vcap SEI naming this capture and a signed segment, indices strictly increasing, each at most once (§5) | none: red |
| Audio replacement on a clip | keeps verified frames, swaps sound | audio frames inside the segment hash (§5) | none on originals and clips |
| Signature malleability | flips `s` to break or forge chains | chain over messages, not signatures; P1363; both `s` halves accepted | none |
| Nested trailer | wraps a hardware-sealed original in a weaker proof | nested trailer detected and reported; writers refuse | none: *nested proof* |
| Metadata stripping by a platform | social network removes the trailer | *no proof found*, distinct from *corrupted*; watermark → *origin traced*, never authentic; sidecar | accepted: provenance lost, origin traceable, never mistaken for tampering |
| Format confusion | crafts a footer to make an unsealed file look edited | structural footer checks before the CRC (§3) | none |
| Proof carried by a forged manifest | writes Content Credentials that carry a genuine proof over another file, or declare a file a derivation of a genuine capture; or adds such a manifest beside a genuine file and its sidecar, to have it accused | a proof in the active manifest is verified exactly as a sidecar; beside a differing sidecar whose outcome is better over the same bytes, the sidecar decides (§3.1 step 4, vectors 169–171); one found up the `parentOf` chain reaches only what it proves of this file — its bytes or located segments — and is otherwise *no proof found* (§3.2); nothing the manifest says is trusted | none: red at depth 0 when nothing better is beside it; a declared derivation is never green unless the proof covers its bytes. A manifest's copy with less evidence than the sidecar can lower a ceiling on a tied outcome, as deleting the evidence would |
| Hostile Content Credentials | builds a store to crash, loop or mislead the reader: cycles, deep nesting, oversized lengths, two stores, a proof off the chain, a redacted proof left in place | structure-only reader bounded by its input; a chain walked without revisits to depth 16; no search off the chain; more than one store is none; a redaction listed anywhere is absence (§3.2) | low; hostile-input tests next to vectors 133–142 |
| Canonicalization divergence | exploits differences between implementations | integers only, no free text, JCS, conformance vectors every implementation runs | low; vectors grow with every finding |

### 5.2 Against the key and the device

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| Software key posing as hardware | generates a key outside the TEE, claims StrongBox | attestation chain to Google/Apple root; `attestationSecurityLevel` and `keyMintSecurityLevel`, the weaker; software → `none` | none |
| Relayed attestation | forwards a genuine device's attestation to register an attacker session (Quarkslab 2026) | single-use challenge issued by us, consumed atomically before any check; proof of possession over `"vcap/1.0/pop" ‖ challenge ‖ channel_binding` (Android) / nonce in the App Attest certificate and assertions (iOS); short RKP certificate validity checked; channel binding when the control plane provides one | **medium** until a spike confirms against Frida on a rooted device; channel binding without a TLS exporter is weaker and the verdict says so |
| Key extraction | reads the private key out of the device | secure hardware; not our control | accepted: the platform's promise, not ours |
| Compromised app | a modified build of our app, or another app, uses the key | `attestationApplicationId` (package + signing digest) / App ID, per tenant; token rotation stops a leaked build | low; a re-signed app has a different digest |
| Imported key | key created elsewhere, imported into the TEE: the chain shows `tee` and a verified boot while the importer keeps the private key | hardware-enforced `origin` must be `GENERATED`, else the proven level is `none` (`vcap-proof-1.0.md` §7 rule 6, vector 152) | none. Until corpus 4.0.0 no verifier checked it, while this row said one did |
| Stolen key, backdated clock | a thief holding a device key revoked for loss or rotation — not retroactive — sets `time.device_clock` before the revocation | with no trusted instant the log is asked about the verifier's clock, never the device's; revoked then → *key revoked*, red (§6.2, vector 155) | none on the key's standing. A capture an honest TSA stamped before the revocation keeps it, as it should |
| Unlocked bootloader / rooted device with virtual camera | genuine hardware signs an injected frame | verified boot state and locked device required in the attestation; integrity statement (Play Integrity / App Attest) signed by the registry as an attachment; both prominent on the verdict | **high and accepted**: see §2. The verdict names it. Green requires a registry-signed `hardware` verdict from Play Integrity (`vcap-proof-1.0.md` §6.2, §7); anything else — absent, `basic`, `failed`, App Attest — is amber with *integrity not proven*, so stripping a `failed` verdict cannot raise the colour. What remains is a device that passes Google's strongest check while compromised, which a leaked attestation key has made possible before. The verdict counts only for the platform it attests (Play Integrity beside an iOS proof proves nothing, vector 153) and only under the key of the log the proof names (vector 154) |
| Cloned Secure Enclave key (theoretical) | two devices with one key | App Attest counter must increase on every assertion; the receipt (future) | low |
| Integrity verdict from another device | the holder of a key on a compromised device has a clean device running the attested app request Play Integrity with the capture's `core_hash` as nonce, and gets a `hardware` verdict for it | the registry relays a verdict only when Google's signed answer echoes `core_hash` and names the attested app as requester; the device holding the key must separately prove a locked, verified boot in its attestation `rootOfTrust` (`vcap-proof-1.0.md` §6.2, §7 rule 4) | **accepted and named**: Play Integrity attests a device and an app, never a key, so the verdict is bound to the capture and not to the key holder. Binding the nonce to a device-key signature adds nothing — a signature over the core is public in the proof, and one over a fresh challenge is what the key holder can hand to the clean device. The device genuineness of the key holder rests on the attestation chain |
| Stripped revocation evidence | deletes a `revoked` `attestation_status` (or any attachment) from a file | none in the file: attachments are outside the core. Every condition for green is present evidence, so deletion never raises a verdict; an online verifier reads the chain's status list itself while the chain is current, and asks the log for the key's status (`vcap-proof-1.0.md` §6.2, §8) | **accepted and named**: red becomes amber with *chain revocation not checked* for a verifier that cannot fetch the list, and for every verifier once the chain has expired and its status is published nowhere |

### 5.3 Against the registry and the log

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| Insider registers a key without a device | writes a leaf for a key nobody attested | the leaf is public; the attestation digest is in it; a mirror or an auditor asks for the chain; KYB before any leaf | medium: detection, not prevention — this is what "transparency" buys |
| Insider rewrites history | edits or deletes a leaf | Postgres triggers refuse UPDATE/DELETE/TRUNCATE; signed tree heads kept forever; consistency proofs; mirrors | none against a database admin acting alone; a rewrite breaks consistency for every mirror |
| Split view | the log shows different trees to different parties | every head is signed and kept; mirrors compare heads and consistency proofs; gossip between verifiers is future work | medium until mirrors exist |
| Hidden revocation | the log says "valid" for a revoked key | status is signed by the log key over key, time, tree size, status; revocation leaves have inclusion proofs; anyone can check the revocation leaves for a key | low; a lying log signs the lie, which is evidence |
| Retroactive revocation abuse | an insider revokes a key retroactively to invalidate inconvenient captures | retroactive only for `compromise`, refused otherwise by the log itself; the leaf is public with its reason | low: visible, attributable |
| Log key compromise | attacker signs heads and statuses | key in KMS; rotation with the old key's heads kept; verifiers pin by `log_id` | medium: recovery is a new log id, published |
| Cross-message signature | presents the log key's signature over one message — a tree head, a key status, an `integrity` or `location_corroboration` statement, a revocation snapshot — as a signature over another | every message the log key signs begins with its own ASCII separator: `"vcap/1.0/sth"`, `"vcap/1.0/status"`, `"vcap/1.0/integrity"`, `"vcap/1.0/location"`, `"vcap/1.0/attestation-status"` (`vcap-proof-1.0.md` §6.2) | none. Before corpus 8.0.0 the `attestation_status` message alone had none; it began with a `core_hash` nobody chooses, so it was not exploitable, only the exception the rule should not have |
| Registered after capture | a key logged after the fact | `tree_head.timestamp` vs declared time and vs the RFC 3161 token: *registered after the declared capture*, amber | none on the ordering claim |

### 5.4 Against the platforms we rely on

| Threat | Mitigation | Residual |
|---|---|---|
| Google or Apple attestation root compromised or an attestation key leaked (older provisioning) | pinned roots; Google's revocation list checked, fail closed server-side; RKP preferred | accepted at the platform level; verifiers degrade, never fail silently |
| QTSP compromised | two providers, failover; token chain validated offline; with an anchor, the token must predate the block and its signer be valid at the block time (§6.2) | a false time from a compromised QTSP is a false time; the token names the issuer |
| TSA signing key leaked | a token is validated at its own `genTime`, which the key holder chooses; with a verified anchor the token must predate the block and the signer certificate must be valid at the block time, so a key leaked after its certificate expired cannot stamp a proof first anchored afterwards | **accepted and named**: a leaked TSA key can backdate a token to any instant inside its certificate's life, and a token that has no anchor has no bound at all. A verifier cannot tell that token from an honest one. This version requires **no** revocation check of the TSA signer (`vcap-proof-1.0.md` §6.2 validates a token offline); the remedy a verifier has is removing the TSA's root from the roots it pins, which un-trusts every token under it. An online check of the TSA's revocation is open (§6) |
| Attestation key leaked (keybox) | a revoked chain certificate is red unless a trusted instant predates the revocation date the source gives, and never for a compromise; `fetched_at` is not a date and a device clock never places a capture before a revocation (§6.2) | low: what remains is a capture stamped by an honest TSA before the date a non-compromise revocation took effect |
| Chain reorganization or censorship | anchoring is optional evidence; *not anchored* is a label | accepted |

### 5.5 Privacy

| Threat | Mitigation | Residual |
|---|---|---|
| Linking captures to a device | `device.key_id` is a pseudonym for device+app; no serial, IMEI or MEID in the attestation (no ID attestation) | **accepted and named** in the spec: pseudonymous ≠ unlinkable; per-capture keys are future work |
| Linking captures across key rotations | the `attestation` chain is not anonymous: a Remote Key Provisioning intermediate is issued to one device and certifies every key it makes while it lives, and `attestationApplicationId` names the app. Two proofs sharing an intermediate come from one device whatever their `device.key_id` | a pseudonymous writer may leave `attestation` out: the chain stays with the registry, committed in the log leaf as `attestation_digest` (`vcap-proof-1.0.md` §6.2) | **accepted and open**: a proof that carries its chain links its device across rotations; one that omits it proves `none` on Android, because only the chain proves an Android level. No offline proof of a level without disclosing the chain exists in this version |
| Personal data in the public log | leaves carry key identifiers, level, digests, log time — nothing else; the registry mapping stays in the control plane | none by construction, enforced by the plane boundary |
| Personal data leaking through the plane boundary | allowlist per endpoint, both sides; second net over values; tests assert names and VAT never cross | low |
| EXIF in the signed file | signed as content; pseudonymous mode must strip **before** sealing | implementation duty of the SDKs |
| Position and key id in a carried proof | the proof assertion is readable by anyone who dumps the Content Credentials; a carrier redacts it (C2PA 6.8) or carries only `policy.pseudonymous` proofs (`c2pa-interop-1.0.md` §2.1) | accepted and named: carrying the proof publishes it |
| Server learning what is in a capture | the data plane sees hashes and keys; a stored original is client-side encrypted in mode A and readable by the service in mode B | none for a capture that is not stored; §5.9 for one that is |

### 5.6 Availability and failure behaviour

- The verification floor contains none of our servers: an outage cannot make
  a file unreadable or turn any verdict red. It can lower green to amber —
  green needs the log's signed key status, and without it the verdict says
  *revocation not checked* (§3).
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
| **Splicing one marked frame into foreign footage** | extracts a single frame from any sealed clip in circulation and splices it into 23 frames of unrelated content; the clip reports that `mark_id` at agreement 0.996 (int8: 0.93), which is the agreement of a clean recovery. No model needed | **a verifier does not decode a clip from frame-averaged logits alone**, and since 20 September 2026 `vcap-proof-1.0.md` §8 requires the count: a verifier reporting a clip recovery MUST say how many of the sampled frames carried the id, and MUST NOT present a confidence figure as if it answered that question. An unmarked frame abstains rather than dissents (mean absolute message logit 11.3 marked against 0.131 unmarked), so one marked frame sets every bit. Decoding frames **individually** and reporting how many carried the id turns the claim into "1 of 8 sampled frames carries this id", which is what happened; the robustness curve found that every chain which recovers already recovers at N = 1, so this costs no recovery. `agreement` does not catch this and must not be presented as if it did | **closed as a policy, and named**: the requirement is in §8, the platform's detector decodes each sampled frame and reports `frames_with_id`, and the reference verifier carries the count into the sentence a reader sees. What remains accepted is the underlying fact — one marked frame is one marked frame — which no format can change: the claim is *a frame of that capture appears in this file*, and the count is how much of it does |

Two wordings follow from the above and hold wherever a verifier speaks about a
watermark: a recovered mark means *a frame of that capture appears in this
file*, never *this file is that capture*; and the mark survives ordinary
re-compression, not ordinary editing.

### 5.9 Against the stored original

Storing originals is optional, per organization, and orthogonal to every
verdict: nothing in this section can turn a green into anything, because a
verdict is reached from the file and its proof alone. What it can do is expose
the *content* a capture holds, which the rest of this document never addresses.

Two shapes exist (`vcap-vault-1.md`). In **mode A** the phone encrypts under
the organization's public key before uploading and the service holds ciphertext
it cannot open. In **mode B** the original reaches the service readable. They
are not variants of one risk and must never be presented together: the second
is an exposure a customer accepts deliberately, with a DPIA behind it.

| Threat | What the attacker does | Mitigation | Residual |
|---|---|---|---|
| **A database or bucket read by somebody who should not** | a dump, a stray backup, a dishonest operator: everything the service holds | mode A: the object is HPKE-encrypted to a key that never reaches this platform; the custodian blobs are inert without a passphrase we never see | **none for the content in mode A** — whoever takes everything we have opens nothing. In mode B, everything: that is what the mode means |
| **A legal order served on us** | compels us to hand over what we hold | the same: in mode A what we hold is unreadable | **named, with its condition**: it holds for the objects, not for the proofs. Those are in the clear and keep saying when, which device, which organization |
| **We substitute the organization's public key** | we serve a phone a key of ours, and from that moment everything it uploads is readable by us | **none cryptographic, and no client-side scheme survives a hostile vendor who controls the client.** What limits the damage is exposure: the key is a leaf on the append-only log with a signed statement (`"vcap/1.0/vault-key"`), the fingerprint is comparable in two places — the organization's console and the phone — and the phone **pins** the key it accepted and refuses a change | **accepted and named, and it is the first line of this section for a reason**: these are detectors, and they work only if somebody looks. With Play App Signing the binary a user installs is signed by Google, so we cannot even demonstrate byte for byte which build runs on a phone |
| **A custodian is compromised** | takes the private key from the person who holds it | the blob is AES-256-GCM under PBKDF2-HMAC-SHA256 at 600 000 iterations, and at least two custodians exist so one lost passphrase is not the end of the archive | **the customer's, and deliberately**: whoever holds the organization's private key holds the organization's archive. The surface moved from our data centre to two laptops, which is the point of the decision and not a flaw in it — but it is a surface the customer has to know it took on. PBKDF2 is weaker against a GPU than Argon2id; the choice is stated where the blobs are created |
| **Somebody who already decrypted** | opens a file and forwards it | none | accepted: there is no DRM here and no promise of control after opening |
| **Metadata about what is stored** | watches sizes, times and counts | none, and none intended: the service must know how big an object is to store it | **accepted and named**: for every object we see the organization, a pseudonymous device, the capture id, the instant, the size and the key epoch — plus the proof, which we already had. Volume and rhythm say things about an activity. The vault is not an anonymous channel and does not pretend to be |
| **A truncated, reordered or substituted upload** | sends parts out of order, stops halfway, or sends bytes that do not match the digest it declared | the digest is recomputed by the service before anything is stored; parts are fixed-size and sequential; an encrypted object's manifest must name this capture and a key the organization published | none: the object is never attached, and the reservation is swept |
| **A capture that was never meant to leave** | pseudonymous captures, which carry no device identity by construction | refused in three places: the app's queue, the transport and the platform | none: the mode exists so that no later setting, ours included, can undo it |
| **Reading an original from the console** | an employee with console access opens somebody's file | mode B: authorization is `manage` — narrower than reading a case — and every retrieval writes an append-only trail entry naming who, what and when | **accepted and named**: an administrator can read. The control is traceability, not impossibility, and an authorization nobody can review afterwards is a promise rather than a control |
| **Deletion that did not happen** | the service claims to have deleted an object and keeps it | a signed receipt states what was deleted, how big, when it arrived, when it went and why | **named**: the receipt proves this installation deleted its copy and that the statement is unaltered. It cannot prove no copy exists anywhere else — nobody can sign that — and backups age out on their own schedule |
| **A compromised phone below the attestation boundary** | a rooted device with a virtual camera encrypts a fabricated scene perfectly well | the same as for sealing (§2): none | accepted, and identical to the sealing case |

The line in §3 that reads *“us, unless the customer chooses the vault”* is made
precise by this section: choosing mode A does not take our future access away,
it makes it **observable**. That is a weaker sentence than a brochure would
like, and it is the true one.

## 6. Open items

- **Relay spike**: the relay attack reproduced with Frida on a rooted device
  against the deployed mitigations. Until then, "relay" stays *medium*.
- **Channel binding** derivation in the control plane (TLS exporter or session
  hash): today optional; the verdict says when it is absent.
- **Mirrors and gossip**: split-view resistance depends on them.
- **Integrity freshness**: the integrity verdict is minted when a capture is
  sent, not when it is taken, and no window bounds the gap. A bound on
  `evaluated_at` relative to the proven instant would narrow it; it needs a
  measured distribution of send delays first.
- **An iOS device-integrity source**: until one exists, iOS captures are
  amber at best (`vcap-proof-1.0.md` §6.2).
- **External audit**: commissioned during phase 1, findings folded here.
- **Per-capture keys** for unlinkability: cost and policy, later. They would
  not unlink a proof that carries its attestation chain (§5.5).
- **TSA revocation**: no verifier checks a TSA signer's revocation (§5.4);
  an online check, and what it may conclude about a token issued before the
  revocation, are to be specified.
- **Position, corroborated** (§5.7): the residual on SIM/device decoupling
  stays *medium* until the registry's combination rule (number verification
  over the capturing session, SIM swap, local signals) exists and is
  measured; Location Verification is not offered by any Italian operator as
  of September 2026, so the *corroborated* level is
  reachable in production only through the other two methods. The
  *authenticated* level waits for a smartphone chipset with OSNMA.

## 7. Change log

- 2026-10-03 — §5.1: a valid-CRC trailer appended to a trailer-stripped
  genuine file beside its sidecar no longer accuses the file
  (`vcap-proof-1.0.md` §3.1, *A sidecar that does better*); an appended
  broken or unsupported footer still does, and is recorded as open.

- 2026-10-03 — §5.1: a forged manifest added beside a genuine file and its
  sidecar no longer accuses the file (`vcap-proof-1.0.md` §3.1 step 4); a
  re-timed clip is an open residual, with a proposal.
- 2026-10-03 — Audit fixes, text only. §1: amber may hide red. §3: the
  verifier boundary states the offline floor and names the services above
  it. §5.2: an integrity verdict is bound to the capture and not to the key
  holder (accepted); stripped revocation evidence (accepted). §5.4: no
  verifier checks TSA revocation, so it was never "the only remedy"; open.
  §5.5: the attestation chain links captures across key rotations (accepted,
  open).

- 2026-10-02 — §5.1: the presentation-edit residual no longer describes a
  proof without `media.presentation` as one that binds no clip; the field is
  required of every video proof and its absence is *no proof found*
  (`vcap-proof-1.0.md` §6.1, §8).

- 2026-10-01 — Verdict hardening. §5.2: the imported-key row claimed a check
  no verifier made; `origin` is now §7 rule 6 and the residual holds. A
  device key revoked for a non-retroactive reason can no longer be dated
  before its revocation by the device clock. Integrity proves only the
  platform it attests, under the named log's key. §5.1: an edit list that
  reorders a genuine video is no longer *verified clip*, and neither is one
  whose presentation — parameter sets, matrix, extra tracks — is not the one
  the core signs.

- 2026-09-27 — Device integrity is a condition for green. §1 claims it, and
  no longer claims green for iOS; §5.2: stripping a `failed` verdict no
  longer raises the colour. This reverses the 2026-09-24 reading below: the
  contradiction it removed is resolved the other way, in §6.2 and §7 too.
  §6: integrity freshness and an iOS source are open.

- 2026-09-25 — Content Credentials as a carrier (`vcap-proof-1.0.md` §3.2).
  §5.1: a forged manifest carrying a proof, and a hostile store. §5.5: a
  carried proof is public.

- 2026-09-24 — Review fixes. §5.1: proof transplant onto a video and a
  reassembled video close on the binding rule of §5 (*Locating segments*).
  §5.2: an integrity verdict of `failed` caps amber, absence caps nothing —
  the earlier "no green without hardware integrity" contradicted §6.2 and §7.
  §5.4: a leaked TSA key and a leaked attestation key, with the anchor bound
  on tokens and the revocation-date rule on chains.

- 2026-09-20 — §5.8's splice item closes as a policy: §8 now **requires** a
  verifier reporting a clip recovery to say how many sampled frames carried
  the id, the platform's detector decodes each frame and reports the count,
  and the reference verifier puts it in the sentence. The underlying fact
  stays accepted and named — one marked frame is one marked frame.
- 2026-09-20 — §5.9, threats against the stored original, written when the vault
  shipped: the two storage modes as different risks, key substitution as the
  first entry because it is the one no cryptography answers, custody moved to
  the customer, metadata, and what a deletion receipt can and cannot prove.
- 2026-09-08 — first draft, from the spec, the crypto review and what phase 1
  built so far.
- 2026-09-12 — §5.8, threats against the watermark, from the 65-attack red
  team published in `watermark-robustness-1.0.md`: removal by re-framing and
  forgery with the public model move out of *Open items* into accepted and
  named; splicing one marked frame into foreign footage is open, with a
  verification-policy mitigation.
- 2026-09-11 — §5.7, threats against the declared position and the
  `location_corroboration` attachment: the false accept with the SIM in the
  cell and the SIM/device decoupling, the registry as
  the asserter, no phone number in a proof.
