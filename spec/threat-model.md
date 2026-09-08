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
- **Where it was**, beyond the level `location.level` declares (declared,
  corroborated, authenticated).
- **That the device was not compromised below the attestation boundary.** A
  rooted device with a virtual camera can hand genuine hardware a fake frame.
  Attestation and integrity signals raise the cost; they do not make it
  impossible. This is the residual risk that matters most and it is stated on
  every verdict where integrity is not `hardware`.
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

## 6. Open items

- **Spike S3**: the relay attack reproduced with Frida on a rooted device
  against the deployed mitigations. Until then, "relay" stays *medium*.
- **Channel binding** derivation in the control plane (TLS exporter or session
  hash): today optional; the verdict says when it is absent.
- **Mirrors and gossip** (C10, C11): split-view resistance depends on them.
- **External audit** (D7): commissioned during phase 1, findings folded here.
- **Watermark red team** (phase 3): removal and forgery of the watermark are
  out of scope for this version; the watermark alone is never green.
- **Per-capture keys** for unlinkability: cost and policy, later.

## 7. Change log

- 2026-09-08 — first draft, from the spec, the crypto review and what phase 1
  built so far.
