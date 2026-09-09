# `_trust/` — the anchors a verifier is assumed to hold

A verdict is never "green"; it is "green **against these anchors**". The §7
vectors therefore ship the anchors next to the inputs, as files a verifier
loads, instead of compiling them into the reference implementation — otherwise
a second implementation could not reproduce a verdict, and the substitution
below would be invisible.

| File | What it is |
|---|---|
| `attestation-roots.pem` | The root the corpus's attestation chains end in. **A test root, standing in for a pinned Google root.** |
| `logs.json` | The public key of the transparency log the corpus pretends to trust: `log_id` (base64url of SHA-256 of the SPKI, as in CT) and `spki` (base64 DER). It signs tree heads and, per §6.2, `attestation_status` snapshots. |

## What this proves, and what it does not

Google's attestation roots sign chains minted inside real secure hardware, and
no test can produce one. So these vectors prove the **logic** of §7 — which
level a chain establishes, at which instant it is validated, what an expired
certificate does to the level, what a revoked one does — and they say nothing
about whether an implementation can walk a real Google chain to a real Google
root.

That is proved elsewhere, and has to be: `vcap-verifier` and `vcap-platform`
both carry real chains from real devices (a moto g75 5G under Remote Key
Provisioning, a Samsung SM-S908B with a StrongBox batch key) as fixtures. An
implementation that passes this corpus and has never met a real chain has
tested its arithmetic, not its trust store.

## Why the private keys are public

`tools/src/testkey.ts` and `tools/src/testlogkey.ts` carry the signing keys in
the clear, and the chains are minted by
`tools/src/make-attestation-chains.ts`. Anyone can regenerate every byte here.
A corpus whose evidence only its authors can produce is a corpus nobody else
can check.
