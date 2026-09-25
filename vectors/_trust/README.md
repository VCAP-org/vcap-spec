# `_trust/` — the anchors a verifier is assumed to hold

A verdict is never "green"; it is "green **against these anchors**". The §7
vectors therefore ship the anchors next to the inputs, as files a verifier
loads, instead of compiling them into the reference implementation — otherwise
a second implementation could not reproduce a verdict, and the substitution
below would be invisible.

| File | What it is |
|---|---|
| `attestation-roots.pem` | The root the corpus's attestation chains end in. **A test root, standing in for a pinned Google root.** |
| `logs.json` | The public key of the transparency log the corpus pretends to trust: `log_id` (base64url of SHA-256 of the SPKI, as in CT) and `spki` (base64 DER). It signs tree heads and, per §6.2, `attestation_status`, `integrity` and `location_corroboration` statements. `app_signing_digests` lists the signing-certificate digests of the app builds the log admits keys from, which §7 compares with an attestation leaf's `attestationApplicationId`. |
| `tsa-roots.pem` | The TSA root the corpus's timestamp tokens chain to, standing in for a qualified TSA's. |
| `c2pa-test/root.pem`, `c2pa-test/signer.pem` | The C2PA test credential that signs the Content Credentials of vectors 123–147: *vcap-spec test CA* and one claim-signing leaf under it (EKU C2PA claim signing 1.3.6.1.4.1.62558.2.1 plus emailProtection, valid 2026–2046). **A test credential, on no C2PA trust list**: a C2PA validator reports those manifests *Trusted* only when this root is loaded as an anchor, which is what each vector's `c2pa` block assumes. The keys are in `tools/src/testc2pakey.ts`. No vcap verdict reads it. |

## What this proves, and what it does not

Google's attestation roots sign chains minted inside real secure hardware, and
no test can produce one. So these vectors prove the **logic** of §7 — which
level a chain establishes, at which instant it is validated, what an expired
certificate does to the level, what a revoked one does — and they say nothing
about whether an implementation can walk a real Google chain to a real Google
root.

That is proved elsewhere, and has to be: the verifier implementations carry
real chains from real devices (a moto g75 5G under Remote Key
Provisioning, a Samsung SM-S908B with a StrongBox batch key) as fixtures. An
implementation that passes this corpus and has never met a real chain has
tested its arithmetic, not its trust store.

## Why the private keys are public

`tools/src/testkey.ts`, `tools/src/testlogkey.ts` and
`tools/src/testc2pakey.ts` carry the signing keys in the clear, the chains are
minted by `tools/src/make-attestation-chains.ts` and the C2PA credential by
`npm run generate:c2pa -- --mint-ca`. Anyone can regenerate every byte here.
A corpus whose evidence only its authors can produce is a corpus nobody else
can check.
