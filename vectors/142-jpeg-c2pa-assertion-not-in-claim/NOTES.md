# 142-jpeg-c2pa-assertion-not-in-claim

Vector 131 — the unsealed photo with a manifest that carries no proof — with vector 123's proof assertion box placed in the manifest's assertion store and the claim left as it was: neither `created_assertions` nor `gathered_assertions` lists it. An assertion the claim does not list is not part of the manifest (C2PA 6.6, 10.2.2), and the reader ignores it (§3.2): **no proof found**. A reader that took any box with the right label would read vector 01's proof over bytes it matches and say *authentic*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): refused the file — `Error: assertion missing: url = io.github.vcap-org.vcap.proof`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
