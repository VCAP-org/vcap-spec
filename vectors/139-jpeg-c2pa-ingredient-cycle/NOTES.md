# 139-jpeg-c2pa-ingredient-cycle

A store of three manifests — urn:c2pa:76636170-0000-4000-8000-000001390000 carrying vector 01's proof, urn:c2pa:76636170-0000-4000-8000-000001390001 opening it as `parentOf`, urn:c2pa:76636170-0000-4000-8000-000001390002 (active) opening that — in which generation 1's parent reference was rewritten to point at generation 2: the chain is 2 → 1 → 2. A reader follows `parentOf` without revisiting a manifest (§3.2), so it stops at the second step with nothing found: **no proof found**. The proof in generation 0 is reachable only by a reader that searched every manifest, which §3.2 forbids; the file is the unsealed photo it would have matched.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): refused the file — `Error: cyclic ingredient found in path: ["urn:c2pa:76636170-0000-4000-8000-000001390002", "urn:c2pa:76636170-0000-4000-8000-000001390001"]`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
