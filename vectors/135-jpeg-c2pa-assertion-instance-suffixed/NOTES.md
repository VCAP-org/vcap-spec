# 135-jpeg-c2pa-assertion-instance-suffixed

Vector 124 whose only proof assertion is labelled `io.github.vcap-org.vcap.proof__1` — the second-instance form of C2PA 6.4. One instance per manifest, and only the unsuffixed label is it (`spec/c2pa-interop-1.0.md` §2.1): a `__n` instance is ignored, so this manifest carries no proof. **No proof found**; a reader that matched the label by prefix would say *authentic*.

## C2PA

- `expected.json` `c2pa`: what c2pa-rs 0.91.0 (c2pa-node 0.9.8), trust anchor _trust/c2pa-test/root.pem reports. Informative: no vcap verdict reads it.
- c2patool 0.28.0 (trust anchor `_trust/c2pa-test/root.pem`): refused the file — `Error: assertion missing: url = io.github.vcap-org.vcap.proof__1`.

Minted by `tools/src/make-c2pa-vectors.ts` with the test key in `tools/src/testkey.ts` and the C2PA test signer in `vectors/_trust/c2pa-test/`. Committed, not regenerated: c2pa-rs salts every assertion at random (`vectors/README.md`).
