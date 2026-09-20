# Vault interoperability vector

All bytes and the private key here are public test data, never a credential.
The key is the existing public proof-vector key, reused only to avoid another
opaque fixture. Production vault encryption keys must be separate from signing keys.

Run `npx tsx src/vault/generate.ts` from `tools/` to reproduce these files.
The generator uses Node ECDH/HMAC/AES-GCM and an independent RFC 9180 schedule;
the decoder uses hpke-js and WebCrypto. `vault.test.ts` checks regeneration,
exact recovered bytes, and adversarial variants. This is not part of the
numbered proof corpus and does not change its manifest or claimed version.
