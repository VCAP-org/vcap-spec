# VCAP encrypted vault object — version 1

**Status: in use, with an offline reference decoder and test vectors.** As of
20 September 2026 the platform stores objects in this format and the Android
app writes them: version 1.0.12 is on Play's internal track and the server it
talks to is deployed. That is **not** a publication, and this envelope is not
frozen: an internal testing track reaches nobody outside, every object written
so far is the owner's own and can be re-made, and the decision of 22 September
2026 (`CHANGELOG.md`) applies here as it does to the proof format. The
additive-only rule binds at the first object sealed under a key that is
somebody else's, because that one cannot be re-encrypted; an earlier revision
of this notice declared it already bound. This is a separate envelope for preserving a sealed
file, not a change to `vcap/1.0`, its signature inputs, or its verification
path.

This document specifies encrypted storage (mode A). It does not define
service-readable originals (mode B), public lookup, custodian passphrase
wrapping, upload authorization or deletion receipts. Those do not acquire
semantics through `policy.retention_ref`, which remains reserved.

## 1. Export and trust boundary

An export consists of `manifest.json` and `ciphertext.bin`. The organization
keeps its P-256 private key separately, as unencrypted PKCS#8 DER or PEM. An
export containing only ciphertext without the manifest is incomplete. A
custodian's passphrase-encrypted key blob must first be opened by its own
protocol; it is not a PKCS#8 key file.

Decrypting requires no account, registry, server or network request. After
recovery, verify the sealed file using a vcap verifier. **Successful decryption
is not a proof verdict or sender authentication:** anyone with the public
organization key can encrypt a different file. Compare the object/capture
identifiers with the expected export record, then verify the recovered proof
and its capture identifier independently. An adversary able to replace an
entire export can replace it with another correctly encrypted object; this
format does not sign the export manifest or establish its provenance.

Each object uses a fresh 32-byte DEK, 16-byte object identifier, 8-byte nonce
prefix and HPKE ephemeral key, all from an operating-system CSPRNG. The DEK is
never derived from content or reused. The organization encryption key is
separate from device signing keys. The uploader receives only its public half.

## 2. Manifest

JSON object with exactly the following fields; unknown fields/versions are
rejected. Integers are exact, nonnegative JSON integers. Base64url is canonical,
unpadded RFC 4648 encoding; hex is lowercase. The reference decoder accepts a
regular manifest file of at most 16,384 bytes. JSON whitespace and member order
have no cryptographic meaning; authentication uses the binary header below.

| Field | Value |
|---|---|
| `version` | `"vcap-vault/1"` |
| `object_id` | 16 random bytes, 32 hex characters |
| `capture_id` | the proof's 16-byte capture identifier, base64url |
| `org_key_id` | SHA-256 of the organization's DER SubjectPublicKeyInfo, 64 hex characters |
| `nonce_prefix` | 8 random bytes, base64url |
| `plaintext_bytes` | 0 to **500,000,000** inclusive (500 MB, decimal) |
| `chunk_bytes` | exactly **1,048,576** (1 MiB) |
| `wrapped_key.enc` | HPKE encapsulated key: 65-byte uncompressed P-256 point, base64url |
| `wrapped_key.ciphertext` | 32-byte DEK plus 16-byte tag, base64url |
| `ciphertext_sha256` | SHA-256 of the whole `ciphertext.bin`, 64 hex characters |

`wrapped_key` has exactly two members. Encapsulated points are validated by
the KEM, not merely checked for their length. The recipient derives the public
SPKI from its private key and checks `org_key_id` before opening the wrapper.
The fingerprint uses a named-curve SPKI (`id-ecPublicKey`, P-256 OID)
with the 65-byte uncompressed point; compressed points are normalized before
fingerprinting. A JSON Schema is supplied in `schema/vcap-vault-1.schema.json`; the decoder also
checks canonical encodings and cryptographic validity.

The 500 MB cap is on the sealed plaintext file. Ciphertext adds 16 bytes per
segment; a storage or upload limit must allow this exact overhead. Empty input
is represented to make truncation unambiguous, although an empty recovered
file cannot itself be a valid sealed capture.

## 3. Binary header and key wrapping

`U32` and `U64` below are unsigned, big-endian integers. `||` means byte
concatenation. String literals are UTF-8; `\0` is one zero byte. Identifiers in
this construction are **decoded bytes**, not their hex/base64 text.

```
header = "vcap/1.0/vault/header\0"
         || object_id[16] || capture_id[16] || org_key_id[32]
         || nonce_prefix[8] || U64(plaintext_bytes) || U32(chunk_bytes)
header_hash = SHA-256(header)
info = "vcap/1.0/vault\0" || header_hash
```

Wrap the DEK using [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
**base mode** (mode 0), with KEM `0x0010` (DHKEM P-256/HKDF-SHA256), KDF
`0x0001` (HKDF-SHA256), and AEAD `0x0002` (AES-256-GCM). Supply `info` above
when creating the context and use `header` as the AEAD additional data.
Seal exactly one 32-byte DEK at sequence number zero; export `enc` and the
resulting 48-byte ciphertext. There is no PSK or authenticated-sender mode.
There is no cipher negotiation or fallback in this version.

The header binds the organization key, object and capture identifiers, size,
segmentation and nonce prefix to the key wrapper. The ciphertext digest is
excluded to avoid a circular construction. It detects export mistakes but is
unkeyed and cannot authenticate the sender or replace GCM tag verification.

## 4. Segments

Let `N = max(1, ceil(plaintext_bytes / chunk_bytes))`. Split the plaintext in
order, with full 1 MiB segments except the last. For exact multiples the last
segment is full; do not append an empty segment. For zero bytes there is one
empty final segment.

For segment `i`, zero-based:

```
nonce_i = nonce_prefix[8] || U32(i)
aad_i = "vcap/1.0/vault/chunk\0" || header_hash
        || U32(i) || (0x01 if i == N-1 else 0x00)
segment_i = AES-256-GCM(DEK, nonce_i, plaintext_i, aad_i)
```

Each segment is ciphertext followed by its **16-byte tag**. `ciphertext.bin`
is their concatenation, with no padding, embedded lengths or trailer. Its
exact length is `plaintext_bytes + 16*N`. Reject missing bytes, trailing bytes,
invalid tags, a missing final marker, or a different digest. Nonces are unique
within an object; fresh DEKs prevent nonce reuse between objects.

No plaintext is a complete recovered file until all segments, the final
marker, size and digest have passed. Streaming callers may stage partial
plaintext in a private temporary destination, but must discard it on rejection
and must not expose it as a recovered original. Segments cannot be reordered
or transplanted to another header while preserving their tags.

## 5. Offline reference decoder

From a checkout, install the pinned Node 22 tooling once:

```sh
cd tools
npm ci
npm run vault:decrypt -- /path/manifest.json /path/ciphertext.bin /path/organization-key.pk8 /path/recovered-file
```

The decoding command itself makes no network calls. It uses the pinned
[`@hpke/core`](https://github.com/dajiaji/hpke-js) implementation for HPKE and
WebCrypto for AES-GCM; it does not implement elliptic-curve arithmetic.
It reads at most one segment at a time, imports a non-extractable DEK, and
stages plaintext beside the output with mode `0600`. After validation it
publishes using an exclusive hard link: an existing output, key, input or
other evidence file is never overwritten. The destination filesystem must
support hard links. A crash can leave a private `.partial` file requiring
operator cleanup; normal rejection removes staging files. Key material lives
in process memory; buffer clearing is best effort, not a hardware custody claim.
Diagnostics never include decrypted content, key bytes or crypto exceptions.

Exit 0 means decryption completed, 1 means failure, and 2 means invalid CLI
usage. Run an independent vcap verifier on the result; the decoder never prints
an authenticity verdict.

## 6. Vectors and limits

`tools/test/vault-vectors/` contains a small plaintext, ciphertext, manifest and
**public test-only private key**. The expected plaintext must match byte for
byte. `tools/src/vault/fixture.ts` is an independent deterministic encoder using
Node's ECDH/HMAC/AES primitives and RFC 9180's labeled key schedule; it does not
use the decoder's HPKE implementation or header helpers. This reduces the risk
of an encoder and decoder agreeing on the same implementation mistake.

The adversarial suite covers empty and exact-boundary files, multiple segments,
wrong keys, altered identifiers/metadata, invalid encapsulated points, corrupted
wrappers/tags, swapped segments, truncation, extra bytes, recomputed unkeyed
digests, missing final markers, output preservation and partial-file cleanup.
The deterministic encoder and its keys/nonces must **never** encrypt real data.
These vectors are separate from the numbered proof conformance corpus; adding a
storage format does not change any existing proof vector or verdict.

This is not an external cryptographic audit. Native phone interoperability,
browser recovery UX, custodian blobs, storage integration and operational
retention remain separate work. Publishing this decoder does not activate any
vault capability or authorize an upload from an enrolled phone.
