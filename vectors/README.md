# Conformance vectors

One directory per case, numbered. Each has `expected.json` and `NOTES.md`, plus
its input:

| `kind` | Input | What it exercises |
|---|---|---|
| `file` | `input.<ext>`, optional `input.<ext>.vcap` sidecar, `proof.json` for reading | trailer, canonical bytes, core signature, key binding, version policy, absence labels |
| `segments` | `segments.json` — `capture_id`, `pub`, `segment_count`, `segments[]` | the §5 chain at message level: content hashes given, no container |
| `jcs` | `core.json` | canonicalization: expected `core_bytes_hex` and `core_hash` |

`expected.json` for `file` and `segments` vectors carries the fields a verifier
must reproduce: `outcome` (`authentic`, `verified_clip`, `tampered`,
`nested_proof`, `corrupted_proof`, `no_proof_found`, `unsupported_format_version`),
`labels` (the §8 labels, sorted), `not_evaluated` (unknown top-level keys,
sorted), `core_hash` (hex, when a core was read) and `segments.verified` (the
indexes that verified). `debug`, where present, is for humans: intermediate
bytes to compare before touching signatures.

Expected verdicts are decided in review from the spec and written down first;
`tools/src/generate.ts` then produces the inputs and aborts if the reference
verifier in `tools/src/verify.ts` disagrees. **Never edit an `expected.json` to
make an implementation pass.** Either the implementation is wrong or the spec
is; fix that.

The test key in `tools/src/testkey.ts` is public by design: anyone can
regenerate the vectors. Base media in `_media/` (a 16×16 JPEG, its HEIC) are
the unsealed inputs.

## Running them

```
cd tools && npm ci && npm test        # every vector against the reference verifier
npm run generate                       # rewrite vectors/NN-* (signatures change: ECDSA is randomized)
```

An implementation passes conformance when, for every directory, it produces
the same `outcome`, `labels`, `not_evaluated`, `core_hash` and `segments.verified`
as `expected.json`, and the same `core_bytes_hex` for `jcs` vectors.

## Not here yet, and why

- **Container-level video** (real MP4/MOV, `content_hash` recomputed from NAL
  units and audio frames): needs each platform's encoder, step 3 of the work
  order. The chain itself is covered at message level (25–31).
- **Proof level** (§7: attestation chains, registry inclusion, revocation):
  after C6 exposes the material. The signature layer here never evaluates it.
- **`timestamp` and `anchor` attachments**: after C7/C8.
- **Watermark-only match, cropped photo beyond the correction budget**:
  detector vectors, ML review.
