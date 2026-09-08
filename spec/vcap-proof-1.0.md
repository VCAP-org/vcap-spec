# vcap proof format, version 1.0

**Status: DRAFT — not frozen.** Until the `v1.0` tag, everything here can change.

## 1. Scope

Defines the artefact that a capture pipeline produces and a verifier consumes:
its container binding (trailer), its canonical bytes, its JSON structure and the
verdict semantics of each field.

## 2. Terminology

- **capture** — one photo or one video clip sealed at the moment of recording.
- **capture id** — 128-bit random identifier, also carried by the watermark.
- **canonical bytes** — the byte sequence the signature covers (see §5).
- **trailer** — the block appended to the file carrying the proof (see §4).

## 3. Open decisions (close these first)

Each of these must take a position, not offer options. Work order and owners in
`Doc/06-fase1-avvio.md` §3.

- [ ] **3.1 Trailer magic and header.** Bytes, endianness, position of the
      length field. Decided shape: `"VCAP" + uint8 major + uint8 minor +
      uint16 flags`. Confirm and specify exactly.
- [ ] **3.2 Canonical bytes.** File minus trailer; for JPEG also minus the C2PA
      APP11 store. Photos embed the manifest *after* sealing, video *before*.
      Write as a reproducible procedure, one vector per container.
- [ ] **3.3 Video signature granularity.** One signature per GOP inside SEI: how
      a segment boundary is defined, what the segment hash covers, what the
      verifier does with contiguous-but-incomplete segments.
- [ ] **3.4 Proof level declaration.** `secure_hw` values and integrity verdict;
      which combination yields which verdict. This is the field that stops the
      web SDK and iOS from passing as Android with StrongBox.
- [ ] **3.5 Optional vs invalidating.** Timestamp, anchor, log reference and
      location are all absent in an offline capture: specify the exact degraded
      labels.
- [ ] **3.6 Compatibility policy.** Major and minor versions, verifier behaviour
      on an unknown minor, and the additive-only rule after freeze.

## 4. Container binding (trailer)

TODO — depends on 3.1.

## 5. Canonical bytes

TODO — depends on 3.2.

## 6. Proof structure

```
{
  "v": "vcap/1.0",
  "capture_id": "...",
  "media":    { "mime", "w", "h", "duration_ms", "hash" },
  "segments": [ { "gop", "range", "hash", "sig" } ],
  "watermark":{ "algo", "layout", "payload_bits", "ecc", "strength" },
  "device":   { "platform", "secure_hw", "integrity_verdict", "key_id" },
  "registry": { "log_id", "leaf_index", "sth_ref" },
  "time":     { "device_clock", "tsr", "tsa_issuer" },
  "anchor":   { "chain", "tx", "block", "merkle_path" },
  "location": { "level", "lat", "lon", "acc_m", "evidence" },
  "policy":   { "pseudonymous", "retention_ref" }
}
```

Per field: type, whether required, who produces it, who verifies it. TODO.

## 7. Verdict semantics

TODO. Invariants that already hold: a watermark match without a valid signature
is never green; a missing field weakens the verdict instead of failing it.

## 8. Compatibility

TODO — depends on 3.6.
