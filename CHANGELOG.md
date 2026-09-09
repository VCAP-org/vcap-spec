# Changelog

`vcap/1.0` is frozen. Changes after the tag are additive only (spec §9): new
optional keys, new values in fields declared extensible. Every entry names the
section it touches, the vectors it adds and what an older verifier does with it.

## Unreleased

Nothing yet.

## v1.0 — 9 September 2026

First frozen version. Trailer and footer (§3), canonical bytes and core
signature (§4), per-GOP segment chain with the vcap SEI (§5), proof structure
(§6), proof levels (§7), optional versus invalidating (§8), compatibility policy
(§9). 34 conformance vectors, JSON Schema, reference verifier in `tools/`.
Reviews absorbed before the freeze: cryptographic
(`reviews/01-crypto-review-draft-1.0.md`), implementability on Android hardware
(`reviews/implementability-android.md`).
