# 47-heic-sealed-ios

The corpus's first proof from an iPhone, and its first from any device other than the two Androids: `platform: "ios"`, `secure_hw: "secureEnclave"`, and a `sig.value` made by a Secure Enclave over the canonical core bytes. 1600×1200 HEIC written by ImageIO, sealed on the device in 34.5 ms.

Its worth is that two independent implementations meet on one number here. The device computed the core hash `18750c77…` and so does `tools/src/verify.ts`, from the same JCS rules applied to the same core — and getting there means the writer's JCS, its DER→P1363 conversion and its low-`s` normalization are all right *together*. Any one of them wrong and this vector would not exist.

One note for anyone writing a signer, learned by breaking it: `SecKeyCreateSignature` returns **DER of variable length** — 71 bytes on this device, 72 in the simulator — so a conversion that assumes 72 works until it does not.

An iPhone 11 Pro (`iPhone12,3`, iOS 18.6.2) during the S1 spike, 10 September 2026 (`vcap-sdk-ios`, `docs/s1-videotoolbox-spike.md`). The proof is the device's own; nothing here re-signs it.
