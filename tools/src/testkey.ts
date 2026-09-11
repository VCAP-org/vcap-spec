// Test-vector signing key. Public by design: it exists so that anyone can
// regenerate the vectors and so that no vector depends on a key nobody has.
// It never signs anything but conformance vectors. Not a secret.
export const TEST_KEY_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVuDNy/oSt/tsLPa7sQaBqiETd5QAKeTr9DyxYV8cw3WhRANCAASnYL9LFS5rUYHH7q7coEgko/A5vrIRiZOp91uDMltUkLLX/C+YoCOOa8P53kR1VakbHQnFx26mmx3RKyk08crI'

// A second test key that is **nobody's**: not the vector signing key, not a
// trusted log key, not in `vectors/_trust/`. It stands in for "another
// device" (vector 51, a registry leaf about somebody else's key) and for "a
// signer this verifier does not follow". Fixed for the same reason the vectors
// sign with RFC 6979: a key minted at generation time rewrote vector 51's
// bytes on every run, so a diff of the corpus never said whether 51 had changed.
export const TEST_OTHER_KEY_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJbHLNHJk0SlG+hLjEnKF3rygp0R5ARoACPuZ4sOepTehRANCAATdreTSXoQSZkTwNIG7eeF8aJELqAbiytwhxaNuLal9IsOPF6Wpkv205VTJXEmKV4dqT84qrU1NZyVv4zXwjqBK'
