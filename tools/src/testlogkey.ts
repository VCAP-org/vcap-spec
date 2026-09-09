// Test transparency-log key. Public by design, like the signing key in
// `testkey.ts`: the corpus must be regenerable by anyone, and a vector whose
// evidence only we can produce tests nothing anybody else can reproduce.
//
// It stands in for the key a real log signs its tree heads — and, per §6.2, the
// `attestation_status` snapshots — with. Its public half is in
// `vectors/_trust/logs.json`, which is what a verifier loads.
export const TEST_LOG_KEY_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNgkn4rBWCoMC6MdIaRgwf4LnixUmHVwV/whyid8yQfuhRANCAARwcBvaHbxBIBgX4DrisfunxMGAlNOK14a1a+0T0YdEo9y5958KIPYoK59KwMbOjXuO7e8u94QrhobfkI6+Nfk5'
