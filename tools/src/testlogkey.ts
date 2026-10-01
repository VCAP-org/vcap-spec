// Test transparency-log key. Public by design, like the signing key in
// `testkey.ts`: the corpus must be regenerable by anyone, and a vector whose
// evidence only we can produce tests nothing anybody else can reproduce.
//
// It stands in for the key a real log signs its tree heads — and, per §6.2, the
// `attestation_status` snapshots — with. Its public half is in
// `vectors/_trust/logs.json`, which is what a verifier loads.
export const TEST_LOG_KEY_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNgkn4rBWCoMC6MdIaRgwf4LnixUmHVwV/whyid8yQfuhRANCAARwcBvaHbxBIBgX4DrisfunxMGAlNOK14a1a+0T0YdEo9y5958KIPYoK59KwMbOjXuO7e8u94QrhobfkI6+Nfk5'

// A second trusted log: in `vectors/_trust/logs.json` beside the first, run by
// a different operator in the corpus's story, and named by no `registry`
// attachment. It exists for the vectors where a countersignature verifies
// under a trusted key that is not the key of the log the proof names (§6.2
// *Which key*): a verifier that tried every trusted key would accept them.
export const TEST_SECOND_LOG_KEY_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfOUK+aqehlB8GJfUxjNKRckGTg5gM+V/skY/o14m3IWhRANCAAT0NM1mLqAQ5l9cH7lNh6RkJbe5bNtmF7WlQCt1t89v6NrkUgkpJs3JRYl/gZuH2WAXBfhIm12Ewd+He90TvLxv'
