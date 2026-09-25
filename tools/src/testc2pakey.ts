// The C2PA test credential of the corpus: the private keys of the root and of
// the claim-signing leaf in `vectors/_trust/c2pa-test/`. Public by design, as
// `testkey.ts` is: anyone can re-mint the certificates and re-sign every C2PA
// vector. They never sign anything but conformance vectors. Not a secret, and
// no C2PA trust list will ever carry them.
export const C2PA_TEST_ROOT_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCcs2rfNsWCk9yQsmlOTiGtOMw+jv+S4zCexbyya8KPOhRANCAAReARNcECcaAJR2QEk3ZOVD+PvCP8MotmSGUy976EFsfPWeEMscS/iKSpevHEbPvI36reh/jTm+fYTAozu9TImB'
export const C2PA_TEST_SIGNER_PKCS8_BASE64 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1ua0Glns0bSJVPjj9bl6Kx6hGPOPGr1CbECThKHPwa2hRANCAARRMUTinaJ2BgdJGD5141v6oC/CdLCYsQhQutH0Mf96IqiBLLNrZGGffBWIwoGXjzFuoLOqahLpgdbZa13Tgw3S'
