import { createHash } from 'node:crypto'

/**
 * The signing-certificate digest of the app the test log admits keys from
 * (§7, attestationApplicationId). A fixed string's hash, so the chains and
 * `_trust/logs.json` agree without either being the source of the other.
 */
export const APP_SIGNING_DIGEST = createHash('sha256').update('vcap test app signing certificate').digest()
