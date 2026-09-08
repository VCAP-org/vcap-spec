/**
 * JSON Canonicalization Scheme, RFC 8785. In JavaScript this is exactly
 * `JSON.stringify` over an object whose keys are sorted by UTF-16 code units at
 * every level: the RFC defines its number and string serialization as
 * ECMAScript's. Other languages must reproduce that — which is why the core
 * (§6.1) contains no floating-point numbers and no free text: integers and
 * enum strings serialize identically everywhere.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

const canonicalize = (value: Json): Json => {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value !== null && typeof value === 'object') {
    const sorted: { [key: string]: Json } = {}
    // Default sort compares UTF-16 code units, as RFC 8785 §3.2.3 requires.
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalize(value[key] as Json)
    return sorted
  }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('JCS: non-finite number')
  return value
}

export const jcs = (value: Json): Buffer => Buffer.from(JSON.stringify(canonicalize(value)), 'utf8')
