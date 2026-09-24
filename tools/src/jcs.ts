/**
 * JSON Canonicalization Scheme, RFC 8785. Its number and string serialization
 * are ECMAScript's, so `JSON.stringify` of a single string or number is
 * exactly what the RFC asks for. Its member order is not: a JavaScript object
 * enumerates integer-like keys ("9", "10") first, in numeric order, whatever
 * order they were inserted in, and assigning `__proto__` sets the prototype
 * instead of adding a member. So the output is written here, member by member,
 * and never rebuilt as an object for `JSON.stringify` to walk — `{"b", "10",
 * "9"}` serialized that way came out 9, 10, b instead of 10, 9, b, and a
 * `__proto__` member vanished.
 *
 * Other languages must reproduce the same bytes, which is why the core (§6.1)
 * contains no floating-point numbers and no free text: integers and enum
 * strings serialize identically everywhere.
 */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

const serialize = (value: Json): string => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`
  // RFC 8785 §3.2.3: members sorted by the UTF-16 code units of their names,
  // which is what the default string sort compares. Undefined members are
  // dropped, as JSON.stringify drops them.
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${serialize(value[key] as Json)}`).join(',')}}`
}

export const jcs = (value: Json): Buffer => Buffer.from(serialize(value), 'utf8')
