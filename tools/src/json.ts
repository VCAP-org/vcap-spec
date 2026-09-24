import { type Json } from './jcs.js'

/**
 * The proof reader's JSON parser (§6.1, *Reading the JSON*).
 *
 * `JSON.parse` is not enough, and not because it is wrong: it answers
 * questions the format needs answered differently. It keeps the last of two
 * duplicate keys, where another parser keeps the first — so one proof would
 * read two ways in two verifiers. It reads `1.25e3` and `4032.0` as integers
 * and `9007199254740993` as a neighbour, so a core whose signature covers one
 * serialization would verify under another. And it accepts a byte-order mark
 * nowhere else would. Each of those is a proof two implementations can
 * disagree about, so each is refused here: the caller reports *no proof
 * found*, the verdict for a proof that is not well formed.
 */
export class ProofSyntaxError extends Error {}

const MAX_SAFE = 9007199254740991n
const INTEGER = /-?(?:0|[1-9][0-9]*)/y
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y

export const parseProofJson = (bytes: Buffer): Json => {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new ProofSyntaxError('a byte-order mark before the JSON')
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new ProofSyntaxError('not UTF-8')
  }
  let at = 0
  const fail = (what: string): never => { throw new ProofSyntaxError(`${what} at character ${at}`) }
  const space = (): void => { while (at < text.length && ' \t\n\r'.includes(text[at] as string)) at++ }

  const string = (): string => {
    const start = at
    at++ // opening quote
    while (at < text.length && text[at] !== '"') {
      if (text[at] === '\\') at++
      at++
    }
    if (at >= text.length) fail('an unterminated string')
    at++
    try {
      return JSON.parse(text.slice(start, at)) as string
    } catch {
      return fail('a malformed string')
    }
  }

  const number = (): number => {
    INTEGER.lastIndex = at
    NUMBER.lastIndex = at
    const whole = NUMBER.exec(text)?.[0]
    if (!whole) return fail('a malformed number')
    const integer = INTEGER.exec(text)?.[0]
    // §6.1: every number in a proof is an integer, written as one.
    if (integer !== whole) fail(`the number ${whole} is not an integer literal`)
    const big = BigInt(whole)
    if (big > MAX_SAFE || big < -MAX_SAFE) fail(`the integer ${whole} is outside ±(2^53 − 1)`)
    at += whole.length
    return Number(big)
  }

  const value = (depth: number): Json => {
    if (depth > 64) fail('nesting deeper than 64')
    space()
    const c = text[at]
    if (c === '{') {
      at++
      const out: { [key: string]: Json } = {}
      const seen = new Set<string>()
      space()
      if (text[at] === '}') { at++; return out }
      for (;;) {
        space()
        if (text[at] !== '"') fail('a member name expected')
        const key = string()
        if (seen.has(key)) fail(`the member name "${key}" appears twice`)
        seen.add(key)
        space()
        if (text[at] !== ':') fail('":" expected')
        at++
        // defineProperty, so a member named `__proto__` stays a member.
        Object.defineProperty(out, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true })
        space()
        if (text[at] === ',') { at++; continue }
        if (text[at] === '}') { at++; return out }
        fail('"," or "}" expected')
      }
    }
    if (c === '[') {
      at++
      const out: Json[] = []
      space()
      if (text[at] === ']') { at++; return out }
      for (;;) {
        out.push(value(depth + 1))
        space()
        if (text[at] === ',') { at++; continue }
        if (text[at] === ']') { at++; return out }
        fail('"," or "]" expected')
      }
    }
    if (c === '"') return string()
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) return number()
    for (const [word, v] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(word, at)) { at += word.length; return v }
    }
    return fail('a value expected')
  }

  const result = value(0)
  space()
  if (at !== text.length) fail('bytes after the JSON value')
  return result
}
