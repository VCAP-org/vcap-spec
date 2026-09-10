import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { verifyFile, verifySegments } from '../src/verify.js'
import { coreBytes } from '../src/core.js'
import { validateExpected, validateProof } from '../src/schema.js'
import { loadTrust } from '../src/trust.js'

// Every committed vector, checked against the reference verifier. A new
// implementation runs the same loop with its own verifier: same inputs, same
// expected.json, no other oracle.
const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')
const dirs = readdirSync(VECTORS).filter((d) => /^\d\d-/.test(d)).sort()
// The anchors a verifier is assumed to hold: a verdict is only ever green
// against a named set of them, so the corpus ships them next to the vectors.
const trust = loadTrust(join(VECTORS, '_trust'))

const pick = (actual: object, expected: Record<string, unknown>): object =>
  Object.fromEntries(Object.keys(expected).filter((k) => k !== 'kind' && k !== 'debug').map((k) => [k, (actual as Record<string, unknown>)[k]]))

describe('conformance vectors', () => {
  it('exist in the expected number', () => {
    expect(dirs.length).toBeGreaterThanOrEqual(30)
  })

  for (const dir of dirs) {
    it(dir, () => {
      const path = join(VECTORS, dir)
      const expected = JSON.parse(readFileSync(join(path, 'expected.json'), 'utf8'))
      expect(validateExpected(expected).errors).toEqual([])
      // `verifier_clock` is an input the vector declares, not a field a
      // verifier produces: it is destructured out with the other inputs.
      const { kind, debug: _debug, schema_valid: schemaValid, verifier_clock: verifierClock, key_status: keyStatus, ...want } = expected

      if (kind === 'file' || kind === 'container') {
        // A container vector is a file vector plus the §5 recomputation: same
        // inputs, one more question asked of them.
        const input = readdirSync(path).find((f) => f.startsWith('input.') && !f.endsWith('.vcap')) as string
        const sidecarPath = join(path, `${input}.vcap`)
        const verdict = verifyFile({
          file: readFileSync(join(path, input)),
          sidecar: existsSync(sidecarPath) ? readFileSync(sidecarPath) : undefined,
          recomputeSegments: kind === 'container',
          // The anchors the corpus ships, the clock the vector pins, and the
          // log's answer it declares the verifier fetched.
          trust,
          clock: verifierClock ? new Date(verifierClock) : undefined,
          keyStatus
        })
        expect(pick(verdict, want)).toEqual(want)
        const proofPath = join(path, 'proof.json')
        if (existsSync(proofPath)) expect(validateProof(JSON.parse(readFileSync(proofPath, 'utf8'))).valid).toBe(schemaValid)
      } else if (kind === 'segments') {
        const verdict = verifySegments(JSON.parse(readFileSync(join(path, 'segments.json'), 'utf8')))
        expect(pick(verdict, want)).toEqual(want)
      } else if (kind === 'jcs') {
        const bytes = coreBytes(JSON.parse(readFileSync(join(path, 'core.json'), 'utf8')))
        expect(bytes.toString('hex')).toBe(want.core_bytes_hex)
        expect(createHash('sha256').update(bytes).digest('hex')).toBe(want.core_hash)
      } else {
        throw new Error(`unknown vector kind ${kind}`)
      }
    })
  }
})
