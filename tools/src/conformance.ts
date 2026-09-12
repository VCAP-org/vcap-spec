import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { coreBytes } from './core.js'
import { validateExpected, validateProof } from './schema.js'
import { loadTrust } from './trust.js'
import { verifyFile, verifySegments } from './verify.js'

/**
 * The corpus as a *runnable contract*, shared by the reference verifier's own
 * suite and by `conformance-report.ts`, which writes the claim a third party
 * publishes. Both had the same loop; a claim produced by a second, slightly
 * different loop would be a claim about something other than what CI runs.
 *
 * The rule this module exists to enforce: **a run of zero vectors is a
 * failure, never a pass.** A suite that enumerates an empty directory — an
 * uninitialised submodule, a moved path, a filter that stopped matching — is
 * green for the worst possible reason, and that is the failure mode a
 * conformance claim has to be immune to. `corpus()` therefore throws when the
 * directory is missing or empty, and reports the count the manifest declares
 * next to the count actually found so a caller can compare the two.
 */

const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')

export interface Corpus {
  /** `vectors/VERSION`: the corpus version a claim names, e.g. `1.0.0`. */
  version: string
  /** SHA-256 of `MANIFEST.json` as committed: the exact bytes a claim is about. */
  manifestSha256: string
  /** `vector_count` as the manifest declares it. */
  declaredCount: number
  /** The `NN-*` directories actually present, sorted. */
  names: string[]
  /** Expected outcome per vector name, as the manifest records it. */
  outcomes: Record<string, string>
}

/** Read the corpus metadata, or throw. Never returns an empty corpus. */
export const corpus = (): Corpus => {
  if (!existsSync(VECTORS)) throw new Error(`[vcap] no corpus at ${VECTORS}: nothing to be conformant with`)
  const names = readdirSync(VECTORS).filter((d) => /^\d\d-/.test(d)).sort()
  if (names.length === 0) throw new Error(`[vcap] the corpus at ${VECTORS} holds no vectors: a run of zero vectors is a failure, not a pass`)
  const versionFile = join(VECTORS, 'VERSION')
  const manifestFile = join(VECTORS, 'MANIFEST.json')
  if (!existsSync(versionFile) || !existsSync(manifestFile)) {
    throw new Error('[vcap] the corpus carries no VERSION/MANIFEST.json: a claim that cannot name a corpus version is not a claim')
  }
  const manifestBytes = readFileSync(manifestFile)
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as { vector_count: number, vectors: Array<{ name: string, outcome?: string }> }
  return {
    version: readFileSync(versionFile, 'utf8').trim(),
    manifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
    declaredCount: manifest.vector_count,
    names,
    outcomes: Object.fromEntries(manifest.vectors.map((v) => [v.name, v.outcome ?? 'n/a']))
  }
}

/** The anchors the corpus assumes a verifier holds (`vectors/_trust`). */
export const trust = (): ReturnType<typeof loadTrust> => loadTrust(join(VECTORS, '_trust'))

export interface VectorResult {
  name: string
  kind: string
  /** True when the verifier reproduced every field `expected.json` pins. */
  pass: boolean
  /** What differed, for a human: empty when `pass`. */
  detail?: string
}

/** Only the fields the vector pins, at the top level: a verdict may carry more. */
const pick = (actual: object, expected: Record<string, unknown>): object =>
  Object.fromEntries(Object.keys(expected).filter((k) => k !== 'kind' && k !== 'debug').map((k) => [k, (actual as Record<string, unknown>)[k]]))

/**
 * Run one vector through the reference verifier and say whether it reproduced
 * the expected verdict. Throws only on a corpus that is malformed (an unknown
 * `kind`); a verdict that disagrees is a `pass: false` result, because a
 * report has to be able to describe a failing implementation.
 */
export const runVector = (name: string, anchors = trust()): VectorResult => {
  const path = join(VECTORS, name)
  const expected = JSON.parse(readFileSync(join(path, 'expected.json'), 'utf8'))
  const schemaErrors = validateExpected(expected).errors
  if (schemaErrors.length > 0) return { name, kind: String(expected.kind), pass: false, detail: `expected.json is not schema-valid: ${JSON.stringify(schemaErrors)}` }

  // `verifier_clock`, `key_status` and `chain_read` are inputs the vector
  // declares, not fields a verifier produces: destructured out with the rest.
  const { kind, debug: _debug, schema_valid: schemaValid, verifier_clock: verifierClock, key_status: keyStatus, chain_read: chainRead, ...want } = expected
  const disagree = (got: object): VectorResult =>
    ({ name, kind, pass: false, detail: `expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}` })

  if (kind === 'file' || kind === 'container') {
    const input = readdirSync(path).find((f) => f.startsWith('input.') && !f.endsWith('.vcap')) as string
    const sidecarPath = join(path, `${input}.vcap`)
    const verdict = verifyFile({
      file: readFileSync(join(path, input)),
      sidecar: existsSync(sidecarPath) ? readFileSync(sidecarPath) : undefined,
      recomputeSegments: kind === 'container',
      trust: anchors,
      clock: verifierClock ? new Date(verifierClock) : undefined,
      keyStatus,
      chainRead
    })
    const got = pick(verdict, want)
    if (JSON.stringify(got) !== JSON.stringify(want)) return disagree(got)
    const proofPath = join(path, 'proof.json')
    if (existsSync(proofPath)) {
      const valid = validateProof(JSON.parse(readFileSync(proofPath, 'utf8'))).valid
      if (valid !== schemaValid) return { name, kind, pass: false, detail: `proof.json schema validity ${valid}, expected ${schemaValid}` }
    }
    return { name, kind, pass: true }
  }

  if (kind === 'segments') {
    const got = pick(verifySegments(JSON.parse(readFileSync(join(path, 'segments.json'), 'utf8'))), want)
    return JSON.stringify(got) === JSON.stringify(want) ? { name, kind, pass: true } : disagree(got)
  }

  if (kind === 'jcs') {
    const bytes = coreBytes(JSON.parse(readFileSync(join(path, 'core.json'), 'utf8')))
    const got = { core_bytes_hex: bytes.toString('hex'), core_hash: createHash('sha256').update(bytes).digest('hex') }
    return got.core_bytes_hex === want.core_bytes_hex && got.core_hash === want.core_hash
      ? { name, kind, pass: true }
      : disagree(got)
  }

  throw new Error(`[vcap] unknown vector kind ${kind} in ${name}`)
}
