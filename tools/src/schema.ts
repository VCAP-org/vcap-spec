import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js'

/**
 * The JSON Schema of the proof (schema/vcap-proof-1.0.schema.json) and of a
 * vector's expected.json, compiled once. `validateProof` is what every
 * implementation repository runs in CI over the proofs it produces.
 */
const SCHEMA_DIR = join(import.meta.dirname, '..', '..', 'schema')
// strictRequired off: the if/then that requires media.segment_count when segments
// exist names a property outside its own subschema, which is the point.
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false })

const compile = (file: string) => ajv.compile(JSON.parse(readFileSync(join(SCHEMA_DIR, file), 'utf8')))
const proofValidator = compile('vcap-proof-1.0.schema.json')
const expectedValidator = compile('expected.schema.json')
const reportValidator = compile('conformance-report.schema.json')

export interface SchemaResult { valid: boolean, errors: string[] }

const describe = (errors: ErrorObject[] | null | undefined): string[] =>
  (errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message ?? e.keyword}`)

export const validateProof = (proof: unknown): SchemaResult =>
  ({ valid: proofValidator(proof) as boolean, errors: describe(proofValidator.errors) })

export const validateExpected = (expected: unknown): SchemaResult =>
  ({ valid: expectedValidator(expected) as boolean, errors: describe(expectedValidator.errors) })

/**
 * A published conformance claim (vectors/CONFORMANCE.md). The schema pins the
 * shape; the two rules it cannot express are checked here, because both are
 * the difference between a claim and a green build that ran nothing:
 * `vectors_run` must be non-zero and must equal `vectors_declared` minus the
 * vectors the report itself lists as deliberately not run.
 */
export const validateConformanceReport = (report: unknown): SchemaResult => {
  const valid = reportValidator(report) as boolean
  const errors = describe(reportValidator.errors)
  if (!valid) return { valid, errors }
  const r = report as { vectors_run: number, vectors_declared: number, passed: number, failed: unknown[], not_run?: unknown[] }
  const skipped = r.not_run?.length ?? 0
  if (r.vectors_run === 0) errors.push('/vectors_run zero vectors ran: that is a failed run, not a pass')
  if (r.vectors_run + skipped !== r.vectors_declared) errors.push(`/vectors_run ${r.vectors_run} run plus ${skipped} declared not-run do not account for the ${r.vectors_declared} vectors of the corpus`)
  if (r.passed + r.failed.length !== r.vectors_run) errors.push('/passed passed plus failed do not add up to vectors_run')
  return { valid: errors.length === 0, errors }
}
