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

export interface SchemaResult { valid: boolean, errors: string[] }

const describe = (errors: ErrorObject[] | null | undefined): string[] =>
  (errors ?? []).map((e) => `${e.instancePath || '/'} ${e.message ?? e.keyword}`)

export const validateProof = (proof: unknown): SchemaResult =>
  ({ valid: proofValidator(proof) as boolean, errors: describe(proofValidator.errors) })

export const validateExpected = (expected: unknown): SchemaResult =>
  ({ valid: expectedValidator(expected) as boolean, errors: describe(expectedValidator.errors) })
