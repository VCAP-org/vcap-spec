import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { validateExpected, validateProof } from './schema.js'

/**
 * CLI. With arguments: validates each given proof JSON file against the
 * schema, exit 1 on the first invalid one — what an implementation repository
 * calls in CI. Without arguments: walks vectors/, validates every expected.json,
 * and checks that each proof.json is schema-valid exactly when its vector says
 * so (`schema_valid`).
 */
const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')
const read = (path: string): unknown => JSON.parse(readFileSync(path, 'utf8'))

const files = process.argv.slice(2)
let failures = 0

if (files.length > 0) {
  for (const file of files) {
    const result = validateProof(read(file))
    console.log(`${result.valid ? 'ok  ' : 'FAIL'} ${file}${result.valid ? '' : `\n     ${result.errors.join('\n     ')}`}`)
    if (!result.valid) failures++
  }
} else {
  for (const dir of readdirSync(VECTORS).filter((d) => /^\d\d-/.test(d)).sort()) {
    const expectedPath = join(VECTORS, dir, 'expected.json')
    const expected = read(expectedPath) as { kind: string, schema_valid?: boolean }
    const shape = validateExpected(expected)
    if (!shape.valid) {
      failures++
      console.log(`FAIL ${dir}/expected.json is malformed: ${shape.errors.join('; ')}`)
      continue
    }
    const proofPath = join(VECTORS, dir, 'proof.json')
    if (expected.kind !== 'file' || !existsSync(proofPath)) continue
    const result = validateProof(read(proofPath))
    const want = expected.schema_valid ?? true
    if (result.valid !== want) {
      failures++
      console.log(`FAIL ${dir}: schema says ${result.valid ? 'valid' : 'invalid'}, expected.json says ${want ? 'valid' : 'invalid'}${result.errors.length ? `\n     ${result.errors.join('\n     ')}` : ''}`)
    } else {
      console.log(`ok   ${dir}: schema ${result.valid ? 'valid' : 'invalid'} as expected`)
    }
  }
}

if (failures) {
  console.error(`[vcap] ${failures} schema failure(s)`)
  process.exit(1)
}
