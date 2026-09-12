import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { validateConformanceReport, validateExpected, validateProof } from './schema.js'

/**
 * CLI. With arguments: validates each given proof JSON file against the
 * schema, exit 1 on the first invalid one — what an implementation repository
 * calls in CI. With `--report` first, the remaining files are validated as
 * conformance reports instead (vectors/CONFORMANCE.md), which is how a third
 * party checks its own claim before publishing it. Without arguments: walks
 * vectors/, validates every expected.json, checks that each proof.json is
 * schema-valid exactly when its vector says so (`schema_valid`), and validates
 * this repository's own committed conformance report.
 */
const VECTORS = join(import.meta.dirname, '..', '..', 'vectors')
const read = (path: string): unknown => JSON.parse(readFileSync(path, 'utf8'))

const args = process.argv.slice(2)
const asReports = args[0] === '--report'
const files = asReports ? args.slice(1) : args
let failures = 0

if (asReports) {
  if (files.length === 0) { console.error('[vcap] --report needs at least one report file'); process.exit(1) }
  for (const file of files) {
    const result = validateConformanceReport(read(file))
    console.log(`${result.valid ? 'ok  ' : 'FAIL'} ${file}${result.valid ? '' : `\n     ${result.errors.join('\n     ')}`}`)
    if (!result.valid) failures++
  }
} else if (files.length > 0) {
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
    if ((expected.kind !== 'file' && expected.kind !== 'container') || !existsSync(proofPath)) continue
    const result = validateProof(read(proofPath))
    const want = expected.schema_valid ?? true
    if (result.valid !== want) {
      failures++
      console.log(`FAIL ${dir}: schema says ${result.valid ? 'valid' : 'invalid'}, expected.json says ${want ? 'valid' : 'invalid'}${result.errors.length ? `\n     ${result.errors.join('\n     ')}` : ''}`)
    } else {
      console.log(`ok   ${dir}: schema ${result.valid ? 'valid' : 'invalid'} as expected`)
    }
  }
  // This repository's own claim, in the format every implementation publishes.
  const reportPath = join(VECTORS, 'conformance-report.json')
  if (existsSync(reportPath)) {
    const result = validateConformanceReport(read(reportPath))
    console.log(`${result.valid ? 'ok  ' : 'FAIL'} conformance-report.json${result.valid ? '' : `\n     ${result.errors.join('\n     ')}`}`)
    if (!result.valid) failures++
  }
}

if (failures) {
  console.error(`[vcap] ${failures} schema failure(s)`)
  process.exit(1)
}
