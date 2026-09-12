import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { corpus, runVector, trust } from './conformance.js'

/**
 * Writes the conformance report this repository's own reference verifier
 * earns, in the format `vectors/CONFORMANCE.md` asks every implementation to
 * publish. Two reasons it exists rather than being left to prose:
 *
 * 1. "I pass the corpus" is only checkable if the claim names *which* corpus
 *    — version and manifest hash — and *how many* vectors it ran. This writes
 *    that down, from the corpus itself, so the claim cannot drift from it.
 * 2. It is the worked example a third-party runner is measured against: the
 *    report validates against `schema/conformance-report.schema.json`, and
 *    the file this writes is the one CI checks.
 *
 * Exits non-zero when the run is not a clean pass **and** when it ran fewer
 * vectors than the manifest declares — including zero, which is the failure
 * a conformance suite most often hides.
 */

const ROOT = join(import.meta.dirname, '..', '..')
const OUT = join(ROOT, 'vectors', 'conformance-report.json')

const c = corpus()
const anchors = trust()
const results = c.names.map((name) => runVector(name, anchors))
const failed = results.filter((r) => !r.pass)

const report = {
  implementation: 'vcap-spec reference verifier (tools/src/verify.ts)',
  corpus_version: c.version,
  manifest_sha256: c.manifestSha256,
  vectors_declared: c.declaredCount,
  vectors_run: results.length,
  passed: results.length - failed.length,
  failed: failed.map((r) => ({ name: r.name, detail: r.detail ?? '' })),
  by_kind: Object.fromEntries(
    [...new Set(results.map((r) => r.kind))].sort().map((kind) => [kind, results.filter((r) => r.kind === kind).length])
  ),
  // What the corpus is *made of*, not only how much of it passed: most of
  // these vectors expect a verdict that is not green, and a reader who only
  // sees "84/84 passed" learns nothing about that.
  by_expected_outcome: Object.fromEntries(
    [...new Set(c.names.map((n) => c.outcomes[n]))].sort().map((o) => [o, c.names.filter((n) => c.outcomes[n] === o).length])
  )
}

const serialized = JSON.stringify(report, null, 2) + '\n'
if (process.argv.includes('--check')) {
  const have = existsSync(OUT) ? readFileSync(OUT, 'utf8') : null
  if (have !== serialized) { console.error('[vcap] vectors/conformance-report.json is stale: run `npm run conformance:report` in tools/ and commit the result'); process.exit(1) }
} else {
  writeFileSync(OUT, serialized)
}
console.log(`[vcap] corpus ${report.corpus_version} (manifest ${report.manifest_sha256.slice(0, 12)}…): ran ${report.vectors_run}/${report.vectors_declared}, passed ${report.passed}, failed ${report.failed.length}`)

// The three ways this run is not a conformance pass. The count check is the
// one that matters most: a suite that ran nothing is the classic green build.
if (report.vectors_run === 0) { console.error('[vcap] zero vectors ran: that is a failure, not a pass'); process.exit(1) }
if (report.vectors_run !== report.vectors_declared) {
  console.error(`[vcap] ran ${report.vectors_run} vectors but the manifest declares ${report.vectors_declared}: the corpus on disk is not the corpus claimed`)
  process.exit(1)
}
if (failed.length > 0) {
  for (const f of failed) console.error(`[vcap] ${f.name}: ${f.detail}`)
  process.exit(1)
}
