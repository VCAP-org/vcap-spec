import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * The documents a third party copies from, pinned to the corpus they describe.
 *
 * `vectors/CONFORMANCE.md` is not commentary: it is the file an implementer
 * copies to declare conformance in their own published material, in our name.
 * Its sample report and its framing sentence were hand-written, and stayed at
 * corpus 1.0.0 with 84 vectors long after the corpus had moved — so a reader
 * copying the sample would have declared conformance with a corpus that no
 * longer exists. Hand-maintained numbers in a document are exactly the
 * mechanism that produces that, so the numbers are checked here against
 * `vectors/VERSION` and `vectors/MANIFEST.json` like any other claim.
 *
 * This does not check what the documents *teach* — the shape of a declaration,
 * what it means and what it does not — only that the corpus they name is the
 * corpus that exists.
 */
const ROOT = join(import.meta.dirname, '..', '..')
const VECTORS = join(ROOT, 'vectors')

const version = readFileSync(join(VECTORS, 'VERSION'), 'utf8').trim()
const manifest = JSON.parse(readFileSync(join(VECTORS, 'MANIFEST.json'), 'utf8')) as { corpus_version: string, vector_count: number }
const conformance = readFileSync(join(VECTORS, 'CONFORMANCE.md'), 'utf8')
const vectorsReadme = readFileSync(join(VECTORS, 'README.md'), 'utf8')

/** What whoever trips one of these assertions has to do about it. */
const FIX = 'the corpus moved: update the numbers in vectors/CONFORMANCE.md and vectors/README.md to match vectors/VERSION and vectors/MANIFEST.json'

describe('the conformance documents name the corpus that exists', () => {
  it('the manifest is the one VERSION describes', () => {
    // Not this test's job (manifest:check owns it), but everything below
    // compares against the manifest, so a stale one would make it vacuous.
    expect(manifest.corpus_version, 'MANIFEST.json disagrees with vectors/VERSION: run `npm run manifest`').toBe(version)
  })

  // Every "corpus X.Y.Z" in the prose, wherever it is written — the framing
  // sentence, the example claim, the closing rule — must be the current one.
  // Matching the pattern rather than known line numbers means a sentence added
  // later is covered without anyone remembering to add it here.
  for (const [name, text] of [['CONFORMANCE.md', conformance], ['README.md', vectorsReadme]] as const) {
    it(`${name} quotes the current corpus version`, () => {
      const quoted = [...text.matchAll(/corpus\s+(\d+\.\d+\.\d+)/g)].map((m) => m[1])
      expect(quoted.length, `${name} no longer illustrates a conformance claim; if that is deliberate, drop this check`).toBeGreaterThan(0)
      expect([...new Set(quoted)], FIX).toEqual([version])
    })
  }

  it('the sample report declares the corpus that exists', () => {
    const block = conformance.match(/```json\n([\s\S]*?)```/)
    expect(block, 'the sample conformance report is gone from vectors/CONFORMANCE.md').not.toBeNull()
    const sample = JSON.parse(block?.[1] ?? '{}') as Record<string, unknown>
    expect(sample.corpus_version, FIX).toBe(version)
    for (const field of ['vectors_declared', 'vectors_run', 'passed']) {
      expect(sample[field], `${field} in the sample report: ${FIX}`).toBe(manifest.vector_count)
    }
  })

  it('the worked example of flooring a count uses the real size of the corpus', () => {
    // "expect(count).toBeGreaterThanOrEqual(30) over a corpus of N hides the
    // loss of N-30 vectors" — the arithmetic is the point of the passage, so
    // both halves move with the corpus.
    expect(conformance, FIX).toContain(`over a corpus of ${manifest.vector_count} hides the loss of ${manifest.vector_count - 30} vectors`)
  })
})
