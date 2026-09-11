import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'

/**
 * The corpus manifest (C19): a byte-exact inventory of `vectors/`, versioned
 * independently of `vcap/1.0` — the format version says what a proof looks
 * like, the corpus version says which vectors an implementation checked
 * itself against. A third party can now say "conformant with corpus 1.0.0"
 * and a consumer (this repository's own tools, or `vcap-verifier` /
 * `vcap-sdk-android`, which read `vectors/` directly) can check it holds
 * exactly those bytes without diffing ninety directories by hand.
 *
 * Additive only, like the format it tests (`AGENTS.md`): a vector's hash
 * never changes once published, so `MANIFEST.json` only ever grows. Bump
 * `vectors/VERSION` (semver) whenever the entry list changes — minor for a
 * vector added, patch for a manifest-only regeneration that adds nothing
 * (there should never be one, since the manifest is a pure function of the
 * directory), major is not expected to occur under the additive-only rule
 * and would mean an existing vector's bytes moved, which `vectors/README.md`
 * already forbids.
 *
 * CLI: `tsx src/manifest.ts` writes `vectors/MANIFEST.json`; `--check` reports
 * a diff and exits 1 instead, the same convention `vcap-verifier`'s
 * `vectors-sync.mjs` uses for its snapshot.
 */
const ROOT = join(import.meta.dirname, '..', '..')
const VECTORS = join(ROOT, 'vectors')
const VERSION_FILE = join(VECTORS, 'VERSION')
const MANIFEST_FILE = join(VECTORS, 'MANIFEST.json')

// Support directories the vectors depend on but that are not vectors
// themselves (vectors/README.md: "Two directories are not vectors" plus the
// committed chains and timestamp tokens). Hashed too, under their own key,
// so a change to a shared fixture is as visible as a change to a vector.
const FIXTURE_DIRS = ['_media', '_trust', '_chains', '_timestamps', '_watermark']

/** Every file under `dir`, recursively, as `[relativePath, bytes]`, sorted by path. */
const filesOf = (dir: string): Array<[string, Buffer]> => {
  const out: Array<[string, Buffer]> = []
  const walk = (d: string): void => {
    for (const name of readdirSync(d).sort()) {
      if (name === '.DS_Store') continue
      const p = join(d, name)
      if (statSync(p).isDirectory()) walk(p)
      else out.push([relative(dir, p), readFileSync(p)])
    }
  }
  if (existsSync(dir)) walk(dir)
  return out.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
}

/** SHA-256 over the sorted file list, each entry as `path\0length\0bytes`, so
 * the hash commits to both content and the exact set of file names. */
const hashOf = (files: Array<[string, Buffer]>): string => {
  const hash = createHash('sha256')
  for (const [path, bytes] of files) {
    hash.update(path, 'utf8')
    hash.update(Buffer.from([0]))
    hash.update(String(bytes.length), 'utf8')
    hash.update(Buffer.from([0]))
    hash.update(bytes)
  }
  return hash.digest('hex')
}

interface VectorEntry { name: string, kind: string, outcome?: string, sha256: string, files: number }

const vectorEntry = (name: string): VectorEntry => {
  const dir = join(VECTORS, name)
  const files = filesOf(dir)
  const expectedPath = join(dir, 'expected.json')
  const expected = existsSync(expectedPath) ? JSON.parse(readFileSync(expectedPath, 'utf8')) as { kind: string, outcome?: string } : null
  return { name, kind: expected?.kind ?? 'unknown', outcome: expected?.outcome, sha256: hashOf(files), files: files.length }
}

const build = (): object => {
  const names = existsSync(VECTORS) ? readdirSync(VECTORS).filter((d) => /^\d\d-/.test(d)).sort() : []
  const version = existsSync(VERSION_FILE) ? readFileSync(VERSION_FILE, 'utf8').trim() : '0.0.0'
  const fixtures: Record<string, string> = {}
  for (const name of FIXTURE_DIRS) {
    const dir = join(VECTORS, name)
    if (existsSync(dir)) fixtures[name] = hashOf(filesOf(dir))
  }
  return {
    corpus_version: version,
    vector_count: names.length,
    vectors: names.map(vectorEntry),
    fixtures
  }
}

const write = (): void => { writeFileSync(MANIFEST_FILE, JSON.stringify(build(), null, 2) + '\n') }

const check = (): boolean => {
  const wanted = JSON.stringify(build(), null, 2) + '\n'
  const have = existsSync(MANIFEST_FILE) ? readFileSync(MANIFEST_FILE, 'utf8') : null
  if (have === wanted) { console.log(`[vcap] MANIFEST.json matches vectors/ (corpus ${JSON.parse(wanted).corpus_version}, ${JSON.parse(wanted).vector_count} vectors)`); return true }
  console.error('[vcap] MANIFEST.json is stale: run `npm run manifest` in tools/ and commit the result')
  return false
}

if (process.argv.includes('--check')) {
  if (!check()) process.exit(1)
} else {
  write()
  console.log(`[vcap] MANIFEST.json written (${JSON.parse(readFileSync(MANIFEST_FILE, 'utf8')).vector_count} vectors)`)
}
