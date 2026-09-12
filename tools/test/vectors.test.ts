import { describe, expect, it } from 'vitest'
import { corpus, runVector, trust } from '../src/conformance.js'

// Every committed vector, checked against the reference verifier. A new
// implementation runs the same loop with its own verifier: same inputs, same
// expected.json, no other oracle. The loop itself lives in src/conformance.ts
// so that this suite and the published conformance report run the same code —
// a report produced by a second, slightly different loop would be a claim
// about something other than what CI runs.
const c = corpus()
const anchors = trust()

describe(`conformance vectors (corpus ${c.version})`, () => {
  // Not a floor. A floor lets a suite shrink silently, and a suite that
  // enumerated zero vectors would be the greenest build in the repository:
  // `corpus()` throws on an empty directory, and this pins the count to the
  // manifest so a corpus that is not the corpus claimed fails here.
  it(`runs exactly the ${c.declaredCount} vectors the manifest declares`, () => {
    expect(c.names.length).toBe(c.declaredCount)
  })

  for (const name of c.names) {
    it(name, () => {
      const result = runVector(name, anchors)
      expect(result.detail ?? '').toBe('')
      expect(result.pass).toBe(true)
    })
  }
})
