/**
 * The numbered vectors: `NN-name`, with as many digits as the corpus needs.
 * Two digits held until vector 99; a pattern that assumed them would have
 * silently dropped vector 100 onward from every runner, and a runner that
 * checks its count against the manifest is the only reason that would show.
 */
export const isVectorDir = (name: string): boolean => /^\d{2,}-/.test(name)

/** Numeric order of the prefix, so 100 follows 99 and not 10. */
export const byNumber = (a: string, b: string): number => parseInt(a, 10) - parseInt(b, 10) || (a < b ? -1 : a > b ? 1 : 0)
