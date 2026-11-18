import { describe, expect, it } from 'vitest'
import { passkeyProblem } from './passkey'

describe('passkeyProblem', () => {
  it('reads a cancelled or aborted prompt the same in every browser', () => {
    const chrome = new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')
    const firefox = new DOMException('The operation was aborted.', 'AbortError')
    for (const err of [chrome, firefox]) {
      expect(passkeyProblem(err)).toBe('The passkey prompt was closed, timed out, or is not allowed on this page.')
    }
  })

  it('names the other cases', () => {
    expect(passkeyProblem(new DOMException('x', 'InvalidStateError'))).toMatch(/already has a passkey/)
    expect(passkeyProblem(new DOMException('x', 'NotSupportedError'))).toMatch(/can't use a passkey/)
    expect(passkeyProblem(new Error('strange'))).toBe('The passkey did not work (strange).')
  })
})
