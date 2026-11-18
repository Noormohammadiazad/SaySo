import { describe, expect, it } from 'vitest'
import { persist, quietAborts, step, StepError } from './boot'
import { LoadError } from './wire/load'
import { NetworkError } from './net'

const instant = async () => undefined

describe('step', () => {
  it('names the step that failed and keeps the cause', async () => {
    const outcome = step('Reading the inbox', async () => {
      throw new DOMException('The operation was aborted.', 'AbortError')
    })
    await expect(outcome).rejects.toBeInstanceOf(StepError)
    await expect(outcome).rejects.toThrow('Reading the inbox failed: The operation was aborted.')
  })

  it('does not wrap a StepError twice', async () => {
    const inner = new StepError('Reading the inbox', 'HTTP 500')
    await expect(step('Starting', () => Promise.reject(inner))).rejects.toBe(inner)
  })
})

describe('persist', () => {
  it('retries network failures, reporting each, until the step works', async () => {
    const problems: string[] = []
    let calls = 0
    const value = await persist(
      'Reading the inbox',
      async () => {
        calls++
        if (calls === 1) throw new NetworkError('this site did not answer within 20 s')
        if (calls === 2) throw new DOMException('The operation was aborted.', 'AbortError')
        if (calls === 3) throw new LoadError('nothing arrived for 10 s (tried 6 times)')
        return 'manifest'
      },
      { onRetry: (problem) => problems.push(problem), wait: instant },
    )
    expect(value).toBe('manifest')
    expect(problems).toEqual([
      'Reading the inbox failed: this site did not answer within 20 s',
      'Reading the inbox failed: The operation was aborted.',
      'Reading the inbox failed: nothing arrived for 10 s (tried 6 times)',
    ])
  })

  it('waits longer each time', async () => {
    const delays: number[] = []
    let calls = 0
    await persist(
      'x',
      async () => {
        if (++calls < 4) throw new NetworkError('down')
        return 1
      },
      { onRetry: (_problem, ms) => delays.push(ms), wait: instant },
    )
    expect(delays).toEqual([2_000, 4_000, 8_000])
  })

  it('does not retry a real error', async () => {
    let calls = 0
    const outcome = persist(
      'Opening storage',
      async () => {
        calls++
        throw new RangeError('quota exceeded')
      },
      { wait: instant },
    )
    await expect(outcome).rejects.toThrow('Opening storage failed: quota exceeded')
    expect(calls).toBe(1)
  })

  it('can be told to stop', async () => {
    let calls = 0
    const outcome = persist(
      'x',
      async () => {
        calls++
        throw new NetworkError('down')
      },
      { wait: instant, giveUp: () => calls >= 2 },
    )
    await expect(outcome).rejects.toThrow('x failed: down')
    expect(calls).toBe(2)
  })
})

describe('quietAborts', () => {
  it('marks unhandled aborts as handled, and nothing else', () => {
    let handler: ((event: Event) => void) | undefined
    quietAborts({ addEventListener: (_type: string, fn: EventListenerOrEventListenerObject) => (handler = fn as (e: Event) => void) } as Pick<
      Window,
      'addEventListener'
    >)
    const event = (reason: unknown) => {
      let prevented = false
      handler!({ reason, preventDefault: () => (prevented = true) } as unknown as Event)
      return prevented
    }
    expect(event(new DOMException('x', 'AbortError'))).toBe(true)
    expect(event(new DOMException('x', 'TimeoutError'))).toBe(true)
    expect(event(new Error('a real bug'))).toBe(false)
  })
})
