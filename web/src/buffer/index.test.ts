import { afterEach, describe, expect, it, vi } from 'vitest'
import { bounded, putEverywhere, RELAY_TIMEOUT_MS, withCooldown, type Buffer } from './index'

const relay = (id: string, put: () => Promise<void>): Buffer => ({ id, put, drain: async () => undefined })
const never = (): Promise<void> => new Promise(() => undefined)
const item = new Uint8Array([1, 2, 3])

afterEach(() => vi.useRealTimers())

describe('putEverywhere', () => {
  it('is done as soon as one relay accepts, while a slow one is still working', async () => {
    let finishSlow!: () => void
    const slow = new Promise<void>((resolve) => (finishSlow = resolve))
    const progress: [number, number][] = []

    await putEverywhere([relay('slow', () => slow), relay('fast', async () => undefined)], item, (accepted, settled) =>
      progress.push([accepted, settled]),
    )
    expect(progress).toEqual([[1, 1]])

    finishSlow()
    await vi.waitFor(() => expect(progress).toEqual([[1, 1], [2, 2]]))
  })

  it('succeeds when one relay is down', async () => {
    const down = relay('down', async () => Promise.reject(new Error('HTTP 503')))
    const progress: [number, number][] = []
    await putEverywhere([down, relay('up', async () => undefined)], item, (a, s) => progress.push([a, s]))
    await vi.waitFor(() => expect(progress.at(-1)).toEqual([1, 2]))
  })

  it('fails with the reason only when every relay failed', async () => {
    const a = relay('a', async () => Promise.reject(new Error('a is down')))
    const b = relay('b', async () => Promise.reject(new Error('b is down')))
    await expect(putEverywhere([a, b], item)).rejects.toThrow(/is down/)
    await expect(putEverywhere([], item)).rejects.toThrow(/no relay/)
  })

  it('gives up on a relay that never answers', async () => {
    vi.useFakeTimers()
    const attempt = putEverywhere([relay('silent', never)], item)
    const outcome = expect(attempt).rejects.toThrow(/silent did not answer in time/)
    await vi.advanceTimersByTimeAsync(RELAY_TIMEOUT_MS + 1)
    await outcome
  })

  it('a silent relay does not hold up one that answers', async () => {
    vi.useFakeTimers()
    await putEverywhere([relay('silent', never), relay('fast', async () => undefined)], item)
  })
})

describe('bounded', () => {
  it('passes results and errors through untouched', async () => {
    await expect(bounded(Promise.resolve(7), 'x')).resolves.toBe(7)
    await expect(bounded(Promise.reject(new Error('boom')), 'x')).rejects.toThrow('boom')
  })
})

describe('withCooldown', () => {
  it('skips a relay for a while after it fails, then tries it again', async () => {
    let clock = 0
    let calls = 0
    let down = true
    const flaky = relay('waku', async () => {
      calls++
      if (down) throw new Error('no peers')
    })
    const guarded = withCooldown(flaky, 60_000, () => clock)

    await expect(guarded.put(item)).rejects.toThrow('no peers')
    await expect(guarded.put(item)).rejects.toThrow('skipped for 1 more min after failing (no peers)')
    expect(calls).toBe(1)

    clock = 60_001
    down = false
    await guarded.put(item)
    expect(calls).toBe(2)
    await guarded.put(item)
    expect(calls).toBe(3)
  })

  it('counts a relay that never answers as failed', async () => {
    vi.useFakeTimers()
    const guarded = withCooldown(relay('silent', never), 60_000, () => 0)
    const first = expect(guarded.put(item)).rejects.toThrow(/silent did not answer in time/)
    await vi.advanceTimersByTimeAsync(RELAY_TIMEOUT_MS + 1)
    await first
    await expect(guarded.put(item)).rejects.toThrow(/skipped/)
  })
})
