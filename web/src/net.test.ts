import { afterEach, describe, expect, it, vi } from 'vitest'
import { backoff, causeOf, isAbort, NetworkError, timed, timedFetch } from './net'

afterEach(() => vi.useRealTimers())

/** A fetch that answers headers at once and then never sends the body. */
const stallingBody: typeof fetch = async (_input, init) =>
  new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]))
        init?.signal?.addEventListener('abort', () => controller.error(new DOMException('aborted', 'AbortError')))
      },
    }),
  )

/** A fetch that never answers at all, but honours its signal like a browser. */
const hanging: typeof fetch = (_input, init) =>
  new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')))
  })

describe('timedFetch', () => {
  it('returns the response with its body already read', async () => {
    const res = await timedFetch('x', 'https://x.test/', {}, { fetcher: async () => new Response('hello', { status: 201 }) })
    expect(res.status).toBe(201)
    expect(await res.text()).toBe('hello')
  })

  it('turns a server that never answers into a NetworkError naming the server', async () => {
    vi.useFakeTimers()
    const pending = timedFetch('GitHub', 'https://api.github.com/', {}, { timeoutMs: 5_000, fetcher: hanging })
    const outcome = expect(pending).rejects.toThrow('GitHub did not answer within 5 s')
    await vi.advanceTimersByTimeAsync(5_001)
    await outcome
    await pending.catch((err) => {
      expect(err).toBeInstanceOf(NetworkError)
      // The browser's bare "The operation was aborted." never reaches the caller.
      expect(isAbort(err)).toBe(false)
    })
  })

  it('times out a body that stops halfway, not just slow headers', async () => {
    vi.useFakeTimers()
    const pending = timedFetch('the relay', 'https://relay.test/', {}, { timeoutMs: 1_000, fetcher: stallingBody })
    const outcome = expect(pending).rejects.toThrow('the relay did not answer within 1 s')
    await vi.advanceTimersByTimeAsync(1_001)
    await outcome
  })

  it('describes a connection that was cut or refused', async () => {
    const cut: typeof fetch = async () => {
      throw new DOMException('The operation was aborted.', 'AbortError')
    }
    await expect(timedFetch('ntfy.sh', 'https://ntfy.sh/', {}, { fetcher: cut })).rejects.toThrow(
      'ntfy.sh could not be reached (the connection was cut)',
    )
    const refused: typeof fetch = async () => {
      throw new TypeError('Failed to fetch')
    }
    await expect(timedFetch('ntfy.sh', 'https://ntfy.sh/', {}, { fetcher: refused })).rejects.toThrow(
      'ntfy.sh could not be reached (Failed to fetch)',
    )
  })

  it('handles answers that have no body', async () => {
    const res = await timedFetch('x', 'https://x.test/', {}, { fetcher: async () => new Response(null, { status: 204 }) })
    expect(res.status).toBe(204)
  })

  it('lets the caller cancel', async () => {
    const controller = new AbortController()
    const pending = timedFetch('x', 'https://x.test/', { signal: controller.signal }, { fetcher: hanging })
    controller.abort()
    await expect(pending).rejects.toSatisfy(isAbort)
  })

  it('timed() wraps a fetcher once for every call', async () => {
    vi.useFakeTimers()
    const http = timed('GitHub', { timeoutMs: 100, fetcher: hanging })
    const outcome = expect(http('https://api.github.com/a')).rejects.toThrow(/GitHub did not answer/)
    await vi.advanceTimersByTimeAsync(101)
    await outcome
  })
})

describe('helpers', () => {
  it('recognise aborts by name, from any realm', () => {
    expect(isAbort(new DOMException('x', 'AbortError'))).toBe(true)
    expect(isAbort(new DOMException('x', 'TimeoutError'))).toBe(true)
    expect(isAbort({ name: 'AbortError' })).toBe(true)
    expect(isAbort(new Error('x'))).toBe(false)
    expect(isAbort(undefined)).toBe(false)
  })

  it('give a cause for anything thrown', () => {
    expect(causeOf(new Error('boom'))).toBe('boom')
    expect(causeOf('plain')).toBe('plain')
    expect(causeOf(undefined)).toBe('unknown error')
  })

  it('back off up to a minute', () => {
    expect([0, 1, 2, 3, 10].map((n) => backoff(n))).toEqual([2_000, 4_000, 8_000, 16_000, 60_000])
  })
})
