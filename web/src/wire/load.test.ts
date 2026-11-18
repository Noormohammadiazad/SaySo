import { createHash, randomBytes } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { LoadError, loadWasmBytes, type WasmParts } from './load'

/** A stand-in module: random bytes compress poorly, like a real one, more or less. */
function build(size = 200_000, partSize = 16_384) {
  const module = new Uint8Array(randomBytes(size))
  const gz = gzipSync(module, { level: 9 })
  const parts: WasmParts = { size, sha256: createHash('sha256').update(module).digest('hex'), parts: [] }
  const files = new Map<string, Uint8Array>()
  for (let at = 0, i = 0; at < gz.length; at += partSize, i++) {
    const bytes = new Uint8Array(gz.subarray(at, at + partSize))
    files.set(`part-${i}.bin`, bytes)
    parts.parts.push({ name: `part-${i}.bin`, size: bytes.length })
  }
  files.set('whole.wasm', module)
  return { module, parts, files }
}

type Behaviour = 'ok' | 'stall' | 'truncate' | 'abort' | 'missing' | 'garble'

/**
 * A server that misbehaves on purpose. `plan(name, attempt)` decides what
 * the n-th request for a file gets.
 */
function server(files: Map<string, Uint8Array>, plan: (name: string, attempt: number) => Behaviour) {
  const requests = new Map<string, number>()
  const fetcher: typeof fetch = async (input, init) => {
    const name = String(input)
    const attempt = requests.get(name) ?? 0
    requests.set(name, attempt + 1)
    const bytes = files.get(name)
    const behaviour = bytes ? plan(name, attempt) : 'missing'
    if (behaviour === 'missing') return new Response('not found', { status: 404 })
    if (behaviour === 'abort') throw new DOMException('The operation was aborted.', 'AbortError')
    const body = behaviour === 'truncate' ? bytes!.subarray(0, bytes!.length >> 1) : bytes!
    // Past the 10-byte gzip header, inside the compressed data.
    const sent = behaviour === 'garble' ? body.map((b, i) => (i === 5_000 ? b ^ 1 : b)) : body
    return new Response(
      new ReadableStream({
        start(controller) {
          if (behaviour === 'stall') {
            // Some bytes, then silence, like the links this exists for.
            controller.enqueue(sent.slice(0, 1000))
            init?.signal?.addEventListener('abort', () =>
              controller.error(new DOMException('The operation was aborted.', 'AbortError')),
            )
            return
          }
          controller.enqueue(sent.slice(0, sent.length >> 1))
          controller.enqueue(sent.slice(sent.length >> 1))
          controller.close()
        },
      }),
    )
  }
  return { fetcher, requests }
}

/** The Cache API, in memory. */
function memoryCaches() {
  const stores = new Map<string, Map<string, Response>>()
  const open = async (name: string) => {
    if (!stores.has(name)) stores.set(name, new Map())
    const store = stores.get(name)!
    return {
      match: async (key: string) => store.get(key)?.clone(),
      put: async (key: string, res: Response) => void store.set(key, res),
      delete: async (key: string | Request) => store.delete(typeof key === 'string' ? key : key.url),
      keys: async () => [...store.keys()].map((url) => new Request(url)),
    }
  }
  return { caches: { open } as unknown as CacheStorage, stores }
}

const quick = { stallMs: 50, firstByteMs: 50, attempts: 4 }

describe('loadWasmBytes', () => {
  it('assembles the parts, checks them and reports progress up to 1', async () => {
    const { module, parts, files } = build()
    const { fetcher } = server(files, () => 'ok')
    const progress: (number | undefined)[] = []
    const bytes = await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, onProgress: (p) => progress.push(p), ...quick })
    expect(bytes).toEqual(module)
    expect(progress[0]).toBe(0)
    expect(progress.at(-1)).toBe(1)
    const numbers = progress as number[]
    expect(numbers.every((p, i) => i === 0 || p >= numbers[i - 1])).toBe(true)
  })

  it('abandons a part that stalls and asks for it again', async () => {
    const { module, parts, files } = build()
    // Every part stalls on its first try, as a fresh connection on a bad link often does.
    const { fetcher, requests } = server(files, (_name, attempt) => (attempt === 0 ? 'stall' : 'ok'))
    const started = Date.now()
    const bytes = await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, ...quick })
    expect(bytes).toEqual(module)
    expect([...requests.values()].every((n) => n === 2)).toBe(true)
    expect(Date.now() - started).toBeLessThan(5_000)
  })

  it('retries parts that come back cut short or aborted', async () => {
    const { module, parts, files } = build()
    const { fetcher } = server(files, (name, attempt) =>
      attempt === 0 ? (name.endsWith('0.bin') ? 'truncate' : name.endsWith('1.bin') ? 'abort' : 'ok') : 'ok',
    )
    expect(await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, ...quick })).toEqual(module)
  })

  it('progress never runs backwards when a try is thrown away', async () => {
    const { parts, files } = build()
    const { fetcher } = server(files, (_name, attempt) => (attempt === 0 ? 'stall' : 'ok'))
    const progress: number[] = []
    await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, onProgress: (p) => progress.push(p ?? -1), ...quick })
    expect(progress.every((p, i) => i === 0 || p >= progress[i - 1])).toBe(true)
    expect(progress.at(-1)).toBe(1)
  })

  it('gives up with the cause after the last try, without the bare abort message', async () => {
    const { parts, files } = build()
    const { fetcher } = server(files, () => 'abort')
    const outcome = loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, ...quick })
    await expect(outcome).rejects.toBeInstanceOf(LoadError)
    await expect(outcome).rejects.toThrow(/tried 4 times/)
  })

  it('refuses a module that arrives damaged, after trying once more', async () => {
    const { parts, files } = build()
    const { fetcher, requests } = server(files, (name) => (name === 'part-0.bin' ? 'garble' : 'ok'))
    const outcome = loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, ...quick })
    await expect(outcome).rejects.toBeInstanceOf(LoadError)
    await expect(outcome).rejects.toThrow('the downloaded module is damaged: it does not match its checksum')
    expect(requests.get('part-0.bin')).toBe(2)
  })

  it('recovers when a part is damaged once and fine the second time', async () => {
    const { module, parts, files } = build()
    const { fetcher } = server(files, (name, attempt) => (name === 'part-1.bin' && attempt === 0 ? 'garble' : 'ok'))
    expect(await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, ...quick })).toEqual(module)
  })

  it('a second visit comes from the cache, with no request at all', async () => {
    const { module, parts, files } = build()
    const { caches } = memoryCaches()
    const first = server(files, () => 'ok')
    await loadWasmBytes(parts, 'whole.wasm', { fetcher: first.fetcher, cache: caches, ...quick })

    const second = server(files, () => 'missing')
    const progress: (number | undefined)[] = []
    const bytes = await loadWasmBytes(parts, 'whole.wasm', { fetcher: second.fetcher, cache: caches, onProgress: (p) => progress.push(p), ...quick })
    expect(bytes).toEqual(module)
    expect(second.requests.size).toBe(0)
    expect(progress).toEqual([1])
  })

  it('a damaged cache entry is thrown away and downloaded again', async () => {
    const { module, parts, files } = build()
    const { caches, stores } = memoryCaches()
    await loadWasmBytes(parts, 'whole.wasm', { fetcher: server(files, () => 'ok').fetcher, cache: caches, ...quick })
    const store = stores.get('sayso-wasm')!
    const [key] = [...store.keys()]
    store.set(key, new Response(new Uint8Array([0, 97, 115, 109])))

    const again = server(files, () => 'ok')
    expect(await loadWasmBytes(parts, 'whole.wasm', { fetcher: again.fetcher, cache: caches, ...quick })).toEqual(module)
    expect(again.requests.size).toBe(parts.parts.length)
  })

  it('an older version in the cache is replaced, not kept beside the new one', async () => {
    const { caches, stores } = memoryCaches()
    const old = build(50_000)
    await loadWasmBytes(old.parts, 'whole.wasm', { fetcher: server(old.files, () => 'ok').fetcher, cache: caches, ...quick })
    const fresh = build(60_000)
    await loadWasmBytes(fresh.parts, 'whole.wasm', { fetcher: server(fresh.files, () => 'ok').fetcher, cache: caches, ...quick })
    expect([...stores.get('sayso-wasm')!.keys()]).toEqual([`https://sayso.invalid/wasm/${fresh.parts.sha256}`])
  })

  it('a cache that refuses to open is no reason to fail', async () => {
    const { module, parts, files } = build()
    const broken = { open: async () => Promise.reject(new DOMException('denied', 'SecurityError')) } as unknown as CacheStorage
    expect(await loadWasmBytes(parts, 'whole.wasm', { fetcher: server(files, () => 'ok').fetcher, cache: broken, ...quick })).toEqual(
      module,
    )
  })

  it('without parts (development) the whole file is fetched, with the same stall rule', async () => {
    const { module, files } = build()
    const { fetcher, requests } = server(files, (_name, attempt) => (attempt === 0 ? 'stall' : 'ok'))
    const progress: (number | undefined)[] = []
    expect(await loadWasmBytes(null, 'whole.wasm', { fetcher, cache: null, onProgress: (p) => progress.push(p), ...quick })).toEqual(module)
    expect(requests.get('whole.wasm')).toBe(2)
    // The size is unknown here, so progress only ever says "working".
    expect(progress.every((p) => p === undefined)).toBe(true)
  })
})

describe('loadWasmBytes on a link that keeps freezing', () => {
  it('is never cut off while parts keep arriving, however long it takes', async () => {
    const { module, parts, files } = build(200_000, 8_192)
    // Every part stalls twice: far longer in total than the idle limit, but
    // something arrives well within every stretch of it.
    const { fetcher } = server(files, (_name, attempt) => (attempt < 2 ? 'stall' : 'ok'))
    const started = Date.now()
    const bytes = await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, stallMs: 30, firstByteMs: 30, idleMs: 200, concurrency: 1 })
    expect(bytes).toEqual(module)
    expect(Date.now() - started).toBeGreaterThan(200)
  })

  it('keeps going past any fixed number of tries until the deadline', async () => {
    const { module, parts, files } = build()
    // Part 0 stalls nine times before it gets through.
    const { fetcher, requests } = server(files, (name, attempt) => (name === 'part-0.bin' && attempt < 9 ? 'stall' : 'ok'))
    const bytes = await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, stallMs: 20, firstByteMs: 20, idleMs: 60_000 })
    expect(bytes).toEqual(module)
    expect(requests.get('part-0.bin')).toBe(10)
  })

  it('gives up once nothing has arrived for a while, saying how often it tried', async () => {
    const { parts, files } = build()
    const { fetcher } = server(files, () => 'stall')
    const started = Date.now()
    const outcome = loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, stallMs: 20, firstByteMs: 20, idleMs: 300 })
    await expect(outcome).rejects.toBeInstanceOf(LoadError)
    await expect(outcome).rejects.toThrow(/the data stopped for 0 s \(tried \d+ times\)/)
    expect(Date.now() - started).toBeLessThan(5_000)
  })

  it('alternates connection pools between tries and counts the stalls', async () => {
    const { parts, files } = build(40_000)
    const pools: (RequestCredentials | undefined)[] = []
    const inner = server(files, (_name, attempt) => (attempt < 2 ? 'stall' : 'ok'))
    const fetcher: typeof fetch = (input, init) => {
      if (String(input) === 'part-0.bin') pools.push(init?.credentials)
      return inner.fetcher(input, init)
    }
    const stalls: number[] = []
    await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, stallMs: 20, firstByteMs: 20, onProgress: (_p, n) => stalls.push(n) })
    expect(pools).toEqual(['same-origin', 'omit', 'same-origin'])
    expect(Math.max(...stalls)).toBe(2 * parts.parts.length)
  })
})

describe('loadWasmBytes and a slow first byte', () => {
  /** Answers after `delayMs`, then sends everything at once: what the throttled link did. */
  function slowStart(files: Map<string, Uint8Array>, delayMs: number): { fetcher: typeof fetch; requests: () => number } {
    let count = 0
    const fetcher: typeof fetch = async (input, init) => {
      count++
      const bytes = files.get(String(input))!
      return new Response(
        new ReadableStream({
          start(controller) {
            const timer = setTimeout(() => {
              controller.enqueue(bytes)
              controller.close()
            }, delayMs)
            init?.signal?.addEventListener('abort', () => {
              clearTimeout(timer)
              controller.error(new DOMException('aborted', 'AbortError'))
            })
          },
        }),
      )
    }
    return { fetcher, requests: () => count }
  }

  it('waits out a first byte slower than the stall limit instead of abandoning it', async () => {
    const { module, parts, files } = build(60_000)
    const { fetcher, requests } = slowStart(files, 120)
    const bytes = await loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, stallMs: 30, firstByteMs: 1_000 })
    expect(bytes).toEqual(module)
    expect(requests()).toBe(parts.parts.length)
  })

  it('still abandons a request whose first byte never comes', async () => {
    const { parts, files } = build(20_000)
    const { fetcher } = slowStart(files, 60_000)
    await expect(
      loadWasmBytes(parts, 'whole.wasm', { fetcher, cache: null, stallMs: 10, firstByteMs: 40, attempts: 2 }),
    ).rejects.toThrow('nothing arrived for 0 s (tried 2 times)')
  })
})
