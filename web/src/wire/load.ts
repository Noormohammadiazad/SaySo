// Fetching the WebAssembly core over a network that stalls.
//
// On some links a large download stops partway and sits there, while a
// fresh request for the same file finishes in a second. So the module is
// built as a gzip stream cut into small parts (see `wasmParts` in
// vite.config.ts). Each part is fetched on its own; a part that stops moving
// is abandoned and asked for again. The reassembled module is checked
// against its SHA-256 and kept in the Cache API, so the next visit needs no
// network at all. Every piece of that is optional: without parts, without
// DecompressionStream or without a cache, it still loads, just less
// resiliently.

export interface WasmPart {
  /** File name, next to the script that loads it. */
  name: string
  size: number
}

export interface WasmParts {
  /** Size of the module itself. */
  size: number
  /** SHA-256 of the module, hex. */
  sha256: string
  /** The gzip stream of the module, cut in order. */
  parts: WasmPart[]
}

export interface LoadOptions {
  fetcher?: typeof fetch
  /** Abandon a request whose data stops flowing for this long. */
  stallMs?: number
  /**
   * How long a request may take to deliver its first byte. Longer than
   * `stallMs`: on the network this was built for, nearly every request
   * waited about 10.5 s before its first byte and then arrived in full.
   */
  firstByteMs?: number
  /** Tries per part before giving up. Unlimited by default: `idleMs` decides. */
  attempts?: number
  /**
   * Give up when no part has arrived for this long. A slow download that
   * keeps making progress is never cut off.
   */
  idleMs?: number
  /** Parts in flight at once. */
  concurrency?: number
  /**
   * 0..1 as bytes arrive; `undefined` while the total is unknown. `stalls`
   * counts requests abandoned so far, so the page can say it is struggling.
   */
  onProgress?: (fraction: number | undefined, stalls: number) => void
  /** Where a verified module is kept. `null` for none. */
  cache?: CacheStorage | null
  /** Turns a part name into the URL to fetch. */
  resolve?: (name: string) => string
}

const CACHE_NAME = 'sayso-wasm'
const cacheKey = (sha256: string): string => `https://sayso.invalid/wasm/${sha256}`

export class LoadError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LoadError'
  }
}

class Stalled extends Error {}

const wait = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

async function sha256Hex(bytes: Uint8Array): Promise<string | undefined> {
  if (!globalThis.crypto?.subtle) return undefined
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>)
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Download one file, abandoning it if nothing arrives for `stallMs`.
 * `onBytes` reports bytes as they come; a failed try reports a negative
 * correction so progress never counts bytes twice.
 */
async function download(
  url: string,
  expected: number | undefined,
  fetcher: typeof fetch,
  stallMs: number,
  onBytes: (n: number) => void,
  credentials: RequestCredentials = 'same-origin',
  firstByteMs = stallMs,
): Promise<Uint8Array> {
  const controller = new AbortController()
  let stalled: number | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  const arm = (ms: number): void => {
    clearTimeout(timer)
    timer = setTimeout(() => {
      stalled = ms
      controller.abort()
    }, ms)
  }
  let received = 0
  try {
    arm(firstByteMs)
    const res = await fetcher(url, { signal: controller.signal, credentials })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const chunks: Uint8Array[] = []
    if (res.body) {
      const reader = res.body.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        arm(stallMs)
        chunks.push(value)
        received += value.length
        onBytes(value.length)
      }
    } else {
      const whole = new Uint8Array(await res.arrayBuffer())
      chunks.push(whole)
      received = whole.length
      onBytes(whole.length)
    }
    const bytes = new Uint8Array(received)
    let at = 0
    for (const chunk of chunks) {
      bytes.set(chunk, at)
      at += chunk.length
    }
    if (expected !== undefined && bytes.length !== expected) {
      throw new Error(`got ${bytes.length} of ${expected} bytes`)
    }
    return bytes
  } catch (err) {
    onBytes(-received)
    if (stalled !== undefined) {
      throw new Stalled(received ? `the data stopped for ${Math.round(stalled / 1000)} s` : `nothing arrived for ${Math.round(stalled / 1000)} s`)
    }
    throw err
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Keep trying `work` until it succeeds, `attempts` runs out or `expired()`
 * says the whole download has stopped getting anywhere. `onFailure` hears
 * each failed try.
 */
async function withRetries<T>(
  attempts: number,
  expired: () => boolean,
  work: (attempt: number) => Promise<T>,
  onFailure: () => void = () => undefined,
): Promise<T> {
  let last: unknown
  let attempt = 0
  for (; attempt < attempts; attempt++) {
    try {
      return await work(attempt)
    } catch (err) {
      last = err
      onFailure()
      if (attempt + 1 >= attempts || expired()) break
      // A stall has already cost its wait; only quick failures (an HTTP
      // error, a refused connection) back off before the next try.
      if (!(err instanceof Stalled)) await wait(Math.min(2_000, 250 * 2 ** attempt))
    }
  }
  const cause = last instanceof Error ? last.message : String(last)
  const tries = attempt + 1
  throw new LoadError(`${cause} (tried ${tries} time${tries === 1 ? '' : 's'})`)
}

/**
 * Browsers keep requests with and without credentials on separate
 * connections. On a link that freezes connections after some data,
 * alternating between the two pools gets past a frozen one.
 */
const poolFor = (attempt: number): RequestCredentials => (attempt % 2 === 0 ? 'same-origin' : 'omit')

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as Uint8Array<ArrayBuffer>]).stream().pipeThrough(new DecompressionStream('gzip'))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

async function fromCache(cache: Cache, parts: WasmParts): Promise<Uint8Array | undefined> {
  const hit = await cache.match(cacheKey(parts.sha256))
  if (!hit) return undefined
  const bytes = new Uint8Array(await hit.arrayBuffer())
  if ((await sha256Hex(bytes)) === parts.sha256) return bytes
  await cache.delete(cacheKey(parts.sha256))
  return undefined
}

async function toCache(cache: Cache, parts: WasmParts, bytes: Uint8Array): Promise<void> {
  // Older versions are of no further use.
  for (const request of await cache.keys()) {
    if (request.url !== cacheKey(parts.sha256)) await cache.delete(request)
  }
  await cache.put(
    cacheKey(parts.sha256),
    new Response(bytes as Uint8Array<ArrayBuffer>, { headers: { 'content-type': 'application/wasm' } }),
  )
}

/**
 * The module's bytes, from the cache or the network.
 *
 * `parts` is what the build produced, or `null` in development, where the
 * single file at `wholeUrl` is fetched instead (with the same stall rule).
 */
export async function loadWasmBytes(
  parts: WasmParts | null,
  wholeUrl: string,
  options: LoadOptions = {},
): Promise<Uint8Array> {
  const {
    fetcher = (input, init) => fetch(input, init),
    stallMs = 8_000,
    firstByteMs = 30_000,
    attempts = Number.POSITIVE_INFINITY,
    idleMs = 120_000,
    // Measured on a throttled link: requests one or two at a time all got
    // through; eight at once left several hanging for minutes.
    concurrency = 2,
    onProgress,
    resolve = (name) => name,
  } = options
  const cacheStorage = options.cache === undefined ? globalThis.caches : options.cache

  // Progress is a part (or the whole file) arriving complete.
  let lastArrival = Date.now()
  const arrived_ = (): void => {
    lastArrival = Date.now()
  }
  const expired = (): boolean => Date.now() - lastArrival >= idleMs
  let stalls = 0
  const failed = (): void => {
    stalls++
  }

  const canAssemble = parts !== null && typeof DecompressionStream === 'function'
  if (!canAssemble) {
    onProgress?.(undefined, 0)
    return withRetries(
      attempts,
      expired,
      (attempt) => download(wholeUrl, undefined, fetcher, stallMs, () => undefined, poolFor(attempt), firstByteMs),
      () => {
        failed()
        onProgress?.(undefined, stalls)
      },
    )
  }

  let cache: Cache | undefined
  try {
    cache = cacheStorage ? await cacheStorage.open(CACHE_NAME) : undefined
    const cached = cache && (await fromCache(cache, parts))
    if (cached) {
      onProgress?.(1, 0)
      return cached
    }
  } catch {
    // Private windows and some embedded browsers refuse the cache; carry on without it.
    cache = undefined
  }

  const total = parts.parts.reduce((sum, part) => sum + part.size, 0)
  let arrived = 0
  let reported = 0
  const report = (n: number): void => {
    arrived += n
    // Never move backwards when a failed try is taken back out.
    reported = Math.max(reported, arrived / total)
    onProgress?.(Math.min(1, reported), stalls)
  }
  onProgress?.(0, 0)

  const fetchAll = async (): Promise<Uint8Array> => {
    const pieces: Uint8Array[] = new Array(parts.parts.length)
    let next = 0
    const worker = async (): Promise<void> => {
      while (next < parts.parts.length) {
        const index = next++
        const part = parts.parts[index]
        pieces[index] = await withRetries(
          attempts,
          expired,
          (attempt) => download(resolve(part.name), part.size, fetcher, stallMs, report, poolFor(attempt), firstByteMs),
          () => {
            failed()
            onProgress?.(Math.min(1, reported), stalls)
          },
        )
        arrived_()
      }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, parts.parts.length) }, worker))
    const gz = new Uint8Array(total)
    let at = 0
    for (const piece of pieces) {
      gz.set(piece, at)
      at += piece.length
    }
    return gunzip(gz)
  }

  // Parts that arrived whole-looking but wrong show up here, as a gzip
  // stream that will not decompress or a module with the wrong checksum.
  const assembled = async (): Promise<Uint8Array | undefined> => {
    let bytes: Uint8Array
    try {
      bytes = await fetchAll()
    } catch (err) {
      if (err instanceof LoadError) throw err
      return undefined
    }
    const digest = await sha256Hex(bytes)
    const intact = bytes.length === parts.size && (digest === undefined || digest === parts.sha256)
    return intact ? bytes : undefined
  }
  let bytes = await assembled()
  if (!bytes) {
    // Once more, from scratch.
    arrived = 0
    bytes = await assembled()
    if (!bytes) throw new LoadError('the downloaded module is damaged: it does not match its checksum')
  }

  if (cache) {
    try {
      await toCache(cache, parts, bytes)
    } catch {
      // Full or refused: next visit downloads again.
    }
  }
  return bytes
}
