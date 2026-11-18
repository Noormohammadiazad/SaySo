// Network calls that cannot hang the page.
//
// Every request the page makes goes through `timedFetch`: it has a deadline
// that covers the whole body, not just the headers, and whatever goes wrong
// comes back as a `NetworkError` that says what was being reached. Nothing
// here ever lets an `AbortError` escape with the browser's bare message.

/** Something the network did. The page may try again later. */
export class NetworkError extends Error {
  constructor(
    message: string,
    /** Status code when the server did answer. */
    readonly status?: number,
  ) {
    super(message)
    this.name = 'NetworkError'
  }
}

/** The browser's own words for a cancelled or timed-out operation. */
export function isAbort(err: unknown): boolean {
  const name = (err as { name?: unknown } | null)?.name
  return name === 'AbortError' || name === 'TimeoutError'
}

/** A short, human cause for any error, without the error type's name. */
export function causeOf(err: unknown): string {
  if (err instanceof Error && err.message) return err.message
  if (typeof err === 'string' && err) return err
  return 'unknown error'
}

const NULL_BODY = new Set([101, 103, 204, 205, 304])

export interface TimedOptions {
  /** Deadline for the whole exchange, body included. */
  timeoutMs?: number
  fetcher?: typeof fetch
}

/**
 * `fetch` with a deadline. Resolves with a Response whose body has already
 * arrived in full, so reading it afterwards cannot stall. `what` names the
 * other side in error messages ("GitHub", "the relay ntfy.sh").
 */
export async function timedFetch(
  what: string,
  input: RequestInfo | URL,
  init: RequestInit = {},
  { timeoutMs = 30_000, fetcher = fetch }: TimedOptions = {},
): Promise<Response> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  // A caller's own signal still works.
  const outer = init.signal
  if (outer) {
    if (outer.aborted) controller.abort()
    else outer.addEventListener('abort', () => controller.abort(), { once: true })
  }
  try {
    const res = await fetcher(input, { ...init, signal: controller.signal })
    const body = NULL_BODY.has(res.status) ? null : await res.arrayBuffer()
    return new Response(body, { status: res.status, statusText: res.statusText, headers: res.headers })
  } catch (err) {
    if (timedOut) throw new NetworkError(`${what} did not answer within ${Math.round(timeoutMs / 1000)} s`)
    if (outer?.aborted) throw err
    throw new NetworkError(`${what} could not be reached (${isAbort(err) ? 'the connection was cut' : causeOf(err)})`)
  } finally {
    clearTimeout(timer)
  }
}

/** A `fetch`-shaped function that applies `timedFetch` to every call. */
export function timed(what: string, options: TimedOptions = {}): typeof fetch {
  return (input, init) => timedFetch(what, input, init, options)
}

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

/** 2 s, 4 s, 8 s ... up to a minute: how long to wait before attempt `n + 1`. */
export const backoff = (attempt: number, base = 2_000, max = 60_000): number =>
  Math.min(max, base * 2 ** Math.max(0, attempt))
