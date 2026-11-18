// Starting up without letting the network decide whether the page works.
//
// Each step of starting is named, so when one fails the page can say which
// ("Reading the inbox failed: ...") instead of a bare browser
// message. Steps that need the network are retried until they succeed,
// with the latest problem shown; only a step that cannot work without the
// network, and failed in a way retrying cannot fix, is final.
import { backoff, causeOf, isAbort, NetworkError, sleep } from './net'

/** A step of starting up that failed, and why. */
export class StepError extends Error {
  constructor(
    readonly step: string,
    readonly reason: string,
  ) {
    super(`${step} failed: ${reason}`)
    this.name = 'StepError'
  }
}

/** Run one named step; a failure comes back as a `StepError` naming it. */
export async function step<T>(name: string, work: () => Promise<T> | T): Promise<T> {
  try {
    return await work()
  } catch (err) {
    if (err instanceof StepError) throw err
    throw new StepError(name, causeOf(err))
  }
}

/** Failures that say something about the network, not about this code. */
export const isTransient = (err: unknown): boolean =>
  err instanceof NetworkError || (err instanceof Error && err.name === 'LoadError') || isAbort(err)

export interface PersistOptions {
  /** Hears each failure, with the delay before the next try. */
  onRetry?: (problem: string, retryInMs: number) => void
  /** Stop trying when this returns true; the last failure is then thrown. */
  giveUp?: () => boolean
  wait?: (ms: number) => Promise<void>
}

/**
 * Run a step until it succeeds. Network failures wait and try again,
 * forever; any other failure is a real error and ends it.
 */
export async function persist<T>(name: string, work: () => Promise<T>, options: PersistOptions = {}): Promise<T> {
  const { onRetry, giveUp, wait = sleep } = options
  for (let attempt = 0; ; attempt++) {
    try {
      return await work()
    } catch (err) {
      if (!isTransient(err) || giveUp?.()) throw new StepError(name, causeOf(err))
      const delay = backoff(attempt)
      onRetry?.(`${name} failed: ${causeOf(err)}`, delay)
      await wait(delay)
    }
  }
}

/**
 * Keep the browser's own "aborted" errors from surfacing as uncaught: the
 * relays and the Waku network cancel requests all the time, and every place
 * that cares already handles them.
 */
export function quietAborts(target: Pick<Window, 'addEventListener'> = window): void {
  target.addEventListener('unhandledrejection', (event) => {
    if (isAbort((event as PromiseRejectionEvent).reason)) event.preventDefault()
  })
}
