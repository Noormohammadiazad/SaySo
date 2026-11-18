// Keeping the Live Wire receiver running, whatever the network does.
import { backoff, causeOf, sleep } from '../net'

export type ReceiverState = 'starting' | 'connecting' | 'online' | 'retrying'

/** What the supervisor needs from a receiver. */
export interface Receiver {
  /** Resolves once a relay answers; may never resolve. */
  online(): Promise<void>
  shutdown(): Promise<void>
}

export interface SuperviseOptions<T extends Receiver> {
  start: () => Promise<T>
  /** Serve requests until the receiver stops. */
  serve: (receiver: T) => Promise<void>
  /** Hears every change, with the receiver in use and the latest problem. */
  onState: (state: ReceiverState, receiver: T | undefined, problem: string | undefined) => void
  /** How long starting may take before it is abandoned and tried again. */
  startTimeoutMs?: number
  /** How long a started receiver may wait for a relay before that is reported. */
  quietMs?: number
  wait?: (ms: number) => Promise<void>
  delay?: (failures: number) => number
  /** Checked before every start; true ends the loop. For tests. */
  stop?: () => boolean
}

/**
 * Start a receiver, serve it, and when starting fails, hangs or the receiver
 * ends, wait a little longer each time and start another. Never throws.
 */
export async function supervise<T extends Receiver>(options: SuperviseOptions<T>): Promise<void> {
  const { start, serve, onState, startTimeoutMs = 60_000, quietMs = 30_000, wait = sleep, delay = backoff, stop } = options
  let failures = 0
  let problem: string | undefined
  let first = true
  while (!stop?.()) {
    onState(first ? 'starting' : 'retrying', undefined, problem)
    first = false
    let receiver: T
    try {
      receiver = await withDeadline(
        start(),
        startTimeoutMs,
        `the receiver did not start within ${Math.round(startTimeoutMs / 1000)} s`,
        // Should it start after all, nobody is using it: stop it.
        (late) => void late.shutdown().catch(() => undefined),
      )
    } catch (err) {
      problem = causeOf(err)
      onState('retrying', undefined, problem)
      await wait(delay(failures++))
      continue
    }
    failures = 0
    problem = undefined
    onState('connecting', receiver, undefined)
    let online = false
    let ended = false
    receiver.online().then(
      () => {
        if (ended) return
        online = true
        onState('online', receiver, undefined)
      },
      () => undefined,
    )
    // Bound but no relay answering is quiet otherwise: say so after a while.
    const quiet = setTimeout(() => {
      if (!online && !ended) onState('connecting', receiver, 'none of the relays has answered yet')
    }, quietMs)
    try {
      await serve(receiver)
    } catch (err) {
      problem = causeOf(err)
    } finally {
      ended = true
      clearTimeout(quiet)
    }
    problem ??= 'the receiver stopped'
  }
}

/**
 * `work`, or a rejection after `ms`. Should `work` finish after the deadline
 * anyway, `late` receives its result so it can be cleaned up.
 */
export function withDeadline<T>(work: Promise<T>, ms: number, message: string, late?: (value: T) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    let expired = false
    const timer = setTimeout(() => {
      expired = true
      reject(new Error(message))
    }, ms)
    work.then(
      (value) => {
        if (expired) return late?.(value)
        clearTimeout(timer)
        resolve(value)
      },
      (err) => {
        if (expired) return
        clearTimeout(timer)
        reject(err)
      },
    )
  })
}
