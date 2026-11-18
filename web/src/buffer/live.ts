// Live delivery over ntfy: a Server-Sent Events subscription to one topic,
// so what is published there arrives in a fraction of a second, with no
// polling. The owner listens on the inbox topic; a sender listens on the
// mailbox topic of its own thread, where the owner pushes replies.
//
// The browser's EventSource reconnects by itself after an error, but not
// when a connection merely goes quiet, which some networks do for minutes.
// ntfy sends a keepalive every 45 seconds, so a subscription that hears
// nothing for longer is reopened, from the last message it saw.

export type LiveState = 'connecting' | 'live' | 'retrying'

export interface Listener {
  /** Where to start: an ntfy message id, a Unix time, or a duration such as `12h`. */
  since?: string
  onMessage(text: string, id: string, time: number): void
  onState?(state: LiveState, problem?: string): void
}

export interface Subscription {
  close(): void
}

export interface LiveOptions {
  EventSource?: typeof EventSource
  /** Reopen a subscription that has heard nothing for this long. */
  silenceMs?: number
}

/** The ntfy topic of an inbox (`sy…`) or of a thread's mailbox (`sm…`). */
export const inboxTopic = (hex: string): string => `sy${hex}`
export const threadTopic = (hex: string): string => `sm${hex}`

export function listen(base: string, topic: string, listener: Listener, options: LiveOptions = {}): Subscription {
  const Source = options.EventSource ?? globalThis.EventSource
  const silenceMs = options.silenceMs ?? 75_000
  const url = `${base.replace(/\/+$/, '')}/${topic}/sse`
  let since = listener.since ?? '12h'
  let source: EventSource | undefined
  let watchdog: ReturnType<typeof setTimeout> | undefined
  let retry: ReturnType<typeof setTimeout> | undefined
  let failures = 0
  let closed = false

  const state = (value: LiveState, problem?: string): void => listener.onState?.(value, problem)

  const quiet = (): void => {
    clearTimeout(watchdog)
    watchdog = setTimeout(() => reopen('the connection went quiet'), silenceMs)
  }

  const heard = (event: MessageEvent<string>): void => {
    quiet()
    failures = 0
    state('live')
    let parsed: { id?: string; time?: number; event?: string; message?: string }
    try {
      parsed = JSON.parse(event.data)
    } catch {
      return
    }
    if (parsed.event !== 'message' || typeof parsed.message !== 'string' || !parsed.id) return
    since = parsed.id
    listener.onMessage(parsed.message, parsed.id, parsed.time ?? 0)
  }

  const reopen = (problem: string): void => {
    source?.close()
    source = undefined
    clearTimeout(watchdog)
    if (closed) return
    state('retrying', problem)
    const delay = Math.min(30_000, 1_000 * 2 ** Math.min(failures++, 5))
    retry = setTimeout(open, delay)
  }

  function open(): void {
    if (closed) return
    state('connecting')
    const next = new Source(`${url}?since=${encodeURIComponent(since)}`)
    source = next
    next.onopen = () => {
      quiet()
      state('live')
    }
    // ntfy names its events open, keepalive and message; listen to all three.
    next.addEventListener('message', heard as EventListener)
    next.addEventListener('open', heard as EventListener)
    next.addEventListener('keepalive', heard as EventListener)
    next.onerror = () => reopen('the relay closed the connection')
    quiet()
  }

  if (Source) open()
  else state('retrying', 'this browser has no EventSource')
  return {
    close() {
      closed = true
      clearTimeout(watchdog)
      clearTimeout(retry)
      source?.close()
    },
  }
}
