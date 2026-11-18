import { afterEach, describe, expect, it, vi } from 'vitest'
import { BufferAssembler } from '../crypto/buffer'
import { listen } from './live'
import { publish } from './publish'

/** A stand-in EventSource the test drives by hand. */
class FakeSource {
  static made: FakeSource[] = []
  onopen?: () => void
  onerror?: () => void
  closed = false
  private handlers = new Map<string, ((event: MessageEvent<string>) => void)[]>()
  constructor(readonly url: string) {
    FakeSource.made.push(this)
  }
  addEventListener(type: string, handler: (event: MessageEvent<string>) => void): void {
    this.handlers.set(type, [...(this.handlers.get(type) ?? []), handler])
  }
  emit(type: string, data: unknown): void {
    for (const handler of this.handlers.get(type) ?? []) handler({ data: JSON.stringify(data) } as MessageEvent<string>)
  }
  close(): void {
    this.closed = true
  }
}

afterEach(() => {
  FakeSource.made = []
  vi.useRealTimers()
})

describe('listen', () => {
  it('delivers messages as they come and remembers where it was', () => {
    const got: string[] = []
    const states: string[] = []
    listen('https://ntfy.example/', 'smabc', { onMessage: (text) => got.push(text), onState: (s) => states.push(s) }, {
      EventSource: FakeSource as unknown as typeof EventSource,
    })
    const [source] = FakeSource.made
    expect(source.url).toBe('https://ntfy.example/smabc/sse?since=12h')
    source.onopen?.()
    source.emit('open', { id: 'o1', event: 'open' })
    source.emit('message', { id: 'm1', time: 5, event: 'message', message: 'hello' })
    source.emit('keepalive', { id: 'k1', event: 'keepalive' })
    expect(got).toEqual(['hello'])
    expect(states).toContain('live')
  })

  it('reopens a connection that goes quiet, from the last message seen', () => {
    vi.useFakeTimers()
    const got: string[] = []
    listen('https://ntfy.example', 'syabc', { since: '100', onMessage: (text) => got.push(text) }, {
      EventSource: FakeSource as unknown as typeof EventSource,
      silenceMs: 1_000,
    })
    FakeSource.made[0].emit('message', { id: 'm7', event: 'message', message: 'one' })
    vi.advanceTimersByTime(1_001)
    expect(FakeSource.made[0].closed).toBe(true)
    vi.advanceTimersByTime(1_000)
    expect(FakeSource.made[1].url).toBe('https://ntfy.example/syabc/sse?since=m7')
  })

  it('backs off after errors and stops when closed', () => {
    vi.useFakeTimers()
    const subscription = listen('https://ntfy.example', 'syabc', { onMessage: () => undefined }, {
      EventSource: FakeSource as unknown as typeof EventSource,
    })
    FakeSource.made[0].onerror?.()
    vi.advanceTimersByTime(1_000)
    expect(FakeSource.made).toHaveLength(2)
    subscription.close()
    FakeSource.made[1].onerror?.()
    vi.advanceTimersByTime(60_000)
    expect(FakeSource.made).toHaveLength(2)
  })
})

describe('publish', () => {
  it('sends framed parts that reassemble into the bytes', async () => {
    const posted: string[] = []
    const http = (async (_url: string, init: RequestInit) => {
      posted.push(String(init.body))
      return new Response('{}')
    }) as unknown as typeof fetch
    const bytes = new Uint8Array(9000).map((_, i) => i % 251)
    await publish('https://ntfy.example', 'smabc', bytes, http)
    expect(posted.length).toBe(4)
    const assembler = new BufferAssembler()
    let out: Uint8Array | undefined
    for (const part of posted.reverse()) out = assembler.push(part) ?? out
    expect(out).toEqual(bytes)
  })
})
