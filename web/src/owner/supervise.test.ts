import { describe, expect, it } from 'vitest'
import { supervise, withDeadline, type Receiver, type ReceiverState } from './supervise'

class FakeReceiver implements Receiver {
  shutdowns = 0
  private goOnline!: () => void
  private end!: () => void
  readonly onlineP = new Promise<void>((resolve) => (this.goOnline = resolve))
  readonly ended = new Promise<void>((resolve) => (this.end = resolve))
  constructor(readonly name: string) {}
  online() {
    return this.onlineP
  }
  async shutdown() {
    this.shutdowns++
  }
  reachRelay() {
    this.goOnline()
  }
  stop() {
    this.end()
  }
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('supervise', () => {
  it('starts again after failures, abandons a start that hangs, and settles on one that works', async () => {
    const log: [ReceiverState, string | undefined, string | undefined][] = []
    const late = new FakeReceiver('late')
    const good = new FakeReceiver('good')
    let lateResolve!: (r: FakeReceiver) => void
    const plan: (() => Promise<FakeReceiver>)[] = [
      () => Promise.reject(new Error('relay refused the connection')),
      () => Promise.reject(new DOMException('The operation was aborted.', 'AbortError')),
      () => new Promise<FakeReceiver>((resolve) => (lateResolve = resolve)),
      () => Promise.resolve(good),
    ]
    let starts = 0
    let served = 0
    const waits: number[] = []
    const run = supervise<FakeReceiver>({
      start: () => plan[starts++](),
      serve: async (receiver) => {
        served++
        await receiver.ended
      },
      onState: (state, receiver, problem) => log.push([state, receiver?.name, problem]),
      startTimeoutMs: 30,
      quietMs: 40,
      wait: async (ms) => void waits.push(ms),
      delay: (failures) => 1000 * (failures + 1),
      stop: () => starts >= plan.length && served > 0 && good === undefined,
    })

    // Let it work through the plan.
    for (let i = 0; i < 20 && starts < 4; i++) await new Promise((resolve) => setTimeout(resolve, 20))
    await tick()
    expect(starts).toBe(4)
    expect(waits).toEqual([1000, 2000, 3000])
    expect(log.slice(0, 7)).toEqual([
      ['starting', undefined, undefined],
      ['retrying', undefined, 'relay refused the connection'],
      ['retrying', undefined, 'relay refused the connection'],
      ['retrying', undefined, 'The operation was aborted.'],
      ['retrying', undefined, 'The operation was aborted.'],
      ['retrying', undefined, 'the receiver did not start within 0 s'],
      ['retrying', undefined, 'the receiver did not start within 0 s'],
    ])
    expect(log[7]).toEqual(['connecting', 'good', undefined])

    // The abandoned start finishing late is shut down, not used.
    lateResolve(late)
    await tick()
    expect(late.shutdowns).toBe(1)

    // No relay yet: after a while that is said, without a state change.
    await new Promise((resolve) => setTimeout(resolve, 60))
    expect(log.at(-1)).toEqual(['connecting', 'good', 'none of the relays has answered yet'])

    good.reachRelay()
    await tick()
    expect(log.at(-1)).toEqual(['online', 'good', undefined])
    expect(served).toBe(1)
    void run
  })

  it('starts a new receiver when the running one stops', async () => {
    const first = new FakeReceiver('first')
    const second = new FakeReceiver('second')
    const receivers = [first, second]
    const log: [ReceiverState, string | undefined, string | undefined][] = []
    let starts = 0
    const run = supervise<FakeReceiver>({
      start: async () => receivers[starts++],
      serve: (receiver) => receiver.ended,
      onState: (state, receiver, problem) => log.push([state, receiver?.name, problem]),
      quietMs: 10_000,
      wait: async () => undefined,
      stop: () => starts >= 2,
    })
    await tick()
    first.reachRelay()
    await tick()
    first.stop()
    await tick()
    await tick()
    second.stop()
    await run
    expect(log).toEqual([
      ['starting', undefined, undefined],
      ['connecting', 'first', undefined],
      ['online', 'first', undefined],
      ['retrying', undefined, 'the receiver stopped'],
      ['connecting', 'second', undefined],
    ])
    // The stopped receiver's late "online" must not be reported for the new one.
    expect(starts).toBe(2)
  })
})

describe('withDeadline', () => {
  it('rejects after the deadline and hands a late result to the clean-up', async () => {
    let resolveLate!: (value: string) => void
    const cleaned: string[] = []
    const outcome = withDeadline(new Promise<string>((resolve) => (resolveLate = resolve)), 10, 'too slow', (v) => cleaned.push(v))
    await expect(outcome).rejects.toThrow('too slow')
    resolveLate('late value')
    await tick()
    expect(cleaned).toEqual(['late value'])
  })

  it('passes a timely result and error straight through', async () => {
    await expect(withDeadline(Promise.resolve(1), 1000, 'x')).resolves.toBe(1)
    await expect(withDeadline(Promise.reject(new Error('no')), 1000, 'x')).rejects.toThrow('no')
  })
})
