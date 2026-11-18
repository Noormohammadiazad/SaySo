import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bufferCheck,
  bufferItem,
  bufferSplit,
  bufferTopic,
  envelopeId,
  epochGenerate,
  Owner,
  randomBytes,
  Sender,
  stampSearch,
  toHex,
} from '../core'
import type { EpochKey, Opened } from '../core'
import { FakeNtfy } from '../test/fake-ntfy'
import { NtfyBuffer } from './ntfy'

const BITS = 8

interface World {
  owner: Owner
  epoch: EpochKey
  topic: string
}

function world(): World {
  const owner = new Owner(randomBytes(32))
  return { owner, epoch: epochGenerate(), topic: bufferTopic(owner.oik) }
}

/** A stamped, sealed message from a new sender. */
function item(w: World, text: string): Uint8Array {
  const sender = new Sender(randomBytes(32), w.owner.oik)
  const envelope = sender.sealDrop(7, w.epoch.public, { id: randomBytes(16), ts: Date.now(), text })
  const eid = envelopeId(envelope)
  let stamp: Uint8Array | undefined
  for (let start = 0; !stamp; start += 10_000) stamp = stampSearch(eid, BITS, start, 10_000)
  return bufferItem(stamp, envelope)
}

const same = (a: Uint8Array[], b: Uint8Array[]): boolean =>
  a.length === b.length && a.every((item, i) => toHex(item) === toHex(b[i]))

async function drained(buffer: NtfyBuffer, cursor?: string): Promise<{ items: Uint8Array[]; cursor?: string }> {
  const items: Uint8Array[] = []
  const next = await buffer.drain(cursor, async (found) => void items.push(found))
  return { items, cursor: next }
}

afterEach(() => vi.useRealTimers())

describe('NtfyBuffer', () => {
  it('carries an item through in parts and the owner can open it', async () => {
    const w = world()
    const server = new FakeNtfy()
    vi.useFakeTimers({ now: server.now * 1000 })
    const sent = item(w, 'left while you were away')

    await new NtfyBuffer('https://relay.example/', w.topic, server.fetch).put(sent)

    const stored = server.topics.get(`sy${w.topic}`)!
    expect(stored.length).toBe(2)
    expect(stored.every((m) => m.message.length <= 4096)).toBe(true)

    // A different instance, as the dashboard would be.
    const { items, cursor } = await drained(new NtfyBuffer('https://relay.example', w.topic, server.fetch))
    expect(same(items, [sent])).toBe(true)
    expect(cursor).toBe(String(server.now))
    const opened = w.owner.openDrop(w.epoch.seed, bufferCheck(items[0], BITS)) as Opened
    expect(opened.payload.text).toBe('left while you were away')
  })

  it('carries the largest message a drop can hold', async () => {
    const w = world()
    const server = new FakeNtfy()
    vi.useFakeTimers({ now: server.now * 1000 })
    const sent = item(w, 'x'.repeat(120_000))
    const buffer = new NtfyBuffer('https://relay.example', w.topic, server.fetch)
    await buffer.put(sent)
    expect(server.topics.get(`sy${w.topic}`)!.length).toBeGreaterThan(40)
    expect(same((await drained(buffer)).items, [sent])).toBe(true)
  })

  it('ignores what strangers post to the topic', async () => {
    const w = world()
    const server = new FakeNtfy()
    vi.useFakeTimers({ now: server.now * 1000 })
    const topic = `sy${w.topic}`
    const sent = item(w, 'real')
    const parts = bufferSplit(sent)

    server.post(topic, 'hello, is this thing on?')
    server.post(topic, parts[1])
    server.post(topic, 'S1.0123456789abcdef.0.1.AAAA')
    server.post(topic, parts[0])

    const { items } = await drained(new NtfyBuffer('https://relay.example', w.topic, server.fetch))
    expect(same(items, [sent])).toBe(true)
  })

  it('keeps separate inboxes on separate topics', async () => {
    const [a, b] = [world(), world()]
    const server = new FakeNtfy()
    vi.useFakeTimers({ now: server.now * 1000 })
    await new NtfyBuffer('https://relay.example', a.topic, server.fetch).put(item(a, 'for a'))
    expect((await drained(new NtfyBuffer('https://relay.example', b.topic, server.fetch))).items).toEqual([])
  })

  it('asks only for what is new, with an overlap, and never beyond retention', async () => {
    const w = world()
    const server = new FakeNtfy()
    vi.useFakeTimers({ now: server.now * 1000 })
    const asked: number[] = []
    const spy: typeof fetch = (input, init) => {
      const since = new URL(String(input)).searchParams.get('since')
      if (since) asked.push(Number(since))
      return server.fetch(input, init)
    }
    const buffer = new NtfyBuffer('https://relay.example', w.topic, spy)

    await drained(buffer)
    expect(asked.at(-1)).toBe(server.now - 12 * 3600)

    const first = item(w, 'first')
    await buffer.put(first)
    const one = await drained(buffer)
    expect(same(one.items, [first])).toBe(true)

    // Later: a new message arrives; the poll starts shortly before the cursor.
    server.now += 3600
    vi.setSystemTime(server.now * 1000)
    const second = item(w, 'second')
    await buffer.put(second)
    const two = await drained(buffer, one.cursor)
    expect(asked.at(-1)).toBe(Number(one.cursor) - 300)
    // The overlap hands `first` over again; receivers drop repeats by envelope id.
    const got = two.items.map((i) => toHex(i).slice(0, 80))
    expect(got).toContain(toHex(second).slice(0, 80))
    expect(got.length).toBeLessThanOrEqual(2)
    expect(two.cursor).toBe(String(server.now))

    // Much later, nothing older than the relay's retention is asked for.
    server.now += 40 * 3600
    vi.setSystemTime(server.now * 1000)
    await drained(buffer, two.cursor)
    expect(asked.at(-1)).toBe(server.now - 12 * 3600)
  })

  it('reports a relay that refuses or cannot be read', async () => {
    const w = world()
    const down: typeof fetch = async () => new Response('', { status: 503 })
    const buffer = new NtfyBuffer('https://relay.example', w.topic, down)
    await expect(buffer.put(item(w, 'x'))).rejects.toThrow(/HTTP 503/)
    await expect(drained(buffer)).rejects.toThrow(/HTTP 503/)
  })
})

// Against the public ntfy.sh service. Run by hand:
//   SAYSO_LIVE_NTFY=1 npx vitest run ntfy
describe.skipIf(!process.env.SAYSO_LIVE_NTFY)('NtfyBuffer against ntfy.sh', () => {
  it('stores an item and returns it', async () => {
    const w = world()
    const sent = item(w, 'live relay check')
    const buffer = new NtfyBuffer('https://ntfy.sh', w.topic)
    await buffer.put(sent)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    const { items } = await drained(new NtfyBuffer('https://ntfy.sh', w.topic))
    expect(same(items, [sent])).toBe(true)
    const opened = w.owner.openDrop(w.epoch.seed, bufferCheck(items[0], BITS)) as Opened
    expect(opened.payload.text).toBe('live relay check')
  }, 30_000)
})
