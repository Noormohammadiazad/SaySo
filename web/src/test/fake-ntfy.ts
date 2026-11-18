// An in-memory ntfy server with the one rule that matters to the buffer
// lane: a message over 4096 bytes is not kept as a message.
interface Stored {
  id: string
  time: number
  event: 'message'
  topic: string
  message: string
}

export class FakeNtfy {
  readonly topics = new Map<string, Stored[]>()
  now = 1_800_000_000
  private next = 1

  /** Post a message as an outsider would, bypassing the buffer class. */
  post(topic: string, message: string): void {
    const list = this.topics.get(topic) ?? []
    this.topics.set(topic, list)
    list.push({ id: `m${this.next++}`, time: this.now, event: 'message', topic, message })
  }

  readonly fetch: typeof fetch = async (input, init = {}) => {
    const url = new URL(String(input))
    const [topic, action] = url.pathname.replace(/^\/+/, '').split('/')
    if (init.method === 'POST' && !action) {
      const message = String(init.body)
      if (new TextEncoder().encode(message).length > 4096) return new Response('{"error":"too large"}', { status: 413 })
      this.post(topic, message)
      return new Response('{}', { status: 200 })
    }
    if (action === 'json') {
      const since = Number(url.searchParams.get('since') ?? 0)
      const lines = (this.topics.get(topic) ?? []).filter((m) => m.time >= since)
      return new Response(['{"event":"open"}', ...lines.map((m) => JSON.stringify(m))].join('\n') + '\n')
    }
    return new Response('', { status: 404 })
  }
}
