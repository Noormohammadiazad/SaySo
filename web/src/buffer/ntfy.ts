import { BufferAssembler, bufferSplit } from '../crypto/buffer'
import { timed } from '../net'
import type { Buffer } from './index'

/** ntfy keeps messages for twelve hours; there is nothing older to ask for. */
const RETENTION = 12 * 3600
/**
 * Read this far back before the last message seen, so an item whose parts
 * straddle two polls is never cut in half.
 */
const OVERLAP = 300

interface NtfyLine {
  event?: string
  time?: number
  message?: string
}

/**
 * A server speaking the ntfy HTTP protocol (https://ntfy.sh or a self-hosted
 * one). Messages there are capped at 4096 bytes, so an item travels as
 * several text parts and is put back together on the way out.
 */
export class NtfyBuffer implements Buffer {
  readonly id: string
  private readonly url: string
  private readonly assembler = new BufferAssembler()
  private readonly http: typeof fetch

  constructor(base: string, topic: string, http: typeof fetch = fetch) {
    const origin = base.replace(/\/+$/, '')
    this.id = `ntfy:${origin}`
    this.http = timed(`the relay ${origin}`, { timeoutMs: 20_000, fetcher: http })
    this.url = `${origin}/sy${topic}`
  }

  async put(item: Uint8Array): Promise<void> {
    for (const part of bufferSplit(item)) {
      const res = await this.http(this.url, { method: 'POST', body: part })
      if (!res.ok) throw new Error(`${this.id} refused the message: HTTP ${res.status}`)
    }
  }

  async drain(cursor: string | undefined, onItem: (item: Uint8Array) => Promise<void>): Promise<string | undefined> {
    const now = Math.floor(Date.now() / 1000)
    const since = Math.max(now - RETENTION, Number(cursor ?? 0) - OVERLAP)
    const res = await this.http(`${this.url}/json?poll=1&since=${since}`, { cache: 'no-store' })
    if (!res.ok) throw new Error(`${this.id} could not be read: HTTP ${res.status}`)

    let latest = Number(cursor ?? 0)
    for (const line of (await res.text()).split('\n')) {
      if (!line) continue
      let parsed: NtfyLine
      try {
        parsed = JSON.parse(line) as NtfyLine
      } catch {
        continue
      }
      if (parsed.event !== 'message' || typeof parsed.message !== 'string') continue
      latest = Math.max(latest, parsed.time ?? 0)
      const item = this.assembler.push(parsed.message)
      if (item) await onItem(item)
    }
    return latest ? String(latest) : cursor
  }
}
