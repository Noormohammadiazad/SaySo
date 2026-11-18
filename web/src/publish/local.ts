import { hash, toHex } from '../core'
import { timedFetch } from '../net'
import { Conflict, type Publisher } from './index'

/** The stand-in served by `vite dev`: a plain directory, no history. */
export class LocalPublisher implements Publisher {
  constructor(private readonly base: string) {}

  private call(path: string, init: RequestInit = {}): Promise<Response> {
    return timedFetch('the local data stand-in', this.base + path, { cache: 'no-store', ...init })
  }

  async get(path: string): Promise<Uint8Array | undefined> {
    const res = await this.call(path)
    return res.ok ? new Uint8Array(await res.arrayBuffer()) : undefined
  }

  async put(path: string, bytes: Uint8Array): Promise<void> {
    const res = await this.call(path, { method: 'PUT', body: bytes as Uint8Array<ArrayBuffer> })
    if (!res.ok) throw new Error(`could not write ${path}: HTTP ${res.status}`)
  }

  async remove(path: string): Promise<void> {
    await this.call(path, { method: 'DELETE' })
  }

  async read(path: string): Promise<{ bytes: Uint8Array; version: string } | undefined> {
    const bytes = await this.get(path)
    return bytes && { bytes, version: toHex(hash(bytes)) }
  }

  /** The stand-in has no compare-and-swap; checking first is close enough for one machine. */
  async write(path: string, bytes: Uint8Array, version: string | undefined): Promise<void> {
    const current = await this.read(path)
    if (current?.version !== version) throw new Conflict(path)
    await this.put(path, bytes)
  }

  async list(prefix: string): Promise<string[]> {
    const res = await this.call('?list')
    return res.ok ? ((await res.json()) as string[]).filter((path) => path.startsWith(prefix)) : []
  }

  async settled(): Promise<void> {
    // The stand-in serves files straight from disk; nothing to wait for.
  }
}
