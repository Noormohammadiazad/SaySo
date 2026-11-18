// Pushing bytes to a relay topic: what the dashboard does to deliver a reply
// the moment it is sealed. (Kept apart from ./live, which the sender's first
// screen loads.)
import { bufferSplit } from '../crypto/buffer'
import { timed } from '../net'

/** Publish bytes to a topic as framed parts (the buffer lane's `S1` parts). */
export async function publish(base: string, topic: string, bytes: Uint8Array, http: typeof fetch = timed(`the relay ${base}`, { timeoutMs: 20_000 })): Promise<void> {
  const url = `${base.replace(/\/+$/, '')}/${topic}`
  for (const part of bufferSplit(bytes)) {
    const res = await http(url, { method: 'POST', body: part })
    if (!res.ok) throw new Error(`the relay ${base} refused the message: HTTP ${res.status}`)
  }
}
