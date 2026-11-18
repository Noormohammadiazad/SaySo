// The buffer lane: public store-and-forward networks that hold a sealed
// envelope while the owner is away (spec section 11).
//
// Anyone can write to a buffer, so what comes out of one is untrusted; the
// reader applies `bufferCheck` from the core before keeping anything.
import { bufferTopic } from '../crypto/buffer'
import { causeOf } from '../net'
import type { BufferSpec } from '../data/docs'
import { NtfyBuffer } from './ntfy'

export interface Buffer {
  /** Stable name: labels this buffer's cursor and its errors. */
  readonly id: string
  /** Leave one item (stamp followed by envelope) for the owner. */
  put(item: Uint8Array): Promise<void>
  /**
   * Hand every item newer than `cursor` to `onItem`, in any order and
   * possibly more than once. Returns the cursor for the next call.
   */
  drain(cursor: string | undefined, onItem: (item: Uint8Array) => Promise<void>): Promise<string | undefined>
}

/** The buffers an owner listed in their manifest, addressed for that owner. */
export function openBuffers(specs: BufferSpec[] | undefined, oik: Uint8Array): Buffer[] {
  const topic = bufferTopic(oik)
  const out: Buffer[] = []
  for (const spec of specs ?? []) {
    if (spec.kind === 'ntfy' && spec.url) out.push(withCooldown(new NtfyBuffer(spec.url, topic)))
    else if (spec.kind === 'waku') out.push(withCooldown(lazyWaku(topic)))
    // An unknown kind is a buffer this version cannot use; skip it.
  }
  return out
}

/** How long a relay that failed is left alone before it is tried again. */
export const COOLDOWN_MS = 10 * 60_000

/**
 * A relay that, once it fails or stalls, is skipped for a while: every call
 * in that time fails at once instead of waiting out the same timeout again.
 */
export function withCooldown(buffer: Buffer, cooldownMs = COOLDOWN_MS, now: () => number = Date.now): Buffer {
  let failedAt: number | undefined
  let cause = ''
  const guard = async <T>(work: () => Promise<T>): Promise<T> => {
    if (failedAt !== undefined && now() - failedAt < cooldownMs) {
      const minutes = Math.ceil((cooldownMs - (now() - failedAt)) / 60_000)
      throw new Error(`skipped for ${minutes} more min after failing (${cause})`)
    }
    try {
      const value = await bounded(work(), buffer.id)
      failedAt = undefined
      return value
    } catch (err) {
      failedAt = now()
      cause = causeOf(err)
      throw err
    }
  }
  return {
    id: buffer.id,
    put: (item) => guard(() => buffer.put(item)),
    drain: (cursor, onItem) => guard(() => buffer.drain(cursor, onItem)),
  }
}

/** How long one relay may take before it counts as unreachable. */
export const RELAY_TIMEOUT_MS = 30_000

/** Reject if `work` has not settled within the relay timeout. */
export function bounded<T>(work: Promise<T>, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} did not answer in time`)), RELAY_TIMEOUT_MS)
    work.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (err) => {
        clearTimeout(timer)
        reject(err)
      },
    )
  })
}

/**
 * Leave an item in every buffer at once. Resolves as soon as one accepts it,
 * so a slow relay does not hold the sender up, and rejects only if none
 * does. `onProgress` reports how many have accepted, and how many are done
 * either way, as the others finish in the background.
 */
export function putEverywhere(
  buffers: Buffer[],
  item: Uint8Array,
  onProgress?: (accepted: number, settled: number) => void,
): Promise<void> {
  if (buffers.length === 0) return Promise.reject(new Error('no relay is configured'))
  return new Promise((resolve, reject) => {
    let accepted = 0
    let settled = 0
    let lastError: unknown
    // Progress is reported before the caller is released, so by the time the
    // send counts as done the caller has already been told on how many relays.
    const done = (ok: boolean, err?: unknown): void => {
      if (ok) accepted++
      else lastError = err
      settled++
      onProgress?.(accepted, settled)
      if (ok) resolve()
      else if (settled === buffers.length && accepted === 0) {
        reject(lastError instanceof Error ? lastError : new Error(String(lastError)))
      }
    }
    for (const buffer of buffers) {
      bounded(buffer.put(item), buffer.id).then(
        () => done(true),
        (err) => done(false, err),
      )
    }
  })
}

/** The Waku relay, its code (and the SDK behind it) loaded only when first used. */
function lazyWaku(topic: string): Buffer {
  let made: Promise<Buffer> | undefined
  const load = (): Promise<Buffer> => (made ??= import('./waku').then(({ WakuBuffer }) => new WakuBuffer(topic)))
  return {
    id: 'waku',
    put: async (item) => (await load()).put(item),
    drain: async (cursor, onItem) => (await load()).drain(cursor, onItem),
  }
}
