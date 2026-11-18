// The plaintext inside an envelope (spec section 4, "Payload"): a CBOR map
// with integer keys, encoded exactly as `sayso-core` encodes it.
import { asArray, asBytes, asMap, asText, asUint, decodeExact, encode, optional, type CborMap, type CborValue } from './cbor'
import { FilePlan } from './file'
import { malformed, tooLarge, type Bytes } from './prims'
import { PUBLIC_LEN } from './xwing'

export const MSG_ID_LEN = 16
export const MAX_FILES = 32
export const MAX_NAME = 255
export const MAX_MIME = 127
export const MAX_CREDS = 4
export const MAX_CRED_LEN = 512
export { CTL_ACK, CTL_DELETE, CTL_PRESENCE, CTL_VERIFIED } from './controls'

export interface FileRef {
  name: string
  mime: string
  /** True size in bytes. */
  size: number
  /** Merkle root over the encrypted chunks: the file's identity. */
  root: Bytes
  key: Bytes
  paddedSize: number
}

export interface Payload {
  id: Bytes
  /** Sender clock, Unix milliseconds. */
  ts: number
  text?: string
  files?: FileRef[]
  replyTo?: Bytes
  creds?: Bytes[]
  /** 1 = presence: binds a live connection, carries no message. */
  ctl?: number
}

/** Drops only: how the owner can answer. */
export interface Hello {
  replyPk: Bytes
  tagKey: Bytes
}

export type FullPayload = Payload & { hello?: Hello }

const byteLength = (text: string): number => new TextEncoder().encode(text).length

export function validate(payload: FullPayload): void {
  if (payload.files) {
    if (payload.files.length > MAX_FILES) throw tooLarge()
    for (const file of payload.files) {
      if (byteLength(file.name) > MAX_NAME || byteLength(file.mime) > MAX_MIME) throw tooLarge()
      FilePlan.fromParts(file.size, file.paddedSize)
    }
  }
  if (payload.hello && payload.hello.replyPk.length !== PUBLIC_LEN) throw malformed('reply key')
  if (payload.creds && (payload.creds.length > MAX_CREDS || payload.creds.some((c) => c.length > MAX_CRED_LEN))) {
    throw tooLarge()
  }
}

export function encodePayload(payload: FullPayload): Bytes {
  const map: CborMap = new Map<number, CborValue>()
  map.set(1, payload.id)
  map.set(2, payload.ts)
  if (payload.text !== undefined) map.set(3, payload.text)
  if (payload.files !== undefined) {
    map.set(
      4,
      payload.files.map(
        (f) =>
          new Map<number, CborValue>([
            [1, f.name],
            [2, f.mime],
            [3, f.size],
            [4, f.root],
            [5, f.key],
            [6, f.paddedSize],
          ]),
      ),
    )
  }
  if (payload.hello !== undefined) {
    map.set(
      5,
      new Map<number, CborValue>([
        [1, payload.hello.replyPk],
        [2, payload.hello.tagKey],
      ]),
    )
  }
  if (payload.replyTo !== undefined) map.set(6, payload.replyTo)
  if (payload.creds !== undefined) map.set(7, payload.creds)
  if (payload.ctl !== undefined) map.set(8, payload.ctl)
  return encode(map)
}

/** A u64 that the page can do arithmetic on. */
const safe = (value: number | bigint): number => {
  if (typeof value === 'bigint') throw tooLarge()
  return value
}

/** Decode and check every protocol limit; the whole input must be consumed. */
export function decodePayload(bytes: Bytes): FullPayload {
  const what = 'payload'
  let payload: FullPayload
  try {
    const map = asMap(decodeExact(bytes, what), what)
    const ts = asUint(map.get(2), what)
    payload = { id: asBytes(map.get(1), what, MSG_ID_LEN), ts: typeof ts === 'bigint' ? Number(ts) : ts }
    const text = optional(map, 3)
    if (text !== undefined) payload.text = asText(text, what)
    const files = optional(map, 4)
    if (files !== undefined) {
      payload.files = asArray(files, what).map((entry) => {
        const f = asMap(entry, what)
        return {
          name: asText(f.get(1), what),
          mime: asText(f.get(2), what),
          size: safe(asUint(f.get(3), what)),
          root: asBytes(f.get(4), what, 32),
          key: asBytes(f.get(5), what, 32),
          paddedSize: safe(asUint(f.get(6), what)),
        }
      })
    }
    const hello = optional(map, 5)
    if (hello !== undefined) {
      const h = asMap(hello, what)
      payload.hello = { replyPk: asBytes(h.get(1), what), tagKey: asBytes(h.get(2), what, 32) }
    }
    const replyTo = optional(map, 6)
    if (replyTo !== undefined) payload.replyTo = asBytes(replyTo, what, MSG_ID_LEN)
    const creds = optional(map, 7)
    if (creds !== undefined) payload.creds = asArray(creds, what).map((c) => asBytes(c, what))
    const ctl = optional(map, 8)
    if (ctl !== undefined) {
      const value = asUint(ctl, what)
      if (typeof value !== 'number' || value > 255) throw malformed(what)
      payload.ctl = value
    }
  } catch (err) {
    if (err instanceof Error && err.message === 'too large') throw err
    throw malformed(what)
  }
  validate(payload)
  return payload
}
