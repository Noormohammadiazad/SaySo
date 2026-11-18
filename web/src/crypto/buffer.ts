// The buffer lane (spec section 11): how an envelope waits on a public
// store-and-forward network. Everything read from a buffer is untrusted;
// `bufferCheck` is the gate every reader applies.
import { b64u } from '../core/bytes'
import { envelopeId, MAX_ENVELOPE, peek } from './shape'
import { concat, invalid, kdf, malformed, toHex, tooLarge, type Bytes } from './prims'
import { STAMP_LEN, stampVerify } from './stamp'

export const MAX_ITEM = STAMP_LEN + MAX_ENVELOPE
/** Base64 characters of item data per part: under ntfy's 4096-byte limit with the header. */
export const PART_DATA = 3600
export const MAX_PARTS = Math.ceil(Math.ceil(MAX_ITEM / 3) / (PART_DATA / 4)) + 1
/** Half-received items held before the oldest is forgotten. */
export const MAX_PENDING = 256

const PART_TAG = 'S1'

/** The public name an owner's buffered items are published under. */
export const bufferTopic = (oik: Bytes): string => toHex(kdf('sayso/v1/buffer/topic', oik).subarray(0, 20))

/** The bytes that go into a buffer for one envelope: its stamp, then the envelope. */
export const bufferItem = (stamp: Bytes, envelope: Bytes): Bytes => concat(stamp, envelope)

/** Returns the envelope if `item` is a drop under a stamp of at least `requiredBits`; throws otherwise. */
export function bufferCheck(item: Bytes, requiredBits: number): Bytes {
  if (item.length > MAX_ITEM) throw tooLarge()
  if (item.length < STAMP_LEN) throw malformed('buffer item')
  const stamp = item.subarray(0, STAMP_LEN)
  const envelope = item.slice(STAMP_LEN)
  if (peek(envelope).kind !== 'drop') throw invalid('envelope kind')
  if (!stampVerify(envelopeId(envelope), stamp, requiredBits)) throw invalid('stamp')
  return envelope
}

const itemId = (item: Bytes): string => toHex(kdf('sayso/v1/buffer/item', item).subarray(0, 8))

/** Split an item into text parts of the form `S1.<id>.<index>.<count>.<data>`. */
export function bufferSplit(item: Bytes): string[] {
  if (item.length > MAX_ITEM) throw tooLarge()
  const id = itemId(item)
  const encoded = b64u.enc(item)
  const count = Math.max(1, Math.ceil(encoded.length / PART_DATA))
  const out: string[] = []
  for (let index = 0; index < count; index++) {
    out.push(`${PART_TAG}.${id}.${index}.${count}.${encoded.slice(index * PART_DATA, (index + 1) * PART_DATA)}`)
  }
  return out
}

const NUMBER = /^\+?[0-9]+$/

/** Puts items back together from parts read off a buffer, in any order. */
export class BufferAssembler {
  private readonly pending = new Map<string, { parts: (string | undefined)[]; missing: number }>()

  /** Feed one message; returns an item when this part completed it. Junk is ignored. */
  push(text: string): Bytes | undefined {
    const fields = text.split('.')
    if (fields.length < 5) return undefined
    const [tag, id, rawIndex, rawCount] = fields
    const data = fields.slice(4).join('.')
    if (tag !== PART_TAG || !/^[0-9a-fA-F]{16}$/.test(id) || !data || data.length > PART_DATA) return undefined
    if (!NUMBER.test(rawIndex) || !NUMBER.test(rawCount)) return undefined
    const index = Number(rawIndex)
    const count = Number(rawCount)
    if (count === 0 || count > MAX_PARTS || index >= count) return undefined

    let partial = this.pending.get(id)
    if (!partial) {
      if (this.pending.size >= MAX_PENDING) this.pending.delete(this.pending.keys().next().value!)
      partial = { parts: new Array(count), missing: count }
      this.pending.set(id, partial)
    }
    if (partial.parts.length !== count) return undefined
    if (partial.parts[index] === undefined) {
      partial.parts[index] = data
      partial.missing--
    }
    if (partial.missing > 0) return undefined
    this.pending.delete(id)
    let item: Bytes
    try {
      item = b64u.dec(partial.parts.join(''))
    } catch {
      return undefined
    }
    // The id is a claim made by whoever posted the parts; hold it to the bytes.
    return itemId(item) === id ? item : undefined
  }
}
