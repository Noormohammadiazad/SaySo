// The slice of CBOR (RFC 8949) the payload and invite formats use, encoded
// exactly as minicbor encodes them: maps with small integer keys in
// ascending order, shortest-form heads, absent options left out.

import { malformed, type Bytes } from './prims'

export type CborValue = number | bigint | string | Bytes | CborValue[] | CborMap | null
/** A map with integer keys; insertion order is the encoding order. */
export type CborMap = Map<number, CborValue>

class Writer {
  private parts: number[] = []
  head(major: number, value: number | bigint): void {
    const n = BigInt(value)
    const m = major << 5
    if (n < 24n) this.parts.push(m | Number(n))
    else if (n < 0x100n) this.parts.push(m | 24, Number(n))
    else if (n < 0x10000n) this.parts.push(m | 25, Number(n >> 8n), Number(n & 0xffn))
    else if (n < 0x100000000n) {
      this.parts.push(m | 26)
      for (let shift = 24n; shift >= 0n; shift -= 8n) this.parts.push(Number((n >> shift) & 0xffn))
    } else {
      this.parts.push(m | 27)
      for (let shift = 56n; shift >= 0n; shift -= 8n) this.parts.push(Number((n >> shift) & 0xffn))
    }
  }
  bytes(data: Bytes): void {
    for (const byte of data) this.parts.push(byte)
  }
  done(): Bytes {
    return new Uint8Array(this.parts)
  }
}

const encoder = /* @__PURE__ */ new TextEncoder()
const decoder = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: true })

function write(w: Writer, value: CborValue): void {
  if (value === null) return w.bytes(new Uint8Array([0xf6]))
  if (typeof value === 'number' || typeof value === 'bigint') {
    if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw malformed('integer')
    return w.head(0, value)
  }
  if (typeof value === 'string') {
    const data = encoder.encode(value)
    w.head(3, data.length)
    return w.bytes(data)
  }
  if (value instanceof Uint8Array) {
    w.head(2, value.length)
    return w.bytes(value)
  }
  if (Array.isArray(value)) {
    w.head(4, value.length)
    for (const item of value) write(w, item)
    return
  }
  w.head(5, value.size)
  for (const [key, item] of value) {
    w.head(0, key)
    write(w, item)
  }
}

export function encode(value: CborValue): Bytes {
  const w = new Writer()
  write(w, value)
  return w.done()
}

/** Reads one value; `position` tells how much was consumed. */
export class Reader {
  position = 0
  constructor(private readonly data: Bytes) {}

  private byte(): number {
    if (this.position >= this.data.length) throw malformed('cbor')
    return this.data[this.position++]
  }

  private head(): { major: number; value: bigint } {
    const first = this.byte()
    const major = first >> 5
    const info = first & 31
    if (info < 24) return { major, value: BigInt(info) }
    const length = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0
    // 28..30 are reserved; 31 (indefinite length) is not produced by Sayso.
    if (!length) throw malformed('cbor')
    let value = 0n
    for (let i = 0; i < length; i++) value = (value << 8n) | BigInt(this.byte())
    return { major, value }
  }

  private take(length: bigint): Bytes {
    if (length > BigInt(this.data.length - this.position)) throw malformed('cbor')
    const out = this.data.slice(this.position, this.position + Number(length))
    this.position += Number(length)
    return out
  }

  value(depth = 0): CborValue {
    if (depth > 16) throw malformed('cbor')
    const start = this.data[this.position]
    if (start === 0xf6) {
      this.position++
      return null
    }
    const { major, value } = this.head()
    switch (major) {
      case 0:
        return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value
      case 2:
        return this.take(value)
      case 3:
        try {
          return decoder.decode(this.take(value))
        } catch {
          throw malformed('cbor')
        }
      case 4: {
        if (value > BigInt(this.data.length)) throw malformed('cbor')
        const out: CborValue[] = []
        for (let i = 0n; i < value; i++) out.push(this.value(depth + 1))
        return out
      }
      case 5: {
        if (value > BigInt(this.data.length)) throw malformed('cbor')
        const out: CborMap = new Map()
        for (let i = 0n; i < value; i++) {
          const key = this.value(depth + 1)
          if (typeof key !== 'number') throw malformed('cbor')
          out.set(key, this.value(depth + 1))
        }
        return out
      }
      default:
        throw malformed('cbor')
    }
  }
}

/** Decode one value that must fill `data` exactly. */
export function decodeExact(data: Bytes, what: string): CborValue {
  const reader = new Reader(data)
  let value: CborValue
  try {
    value = reader.value()
  } catch {
    throw malformed(what)
  }
  if (reader.position !== data.length) throw malformed(what)
  return value
}

// ---- typed field access, failing as `malformed <what>` --------------------

export const asMap = (value: CborValue | undefined, what: string): CborMap => {
  if (!(value instanceof Map)) throw malformed(what)
  return value
}
export const asBytes = (value: CborValue | undefined, what: string, length?: number): Bytes => {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) throw malformed(what)
  return value
}
export const asText = (value: CborValue | undefined, what: string): string => {
  if (typeof value !== 'string') throw malformed(what)
  return value
}
/** An unsigned integer of up to 64 bits, as a number when it is a safe integer. */
export const asUint = (value: CborValue | undefined, what: string): number | bigint => {
  if (typeof value === 'number' || typeof value === 'bigint') return value
  throw malformed(what)
}
export const asArray = (value: CborValue | undefined, what: string): CborValue[] => {
  if (!Array.isArray(value)) throw malformed(what)
  return value
}
/** `undefined` for an absent key or an explicit null, as minicbor reads `Option`. */
export const optional = (map: CborMap, key: number): CborValue | undefined => {
  const value = map.get(key)
  return value === null ? undefined : value
}
