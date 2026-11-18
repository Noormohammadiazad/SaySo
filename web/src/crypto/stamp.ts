// Stamps (spec section 7): proof of work a receiver can demand before it
// stores anything.
import { kdfFor, type Bytes } from './prims'

export const STAMP_LEN = 10
export const ALG_BLAKE3 = 1
export const MAX_BITS = 40

let derive: ((...parts: Bytes[]) => Bytes) | undefined

function zeroBits(eid: Bytes, nonce: Bytes): number {
  derive ??= kdfFor('sayso/v1/stamp')
  const d = derive(eid, nonce)
  const hi = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0
  if (hi) return Math.clz32(hi)
  const lo = ((d[4] << 24) | (d[5] << 16) | (d[6] << 8) | d[7]) >>> 0
  return 32 + Math.clz32(lo)
}

function setNonce(out: Bytes, nonce: number): void {
  const view = new DataView(out.buffer, out.byteOffset, 8)
  view.setUint32(0, Math.floor(nonce / 2 ** 32))
  view.setUint32(4, nonce >>> 0)
}

export function encodeStamp(bits: number, nonce: number): Bytes {
  const out = new Uint8Array(STAMP_LEN)
  out[0] = ALG_BLAKE3
  out[1] = bits
  setNonce(out.subarray(2), nonce)
  return out
}

/**
 * Try `attempts` nonces from `start`. Returns the 10-byte stamp, or
 * `undefined` to continue from `start + attempts`.
 */
export function stampSearch(eid: Bytes, bits: number, start: number, attempts: number): Bytes | undefined {
  if (bits > MAX_BITS) throw new Error('invalid stamp difficulty')
  const nonce = new Uint8Array(8)
  for (let n = start; n < start + attempts; n++) {
    setNonce(nonce, n)
    if (zeroBits(eid, nonce) >= bits) return encodeStamp(bits, n)
  }
  return undefined
}

/** Is `stamp` valid for `eid` and at least as strong as `required`? */
export function stampVerify(eid: Bytes, stamp: Bytes, required: number): boolean {
  if (eid.length !== 32 || stamp.length !== STAMP_LEN || stamp[0] !== ALG_BLAKE3) return false
  const bits = stamp[1]
  return bits >= required && zeroBits(eid, stamp.subarray(2)) >= bits
}
