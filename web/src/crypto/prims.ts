// The primitives every Sayso format is built from: BLAKE3 as KDF, MAC and
// hash, plus errors and byte helpers. The ciphers are in ./aead, so that
// what only hashes and verifies stays small. Byte-for-byte the same as
// `sayso-core`; see vectors.test.ts.
import { blake3 } from '@noble/hashes/blake3.js'

export type Bytes = Uint8Array

/** Every failure the core reports. Coarse on purpose, like the Rust `Error`. */
export class CoreError extends Error {
  readonly kind = 'core'
  constructor(message: string) {
    super(message)
    this.name = 'SaysoError'
  }
}

export const malformed = (what: string): CoreError => new CoreError(`malformed ${what}`)
export const unsupported = (what: string): CoreError => new CoreError(`unsupported ${what}`)
export const invalid = (what: string): CoreError => new CoreError(`invalid ${what}`)
export const badKey = (): CoreError => new CoreError('wrong or invalid key')
export const decryptFailed = (): CoreError => new CoreError('decryption failed')
export const badSignature = (): CoreError => new CoreError('signature does not verify')
export const wrongSigner = (): CoreError => new CoreError('signed by an unexpected key')
export const tooLarge = (): CoreError => new CoreError('too large')
export const expired = (): CoreError => new CoreError('expired')

const encoder = /* @__PURE__ */ new TextEncoder()
export const ascii = (text: string): Bytes => encoder.encode(text)

export function concat(...parts: Bytes[]): Bytes {
  let length = 0
  for (const part of parts) length += part.length
  const out = new Uint8Array(length)
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}

export const equal = (a: Bytes, b: Bytes): boolean => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

const contexts = new Map<string, Bytes>()
const contextBytes = (ctx: string): Bytes => {
  let bytes = contexts.get(ctx)
  if (!bytes) contexts.set(ctx, (bytes = ascii(ctx)))
  return bytes
}

/** `KDF(ctx, parts)`: BLAKE3 `derive_key` over the concatenated parts. */
export function kdf(ctx: string, ...parts: Bytes[]): Bytes {
  const hasher = blake3.create({ context: contextBytes(ctx) })
  for (const part of parts) hasher.update(part)
  return hasher.digest()
}

/**
 * A KDF context set up once, for hot loops (stamps): `derive(parts)` equals
 * `kdf(ctx, ...parts)`.
 */
export function kdfFor(ctx: string): (...parts: Bytes[]) => Bytes {
  const base = blake3.create({ context: contextBytes(ctx) })
  return (...parts) => {
    const hasher = base.clone()
    for (const part of parts) hasher.update(part)
    return hasher.digest()
  }
}

/** `MAC(key, parts)`: BLAKE3 keyed hash. */
export function mac(key: Bytes, ...parts: Bytes[]): Bytes {
  const hasher = blake3.create({ key })
  for (const part of parts) hasher.update(part)
  return hasher.digest()
}

/** Plain BLAKE3. */
export const hash = (bytes: Bytes): Bytes => blake3(bytes)

export const TAG_LEN = 16

export function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length)
  // getRandomValues fills at most 64 KiB per call.
  for (let at = 0; at < length; at += 65_536) crypto.getRandomValues(out.subarray(at, Math.min(length, at + 65_536)))
  return out
}

const DIGITS = '0123456789abcdef'

export function toHex(bytes: Bytes): string {
  let out = ''
  for (const byte of bytes) out += DIGITS[byte >> 4] + DIGITS[byte & 15]
  return out
}

/** Strict lower-case hex. */
export function fromHex(text: string): Bytes {
  if (text.length % 2 || !/^[0-9a-f]*$/.test(text)) throw malformed('hex')
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16)
  return out
}

export const u32be = (n: number): Bytes => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n)
  return out
}

export const u64be = (n: number | bigint): Bytes => {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, BigInt(n))
  return out
}
