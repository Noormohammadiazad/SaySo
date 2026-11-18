// The outer shape of an envelope: what anyone can check without a key (a
// relay, the harvest job, a receiver before it decapsulates), and its name.
// Kept apart from the sealing code so the light half of the core needs no
// KEM and no cipher.
import { ascii, kdf, malformed, TAG_LEN, unsupported, type Bytes } from './prims'

export const VERSION = 1
export const SUITE = 0x0001
export const HEADER_LEN = 20
/** X-Wing ciphertext: ML-KEM-768's 1088 bytes and an X25519 share. */
export const CIPHERTEXT_LEN = 1120
export const MIN_PADDED = 1 << 11
export const MAX_PADDED = 1 << 17
export const MAX_ENVELOPE = HEADER_LEN + CIPHERTEXT_LEN + MAX_PADDED + TAG_LEN

export const MAGIC = /* @__PURE__ */ ascii('SYSO')

export type Kind = 'drop' | 'reply'

export interface Header {
  kind: Kind
  epoch: number
  keyHint: Bytes
}

export function decodeHeader(bytes: Bytes): Header {
  if (bytes.length < HEADER_LEN) throw malformed('envelope')
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC[i]) throw malformed('envelope')
  if (bytes[4] !== VERSION) throw unsupported('envelope version')
  const kind = bytes[5] === 1 ? 'drop' : bytes[5] === 2 ? 'reply' : undefined
  if (!kind) throw unsupported('envelope kind')
  if (((bytes[6] << 8) | bytes[7]) !== SUITE) throw unsupported('suite')
  const epoch = new DataView(bytes.buffer, bytes.byteOffset + 8, 4).getUint32(0)
  return { kind, epoch, keyHint: bytes.slice(12, 20) }
}

/** `eid`: the name of an envelope in every store and on every transport. */
export const envelopeId = (envelope: Bytes): Bytes => kdf('sayso/v1/envelope/id', envelope)

const isPowerOfTwo = (n: number): boolean => n > 0 && (n & (n - 1)) === 0

/** Check that bytes have the shape of an envelope, without any key. */
export function peek(envelope: Bytes): Header {
  const header = decodeHeader(envelope)
  const padded = envelope.length - (HEADER_LEN + CIPHERTEXT_LEN + TAG_LEN)
  if (padded < MIN_PADDED || padded > MAX_PADDED || !isPowerOfTwo(padded)) throw malformed('envelope')
  return header
}
