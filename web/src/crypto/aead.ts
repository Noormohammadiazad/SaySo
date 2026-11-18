// ChaCha20-Poly1305, in the two shapes the protocol uses: RFC 8439 for
// envelopes and file chunks, XChaCha20 for records kept at rest.
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { concat, decryptFailed, malformed, randomBytes, TAG_LEN, type Bytes } from './prims'

/** RFC 8439 AEAD. The caller guarantees `(key, nonce)` is never reused. */
export const seal = (key: Bytes, nonce: Bytes, aad: Bytes, msg: Bytes): Bytes =>
  chacha20poly1305(key, nonce, aad).encrypt(msg)

export function open(key: Bytes, nonce: Bytes, aad: Bytes, sealed: Bytes): Bytes {
  try {
    return chacha20poly1305(key, nonce, aad).decrypt(sealed)
  } catch {
    throw decryptFailed()
  }
}

/**
 * Encrypt a record for storage: `nonce || ciphertext` with a fresh random
 * 24-byte nonce, so a long-lived key can seal any number of records.
 */
export function wrap(key: Bytes, aad: Bytes, msg: Bytes, nonce: Bytes = randomBytes(24)): Bytes {
  return concat(nonce, xchacha20poly1305(key, nonce, aad).encrypt(msg))
}

export function unwrap(key: Bytes, aad: Bytes, wrapped: Bytes): Bytes {
  if (wrapped.length < 24 + TAG_LEN) throw malformed('wrapped record')
  try {
    return xchacha20poly1305(key, wrapped.subarray(0, 24), aad).decrypt(wrapped.subarray(24))
  } catch {
    throw decryptFailed()
  }
}
