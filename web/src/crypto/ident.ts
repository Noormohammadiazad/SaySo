// The light half of the core: what the first screen needs to check who the
// owner is (an Ed25519 signature and a fingerprint) without loading the
// post-quantum KEM or the ciphers. Everything else is in ./index.
import { ed25519 } from '@noble/curves/ed25519.js'
import { ascii, badKey, badSignature, concat, kdf, toHex, type Bytes } from './prims'

export const ID_LEN = 32
export const SIG_LEN = 64

/**
 * Strict Ed25519 verification, as ed25519-dalek's `verify_strict`: canonical
 * encodings only, and no small-order key or commitment.
 */
export function verify(publicKey: Bytes, message: Bytes, sig: Bytes): void {
  let point: ReturnType<typeof ed25519.Point.fromBytes>
  try {
    point = ed25519.Point.fromBytes(publicKey)
  } catch {
    throw badKey()
  }
  let ok = false
  try {
    const commitment = ed25519.Point.fromBytes(sig.subarray(0, 32))
    ok =
      sig.length === SIG_LEN &&
      !point.isSmallOrder() &&
      !commitment.isSmallOrder() &&
      ed25519.verify(sig, message, publicKey, { zip215: false })
  } catch {
    ok = false
  }
  if (!ok) throw badSignature()
}

/** Eight groups of four hex digits, for people to compare out of band. */
export function fingerprint(identity: Bytes): string {
  return toHex(kdf('sayso/v1/fingerprint', identity).subarray(0, 16)).match(/.{4}/g)!.join(' ')
}

/** The id an iroh endpoint started with `secret` has: its Ed25519 public key in hex. */
export const endpointIdFor = (secret: Bytes): string => toHex(ed25519.getPublicKey(secret))

/** Verify a signature over owner.json's body bytes. */
export function verifyDoc(key: Bytes, body: Bytes, sig: Bytes): boolean {
  try {
    verify(key, concat(ascii('sayso/v1/doc/owner'), body), sig)
    return true
  } catch {
    return false
  }
}
