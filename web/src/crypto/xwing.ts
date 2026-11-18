// X-Wing, the hybrid KEM of suite 0x0001: ML-KEM-768 + X25519, combined with
// SHA3-256 (draft-connolly-cfrg-xwing-kem). Secret keys are 32-byte seeds;
// encapsulation is deterministic in 64 bytes of fresh randomness.
import { x25519 } from '@noble/curves/ed25519.js'
import { sha3_256, shake256 } from '@noble/hashes/sha3.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { badKey, concat, decryptFailed, type Bytes } from './prims'
import { CIPHERTEXT_LEN } from './shape'

export { CIPHERTEXT_LEN }

export const PUBLIC_LEN = 1216
export const SEED_LEN = 32
export const ENTROPY_LEN = 64

const ML_PUBLIC = 1184
const ML_CIPHERTEXT = 1088
const LABEL = /* @__PURE__ */ new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c])

const combine = (ssM: Bytes, ssX: Bytes, ctX: Bytes, pkX: Bytes): Bytes => sha3_256(concat(ssM, ssX, ctX, pkX, LABEL))

/** A decapsulation key, expanded from its seed, with its public half. */
export class XWingSecret {
  readonly public: Bytes
  private readonly mlSecret: Bytes
  private readonly xSecret: Bytes
  private readonly xPublic: Bytes

  constructor(seed: Bytes) {
    if (seed.length !== SEED_LEN) throw badKey()
    const expanded = shake256(seed, { dkLen: 96 })
    const ml = ml_kem768.keygen(expanded.subarray(0, 64))
    this.mlSecret = ml.secretKey
    this.xSecret = expanded.slice(64, 96)
    this.xPublic = x25519.getPublicKey(this.xSecret)
    this.public = concat(ml.publicKey, this.xPublic)
  }

  /**
   * Rejects X25519 shares that contribute nothing to the shared secret, so a
   * sender cannot quietly disable the classical half.
   */
  decapsulate(ciphertext: Bytes): Bytes {
    if (ciphertext.length !== CIPHERTEXT_LEN) throw decryptFailed()
    const ctX = ciphertext.subarray(ML_CIPHERTEXT)
    let ssX: Bytes
    try {
      ssX = x25519.getSharedSecret(this.xSecret, ctX)
    } catch {
      throw decryptFailed()
    }
    const ssM = ml_kem768.decapsulate(ciphertext.subarray(0, ML_CIPHERTEXT), this.mlSecret)
    return combine(ssM, ssX, ctX, this.xPublic)
  }
}

/** Encapsulate to `publicKey` with 64 bytes of fresh randomness. */
export function encapsulate(publicKey: Bytes, entropy: Bytes): { ciphertext: Bytes; shared: Bytes } {
  if (publicKey.length !== PUBLIC_LEN || entropy.length !== ENTROPY_LEN) throw badKey()
  const pkM = publicKey.subarray(0, ML_PUBLIC)
  const pkX = publicKey.subarray(ML_PUBLIC)
  let ml: { cipherText: Bytes; sharedSecret: Bytes }
  let ctX: Bytes
  let ssX: Bytes
  try {
    ml = ml_kem768.encapsulate(pkM, entropy.subarray(0, 32))
    const ekX = entropy.subarray(32, 64)
    ctX = x25519.getPublicKey(ekX)
    ssX = x25519.getSharedSecret(ekX, pkX)
  } catch {
    throw badKey()
  }
  return { ciphertext: concat(ml.cipherText, ctX), shared: combine(ml.sharedSecret, ssX, ctX, pkX) }
}
