// The key hierarchy (spec section 2).
import { ed25519 } from '@noble/curves/ed25519.js'
import { badKey, kdf, u32be, type Bytes } from './prims'
import { XWingSecret } from './xwing'

import { ID_LEN } from './ident'

export { ID_LEN, SIG_LEN } from './ident'
export const THREAD_ID_LEN = 16

/**
 * The owner's long-term keys, all derived from `root`. Epoch secrets are
 * deliberately absent: they are random, kept separately and destroyed on
 * schedule.
 */
export class OwnerKeys {
  readonly oik: Bytes
  /** Wraps records at rest: this device's archive and the key vault body. */
  readonly storeKey: Bytes
  private readonly signing: Bytes

  constructor(root: Bytes) {
    if (root.length !== 32) throw badKey()
    this.signing = kdf('sayso/v1/owner/ident', root)
    this.oik = ed25519.getPublicKey(this.signing)
    this.storeKey = kdf('sayso/v1/owner/store', root)
  }

  /** Secret key of the transport endpoint for receiver slot `slot` (0 is the dashboard). */
  static wireSecret(root: Bytes, slot: number): Bytes {
    return kdf('sayso/v1/owner/wire', root, u32be(slot))
  }

  sign(message: Bytes): Bytes {
    return ed25519.sign(message, this.signing)
  }
}

/** Everything a sender needs for one owner, derived from one 32-byte seed. */
export class SenderKeys {
  readonly sid: Bytes
  readonly reply: XWingSecret
  /** Derives the reply mailbox addresses; shared with the owner in `hello`. */
  readonly tagKey: Bytes
  /** Encrypts the sender's own history in browser storage. */
  readonly localKey: Bytes
  readonly threadId: Bytes
  private readonly signing: Bytes

  constructor(
    seed: Bytes,
    readonly oik: Bytes,
  ) {
    if (seed.length !== 32 || oik.length !== ID_LEN) throw badKey()
    this.signing = kdf('sayso/v1/sender/ident', seed, oik)
    this.sid = ed25519.getPublicKey(this.signing)
    this.reply = new XWingSecret(kdf('sayso/v1/sender/reply', seed, oik))
    this.tagKey = kdf('sayso/v1/sender/tag', seed, oik)
    this.localKey = kdf('sayso/v1/sender/local', seed, oik)
    this.threadId = threadId(this.sid, oik)
  }

  sign(message: Bytes): Bytes {
    return ed25519.sign(message, this.signing)
  }
}

/** `KeyId(pk)`: names a KEM public key without revealing it. */
export const keyId = (publicKey: Bytes): Bytes => kdf('sayso/v1/key-id', publicKey)

/** The thread between one sender identity and one owner. */
export const threadId = (sid: Bytes, oik: Bytes): Bytes => kdf('sayso/v1/thread', sid, oik).slice(0, THREAD_ID_LEN)

export { endpointIdFor, fingerprint, verify } from './ident'
