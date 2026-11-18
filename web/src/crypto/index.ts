// The Sayso core in TypeScript: the same formats and keys as `sayso-core`
// (checked byte for byte against its vectors), small enough to load with
// the page. Only Live Wire still needs the WebAssembly module, and the page
// fetches that when a live transfer starts.
import { peek } from './shape'
import { openDrop as openDropWith, openReply as openReplyWith, sealDrop as sealDropWith, sealReply as sealReplyWith } from './envelope'
import { mintInvite, verifyInvite, type InviteInfo } from './invite'
import { fingerprint, OwnerKeys, SenderKeys, threadId as threadIdOf } from './keys'
import { mailboxPath, mailboxTopic } from './mailbox'
import { checkVerification, mintVerification, type Verification } from './verified'
import type { Payload } from './payload'
import { unwrap, wrap } from './aead'
import { ascii, concat, randomBytes, toHex, type Bytes } from './prims'
import { XWingSecret } from './xwing'

export { envelopeId, MAX_ENVELOPE } from './envelope'
export { Epochs, type EpochState } from './epoch'
export { FileChanged, FileOpener, FilePlan, FileSealer, CHUNK, type SealedFile } from './file'
export { fingerprint, endpointIdFor, OwnerKeys, SenderKeys } from './keys'
export { mailboxAppend, mailboxPath, mailboxSplit, mailboxTopic } from './mailbox'
export { checkVerification, mintVerification, type Verification } from './verified'
export { CTL_ACK, CTL_DELETE, CTL_PRESENCE, CTL_VERIFIED } from './controls'
export { stampSearch, stampVerify } from './stamp'
export { bufferCheck, bufferItem, bufferSplit, bufferTopic, BufferAssembler } from './buffer'
export { XWingSecret } from './xwing'
export { CoreError, randomBytes, toHex, fromHex, kdf, hash, concat, equal } from './prims'
export { wrap, unwrap } from './aead'
export type { FileRef, Payload } from './payload'
export type { InviteInfo } from './invite'

/** An opened envelope, as the page uses it. */
export interface Opened {
  eid: Bytes
  signer: Bytes
  epoch: number
  threadId: Bytes
  payload: Payload
  /** Drops only: the sender's reply key and mailbox tag key. */
  replyPk?: Bytes
  tagKey?: Bytes
}

export interface EpochKey {
  seed: Bytes
  public: Bytes
}

/** `{ kind, epoch }` of anything shaped like an envelope; throws otherwise. */
export function envelopePeek(envelope: Bytes): { kind: 'drop' | 'reply'; epoch: number } {
  const { kind, epoch } = peek(envelope)
  return { kind, epoch }
}

/** A fresh epoch key: the seed is random, never derived, so deleting it destroys the key. */
export function epochGenerate(): EpochKey {
  const seed = randomBytes(32)
  return { seed, public: new XWingSecret(seed).public }
}

export { verifyDoc } from './ident'

/** The owner's keys, derived from the 32-byte root. */
export class Owner {
  readonly keys: OwnerKeys
  private readonly secrets = new Map<string, XWingSecret>()

  constructor(readonly root: Bytes) {
    this.keys = new OwnerKeys(root)
  }

  get oik(): Bytes {
    return this.keys.oik
  }

  get fingerprint(): string {
    return fingerprint(this.keys.oik)
  }

  wireSecret(slot: number): Bytes {
    return OwnerKeys.wireSecret(this.root, slot)
  }

  signDoc(body: Bytes): Bytes {
    return this.keys.sign(concat(ascii('sayso/v1/doc/owner'), body))
  }

  /** Encrypt a record for storage, bound to `label`. */
  wrap(label: string, data: Bytes): Bytes {
    return wrap(this.keys.storeKey, ascii(label), data)
  }

  unwrap(label: string, wrapped: Bytes): Bytes {
    return unwrap(this.keys.storeKey, ascii(label), wrapped)
  }

  /** Open a drop with the secret seed of the epoch it names. */
  openDrop(epochSeed: Bytes, envelope: Bytes): Opened {
    const tag = toHex(epochSeed)
    let secret = this.secrets.get(tag)
    if (!secret) this.secrets.set(tag, (secret = new XWingSecret(epochSeed)))
    const opened = openDropWith(secret, this.keys.oik, envelope)
    const { hello, ...payload } = opened.payload
    return {
      eid: opened.eid,
      signer: opened.signer,
      epoch: opened.header.epoch,
      threadId: threadIdOf(opened.signer, this.keys.oik),
      payload,
      replyPk: hello!.replyPk,
      tagKey: hello!.tagKey,
    }
  }

  /** Forget the expanded secret of a destroyed epoch. */
  forget(epochSeed: Bytes): void {
    this.secrets.delete(toHex(epochSeed))
  }

  sealReply(sid: Bytes, replyPk: Bytes, epoch: number, payload: Payload): Bytes {
    return sealReplyWith(this.keys, sid, replyPk, epoch, randomBytes(64), payload)
  }

  mintInvite(label: string, notAfter: number): Bytes {
    return mintInvite(this.keys, randomBytes(16), label, notAfter)
  }

  verifyInvite(invite: Bytes, now: number): InviteInfo {
    return verifyInvite(this.keys.oik, invite, now)
  }

  /** Vouch for the sender `sid` under `label`. */
  verifySender(sid: Bytes, label: string, now: number): Bytes {
    return mintVerification(this.keys, sid, label, now)
  }
}


/** A sender's keys towards one owner, derived from the 32-byte seed. */
export class Sender {
  readonly keys: SenderKeys

  constructor(seed: Bytes, oik: Bytes) {
    this.keys = new SenderKeys(seed, oik)
  }

  get sid(): Bytes {
    return this.keys.sid
  }

  get threadId(): Bytes {
    return this.keys.threadId
  }

  mailboxPath(epoch: number): string {
    return mailboxPath(this.keys.tagKey, epoch)
  }

  /** Where the owner pushes this thread's replies live. */
  get mailboxTopic(): string {
    return mailboxTopic(this.keys.tagKey)
  }

  /** A verification the owner sent; throws unless it is the owner's, for this sender. */
  checkVerification(credential: Bytes): Verification {
    return checkVerification(this.keys.oik, credential, this.keys.sid)
  }

  sealDrop(epoch: number, epochPublic: Bytes, payload: Payload): Bytes {
    return sealDropWith(this.keys, epoch, epochPublic, randomBytes(64), payload)
  }

  openReply(envelope: Bytes): Opened {
    const opened = openReplyWith(this.keys, envelope)
    return {
      eid: opened.eid,
      signer: opened.signer,
      epoch: opened.header.epoch,
      threadId: this.keys.threadId,
      payload: opened.payload,
    }
  }

  wrap(label: string, data: Bytes): Bytes {
    return wrap(this.keys.localKey, ascii(label), data)
  }

  unwrap(label: string, wrapped: Bytes): Bytes {
    return unwrap(this.keys.localKey, ascii(label), wrapped)
  }
}
