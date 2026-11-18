// The sealed envelope (spec section 4): the only thing a transport or a
// store ever sees.
import { ID_LEN, keyId, SIG_LEN, verify, type OwnerKeys, type SenderKeys } from './keys'
import { decodePayload, encodePayload, validate, type FullPayload, type Payload } from './payload'
import { open, seal } from './aead'
import { ascii, badKey, concat, hash, invalid, kdf, malformed, tooLarge, u32be, wrongSigner, type Bytes } from './prims'
import { CIPHERTEXT_LEN, envelopeId, HEADER_LEN, MAGIC, MAX_PADDED, MIN_PADDED, peek, SUITE, VERSION, type Header, type Kind } from './shape'
import { encapsulate, type XWingSecret } from './xwing'

export { CIPHERTEXT_LEN, envelopeId, HEADER_LEN, MAX_ENVELOPE, MAX_PADDED, MIN_PADDED, peek, SUITE, VERSION, type Header, type Kind } from './shape'

const SIG_CONTEXT = /* @__PURE__ */ ascii('sayso/v1/envelope/sig')

export interface Opened {
  header: Header
  eid: Bytes
  /** Who signed it: the sender identity for a drop, the owner for a reply. */
  signer: Bytes
  payload: FullPayload
}

function encodeHeader(kind: Kind, epoch: number, keyHint: Bytes): Bytes {
  const out = new Uint8Array(HEADER_LEN)
  out.set(MAGIC)
  out[4] = VERSION
  out[5] = kind === 'drop' ? 1 : 2
  out[6] = SUITE >> 8
  out[7] = SUITE & 0xff
  out.set(u32be(epoch), 8)
  out.set(keyHint, 12)
  return out
}

function schedule(shared: Bytes, header: Bytes, recipientId: Bytes): { key: Bytes; nonce: Bytes } {
  return {
    key: kdf('sayso/v1/envelope/key', shared, header, recipientId),
    nonce: kdf('sayso/v1/envelope/nonce', shared, header, recipientId).slice(0, 12),
  }
}

const signedMessage = (header: Bytes, kemCt: Bytes, peer: Bytes, signer: Bytes, payload: Bytes): Bytes =>
  concat(SIG_CONTEXT, header, hash(kemCt), peer, signer, payload)

function pad(inner: Bytes): Bytes {
  const needed = inner.length + 4
  if (needed > MAX_PADDED) throw tooLarge()
  let size = MIN_PADDED
  while (size < needed) size *= 2
  const out = new Uint8Array(size)
  new DataView(out.buffer).setUint32(0, inner.length)
  out.set(inner, 4)
  return out
}

function unpad(padded: Bytes): Bytes {
  if (padded.length < 4) throw malformed('padding')
  const length = new DataView(padded.buffer, padded.byteOffset, 4).getUint32(0)
  const rest = padded.subarray(4)
  if (length > rest.length) throw malformed('padding')
  for (let i = length; i < rest.length; i++) if (rest[i] !== 0) throw malformed('padding')
  return rest.subarray(0, length)
}

function sealEnvelope(
  kind: Kind,
  epoch: number,
  recipient: Bytes,
  entropy: Bytes,
  signer: Bytes,
  peer: Bytes,
  payload: Bytes,
  sign: (message: Bytes) => Bytes,
): Bytes {
  const recipientId = keyId(recipient)
  const header = encodeHeader(kind, epoch, kind === 'drop' ? recipientId.subarray(0, 8) : new Uint8Array(8))
  const { ciphertext, shared } = encapsulate(recipient, entropy)
  const sig = sign(signedMessage(header, ciphertext, peer, signer, payload))
  const padded = pad(concat(sig, signer, payload))
  const { key, nonce } = schedule(shared, header, recipientId)
  const associated = concat(header, ciphertext)
  return concat(associated, seal(key, nonce, associated, padded))
}

function openEnvelope(kind: Kind, secret: XWingSecret, hinted: boolean, peer: Bytes, envelope: Bytes): Opened {
  const header = peek(envelope)
  if (header.kind !== kind) throw invalid('envelope kind')
  const recipientId = keyId(secret.public)
  const expectedHint = hinted ? recipientId.subarray(0, 8) : new Uint8Array(8)
  for (let i = 0; i < 8; i++) if (header.keyHint[i] !== expectedHint[i]) throw badKey()

  const split = HEADER_LEN + CIPHERTEXT_LEN
  const associated = envelope.subarray(0, split)
  const headerBytes = envelope.subarray(0, HEADER_LEN)
  const kemCt = envelope.subarray(HEADER_LEN, split)
  const shared = secret.decapsulate(kemCt)
  const { key, nonce } = schedule(shared, headerBytes, recipientId)
  const inner = unpad(open(key, nonce, associated, envelope.subarray(split)))
  if (inner.length < SIG_LEN + ID_LEN) throw malformed('envelope')
  const sig = inner.subarray(0, SIG_LEN)
  const signer = inner.slice(SIG_LEN, SIG_LEN + ID_LEN)
  const payload = inner.subarray(SIG_LEN + ID_LEN)
  verify(signer, signedMessage(headerBytes, kemCt, peer, signer, payload), sig)
  return { header, eid: envelopeId(envelope), signer, payload: decodePayload(payload) }
}

/** Seal a message from a sender to the owner's epoch key. `entropy`: 64 fresh random bytes. */
export function sealDrop(sender: SenderKeys, epoch: number, epochPublic: Bytes, entropy: Bytes, payload: Payload): Bytes {
  const full: FullPayload = { ...payload, hello: { replyPk: sender.reply.public, tagKey: sender.tagKey } }
  validate(full)
  return sealEnvelope('drop', epoch, epochPublic, entropy, sender.sid, sender.oik, encodePayload(full), (m) => sender.sign(m))
}

/** Open a drop with the secret of the epoch it names. */
export function openDrop(epochSecret: XWingSecret, oik: Bytes, envelope: Bytes): Opened {
  const opened = openEnvelope('drop', epochSecret, true, oik, envelope)
  if (!opened.payload.hello) throw invalid('drop without hello')
  return opened
}

/** Seal a reply from the owner to a sender's reply key. */
export function sealReply(owner: OwnerKeys, sid: Bytes, replyPublic: Bytes, epoch: number, entropy: Bytes, payload: Payload): Bytes {
  if ((payload as FullPayload).hello) throw invalid('reply with hello')
  validate(payload)
  return sealEnvelope('reply', epoch, replyPublic, entropy, owner.oik, sid, encodePayload(payload), (m) => owner.sign(m))
}

/** Open a reply; refused unless the pinned owner identity signed it for this sender. */
export function openReply(sender: SenderKeys, envelope: Bytes): Opened {
  const opened = openEnvelope('reply', sender.reply, false, sender.sid, envelope)
  for (let i = 0; i < ID_LEN; i++) if (opened.signer[i] !== sender.oik[i]) throw wrongSigner()
  if (opened.payload.hello) throw invalid('reply with hello')
  return opened
}
