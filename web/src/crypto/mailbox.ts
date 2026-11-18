// Reply mailboxes (spec section 6): where a sender with no account finds
// replies that could not be delivered live.
import { MAX_ENVELOPE, peek } from './shape'
import { ascii, concat, kdf, mac, malformed, toHex, u32be, type Bytes } from './prims'

const LABEL = /* @__PURE__ */ ascii('sayso/v1/mbox')

export const mailboxAddress = (tagKey: Bytes, epoch: number): Bytes => mac(tagKey, LABEL, u32be(epoch)).slice(0, 16)

/** Path of a thread's mailbox for one epoch on the data branch. */
export const mailboxPath = (tagKey: Bytes, epoch: number): string => `mail/e${epoch}/${toHex(mailboxAddress(tagKey, epoch))}.bin`

/**
 * The live mailbox of one thread on a relay, where replies are pushed the
 * moment they are sealed: unlinkable without the tag key, the same in every
 * epoch, so a sender subscribes once.
 */
export const mailboxTopic = (tagKey: Bytes): string => toHex(kdf('sayso/v1/mbox-topic', tagKey).subarray(0, 20))

/** Append one reply envelope to the bytes of a mailbox file. */
export function mailboxAppend(file: Bytes, envelope: Bytes): Bytes {
  peek(envelope)
  return concat(file, u32be(envelope.length), envelope)
}

/** Split a mailbox file into its envelopes. */
export function mailboxSplit(file: Bytes): Bytes[] {
  const out: Bytes[] = []
  let at = 0
  while (at < file.length) {
    if (file.length - at < 4) throw malformed('mailbox')
    const length = new DataView(file.buffer, file.byteOffset + at, 4).getUint32(0)
    at += 4
    if (length > MAX_ENVELOPE || length > file.length - at) throw malformed('mailbox')
    out.push(file.slice(at, at + length))
    at += length
  }
  return out
}
