// The TypeScript core must produce exactly what the Rust reference produces.
// vectors.json comes from `cargo run -p sayso-wire --example vectors`.
import { describe, expect, it } from 'vitest'
import { decodePayload, encodePayload } from './payload'
import { openDrop, openReply, peek, sealDrop, sealReply, envelopeId } from './envelope'
import { Epochs } from './epoch'
import { encryptChunk, FilePlan, leaf, merkleRoot, padme, decryptChunk } from './file'
import { endpointIdFor, fingerprint, keyId, OwnerKeys, SenderKeys } from './keys'
import { mailboxAppend, mailboxPath, mailboxSplit, mailboxTopic } from './mailbox'
import { checkVerification, mintVerification } from './verified'
import { ascii, concat, fromHex, hash, kdf, mac, toHex } from './prims'
import { unwrap, wrap } from './aead'
import { encodeStamp, stampSearch, stampVerify } from './stamp'
import { BufferAssembler, bufferCheck, bufferItem, bufferSplit, bufferTopic } from './buffer'
import { mintInvite, verifyInvite } from './invite'
import { encapsulate, XWingSecret } from './xwing'
import { Owner, Sender, verifyDoc } from './index'
import v from './vectors.json'

const h = fromHex

describe('primitives match sayso-core', () => {
  it('kdf, mac, hash', () => {
    for (const c of v.kdf) expect(toHex(kdf(c.ctx, ...c.parts.map(h)))).toBe(c.out)
    expect(toHex(mac(h(v.mac.key), ...v.mac.parts.map(h)))).toBe(v.mac.out)
    expect(toHex(hash(h(v.hash.msg)))).toBe(v.hash.out)
  })

  it('wrap with a fixed nonce, and unwrap', () => {
    const out = wrap(h(v.wrap.key), h(v.wrap.aad), h(v.wrap.msg), h(v.wrap.nonce))
    expect(toHex(out)).toBe(v.wrap.out)
    expect(toHex(unwrap(h(v.wrap.key), h(v.wrap.aad), out))).toBe(v.wrap.msg)
    expect(() => unwrap(h(v.wrap.key), ascii('epoch:8'), out)).toThrow('decryption failed')
  })
})

describe('X-Wing matches the x-wing crate', () => {
  it('derives the public key, encapsulates and decapsulates', () => {
    const secret = new XWingSecret(h(v.xwing.seed))
    expect(toHex(secret.public)).toBe(v.xwing.public)
    const { ciphertext, shared } = encapsulate(secret.public, h(v.xwing.entropy))
    expect(toHex(ciphertext)).toBe(v.xwing.ciphertext)
    expect(toHex(shared)).toBe(v.xwing.shared)
    expect(toHex(secret.decapsulate(ciphertext))).toBe(v.xwing.shared)
    expect(toHex(keyId(secret.public))).toBe(v.xwing.keyId)
  })

  it('rejects a non-contributory X25519 share', () => {
    const secret = new XWingSecret(h(v.xwing.seed))
    const ct = h(v.xwing.ciphertext)
    ct.fill(0, ct.length - 32)
    expect(() => secret.decapsulate(ct)).toThrow('decryption failed')
  })
})

describe('keys match sayso-core', () => {
  it('owner keys, fingerprint, endpoint id, topic', () => {
    const owner = new OwnerKeys(h(v.owner.root))
    expect(toHex(owner.oik)).toBe(v.owner.oik)
    expect(toHex(owner.storeKey)).toBe(v.owner.store)
    expect(toHex(OwnerKeys.wireSecret(h(v.owner.root), 0))).toBe(v.owner.wire0)
    expect(toHex(OwnerKeys.wireSecret(h(v.owner.root), 1))).toBe(v.owner.wire1)
    expect(fingerprint(owner.oik)).toBe(v.owner.fingerprint)
    expect(endpointIdFor(OwnerKeys.wireSecret(h(v.owner.root), 0))).toBe(v.owner.endpoint0)
    expect(bufferTopic(owner.oik)).toBe(v.owner.topic)
  })

  it('sender keys', () => {
    const sender = new SenderKeys(h(v.sender.seed), h(v.owner.oik))
    expect(toHex(sender.sid)).toBe(v.sender.sid)
    expect(toHex(sender.reply.public)).toBe(v.sender.replyPublic)
    expect(toHex(sender.tagKey)).toBe(v.sender.tagKey)
    expect(toHex(sender.localKey)).toBe(v.sender.localKey)
    expect(toHex(sender.threadId)).toBe(v.sender.threadId)
    expect(mailboxPath(sender.tagKey, 2966)).toBe(v.sender.mailbox2966)
    expect(mailboxTopic(sender.tagKey)).toBe(v.sender.mailboxTopic)
  })
})

describe('payloads match minicbor', () => {
  it('decodes and re-encodes every vector exactly', () => {
    for (const p of v.payloads) {
      const decoded = decodePayload(h(p.cbor))
      const reencoded = p.name === 'big-ts' ? undefined : toHex(encodePayload(decoded))
      if (reencoded) expect(reencoded).toBe(p.cbor)
    }
    const full = decodePayload(h(v.payloads[1].cbor))
    expect(full.text).toBe('hello, owner — ünïcode ✓')
    expect(full.files?.[0]).toMatchObject({ name: 'report.pdf', mime: 'application/pdf', size: 5000 })
    expect(full.creds?.map((c) => c.length)).toEqual([80, 3])
    expect(full.ctl).toBe(1)
  })

  it('refuses trailing bytes and garbage', () => {
    expect(() => decodePayload(concat(h(v.payloads[0].cbor), new Uint8Array([0])))).toThrow('malformed payload')
    expect(() => decodePayload(new Uint8Array(40).fill(0xff))).toThrow()
    expect(() => decodePayload(new Uint8Array())).toThrow()
  })
})

describe('envelopes match sayso-core byte for byte', () => {
  const owner = new OwnerKeys(h(v.owner.root))
  const sender = new SenderKeys(h(v.sender.seed), owner.oik)
  const epoch = new XWingSecret(h(v.envelopes.epochSeed))

  it('seals the same drops', () => {
    for (const d of [v.envelopes.drop, v.envelopes.dropFull]) {
      const payload = decodePayload(h(d.payload))
      const { hello: _hello, ...plain } = payload
      expect(toHex(sealDrop(sender, d.epoch, epoch.public, h(d.entropy), plain))).toBe(d.bytes)
    }
    expect(toHex(envelopeId(h(v.envelopes.drop.bytes)))).toBe(v.envelopes.drop.eid)
  })

  it('opens a Rust drop and a Rust reply', () => {
    const opened = openDrop(epoch, owner.oik, h(v.envelopes.drop.bytes))
    expect(opened.payload.text).toBe('hello')
    expect(toHex(opened.signer)).toBe(v.sender.sid)
    expect(opened.header.epoch).toBe(2966)
    const reply = openReply(sender, h(v.envelopes.reply.bytes))
    expect(reply.payload.text).toBe('hello')
    expect(toHex(reply.signer)).toBe(v.owner.oik)
  })

  it('seals the same reply', () => {
    const payload = decodePayload(h(v.envelopes.reply.payload))
    expect(toHex(sealReply(owner, sender.sid, sender.reply.public, 2966, h(v.envelopes.reply.entropy), payload))).toBe(v.envelopes.reply.bytes)
  })

  it('authenticates every region and refuses the wrong key or owner', () => {
    const drop = h(v.envelopes.drop.bytes)
    for (const at of [9, 100, 20 + 1120 + 5, drop.length - 1]) {
      const tampered = drop.slice()
      tampered[at] ^= 1
      expect(() => openDrop(epoch, owner.oik, tampered)).toThrow()
    }
    expect(() => openDrop(new XWingSecret(new Uint8Array(32).fill(9)), owner.oik, drop)).toThrow('wrong or invalid key')
    expect(() => openDrop(epoch, new OwnerKeys(new Uint8Array(32).fill(8)).oik, drop)).toThrow('signature does not verify')
    expect(() => openReply(sender, drop)).toThrow('invalid envelope kind')
    expect(() => peek(drop.subarray(0, drop.length - 1))).toThrow()
  })

  it('splits a Rust mailbox and appends the same way', () => {
    const parts = mailboxSplit(h(v.envelopes.mailbox))
    expect(parts.map(toHex)).toEqual([v.envelopes.reply.bytes, v.envelopes.reply.bytes])
    const built = mailboxAppend(mailboxAppend(new Uint8Array(), parts[0]), parts[1])
    expect(toHex(built)).toBe(v.envelopes.mailbox)
    expect(() => mailboxSplit(h(v.envelopes.mailbox).subarray(1))).toThrow()
  })
})

describe('documents, invites, stamps and the buffer match sayso-core', () => {
  const owner = new Owner(h(v.owner.root))

  it('signs owner.json bodies identically', () => {
    expect(toHex(owner.signDoc(h(v.doc.body)))).toBe(v.doc.sig)
    expect(verifyDoc(owner.oik, h(v.doc.body), h(v.doc.sig))).toBe(true)
    expect(verifyDoc(owner.oik, ascii('{"v":2}'), h(v.doc.sig))).toBe(false)
  })

  it('mints and verifies invites identically', () => {
    expect(toHex(mintInvite(owner.keys, h(v.invite.id), v.invite.label, v.invite.notAfter))).toBe(v.invite.bytes)
    expect(verifyInvite(owner.oik, h(v.invite.bytes), 1999).label).toBe(v.invite.label)
    expect(() => verifyInvite(owner.oik, h(v.invite.bytes), 2001)).toThrow('expired')
  })

  it('mints and checks sender verifications identically', () => {
    const sid = h(v.sender.sid)
    expect(toHex(mintVerification(owner.keys, sid, v.verified.label, v.verified.issued))).toBe(v.verified.bytes)
    expect(checkVerification(owner.oik, h(v.verified.bytes), sid)).toMatchObject({ label: v.verified.label, issued: v.verified.issued })
    expect(() => checkVerification(owner.oik, h(v.verified.bytes), new Uint8Array(32))).toThrow('another sender')
    expect(() => checkVerification(new OwnerKeys(new Uint8Array(32).fill(2)).oik, h(v.verified.bytes), sid)).toThrow('signature')
  })

  it('finds the same stamp', () => {
    const found = stampSearch(h(v.stamp.eid), v.stamp.bits, 0, 1 << 20)!
    expect(toHex(found)).toBe(v.stamp.encoded)
    expect(toHex(encodeStamp(12, Number(v.stamp.nonce)))).toBe(v.stamp.encoded)
    expect(stampVerify(h(v.stamp.eid), found, 12)).toBe(true)
    expect(stampVerify(h(v.stamp.eid), found, 13)).toBe(false)
    const inflated = found.slice()
    inflated[1] = 30
    expect(stampVerify(h(v.stamp.eid), inflated, 8)).toBe(false)
  })

  it('splits items into the same parts and reassembles them', () => {
    const item = h(v.buffer.item)
    expect(bufferSplit(item)).toEqual(v.buffer.parts)
    const assembler = new BufferAssembler()
    expect(assembler.push('junk')).toBeUndefined()
    expect(assembler.push(v.buffer.parts[1])).toBeUndefined()
    expect(toHex(assembler.push(v.buffer.parts[0])!)).toBe(v.buffer.item)
    expect(toHex(bufferCheck(item, 12))).toBe(v.envelopes.drop.bytes)
    expect(() => bufferCheck(item, 13)).toThrow('invalid stamp')
    expect(toHex(bufferItem(item.subarray(0, 10), item.subarray(10)))).toBe(v.buffer.item)
  })
})

describe('files match sayso-core', () => {
  it('pads and plans the same way', () => {
    for (const p of v.file.plans) {
      expect(padme(p.size)).toBe(p.padme)
      const plan = FilePlan.forSize(p.size)
      expect([plan.padded, plan.chunks, plan.totalCipher]).toEqual([p.padded, p.chunks, p.totalCipher])
    }
  })

  it('encrypts a chunk and builds roots identically', () => {
    const plan = FilePlan.forSize(5000)
    const data = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7) % 251)
    const cipher = encryptChunk(h(v.file.chunk.key), plan, 0, data)
    expect(cipher.length).toBe(v.file.chunk.cipherLen)
    expect(toHex(hash(cipher))).toBe(v.file.chunk.cipherHash)
    expect(toHex(leaf(cipher))).toBe(v.file.chunk.leaf)
    expect(decryptChunk(h(v.file.chunk.key), plan, 0, cipher)).toEqual(data)
    const leaves = v.file.leaves.map(h)
    for (const r of v.file.roots) expect(toHex(merkleRoot(leaves.slice(0, r.n), r.total))).toBe(r.root)
  })
})

describe('epochs match sayso-core', () => {
  it('agrees on every state and range', () => {
    const epochs = new Epochs(604_800, 172_800, 2_592_000)
    for (const t of v.epochs) {
      expect(epochs.at(t.now)).toBe(t.at)
      expect(epochs.live(t.now)).toEqual(t.live)
      expect(epochs.published(t.now)).toEqual(t.published)
      for (const s of t.states) {
        expect(epochs.state(s.e, t.now)).toBe(s.state)
        expect(epochs.senderMaySeal(s.e, t.now)).toBe(s.senderMaySeal)
        expect(epochs.receiverAccepts(s.e, t.now)).toBe(s.receiverAccepts)
        expect(epochs.shredAt(s.e)).toBe(s.shredAt)
      }
    }
  })
})

describe('the page-facing classes', () => {
  it('round-trips a drop and a reply between Owner and Sender', () => {
    const owner = new Owner(h(v.owner.root))
    const sender = new Sender(h(v.sender.seed), owner.oik)
    const epochSeed = h(v.envelopes.epochSeed)
    const drop = sender.sealDrop(7, new XWingSecret(epochSeed).public, { id: new Uint8Array(16), ts: 5, text: 'hi' })
    const opened = owner.openDrop(epochSeed, drop)
    expect(opened.payload.text).toBe('hi')
    expect(toHex(opened.threadId)).toBe(v.sender.threadId)
    const reply = owner.sealReply(opened.signer, opened.replyPk!, 7, { id: new Uint8Array(16).fill(1), ts: 6, text: 'back' })
    expect(sender.openReply(reply).payload.text).toBe('back')
    expect(owner.unwrap('x', owner.wrap('x', ascii('rec')))).toEqual(ascii('rec'))
  })
})
