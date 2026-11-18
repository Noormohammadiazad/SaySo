// Everything the sender view does, without any markup.
import { openBuffers, putEverywhere, type Buffer } from '../buffer'
import { b64u, nowSeconds, record, utf8 } from '../core/bytes'
import { isSaysoError, Refusal } from '../core/types'
import type { FileRef, Opened, Payload, Sender } from '../crypto'
import { BufferAssembler, bufferItem } from '../crypto/buffer'
import { CTL_ACK, CTL_DELETE, CTL_VERIFIED } from '../crypto/controls'
import { listen, threadTopic, type LiveState, type Subscription } from '../buffer/live'
import { Epochs } from '../crypto/epoch'
import { fingerprint } from '../crypto/ident'
import { mailboxSplit } from '../crypto/mailbox'
import { randomBytes, toHex } from '../crypto/prims'
import { persist, step, StepError } from '../boot'
import { anchoredTo, fetchData, openOwner, OWNER_PATH, type Opened as OpenedDoc, type OwnerProfile } from '../data/docs'
import { inlineData } from '../data/inline'
import { locateData, rememberedLocation, type DataLocation } from '../data/location'
import { causeOf, NetworkError } from '../net'
import type { ChunkStore } from '../store/chunks'
import { keepStorage, Kv } from '../store/db'
import type { StagedFile } from '../ui/files'
import { errorText } from '../ui/format'
import { mintStamp } from '../ui/stamp'
import { Observable } from '../ui/store'
import type { WireClient } from '../wire'

/** How long to wait for a receiver before deciding nobody is online. */
const DIAL_TIMEOUT_MS = 8_000
const RETRY_MS = 20_000
/** The repository copy of the mailbox is a fallback: replies arrive live. */
const POLL_MS = 5 * 60_000
/** How often the owner's published keys are checked for changes. */
const OWNER_REFRESH_MS = 10 * 60_000

export interface ChatMessage {
  id: string
  dir: 'out' | 'in'
  ts: number
  text?: string
  files?: FileRef[]
  /**
   * `buffered`: sealed and left on a public relay for the owner to collect.
   * `delivered`: the owner's dashboard has it (it said so, live or on a relay).
   */
  state: 'queued' | 'sending' | 'uploading' | 'buffered' | 'delivered' | 'failed'
  /** 0..1 while files are moving. */
  progress?: number
  note?: string
}

/**
 * A message on its way out. All of it is kept in browser storage, the files
 * as encrypted chunks, so closing the page loses nothing.
 */
interface Outgoing {
  message: ChatMessage
  payload: Payload
  envelope: Uint8Array
  stamp: Uint8Array
  files: StagedFile[]
  /** The envelope has been left in at least one buffer. */
  buffered: boolean
}

type StoredOutgoing = Omit<Outgoing, 'message'>

/** A queued file's chunks are gone from browser storage. */
class LostFile extends Error {}

export class SenderSession extends Observable {
  /**
   * `starting`: the few milliseconds before the owner's document is checked.
   * `connecting`: waiting for the network to give up the inbox's data, with
   * the latest problem in `status`; it keeps trying on its own. Only a first
   * visit to a page deployed before the inbox existed ever waits here.
   */
  phase: 'starting' | 'connecting' | 'unconfigured' | 'no-inbox' | 'key-changed' | 'locked' | 'ready' | 'error' = 'starting'
  /** The Live Wire module, which only files need: 0..1 while it downloads. */
  liveProgress?: number
  /** What starting up is waiting for, while it waits. */
  status?: string
  /** Why starting failed: the step and its cause. */
  failure?: { step: string; reason: string }
  name = ''
  fingerprint = ''
  /** The GitHub account and repository that vouch for the owner, when they match this site. */
  github?: { login: string; repo: string }
  /**
   * The live connection to the owner. `idle` until something needs it: a
   * file to send or fetch, or no relay to leave messages on.
   */
  link: 'idle' | 'loading' | 'offline' | 'connecting' | 'live' = 'idle'
  identity: 'none' | 'device' | 'passkey' = 'none'
  messages: ChatMessage[] = []
  busy?: string
  invited = false
  /** How many public relays the owner accepts messages through. */
  relays = 0
  /** The owner verified this sender, under this name. */
  verifiedAs?: string
  /** The live subscription to this conversation's mailbox topic, where replies arrive. */
  replies: LiveState | 'off' = 'off'
  readonly passkeys = typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials

  private where!: DataLocation
  private kv!: Kv
  private store?: Promise<ChunkStore>

  /** Encrypted file chunks in browser storage; opened the first time a file is involved. */
  private chunkStore(): Promise<ChunkStore> {
    return (this.store ??= import('../store/chunks').then(({ openChunks }) => openChunks('sayso-sender-files')))
  }
  private oik!: Uint8Array
  private profile!: OwnerProfile
  private epochs!: Epochs
  private epochKeys: OwnerProfile['epochs'] = []
  private buffers: Buffer[] = []
  private seed?: Uint8Array
  private sender?: Sender
  private invite?: Uint8Array
  private readonly outbox: Outgoing[] = []
  private client?: WireClient
  private dialing?: Promise<WireClient | undefined>
  private bound = false
  private listening = false
  private flushing = false
  private flushAgain = false
  private heavy?: Promise<typeof import('./heavy')>
  private subscriptions: Subscription[] = []
  /** Messages up to this time (Unix ms) were deleted with the conversation. */
  private clearedAt = 0
  private verifiedTs = 0

  /** The sealing half of the core; see ./heavy. */
  private loadHeavy(): Promise<typeof import('./heavy')> {
    return (this.heavy ??= import('./heavy'))
  }

  async start(): Promise<void> {
    this.phase = 'starting'
    this.failure = undefined
    this.changed()
    // Fetched alongside everything below; only sending waits for it.
    this.loadHeavy().catch(() => undefined)
    try {
      // A returning visitor, or any visitor of a page with its data written
      // in, knows which inbox this is without a request.
      const remembered = rememberedLocation()
      if (remembered && !inlineData().config) void locateData().catch(() => undefined)
      const where = remembered ?? (await persist("Reading this site's settings", () => locateData(), { onRetry: this.retrying }))
      if (where === 'unconfigured') {
        this.phase = 'unconfigured'
        return this.changed()
      }
      this.where = where
      this.kv = await step("Opening this browser's storage", () => Kv.open(`sayso-sender:${where.id}`))

      // The owner's document: written into the page, or kept from the last
      // visit, or (only when neither exists) fetched. Every copy is verified
      // against the pinned identity, and the live one is re-read in the
      // background either way.
      const known = await this.knownOwner()
      if (known === 'key-changed') {
        this.phase = 'key-changed'
        return this.changed()
      }
      if (!known) {
        // A deployed page says what the repository held when it was built.
        // With no owner.json then, say so now and keep looking: the owner's
        // first publish redeploys the page with it written in.
        const deployedWithout = !!inlineData().config && !inlineData().owner
        if (deployedWithout) {
          this.phase = 'no-inbox'
          this.changed()
        }
        const quiet = (): void => undefined
        const outcome = await persist('Reading the inbox', () => this.fetchOwner(), { onRetry: deployedWithout ? quiet : this.retrying })
        if (outcome !== 'ok') {
          this.phase = outcome
          return this.changed()
        }
      }
      this.status = undefined
      // The owner is verified: show them now. Opening this browser's side of
      // the conversation needs the sealing code, which is on its way.
      this.phase = 'ready'
      this.changed()
      // For measuring: how long after navigation the verified owner showed.
      performance.mark?.('sayso:owner-shown')
      await step('Opening your conversation', () => this.loadIdentity())
      this.changed()
      if (known) void this.refreshOwner()
      if (this.sender) void this.resume()
      setInterval(() => void this.tick(), RETRY_MS)
      setInterval(() => void this.pollMailboxes(), POLL_MS)
      setInterval(() => void this.refreshOwner(), OWNER_REFRESH_MS)
    } catch (err) {
      this.phase = 'error'
      this.failure = err instanceof StepError ? { step: err.step, reason: err.reason } : { step: 'Starting', reason: causeOf(err) }
      this.changed()
    }
  }

  /** Shown while a network step waits to try again. */
  private readonly retrying = (problem: string, retryInMs: number): void => {
    this.phase = 'connecting'
    this.status = `${problem}. Trying again in ${Math.round(retryInMs / 1000)} s.`
    this.changed()
  }

  // ---- the owner's document ------------------------------------------------

  /** Take a verified owner.json into use, unless it is older than the one in use. */
  private adoptOwner(opened: Extract<OpenedDoc, { status: 'ok' }>): void {
    const profile = opened.body
    if (this.profile && profile.issued < this.profile.issued) return
    this.oik = opened.key
    this.profile = profile
    this.name = profile.name
    this.fingerprint = fingerprint(this.oik)
    this.github = anchoredTo(profile, this.where.repo) ? profile.github : undefined
    this.epochs = new Epochs(profile.epoch_len, profile.grace, profile.ttl)
    this.buffers = openBuffers(profile.buffers, this.oik)
    this.relays = this.buffers.length
    this.epochKeys = profile.epochs
  }

  /**
   * The newest verified copy available without the network: the one written
   * into the page, or the one kept from the last visit. Pins the identity on
   * first contact.
   */
  private async knownOwner(): Promise<boolean | 'key-changed'> {
    const pinned = await this.kv.get('pin')
    let found = false
    for (const copy of [inlineData().owner, await this.kv.get('doc:owner')]) {
      if (!copy) continue
      const opened = openOwner(copy, pinned)
      if (opened.status === 'bad-signature') return 'key-changed'
      if (opened.status !== 'ok') continue
      this.adoptOwner(opened)
      found = true
    }
    if (found && !pinned) await this.kv.set('pin', this.oik)
    return found
  }

  /**
   * Read and verify owner.json from the site, pinning the identity on first
   * contact and keeping a copy for the next visit.
   *
   * A missing document is `no-inbox`; one signed by a different key than the
   * pinned one is `key-changed`. Anything the network mangled is a
   * `NetworkError`: a reason to try again, not a verdict.
   */
  private async fetchOwner(): Promise<'ok' | 'no-inbox' | 'key-changed'> {
    const bytes = await fetchData(this.where.base, OWNER_PATH)
    // Gone from the site while a verified copy is in use: a redeploy in
    // progress, most likely. Keep using the copy.
    if (!bytes) return this.profile ? 'ok' : 'no-inbox'
    const pinned = await this.kv.get('pin')
    const opened = openOwner(bytes, pinned)
    if (opened.status === 'bad-signature') return 'key-changed'
    if (opened.status === 'unreadable') throw new NetworkError("the inbox's data came back unreadable")
    if (!pinned) await this.kv.set('pin', opened.key)
    this.adoptOwner(opened)
    await this.kv.set('doc:owner', bytes)
    return 'ok'
  }

  /** Bring the owner's document up to date; network trouble keeps the old one. */
  private async refreshOwner(): Promise<void> {
    try {
      const outcome = await this.fetchOwner()
      if (outcome !== 'ok') this.phase = outcome
      this.changed()
    } catch {
      // Unreachable for now; the copy in use stands until the next try.
    }
  }

  /** Re-read the owner's document now. False when it can no longer be used. */
  private async loadOwner(): Promise<boolean> {
    const outcome = await this.fetchOwner()
    if (outcome === 'ok') return true
    this.phase = outcome
    this.changed()
    return false
  }

  /** The epoch key a drop sealed now should use. */
  private currentEpoch(): { epoch: number; pk: Uint8Array } {
    const now = nowSeconds()
    const usable = this.epochKeys.filter((k) => this.epochs.senderMaySeal(k.e, now))
    // Prefer the epoch that contains now; one that starts within the allowed
    // clock skew is the fallback.
    const pick = usable.find((k) => k.e === this.epochs.at(now)) ?? usable[0]
    if (!pick) throw new Error("the owner's published keys are out of date; they need to open their dashboard")
    return { epoch: pick.e, pk: b64u.dec(pick.pk) }
  }

  // ---- identity -------------------------------------------------------------

  private async loadIdentity(): Promise<void> {
    const fragment = new URLSearchParams(location.hash.replace(/^#/, ''))
    const invite = fragment.get('i')
    if (invite) await this.kv.set('invite', b64u.dec(invite))
    this.invite = await this.kv.get('invite')
    this.invited = !!this.invite

    const key = fragment.get('k')
    if (key) {
      const seed = b64u.dec(key)
      if (seed.length === 32) {
        await this.kv.set('seed', seed)
        await this.kv.del('passkey')
      }
    }
    // The fragment has done its job; keep secrets out of the address bar.
    if (key || invite) history.replaceState(null, '', location.pathname + location.search)

    const seed = await this.kv.get('seed')
    if (seed) {
      await this.adopt(seed, 'device')
    } else if (await this.kv.get('passkey')) {
      this.phase = 'locked'
    }
  }

  private async adopt(seed: Uint8Array, identity: 'device' | 'passkey'): Promise<void> {
    const { Sender } = await this.loadHeavy()
    this.seed = seed
    this.sender = new Sender(seed, this.oik)
    const cleared = await this.kv.get('cleared')
    this.clearedAt = cleared ? Number(utf8.dec(cleared)) : 0
    const verified = await this.kv.get('verified')
    if (verified) {
      try {
        const kept = record.dec<{ label?: string; ts: number }>(this.sender.unwrap('verified', verified))
        this.verifiedAs = kept.label
        this.verifiedTs = kept.ts
      } catch {
        // Another identity's.
      }
    }
    this.listenForReplies()
    this.identity = identity
    // From here on this browser holds a conversation and maybe queued files.
    void keepStorage()
  }

  /** Sign in with a passkey for this site, creating one if there is none. */
  async usePasskey(): Promise<void> {
    let secret: Uint8Array | undefined
    try {
      const { passkeySecret } = await import('../identity/passkey')
      secret = await passkeySecret('sender')
    } catch {
      // No passkey chosen; fall through to creating one.
    }
    secret ??= await (await import('../identity/passkey')).createPasskey('sender', 'Sayso conversation')
    if (!secret) throw new Error('This browser or passkey provider cannot derive keys from a passkey.')
    await this.kv.set('passkey', new Uint8Array([1]))
    await this.adopt(secret, 'passkey')
    this.phase = 'ready'
    this.changed()
    await this.resume()
  }

  /** A link that reopens this conversation on another device or browser. */
  resumeLink(): string | undefined {
    if (this.identity !== 'device' || !this.seed) return undefined
    return `${location.origin}${location.pathname}#k=${b64u.enc(this.seed)}`
  }

  private async ensureIdentity(): Promise<Sender> {
    if (!this.sender) {
      const seed = randomBytes(32)
      await this.kv.set('seed', seed)
      await this.adopt(seed, 'device')
    }
    return this.sender!
  }

  // ---- history and the persistent outbox ------------------------------------

  private async persist(message: ChatMessage): Promise<void> {
    const { progress: _progress, ...stored } = message
    await this.kv.set(`msg:${message.id}`, this.sender!.wrap('msg', record.enc(stored)))
  }

  private async persistOut(out: Outgoing): Promise<void> {
    const { message, ...stored } = out
    await this.kv.set(`out:${message.id}`, this.sender!.wrap('out', record.enc(stored satisfies StoredOutgoing)))
  }

  private async loadHistory(): Promise<void> {
    const sender = this.sender!
    const queued = new Map<string, StoredOutgoing>()
    for (const [key, value] of await this.kv.scan('out:')) {
      try {
        queued.set(key.slice('out:'.length), record.dec<StoredOutgoing>(sender.unwrap('out', value)))
      } catch {
        // Written under another identity; not ours to send.
      }
    }

    const known = new Set(this.messages.map((m) => m.id))
    for (const [, value] of await this.kv.scan('msg:')) {
      let message: ChatMessage
      try {
        message = record.dec<ChatMessage>(sender.unwrap('msg', value))
      } catch {
        continue // Another identity's history.
      }
      if (known.has(message.id)) continue
      const unfinished = message.dir === 'out' && !['delivered', 'buffered', 'failed'].includes(message.state)
      const stored = queued.get(message.id)
      if (unfinished && stored) {
        // Still in the outbox, files and all: pick up where it stopped.
        message.state = 'queued'
        this.outbox.push({ message, ...stored })
      } else if (unfinished) {
        message.state = 'failed'
        message.note = 'Not sent: the page was closed before it was queued.'
      }
      this.messages.push(message)
    }
    this.messages.sort((a, b) => a.ts - b.ts)
    this.outbox.sort((a, b) => a.message.ts - b.message.ts)
  }

  /** A returning sender: load history, fetch stored replies, send what is queued. */
  private async resume(): Promise<void> {
    await this.loadHistory()
    this.changed()
    void this.pollMailboxes()
    void this.flush()
    void this.tick()
  }

  /**
   * Whether anything needs a live connection, and so the Live Wire module:
   * files (they only travel live), or an owner who lists no relay to leave
   * messages on. Text alone never waits for it.
   */
  private needsLive(): boolean {
    return this.buffers.length === 0 || this.outbox.some((out) => out.files.length > 0)
  }

  // ---- sending --------------------------------------------------------------

  async send(text: string, files: File[], options: { signal?: AbortSignal; onProgress?: (fraction: number) => void } = {}): Promise<void> {
    const sender = await this.ensureIdentity()
    const { stageFile } = await this.loadHeavy()
    const staged: StagedFile[] = []
    const refs: FileRef[] = []
    try {
      for (const [n, file] of files.entries()) {
        const result = await stageFile(file, await this.chunkStore(), (done) => options.onProgress?.((n + done) / files.length), options.signal)
        staged.push(result.staged)
        refs.push(result.ref)
      }
      options.signal?.throwIfAborted()
      const payload: Payload = {
        id: randomBytes(16),
        ts: Date.now(),
        text: text.trim() || undefined,
        files: refs.length ? refs : undefined,
        creds: this.invite ? [this.invite] : undefined,
      }
      const message: ChatMessage = {
        id: toHex(payload.id),
        dir: 'out',
        ts: payload.ts,
        text: payload.text,
        files: payload.files,
        state: 'queued',
      }
      const out: Outgoing = { message, payload, files: staged, buffered: false, ...(await this.seal(sender, payload)) }
      // Outbox first: once the message shows, it must survive a reload.
      await this.persistOut(out)
      await this.persist(message)
      this.messages.push(message)
      this.outbox.push(out)
    } catch (err) {
      for (const file of staged) await (await this.chunkStore()).remove(file.store)
      throw err
    } finally {
      this.busy = undefined
      this.changed()
    }
    void this.flush()
    void this.tick()
  }

  private async seal(sender: Sender, payload: Payload): Promise<{ envelope: Uint8Array; stamp: Uint8Array }> {
    const { epoch, pk } = this.currentEpoch()
    const { envelopeId } = await this.loadHeavy()
    const envelope = sender.sealDrop(epoch, pk, payload)
    const stamp = await mintStamp(envelopeId(envelope), this.profile.pow.bits)
    return { envelope, stamp }
  }

  /**
   * Move the outbox along. With a live connection everything goes straight
   * to the owner. Without one, each envelope is left on the public relays;
   * a message with no files is finished at that point, while files wait
   * here for the owner to be online.
   */
  private async flush(): Promise<void> {
    if (this.flushing) {
      this.flushAgain = true
      return
    }
    this.flushing = true
    try {
      do {
        this.flushAgain = false
        // Never wait for a dial: it may first have to download the live
        // module. What goes now goes on the relays; files wait for it.
        for (const out of [...this.outbox]) {
          const client = this.client
          const finished = client ? await this.deliver(client, out) : await this.park(out)
          if (finished) await this.settle(out)
          this.changed()
        }
      } while (this.flushAgain)
    } finally {
      this.flushing = false
      this.changed()
    }
  }

  /** A message has reached its end state: forget its outbox entry. */
  private async settle(out: Outgoing): Promise<void> {
    const at = this.outbox.indexOf(out)
    if (at >= 0) this.outbox.splice(at, 1)
    await this.persist(out.message)
    await this.kv.del(`out:${out.message.id}`)
    for (const file of out.files) await (await this.chunkStore()).remove(file.store)
  }

  /** The owner is away: leave the envelope on the relays. */
  private async park(out: Outgoing): Promise<boolean> {
    const { message } = out
    message.note = undefined
    let trouble: string | undefined
    let relays: string | undefined
    if (!out.buffered && this.buffers.length) {
      const total = this.buffers.length
      try {
        await putEverywhere(this.buffers, bufferItem(out.stamp, out.envelope), (accepted, settled) => {
          if (total === 1) return
          relays = settled < total ? `On ${accepted} of ${total} relays so far.` : `On ${accepted} of ${total} relays.`
          // The slower relays finish after the message is already safe on one.
          if (message.state === 'buffered') {
            message.note = relays
            void this.persist(message)
            this.changed()
          }
        })
        out.buffered = true
        await this.persistOut(out)
      } catch (err) {
        trouble = `No relay could be reached (${errorText(err)}).`
      }
    }
    if (out.buffered && out.files.length === 0) {
      message.state = 'buffered'
      message.note = relays
      return true
    }
    message.state = 'queued'
    message.note = out.buffered
      ? 'The message is left for the owner. Its files upload when you are both online; you can close this page meanwhile.'
      : `${trouble ?? ''} It will send when you and the owner are both online; you can close this page meanwhile.`.trim()
    return false
  }

  /** Hand one message to a live receiver. True when it reached an end state. */
  private async deliver(client: WireClient, out: Outgoing): Promise<boolean> {
    const { message } = out
    try {
      message.state = 'sending'
      message.note = undefined
      this.changed()
      await client.deliver(out.stamp, out.envelope)
      this.bound = true
      void this.listen(client)
      for (const [n, file] of out.files.entries()) {
        message.state = 'uploading'
        await this.upload(client, file, (done) => {
          message.progress = (n + done) / out.files.length
          this.changed()
        })
      }
      message.state = 'delivered'
      message.progress = undefined
      return true
    } catch (err) {
      message.progress = undefined
      if (err instanceof LostFile) {
        message.state = 'failed'
        message.note = 'The queued file is no longer in browser storage. Attach it again.'
        return true
      }
      if (isSaysoError(err) && err.kind === 'refused') {
        if (err.code === Refusal.EpochNotAccepted || err.code === Refusal.WeakStamp) {
          // The owner's keys or demands moved on while this waited: seal again.
          try {
            await this.loadOwner()
            Object.assign(out, await this.seal(this.sender!, out.payload), { buffered: false })
            await this.persistOut(out)
            message.state = 'queued'
            this.flushAgain = true
            return false
          } catch {
            // Fall through to failure with the original reason.
          }
        }
        message.state = 'failed'
        message.note = `The owner's receiver refused this: ${err.message}.`
        return true
      }
      // The connection went away; the message stays queued.
      message.state = 'queued'
      message.note = 'Waiting for the owner to be online.'
      this.dropClient(client)
      return false
    }
  }

  /** Upload a staged file, starting from whatever the receiver already has. */
  private async upload(client: WireClient, file: StagedFile, onProgress: (done: number) => void): Promise<void> {
    const put = await client.put(file.root, file.leaves, file.totalCipher)
    onProgress(put.nextIndex / file.chunks)
    for (let index = put.nextIndex; index < file.chunks; index++) {
      const cipher = await (await this.chunkStore()).read(file.store, index)
      if (!cipher) throw new LostFile()
      await put.chunk(index, cipher)
      onProgress((index + 1) / file.chunks)
    }
    await put.finish()
  }

  // ---- live connection ------------------------------------------------------

  private live(): Promise<WireClient | undefined> {
    if (this.client) return Promise.resolve(this.client)
    return (this.dialing ??= this.dial().finally(() => (this.dialing = undefined)))
  }

  private async dial(): Promise<WireClient | undefined> {
    this.link = 'loading'
    this.changed()
    let wire: typeof import('../wire/pkg/sayso_wasm.js')
    try {
      const { loadWire } = await import('../wire')
      wire = await loadWire((fraction) => {
        this.liveProgress = fraction
        this.changed()
      })
    } catch {
      // Tried again on the next tick.
      this.link = 'offline'
      this.liveProgress = undefined
      this.changed()
      return undefined
    }
    this.liveProgress = undefined
    this.link = 'connecting'
    this.changed()
    for (const receiver of this.profile.receivers) {
      try {
        const client = await wire.WireClient.connect(receiver.node, DIAL_TIMEOUT_MS)
        this.client = client
        this.bound = false
        this.link = 'live'
        this.changed()
        void client.closed().then(() => this.dropClient(client))
        return client
      } catch {
        // Not online; try the next receiver.
      }
    }
    this.link = 'offline'
    this.changed()
    return undefined
  }

  private dropClient(client: WireClient): void {
    if (this.client !== client) return
    this.client = undefined
    this.bound = false
    this.listening = false
    this.link = 'offline'
    this.changed()
    void client.close().catch(() => undefined)
  }

  /**
   * Tell the receiver which thread this connection belongs to, with a sealed
   * presence note. Needed before it will push replies or serve attachments.
   */
  private async bind(client: WireClient): Promise<void> {
    if (this.bound) return
    const payload: Payload = { id: randomBytes(16), ts: Date.now(), ctl: 1 }
    const { envelope, stamp } = await this.seal(this.sender!, payload)
    await client.deliver(stamp, envelope)
    this.bound = true
  }

  /** A fresh connection: bind it, listen for replies, send what is queued. */
  private async attach(client: WireClient): Promise<void> {
    // A queued message binds the connection by itself when it is delivered.
    if (!this.outbox.length) await this.bind(client)
    if (this.bound) void this.listen(client)
    void this.flush()
  }

  private async listen(client: WireClient): Promise<void> {
    if (this.listening) return
    this.listening = true
    try {
      const listener = await client.listen()
      for (;;) {
        const envelope = await listener.next()
        if (!envelope) break
        const eid = await this.receive(envelope)
        if (eid) await listener.seen(eid)
      }
    } catch {
      // The connection closed; `closed()` handles the state.
    } finally {
      if (this.client === client) this.listening = false
    }
  }

  private async tick(): Promise<void> {
    if (this.phase !== 'ready') return
    // Anything no relay has taken yet gets another try.
    if (this.outbox.some((out) => !out.buffered)) void this.flush()
    if (this.client || this.dialing || !this.sender || !this.needsLive()) return
    const client = await this.live()
    if (client) await this.attach(client).catch(() => undefined)
  }

  // ---- replies --------------------------------------------------------------

  /**
   * Listen on this conversation's mailbox topic on every relay the owner
   * named: the owner pushes replies there the moment they are sealed.
   */
  private listenForReplies(): void {
    if (!this.sender || this.subscriptions.length) return
    const topic = threadTopic(this.sender.mailboxTopic)
    for (const spec of this.profile.buffers ?? []) {
      if (spec.kind !== 'ntfy') continue
      const assembler = new BufferAssembler()
      const key = `mbox-cursor:${spec.url}`
      void this.kv.get(key).then((cursor) => {
        this.subscriptions.push(
          listen(spec.url, topic, {
            since: cursor ? utf8.dec(cursor) : '12h',
            onMessage: (text, id) => {
              const bytes = assembler.push(text)
              if (bytes) void this.receive(bytes)
              void this.kv.set(key, utf8.enc(id))
            },
            onState: (state) => {
              this.replies = state
              this.changed()
            },
          }),
        )
      })
    }
  }

  /**
   * Open one reply envelope and act on it. Returns its id when it was ours
   * and valid. Replays are harmless: every action is idempotent, and nothing
   * from before a deletion of the conversation is taken back in.
   */
  private async receive(envelope: Uint8Array): Promise<Uint8Array | undefined> {
    let opened: Opened
    try {
      opened = this.sender!.openReply(envelope)
    } catch {
      return undefined
    }
    const { payload } = opened
    if (payload.ts <= this.clearedAt) return opened.eid
    const refers = payload.replyTo && toHex(payload.replyTo)
    switch (payload.ctl) {
      case CTL_ACK: {
        const message = this.messages.find((m) => m.id === refers && m.dir === 'out')
        // A message with files is delivered when its files are, not when its text is.
        if (message && message.state !== 'delivered' && !message.files?.length) {
          message.state = 'delivered'
          message.note = undefined
          await this.persist(message)
          this.changed()
        }
        return opened.eid
      }
      case CTL_DELETE:
        if (refers) await this.removeLocally([refers])
        else await this.clearLocally(payload.ts)
        return opened.eid
      case CTL_VERIFIED: {
        if (payload.ts < this.verifiedTs) return opened.eid
        let label: string | undefined
        try {
          label = payload.creds?.[0] && this.sender!.checkVerification(payload.creds[0]).label
        } catch {
          return opened.eid
        }
        this.verifiedAs = label
        this.verifiedTs = payload.ts
        await this.kv.set('verified', this.sender!.wrap('verified', record.enc({ label, ts: payload.ts })))
        this.changed()
        return opened.eid
      }
      case undefined:
        break
      default:
        return opened.eid
    }
    const id = toHex(payload.id)
    if (!this.messages.some((m) => m.id === id)) {
      const message: ChatMessage = {
        id,
        dir: 'in',
        ts: payload.ts,
        text: payload.text,
        files: payload.files,
        state: 'delivered',
      }
      this.messages.push(message)
      this.messages.sort((a, b) => a.ts - b.ts)
      await this.persist(message)
      this.changed()
    }
    return opened.eid
  }

  // ---- deleting -------------------------------------------------------------

  /** Seal a control payload to the owner and leave it on the relays (and live, if connected). */
  private async sendControl(fields: Partial<Payload>): Promise<void> {
    const sender = this.sender
    if (!sender) return
    const payload: Payload = { id: randomBytes(16), ts: Date.now(), ...fields }
    const { envelope, stamp } = await this.seal(sender, payload)
    const client = this.client
    if (client) await client.deliver(stamp, envelope).catch(() => undefined)
    if (this.buffers.length) await putEverywhere(this.buffers, bufferItem(stamp, envelope)).catch(() => undefined)
  }

  /**
   * Delete one message for both of you: here at once, and on the owner's
   * side once their dashboard reads the notice.
   */
  async deleteMessage(id: string): Promise<void> {
    const message = this.messages.find((m) => m.id === id)
    if (!message) return
    const reachedOwner = message.dir === 'in' || ['buffered', 'delivered', 'uploading', 'sending'].includes(message.state)
    await this.removeLocally([id])
    if (reachedOwner) await this.sendControl({ ctl: CTL_DELETE, replyTo: fromHexId(id) })
  }

  /** Delete the whole conversation for both of you. The identity stays, so you can write again. */
  async deleteConversation(): Promise<void> {
    const until = Date.now()
    await this.clearLocally(until)
    await this.sendControl({ ctl: CTL_DELETE, ts: until })
  }

  private async removeLocally(ids: string[]): Promise<void> {
    for (const id of ids) {
      const message = this.messages.find((m) => m.id === id)
      if (!message) continue
      this.messages.splice(this.messages.indexOf(message), 1)
      await this.kv.del(`msg:${id}`)
      const out = this.outbox.find((o) => o.message.id === id)
      if (out) {
        this.outbox.splice(this.outbox.indexOf(out), 1)
        await this.kv.del(`out:${id}`)
        for (const file of out.files) await (await this.chunkStore()).remove(file.store)
      }
      for (const ref of message.files ?? []) await (await this.chunkStore()).remove(toHex(ref.root))
    }
    this.changed()
  }

  private async clearLocally(until: number): Promise<void> {
    await this.removeLocally(this.messages.filter((m) => m.ts <= until).map((m) => m.id))
    this.clearedAt = Math.max(this.clearedAt, until)
    await this.kv.set('cleared', utf8.enc(String(this.clearedAt)))
    this.changed()
  }

  /** Fetch replies that were kept in the repository while this sender was away. */
  private async pollMailboxes(): Promise<void> {
    if (!this.sender) return
    const [first, last] = this.epochs.live(nowSeconds())
    for (let epoch = first; epoch <= last; epoch++) {
      try {
        const file = await fetchData(this.where.base, this.sender.mailboxPath(epoch))
        if (file) for (const envelope of mailboxSplit(file)) await this.receive(envelope)
      } catch {
        // A mailbox that cannot be read now will be read on the next poll.
      }
    }
  }

  /** Download a file the owner attached, then hand it to the user. */
  async download(message: ChatMessage, ref: FileRef): Promise<void> {
    const root = toHex(ref.root)
    const client = await this.live()
    if (!client) throw new Error('The owner is not online, and attachments can only be fetched while you both are.')
    await this.bind(client)
    const get = await client.get(ref.root, await (await this.chunkStore()).have(root, Number.MAX_SAFE_INTEGER))
    for (;;) {
      const next = (await get.next()) as { index: number; cipher: Uint8Array } | undefined
      if (!next) break
      await (await this.chunkStore()).write(root, next.index, next.cipher)
      message.progress = (next.index + 1) / get.chunks
      this.changed()
    }
    message.progress = undefined
    this.changed()
    const { saveFile } = await this.loadHeavy()
    await saveFile(ref, await this.chunkStore())
  }
}

const fromHexId = (hex: string): Uint8Array => Uint8Array.from(hex.match(/../g)!.map((byte) => parseInt(byte, 16)))
