// Everything the owner dashboard does, without any markup: it is the Live
// Wire receiver, the collector for the relays and the vault, the only holder
// of epoch secrets, and the only writer of the data branch.
//
// The owner signs in with two things: a GitHub token that can write to the
// repository (checked against GitHub), and the passphrase or a passkey that
// opens the key vault the repository keeps (data/owner-vault.enc). So any
// browser on any device can open the inbox, and none has to be trusted to
// keep the only copy of a key.
import { persist, step, StepError } from '../boot'
import { bounded, openBuffers, type Buffer } from '../buffer'
import { inboxTopic, listen, threadTopic, type LiveState, type Subscription } from '../buffer/live'
import { publish } from '../buffer/publish'
import {
  b64u,
  BufferAssembler,
  bufferCheck,
  bufferTopic,
  CTL_ACK,
  CTL_DELETE,
  CTL_VERIFIED,
  endpointIdFor,
  envelopeId,
  envelopePeek,
  epochGenerate,
  Epochs,
  FileOpener,
  XWingSecret,
  fromHex,
  mailboxAppend,
  mailboxPath,
  mailboxSplit,
  mailboxTopic,
  nowSeconds,
  Owner,
  randomBytes,
  record,
  Refusal,
  stampVerify,
  toHex,
  utf8,
} from '../core'
import type { EpochKey, FileRef, InviteInfo, Opened, Payload, WireEvent } from '../core'
import { fetchData, OWNER_PATH, signOwner, type BufferSpec, type OwnerProfile } from '../data/docs'
import { inlineData } from '../data/inline'
import { locateData, rememberedLocation, type DataLocation } from '../data/location'
import { openVault, type Vault } from '../data/vault'
import {
  addPasskey,
  changePassphrase,
  createVault,
  decodeVault,
  encodeVault,
  mergeSecrets,
  openBody,
  passkeyCredentials,
  passphraseProblem,
  sameSecrets,
  sealBody,
  unlockWithPasskey,
  unlockWithPassphrase,
  VAULT_PATH,
  WrongPassphrase,
  type ThreadMeta,
  type VaultFile,
  type VaultSecrets,
  type VaultSettings,
} from '../identity/keyvault'
import { createPasskeyWithId, passkeyProblem, passkeysSupported, passkeyWithId } from '../identity/passkey'
import { causeOf, sleep, backoff } from '../net'
import { openPublisher, openVaultWriter, type Publisher } from '../publish'
import { checkToken, TokenProblem } from '../publish/token'
import { openChunks, type ChunkStore } from '../store/chunks'
import { keepStorage, Kv } from '../store/db'
import { saveFile, stageFile, type StagedFile } from '../ui/files'
import { errorText } from '../ui/format'
import { Observable } from '../ui/store'
import type { WireServer } from '../wire'
import { clearSession, loadSession, saveSession } from './device'
import { supervise } from './supervise'

/** Protocol defaults (spec section 3), in seconds. */
const PARAMS = { epoch_len: 7 * 86_400, grace: 2 * 86_400, ttl: 30 * 86_400 }
const POW_BITS = 16
const TICK_MS = 10 * 60_000
/**
 * How often an open dashboard also reads the relays and the vault in full.
 * Live messages do not wait for this: they arrive through the inbox topic.
 */
const COLLECT_MS = 10 * 60_000
/** Drops younger than this are acknowledged to their sender on arrival. */
const ACK_WINDOW_MS = 6 * 3600_000
const INVITE_LIFETIME = 30 * 86_400
/** This browser's copy of the key vault, so a remembered sign-in opens offline. */
const LOCAL_VAULT = 'vault'

export interface Thread {
  id: string
  sid: Uint8Array
  replyPk: Uint8Array
  tagKey: Uint8Array
  /** Label of the invite this sender presented, if any. */
  invited?: string
  lastTs: number
  unread: number
  preview: string
}

export interface OwnerMessage {
  id: string
  thread: string
  dir: 'in' | 'out'
  ts: number
  text?: string
  files?: FileRef[]
  /**
   * Outgoing: `sending` until a relay took it, then `sent` (pushed to the
   * sender's live mailbox); `failed` when no relay could, and it is retried.
   */
  state: 'received' | 'sending' | 'sent' | 'failed'
  /** Outgoing: also kept in the thread's mailbox file in the repository. */
  saved?: boolean
  /** Fraction of each incoming file stored on this device, by root. */
  stored?: Record<string, number>
  /** Outgoing, until it is both sent and saved. */
  envelope?: Uint8Array
  /** The envelope's id (hex): how its copies are found to delete them. */
  eid?: string
  epoch?: number
  note?: string
}

export interface EpochRow {
  epoch: number
  state: string
  shredAt: number
}

export type Settings = Omit<VaultSettings, 'updated'>

/** An encrypted attachment of a reply, kept to serve its thread on request. */
interface StoredFile extends StagedFile {
  thread: string
}

const pad = (n: number, width: number): string => String(n).padStart(width, '0')

/** Paths on the data branch that belong to an epoch: `mail/e12/...`, `blob/e12/...`. */
const EPOCH_PATH = /^(?:mail|blob)\/e(\d+)\//

/** What to say when signing in or creating the inbox did not work. */
function formProblem(err: unknown): string {
  if (err instanceof TokenProblem || err instanceof WrongPassphrase) return err.message
  if (err instanceof Error && err.name === 'NetworkError') return `${err.message}. Check the connection and try again.`
  return errorText(err)
}

export class Dashboard extends Observable {
  /**
   * `connecting`: waiting for this site's settings, retrying on its own.
   * `signin`: not unlocked in this browser; `setup`: creating the inbox.
   * Nothing after sign-in waits for the network: `running` is reached with
   * the receiver, the relays and GitHub still connecting in the background.
   */
  phase: 'connecting' | 'unconfigured' | 'signin' | 'setup' | 'running' | 'error' = 'connecting'
  /** What starting up is waiting for, while it waits. */
  status?: string
  /** Why starting failed: the step and its cause. */
  failure?: { step: string; reason: string }
  /** Whether this repository already has an inbox; `undefined` while unknown. */
  inboxExists?: boolean
  /** What the sign-in or setup form is doing right now. */
  busy?: string
  /** Why signing in or setting up did not work, shown in the form. */
  formError?: string
  /** A note for the setup form, such as why it was shown. */
  formNote?: string
  /** Setup reached from sign-in: the token was checked already. */
  checkedToken?: string
  /** The GitHub account the token belongs to. */
  login?: string
  /** Why saving settings did not work. */
  settingsError?: string
  settingsNote?: string
  /**
   * The Live Wire receiver: `off` when turned off in settings, `loading`
   * while its module downloads (see `receiverProgress`), `starting` until it
   * is bound, `connecting` until a relay answers, `online` once senders can
   * reach it. `retrying` after a failure, with the cause in `receiverProblem`.
   */
  receiver: 'off' | 'loading' | 'starting' | 'connecting' | 'online' | 'retrying' = 'off'
  receiverProgress?: number
  receiverProblem?: string
  settings: Settings = { name: '', waku: false, ntfy: '', live: true }
  fingerprint = ''
  endpointId = ''
  reachable = false
  /** False when the deployment needs a GitHub token and none is set. */
  canPublish = false
  /** The key vault and owner.json in the repository match this browser. */
  synced = false
  syncing = false
  publishError?: string
  /** How many passkeys can open the vault. */
  passkeySlots = 0
  /** Why the last collection from a relay or the vault failed, by source. */
  collectErrors: Record<string, string> = {}
  /** The live inbox subscription on each ntfy relay. */
  relayStates: Record<string, LiveState> = {}
  relayProblem?: string
  /** When the relays and the vault were last collected from, Unix ms. */
  collectedAt?: number
  collecting = false
  threads: Thread[] = []
  messages = new Map<string, OwnerMessage[]>()
  epochRows: EpochRow[] = []
  connected = new Set<string>()
  readonly passkeys = passkeysSupported()
  local = false
  /** Whether the browser agreed not to evict this inbox's data. */
  durable = true

  private where!: DataLocation
  private kv!: Kv
  private chunks!: ChunkStore
  private owner!: Owner
  private token?: string
  private vaultKey!: Uint8Array
  private vaultFile!: VaultFile
  private secrets!: VaultSecrets
  /** Slots were changed here (passkey added, passphrase changed) and must be written. */
  private slotsChanged = false
  private readonly epochs = new Epochs(PARAMS.epoch_len, PARAMS.grace, PARAMS.ttl)
  private server?: WireServer
  private publisher?: Publisher
  private vaultWriter?: Publisher
  private subscriptions: Subscription[] = []
  /** Tail of the queue of mailbox file edits. */
  private mailboxes: Promise<void> = Promise.resolve()
  private vault?: Vault
  private buffers: Buffer[] = []
  private readonly epochKeys = new Map<number, EpochKey>()
  /** Connection id to thread id, set by the first drop that opens. */
  private readonly conns = new Map<number, string>()
  private readonly listening = new Set<number>()
  /** Files announced by accepted drops: the only uploads this receiver takes. */
  private readonly expected = new Map<string, { ref: FileRef; message: OwnerMessage }>()
  private readonly outgoing = new Map<string, StoredFile>()
  /** Tail of the queue every opened drop is recorded through. */
  private taking: Promise<void> = Promise.resolve()
  private ticking = false

  async start(): Promise<void> {
    this.phase = 'connecting'
    this.failure = undefined
    this.changed()
    try {
      const remembered = rememberedLocation()
      if (remembered && !inlineData().config) void locateData().catch(() => undefined)
      const where = remembered ?? (await persist("Reading this site's settings", () => locateData(), { onRetry: this.retrying }))
      if (where === 'unconfigured') {
        this.phase = 'unconfigured'
        return this.changed()
      }
      this.where = where
      this.local = where.local
      this.kv = await step("Opening this browser's storage", () => Kv.open(`sayso-owner:${where.id}`))
      this.chunks = await step("Opening this browser's file storage", () => openChunks('sayso-owner-files'))

      // Signed in here before: open from this browser's copy, then catch up
      // with the repository in the background.
      const [session, cached] = await step('Reading the saved sign-in', () =>
        Promise.all([loadSession(this.kv), this.kv.get(LOCAL_VAULT)]),
      )
      if (session && cached) {
        try {
          const file = decodeVault(cached)
          const secrets = openBody(file, session.vaultKey)
          this.token = session.token
          this.login = session.login
          this.vaultKey = session.vaultKey
          this.vaultFile = file
          return void (await this.run(secrets))
        } catch {
          // A sign-in for an inbox that was replaced; sign in again.
        }
      }
      // What the repository held when this page was deployed; checked again
      // in the background, since the inbox may have been created since.
      const inline = inlineData()
      this.inboxExists = inline.owner ? true : inline.config ? false : undefined
      this.phase = this.inboxExists === false ? 'setup' : 'signin'
      this.changed()
      if (!inline.owner) void this.checkInbox()
    } catch (err) {
      this.fail(err)
    }
  }

  private fail(err: unknown): void {
    this.phase = 'error'
    this.failure = err instanceof StepError ? { step: err.step, reason: err.reason } : { step: 'Starting', reason: causeOf(err) }
    this.changed()
  }

  /** Shown while a network step waits to try again. */
  private readonly retrying = (problem: string, retryInMs: number): void => {
    this.phase = 'connecting'
    this.status = `${problem}. Trying again in ${Math.round(retryInMs / 1000)} s.`
    this.changed()
  }

  /** Whether owner.json exists, to word the first screen. Never blocks it. */
  private async checkInbox(): Promise<void> {
    try {
      this.inboxExists = (await fetchData(this.where.base, OWNER_PATH)) !== undefined
      if (!this.busy && (this.phase === 'signin' || this.phase === 'setup')) this.phase = this.inboxExists ? 'signin' : 'setup'
      this.changed()
    } catch {
      // Unknown; the sign-in form finds out from GitHub anyway.
    }
  }

  get repoName(): string {
    return this.where?.repo ? `${this.where.repo.owner}/${this.where.repo.name}` : 'this site'
  }

  /** The public ntfy relay for a real deployment; the local stand-in when testing. */
  private defaults(name: string): VaultSettings {
    // Waku stays off unless the owner turns it on: on some networks it never
    // connects, and a relay that never answers only slows everything down.
    return { name, waku: false, ntfy: this.where.ntfy, live: false, updated: Date.now() }
  }

  // ---- signing in and creating the inbox ----------------------------------------

  /** Check the token against the repository. Locally there is none to check. */
  private async grant(token: string): Promise<string | undefined> {
    if (this.local) return undefined
    this.busy = 'Checking your GitHub token'
    this.changed()
    return (await checkToken(this.where.repo!, token)).login
  }

  /** The key vault in the repository, read with the owner's token. */
  private async remoteVault(token: string): Promise<VaultFile | undefined> {
    this.busy = 'Reading your key vault from GitHub'
    this.changed()
    const found = await openPublisher(this.where, token)!.read(VAULT_PATH)
    return found && decodeVault(found.bytes)
  }

  private async form(work: () => Promise<void>): Promise<void> {
    if (this.busy) return
    this.formError = undefined
    this.changed()
    try {
      await work()
    } catch (err) {
      this.formError = formProblem(err)
    } finally {
      this.busy = undefined
      this.changed()
    }
  }

  /** Sign in with the GitHub token and the vault passphrase. */
  signIn(token: string, passphrase: string, remember: boolean): Promise<void> {
    return this.form(async () => {
      token = token.trim()
      const login = await this.grant(token)
      const file = await this.remoteVault(token)
      if (!file) return this.offerSetup(token, login)
      this.busy = 'Unlocking your key vault'
      this.changed()
      const key = await unlockWithPassphrase(file, passphrase)
      await this.adopt(file, key, token, login, remember)
    })
  }

  /** Sign in with the GitHub token and a passkey that has a slot in the vault. */
  signInWithPasskey(token: string, remember: boolean): Promise<void> {
    return this.form(async () => {
      token = token.trim()
      const login = await this.grant(token)
      const file = await this.remoteVault(token)
      if (!file) return this.offerSetup(token, login)
      const allowed = passkeyCredentials(file)
      if (!allowed.length) {
        throw new Error('No passkey can open this inbox yet. Sign in with your passphrase, then add one under Settings.')
      }
      this.busy = 'Waiting for your passkey'
      this.changed()
      let answer: { id: Uint8Array; secret: Uint8Array } | undefined
      try {
        answer = await passkeyWithId('vault', allowed)
      } catch (err) {
        throw new Error(passkeyProblem(err))
      }
      if (!answer) throw new Error('That passkey did not produce a key. Sign in with your passphrase instead.')
      await this.adopt(file, unlockWithPasskey(file, answer.id, answer.secret), token, login, remember)
    })
  }

  /** Switch the first screen between signing in and creating the inbox. */
  showForm(which: 'signin' | 'setup'): void {
    this.formError = undefined
    this.formNote = undefined
    this.phase = which
    this.changed()
  }

  private offerSetup(token: string, login?: string): void {
    this.checkedToken = token
    this.login = login
    this.inboxExists = false
    this.formNote = `There is no inbox in ${this.repoName} yet. Name it to create it with the passphrase you entered.`
    this.phase = 'setup'
  }

  /**
   * Create the inbox: fresh keys, sealed into a new vault under the
   * passphrase. The dashboard opens at once; the vault and owner.json are
   * written to the repository in the background, and retried until they are.
   */
  create(name: string, token: string, passphrase: string, confirm: string, remember: boolean): Promise<void> {
    return this.form(async () => {
      token = token.trim()
      const weak = passphraseProblem(passphrase)
      if (weak) throw new Error(weak)
      if (passphrase !== confirm) throw new Error('The two passphrases are not the same.')
      if (!name.trim()) throw new Error('Enter the name senders will see.')
      const login = token === this.checkedToken ? this.login : await this.grant(token)
      if (await this.remoteVault(token)) {
        this.inboxExists = true
        this.phase = 'signin'
        throw new Error(`${this.repoName} already has an inbox. Sign in to it with its passphrase.`)
      }
      this.busy = 'Making your keys and sealing them with your passphrase'
      this.changed()
      const secrets: VaultSecrets = {
        root: randomBytes(32),
        epochs: new Map(),
        settings: this.defaults(name.trim()),
        threads: new Map(),
        purged: new Map(),
      }
      const { file, key } = await createVault(secrets, passphrase)
      await this.adopt(file, key, token, login, remember)
    })
  }

  /** An unlocked vault: keep what is needed to stay signed in, then run. */
  private async adopt(file: VaultFile, key: Uint8Array, token: string, login: string | undefined, remember: boolean): Promise<void> {
    const secrets = openBody(file, key)
    this.vaultFile = file
    this.vaultKey = key
    this.token = token || undefined
    this.login = login
    this.busy = 'Opening your inbox'
    this.changed()
    await this.kv.set(LOCAL_VAULT, encodeVault(file))
    if (remember) await saveSession(this.kv, { vaultKey: key, token: this.token, login })
    else await clearSession(this.kv)
    await this.run(secrets)
  }

  /** Forget this browser's sign-in. Messages kept here stay encrypted under the inbox key. */
  async signOut(): Promise<void> {
    await clearSession(this.kv)
    await this.kv.del(LOCAL_VAULT)
    location.reload()
  }

  // ---- settings, passkeys, passphrase ------------------------------------------

  /** Save settings in the vault, then publish and collect in the background. Never throws. */
  async saveSettings(settings: Settings): Promise<void> {
    this.settingsError = undefined
    this.settingsNote = undefined
    const relaysMoved = settings.ntfy !== this.settings.ntfy || settings.waku !== this.settings.waku
    this.secrets.settings = { ...settings, updated: Date.now() }
    this.settings = this.secrets.settings
    try {
      await this.saveLocal()
    } catch (err) {
      this.settingsError = `Could not save the settings in this browser: ${causeOf(err)}`
    }
    this.connectServices()
    if (relaysMoved) this.listenInbox()
    this.ensureReceiver()
    this.changed()
    void this.tick()
    void this.collect()
  }

  /** Use a new GitHub token on this browser. */
  async replaceToken(token: string): Promise<void> {
    this.settingsError = undefined
    this.settingsNote = undefined
    try {
      token = token.trim()
      this.login = await checkToken(this.where.repo!, token).then((g) => g.login)
      this.token = token
      if (await loadSession(this.kv)) await saveSession(this.kv, { vaultKey: this.vaultKey, token, login: this.login })
      this.connectServices()
      this.settingsNote = `Token saved for @${this.login}.`
      void this.tick()
    } catch (err) {
      this.settingsError = formProblem(err)
    }
    this.changed()
  }

  /** Add a passkey that can open the vault, on any device it syncs to. */
  async addPasskey(): Promise<void> {
    this.settingsError = undefined
    this.settingsNote = undefined
    this.changed()
    try {
      const made = await createPasskeyWithId('vault', `Sayso inbox: ${this.settings.name || this.repoName}`)
      if (!made) throw new Error('This browser or passkey provider cannot derive keys from a passkey.')
      this.vaultFile = addPasskey(this.vaultFile, this.vaultKey, made.id, made.secret)
      this.slotsChanged = true
      await this.saveLocal()
      this.settingsNote = 'Passkey added. It opens this inbox wherever it syncs, together with your GitHub token.'
      void this.tick()
    } catch (err) {
      this.settingsError = err instanceof Error && err.name !== 'Error' ? passkeyProblem(err) : errorText(err)
    }
    this.changed()
  }

  async changePassphrase(passphrase: string, confirm: string): Promise<void> {
    this.settingsError = undefined
    this.settingsNote = undefined
    try {
      const weak = passphraseProblem(passphrase)
      if (weak) throw new Error(weak)
      if (passphrase !== confirm) throw new Error('The two passphrases are not the same.')
      this.settingsNote = 'Sealing the vault with the new passphrase…'
      this.changed()
      this.vaultFile = await changePassphrase(this.vaultFile, this.vaultKey, passphrase)
      this.slotsChanged = true
      await this.saveLocal()
      this.settingsNote = 'Passphrase changed. Copies of the vault from before still open with the old one.'
      void this.tick()
    } catch (err) {
      this.settingsNote = undefined
      this.settingsError = errorText(err)
    }
    this.changed()
  }

  private bufferSpecs(): BufferSpec[] {
    const specs: BufferSpec[] = []
    if (this.settings.waku) specs.push({ kind: 'waku' })
    if (this.settings.ntfy.trim()) specs.push({ kind: 'ntfy', url: this.settings.ntfy.trim().replace(/\/+$/, '') })
    return specs
  }

  /** (Re)open everything that depends on settings and the token. */
  private connectServices(): void {
    this.publisher = openPublisher(this.where, this.token, { login: this.login })
    this.vaultWriter = openVaultWriter(this.where, this.token, { login: this.login })
    this.canPublish = !!this.publisher
    this.vault = openVault(this.where, this.token)
    this.buffers = openBuffers(this.bufferSpecs(), this.owner.oik)
  }

  // ---- running ----------------------------------------------------------------

  /**
   * Open the inbox. Everything here is local, so the dashboard shows at
   * once; syncing, publishing, collecting and the receiver start in the
   * background and report how they are doing instead of holding the page up.
   */
  private async run(secrets: VaultSecrets): Promise<void> {
    this.secrets = secrets
    this.owner = new Owner(secrets.root)
    this.fingerprint = this.owner.fingerprint
    // The receiver's address is the public half of its key: known now, so
    // owner.json can name it before the receiver ever runs.
    this.endpointId = endpointIdFor(this.owner.wireSecret(0))
    this.settings = secrets.settings
    this.passkeySlots = passkeyCredentials(this.vaultFile).length
    this.takeEpochs()
    this.connectServices()
    void keepStorage().then((durable) => {
      this.durable = durable
      this.changed()
    })

    await step('Reading your messages', () => this.loadState())
    await this.rotateKeys()
    this.phase = 'running'
    this.changed()

    void this.firstRound()
    setInterval(() => void this.tick(), TICK_MS)
    setInterval(() => void this.collect(), COLLECT_MS)
  }

  /**
   * Go live on the inbox, catch up with what arrived meanwhile, and bring
   * the repository up to date. The Live Wire receiver only starts when there
   * is a file to move (or the owner asked for it).
   */
  private async firstRound(): Promise<void> {
    this.listenInbox()
    await Promise.race([Promise.all([this.tick(), this.collect()]), sleep(20_000)])
    this.ensureReceiver()
  }

  /** The epoch keys in the vault, with their public halves. */
  private takeEpochs(): void {
    for (const [epoch, key] of this.epochKeys) {
      if (!this.secrets.epochs.has(epoch)) {
        key.seed.fill(0)
        this.owner.forget(key.seed)
        this.epochKeys.delete(epoch)
      }
    }
    for (const [epoch, seed] of this.secrets.epochs) {
      const known = this.epochKeys.get(epoch)
      if (known && toHex(known.seed) === toHex(seed)) continue
      this.epochKeys.set(epoch, { seed, public: epochPublic(seed) })
    }
    this.refreshEpochRows()
  }

  /** Keep this browser's copy of the vault current. */
  private async saveLocal(): Promise<void> {
    this.vaultFile = sealBody(this.vaultFile, this.vaultKey, this.secrets)
    this.passkeySlots = passkeyCredentials(this.vaultFile).length
    await this.kv.set(LOCAL_VAULT, encodeVault(this.vaultFile))
  }

  /** Start the Live Wire receiver when it is wanted, and keep it running. Never throws. */
  private ensureReceiver(): void {
    if (!this.wantsReceiver() || this.receiver !== 'off') return
    this.receiver = 'loading'
    this.changed()
    void (async () => {
      // The module is downloaded once and kept; a failed download is tried
      // again after a pause, for as long as the page is open.
      const { loadWire } = await import('../wire')
      let wire: Awaited<ReturnType<typeof loadWire>> | undefined
      for (let attempt = 0; !wire; attempt++) {
        try {
          wire = await loadWire((fraction) => {
            this.receiverProgress = fraction
            this.changed()
          })
        } catch (err) {
          this.receiverProblem = `the live module did not download (${causeOf(err)})`
          this.changed()
          await sleep(backoff(attempt))
        }
      }
      this.receiverProblem = undefined
      const secret = this.owner.wireSecret(0)
      await supervise<WireServer>({
        start: () => wire.WireServer.start(secret),
        serve: (server) => this.serve(server),
        onState: (state, server, problem) => {
          this.receiver = state
          this.receiverProblem = problem
          this.server = server
          this.reachable = state === 'online'
          this.changed()
        },
      })
    })()
  }

  private async loadState(): Promise<void> {
    for (const [, value] of await this.kv.scan('thread:')) {
      this.threads.push(record.dec<Thread>(this.owner.unwrap('thread', value)))
    }
    for (const [, value] of await this.kv.scan('msg:')) {
      const message = record.dec<OwnerMessage>(this.owner.unwrap('msg', value))
      this.list(message.thread).push(message)
      // Uploads that were interrupted can resume: keep expecting their files.
      for (const ref of message.dir === 'in' ? (message.files ?? []) : []) {
        if ((message.stored?.[toHex(ref.root)] ?? 0) < 1) this.expected.set(toHex(ref.root), { ref, message })
      }
    }
    for (const [key, value] of await this.kv.scan('outfile:')) {
      this.outgoing.set(key.slice('outfile:'.length), record.dec<StoredFile>(this.owner.unwrap('outfile', value)))
    }
    this.sortThreads()
  }

  private list(thread: string): OwnerMessage[] {
    let list = this.messages.get(thread)
    if (!list) this.messages.set(thread, (list = []))
    return list
  }

  private sortThreads(): void {
    this.threads.sort((a, b) => b.lastTs - a.lastTs)
  }

  private async saveThread(thread: Thread): Promise<void> {
    await this.kv.set(`thread:${thread.id}`, this.owner.wrap('thread', record.enc(thread)))
  }

  private async saveMessage(message: OwnerMessage): Promise<void> {
    await this.kv.set(messageKey(message), this.owner.wrap('msg', record.enc(message)))
  }

  // ---- epoch keys: the TTL state machine ---------------------------------------

  /** Create keys for upcoming epochs, in the vault. Local only. */
  private async rotateKeys(): Promise<void> {
    const [first, last] = this.epochs.published(nowSeconds())
    let added = false
    for (let epoch = first; epoch <= last; epoch++) {
      if (this.secrets.epochs.has(epoch)) continue
      this.secrets.epochs.set(epoch, epochGenerate().seed)
      added = true
    }
    if (added) {
      this.takeEpochs()
      await this.saveLocal()
    }
  }

  private refreshEpochRows(): void {
    const now = nowSeconds()
    this.epochRows = [...this.epochKeys.keys()]
      .sort((a, b) => a - b)
      .map((epoch) => ({ epoch, state: this.epochs.state(epoch, now), shredAt: this.epochs.shredAt(epoch) }))
    this.changed()
  }

  /**
   * Advance the epoch state machine (spec section 3): create keys for
   * upcoming epochs, destroy the secrets of expired ones, and bring the
   * repository up to date. Runs in the background; never throws.
   */
  async tick(): Promise<void> {
    if (this.phase !== 'running' || this.ticking) return
    this.ticking = true
    try {
      await this.rotateKeys()
      const now = nowSeconds()
      // Before a secret goes, take in whatever was sealed to it and is still
      // waiting on a relay or in the vault. After this it can never be read.
      const due = [...this.secrets.epochs.keys()].filter((epoch) => this.epochs.state(epoch, now) === 'shredded')
      if (due.length) {
        await this.collect()
        // Destroying the secret is what makes the TTL real: the vault is
        // rewritten without it, and the branch history that held older
        // copies is squashed below.
        for (const epoch of due) this.secrets.epochs.delete(epoch)
        this.takeEpochs()
        await this.saveLocal()
      }
      await this.publish(now)
      await this.redeliver()
    } catch (err) {
      this.publishError = causeOf(err)
    } finally {
      this.ticking = false
      this.changed()
    }
  }

  /**
   * Merge with the vault in the repository and write the result back if it
   * differs, compare-and-swap, so two signed-in devices never undo each
   * other: a write that lost a race is merged again and retried.
   */
  private async syncVault(): Promise<{ written: Promise<void> }> {
    const publisher = this.publisher!
    {
      const found = await publisher.read(VAULT_PATH)
      let theirs: VaultSecrets | undefined
      let base = this.vaultFile
      if (found) {
        const file = decodeVault(found.bytes)
        if (file.oik !== this.vaultFile.oik) {
          throw new Error(`${this.repoName} now holds the key vault of a different inbox; sign out and sign in again`)
        }
        theirs = openBody(file, this.vaultKey)
        // Passkeys added on another device live in the repository's copy.
        const ours = this.vaultFile.slots
        base = this.slotsChanged ? { ...file, slots: mergeSlots(ours, file.slots) } : file
      }
      const now = nowSeconds()
      const merged = theirs ? mergeSecrets(this.secrets, theirs, (e) => this.epochs.state(e, now) === 'shredded') : this.secrets
      const settingsMoved = JSON.stringify(merged.settings) !== JSON.stringify(this.secrets.settings)
      this.secrets = merged
      this.settings = merged.settings
      this.takeEpochs()
      if (settingsMoved) this.connectServices()

      if (theirs && found && sameSecrets(merged, theirs) && !this.slotsChanged) {
        this.vaultFile = decodeVault(found.bytes)
        this.passkeySlots = passkeyCredentials(this.vaultFile).length
        await this.kv.set(LOCAL_VAULT, found.bytes)
        return { written: Promise.resolve() }
      }
      const next = sealBody(base, this.vaultKey, merged)
      this.vaultFile = next
      this.passkeySlots = passkeyCredentials(next).length
      await this.kv.set(LOCAL_VAULT, encodeVault(next))
      // Queued, not awaited: owner.json joins it in the same commit. A lost
      // race shows as a Conflict there, and the next tick merges again.
      const slotsWritten = this.slotsChanged
      // Wrapped: an async function returning a bare promise would wait for it.
      const written = publisher.write(VAULT_PATH, encodeVault(next), found?.version).then(() => {
        if (slotsWritten) this.slotsChanged = false
      })
      return { written }
    }
  }

  private async publish(now: number): Promise<void> {
    if (!this.publisher) return
    this.syncing = true
    this.changed()
    try {
      const { written: vaultWritten } = await this.syncVault()
      const [first, last] = this.epochs.published(now)
      const oldest = this.epochs.live(now)[0]
      const profile: OwnerProfile = {
        v: 1,
        issued: now,
        name: this.settings.name,
        github: this.where.repo && this.login ? { login: this.login, repo: this.repoName } : undefined,
        ...PARAMS,
        receivers: [{ kind: 'dashboard', node: this.endpointId }],
        pow: { alg: 1, bits: POW_BITS },
        buffers: this.bufferSpecs(),
        shredded_before: oldest,
        epochs: [],
      }
      for (let epoch = first; epoch <= last; epoch++) {
        const key = this.epochKeys.get(epoch)
        if (key) profile.epochs.push({ e: epoch, pk: b64u.enc(key.public) })
      }
      const { written: ownerWritten } = await this.queueOwner(profile)

      // Replies of expired epochs go. Every commit has no parent, so nothing
      // removed (nor an older vault, with destroyed epoch secrets in it)
      // stays reachable from the branch. Selecting by path also catches
      // expiries this dashboard was closed for.
      const expired = (await this.publisher.list('')).filter((path) => {
        const epoch = EPOCH_PATH.exec(path)
        return epoch !== null && Number(epoch[1]) < oldest
      })
      const removed = expired.map((path) => this.publisher!.remove(path))
      // One commit for all of it: one run of the workflow, which redeploys the page.
      await this.publisher.settled()
      await Promise.all([vaultWritten, ownerWritten, ...removed])
      this.publishError = undefined
      this.synced = true
      this.inboxExists = true
    } catch (err) {
      this.publishError = errorText(err)
      this.synced = false
    } finally {
      this.syncing = false
      this.changed()
    }
  }

  /**
   * Queue owner.json when something besides its date changed. Returns once
   * it is queued, so it joins the commit that is about to be made; `written`
   * settles with that commit.
   */
  private async queueOwner(body: OwnerProfile): Promise<{ written: Promise<void> }> {
    const digest = utf8.enc(JSON.stringify({ ...body, issued: 0 }))
    const last = await this.kv.get('published:owner')
    if (last && utf8.dec(last) === utf8.dec(digest)) return { written: Promise.resolve() }
    const written = this.publisher!.put(OWNER_PATH, signOwner(this.owner, body)).then(() => this.kv.set('published:owner', digest))
    return { written }
  }



  // ---- the inbox, live ----------------------------------------------------------

  /**
   * Subscribe to the inbox topic on every ntfy relay: a drop left there
   * arrives within a fraction of a second, with no polling. Reopened when
   * the relay settings change.
   */
  private listenInbox(): void {
    for (const subscription of this.subscriptions) subscription.close()
    this.subscriptions = []
    this.relayStates = {}
    const topic = inboxTopic(bufferTopic(this.owner.oik))
    for (const spec of this.bufferSpecs()) {
      if (spec.kind !== 'ntfy') continue
      const assembler = new BufferAssembler()
      const cursorKey = `cursor:ntfy:${spec.url}`
      void this.kv.get(cursorKey).then((cursor) => {
        if (this.phase !== 'running') return
        const since = cursor ? String(Math.max(Number(utf8.dec(cursor)) - 300, nowSeconds() - 12 * 3600)) : '12h'
        this.subscriptions.push(
          listen(spec.url, topic, {
            since,
            onMessage: (text, _id, time) => {
              const item = assembler.push(text)
              if (item) void this.takeBuffered(item)
              if (time) void this.kv.set(cursorKey, utf8.enc(String(time)))
            },
            onState: (state, problem) => {
              const was = this.relayStates[spec.url]
              this.relayStates = { ...this.relayStates, [spec.url]: state }
              this.relayProblem = state === 'live' ? undefined : problem
              // Back after a gap: also read the harvest vault, which may hold what the relay no longer does.
              if (state === 'live' && was === 'retrying') void this.collect()
              this.changed()
            },
          }),
        )
      })
    }
  }

  /** How the live inbox is doing, over all relays. */
  get relay(): 'live' | 'connecting' | 'retrying' | 'off' {
    const states = Object.values(this.relayStates)
    if (!this.bufferSpecs().some((spec) => spec.kind === 'ntfy')) return 'off'
    if (states.includes('live')) return 'live'
    if (!states.length || states.includes('connecting')) return 'connecting'
    return 'retrying'
  }

  // ---- collecting from the relays and the vault ----------------------------------

  /**
   * Take in everything senders left while this dashboard was closed: from
   * each relay directly, and from the vault, where the harvest job files
   * what it found on the relays before their retention ran out. Runs on
   * opening, when a relay comes back, and every few minutes; live messages
   * do not wait for it.
   */
  async collect(): Promise<void> {
    if (this.phase !== 'running' || this.collecting) return
    this.collecting = true
    this.changed()
    const errors: Record<string, string> = {}
    // Every source at once: a relay that is slow or down must not hold up
    // the others. What they return is taken in one at a time (see `taking`).
    const fromBuffer = async (buffer: Buffer): Promise<void> => {
      const key = `cursor:${buffer.id}`
      try {
        const cursor = await this.kv.get(key)
        const next = await bounded(
          buffer.drain(cursor && utf8.dec(cursor), (item) => this.takeBuffered(item)),
          buffer.id,
        )
        if (next) await this.kv.set(key, utf8.enc(next))
      } catch (err) {
        errors[buffer.id] = errorText(err)
      }
    }
    const fromVault = async (): Promise<void> => {
      try {
        for (const entry of (await this.vault?.list()) ?? []) {
          const eid = /([0-9a-f]{64})\.bin$/.exec(entry.path)?.[1]
          // Deleted by the owner: remove the copy the harvest job filed again.
          if (eid && this.secrets.purged.has(eid)) {
            void this.vaultWriter?.remove(entry.path).catch(() => undefined)
            continue
          }
          const seen = `vault:${entry.path}`
          if (await this.kv.get(seen)) continue
          const envelope = await this.vault!.get(entry)
          if (!envelope) continue
          await this.takeEnvelope(envelope)
          await this.kv.set(seen, new Uint8Array([1]))
        }
      } catch (err) {
        errors.vault = errorText(err)
      }
    }
    await Promise.all([...this.buffers.map(fromBuffer), fromVault()])
    this.collectErrors = errors
    this.collectedAt = Date.now()
    this.collecting = false
    this.changed()
  }

  /** A relay is public: keep only what carries the stamp this inbox demands. */
  private async takeBuffered(item: Uint8Array): Promise<void> {
    let envelope: Uint8Array
    try {
      envelope = bufferCheck(item, POW_BITS)
    } catch {
      return
    }
    await this.takeEnvelope(envelope)
  }

  /**
   * Open a stored drop with whichever epoch secret still exists for it. The
   * acceptance window does not apply here: it limits how late a receiver
   * takes custody, and this drop was taken into custody earlier, by a relay
   * or by the harvest job.
   */
  private takeEnvelope(envelope: Uint8Array): Promise<void> {
    return this.oneAtATime(async () => {
      let opened: Opened
      try {
        const head = envelopePeek(envelope)
        const key = this.epochKeys.get(head.epoch)
        if (head.kind !== 'drop' || !key) return
        opened = this.owner.openDrop(key.seed, envelope)
      } catch {
        return
      }
      await this.ingest(opened, undefined, nowSeconds())
    })
  }

  /**
   * Run `task` after every task queued before it. The same envelope can
   * arrive live and from each relay moments apart, and recording one must
   * not interleave with the check that another already recorded it.
   */
  private oneAtATime<T>(task: () => Promise<T>): Promise<T> {
    const run = this.taking.then(task, task)
    this.taking = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  // ---- receiving files live (Live Wire, on demand) -----------------------------------

  private async serve(server: WireServer): Promise<void> {
    for (;;) {
      const event = (await server.next()) as WireEvent | null
      if (!event) break
      try {
        await this.handle(server, event)
      } catch {
        if ('id' in event) {
          try {
            server.refuse(event.id, Refusal.Busy)
          } catch {
            // Already answered.
          }
        }
      }
    }
  }

  private async handle(server: WireServer, event: WireEvent): Promise<void> {
    switch (event.type) {
      case 'opened':
      case 'seen':
        return
      case 'closed': {
        this.conns.delete(event.conn)
        this.listening.delete(event.conn)
        return this.refreshConnected()
      }
      case 'listening': {
        this.listening.add(event.conn)
        return
      }
      case 'drop':
        return this.onDrop(server, event)
      case 'putBegin': {
        const root = toHex(event.root)
        const expected = this.expected.get(root)
        if (!expected) return server.refuse(event.id, Refusal.NotFound)
        const { ref } = expected
        const shape = new FileOpener(ref.key, ref.size, ref.paddedSize)
        const fits = shape.chunks === event.chunks && shape.totalCipher === event.totalCipher
        if (!fits) return server.refuse(event.id, Refusal.Malformed)
        return server.acceptFrom(event.id, await this.chunks.have(root, event.chunks))
      }
      case 'putChunk': {
        const root = toHex(event.root)
        const expected = this.expected.get(root)
        if (!expected) return server.refuse(event.id, Refusal.NotFound)
        await this.chunks.write(root, event.index, event.cipher)
        const total = Math.max(1, Math.ceil(expected.ref.paddedSize / (1 << 20)))
        // Leave 100% for putEnd, when the sender confirmed the file is whole.
        ;(expected.message.stored ??= {})[root] = Math.min((event.index + 1) / total, 0.999)
        this.changed()
        return server.accept(event.id)
      }
      case 'putEnd': {
        const root = toHex(event.root)
        const expected = this.expected.get(root)
        if (!expected) return server.refuse(event.id, Refusal.NotFound)
        ;(expected.message.stored ??= {})[root] = 1
        this.expected.delete(root)
        await this.saveMessage(expected.message)
        this.changed()
        return server.accept(event.id)
      }
      case 'getBegin': {
        const file = this.outgoing.get(toHex(event.root))
        // Attachments are served only to the thread they were sent to.
        if (!file || this.conns.get(event.conn) !== file.thread) return server.refuse(event.id, Refusal.NotFound)
        return server.acceptFile(event.id, event.root, file.leaves, file.totalCipher)
      }
      case 'getChunk': {
        const file = this.outgoing.get(toHex(event.root))
        const cipher =
          file && this.conns.get(event.conn) === file.thread && (await this.chunks.read(file.store, event.index))
        return cipher ? server.acceptChunk(event.id, cipher) : server.refuse(event.id, Refusal.NotFound)
      }
    }
  }

  private async onDrop(server: WireServer, event: Extract<WireEvent, { type: 'drop' }>): Promise<void> {
    const now = nowSeconds()
    const eid = envelopeId(event.envelope)
    if (!stampVerify(eid, event.stamp, POW_BITS)) return server.refuse(event.id, Refusal.WeakStamp)

    const head = envelopePeek(event.envelope)
    const key = this.epochKeys.get(head.epoch)
    if (head.kind !== 'drop' || !key || !this.epochs.receiverAccepts(head.epoch, now)) {
      return server.refuse(event.id, Refusal.EpochNotAccepted)
    }
    let opened: Opened
    try {
      opened = this.owner.openDrop(key.seed, event.envelope)
    } catch {
      return server.refuse(event.id, Refusal.Malformed)
    }
    await this.oneAtATime(() => this.ingest(opened, event.conn, now))
    server.accept(event.id)
  }

  /**
   * Whether the Live Wire receiver should run: files on their way in, files
   * this dashboard sent that may be fetched, or the owner asked for it.
   */
  private wantsReceiver(): boolean {
    return this.settings.live || this.expected.size > 0 || this.outgoing.size > 0
  }

  // ---- recording what arrives -----------------------------------------------------

  /**
   * Record an opened drop. `conn` is the live connection it arrived on, which
   * it binds to its thread; a drop from a relay or the vault has none.
   */
  private async ingest(opened: Opened, conn: number | undefined, now: number): Promise<void> {
    const { payload } = opened
    const threadId = toHex(opened.threadId)
    const eid = toHex(opened.eid)
    if (this.secrets.purged.has(eid)) return
    if (conn !== undefined) {
      this.conns.set(conn, threadId)
      this.refreshConnected()
    }
    const meta = this.secrets.threads.get(threadId)
    // Deleted before this was written: it belongs to the deleted past.
    if (meta?.clearedAt !== undefined && payload.ts <= meta.clearedAt) return

    const control = payload.ctl
    let thread = this.threads.find((t) => t.id === threadId)
    // A stranger whose first word is a control message has said nothing yet.
    if (!thread && control !== undefined) return
    if (!thread) {
      if (meta?.blocked) return
      thread = {
        id: threadId,
        sid: opened.signer,
        replyPk: opened.replyPk!,
        tagKey: opened.tagKey!,
        lastTs: 0,
        unread: 0,
        preview: '',
      }
      this.threads.push(thread)
    }
    for (const cred of payload.creds ?? []) await this.acceptInvite(thread, cred, now)

    if (control === CTL_DELETE) {
      // The sender deleted one message, or the whole conversation, for both of you.
      if (payload.replyTo) await this.removeMessages(thread, [toHex(payload.replyTo)], false)
      else await this.clearThread(thread, payload.ts, false)
      return
    }
    // The same envelope may arrive live, from each relay and from the vault.
    const eidKey = `eid:${eid}`
    if (control !== undefined || (await this.kv.get(eidKey))) {
      await this.saveThread(thread)
      return this.changed()
    }
    await this.kv.set(eidKey, new Uint8Array([1]))
    if (meta?.blocked) return

    const message: OwnerMessage = {
      id: toHex(payload.id),
      thread: threadId,
      dir: 'in',
      ts: payload.ts,
      text: payload.text,
      files: payload.files,
      state: 'received',
      eid,
      epoch: opened.epoch,
    }
    for (const ref of payload.files ?? []) this.expected.set(toHex(ref.root), { ref, message })
    const list = this.list(threadId)
    list.push(message)
    list.sort((a, b) => a.ts - b.ts)
    thread.lastTs = Math.max(thread.lastTs, payload.ts)
    thread.unread++
    thread.preview = payload.text?.slice(0, 80) ?? (payload.files?.length ? `📎 ${payload.files.map((f) => f.name).join(', ')}` : '')
    this.sortThreads()
    await this.saveMessage(message)
    await this.saveThread(thread)
    this.changed()
    // Tell a sender who is still around that it arrived. Old messages, read
    // back from the vault on a new device, are not acknowledged again.
    if (Date.now() - payload.ts < ACK_WINDOW_MS) void this.sendControl(thread, { ctl: CTL_ACK, replyTo: payload.id }, false)
    if (payload.files?.length) this.ensureReceiver()
  }

  /** An invite verifies the first sender who presents it, and only that one. */
  private async acceptInvite(thread: Thread, cred: Uint8Array, now: number): Promise<void> {
    let invite: InviteInfo
    try {
      invite = this.owner.verifyInvite(cred, now)
    } catch {
      return
    }
    const key = `invite:${toHex(invite.id)}`
    const claimed = await this.kv.get(key)
    if (!claimed) await this.kv.set(key, utf8.enc(thread.id))
    if (!claimed || utf8.dec(claimed) === thread.id) thread.invited = invite.label
  }

  private refreshConnected(): void {
    this.connected = new Set(this.conns.values())
    this.changed()
  }

  markRead(threadId: string): void {
    const thread = this.threads.find((t) => t.id === threadId)
    if (!thread?.unread) return
    thread.unread = 0
    void this.saveThread(thread)
    this.changed()
  }

  // ---- what the owner decided about a thread ----------------------------------------

  /** How a thread shows: its name, whether verified (and as what), whether blocked. */
  view(thread: Thread): { name: string; verified?: string; blocked: boolean; anonymous: boolean } {
    const meta = this.secrets?.threads.get(thread.id)
    const verified = meta?.verified?.label ?? thread.invited
    const name = meta?.name ?? verified
    return { name: name ?? `#${thread.id.slice(0, 6)}`, verified, blocked: !!meta?.blocked, anonymous: !name }
  }

  private async setMeta(threadId: string, change: (meta: ThreadMeta) => ThreadMeta): Promise<void> {
    const current = this.secrets.threads.get(threadId) ?? { updated: 0 }
    this.secrets.threads.set(threadId, { ...change({ ...current }), updated: Date.now() })
    await this.saveLocal()
    this.changed()
    void this.tick()
  }

  /** Whether the owner (not an invite) verified this thread. */
  secretsVerified(threadId: string): boolean {
    return !!this.secrets?.threads.get(threadId)?.verified
  }

  renameThread(threadId: string, name: string): Promise<void> {
    return this.setMeta(threadId, (meta) => ({ ...meta, name: name.trim() || undefined }))
  }

  blockThread(threadId: string, blocked: boolean): Promise<void> {
    return this.setMeta(threadId, (meta) => ({ ...meta, blocked: blocked || undefined }))
  }

  /**
   * Verify an existing sender under `label`: a credential signed by the
   * owner identity, bound to this sender's identity key, kept with the keys
   * and sent to the sender so their side shows it too.
   */
  async verifyThread(threadId: string, label: string): Promise<void> {
    const thread = this.threads.find((t) => t.id === threadId)
    if (!thread || !label.trim()) return
    const cred = this.owner.verifySender(thread.sid, label.trim(), nowSeconds())
    await this.setMeta(threadId, (meta) => ({ ...meta, name: meta.name ?? label.trim(), verified: { label: label.trim(), cred: b64u.enc(cred) } }))
    await this.sendControl(thread, { ctl: CTL_VERIFIED, creds: [cred] }, true)
  }

  async unverifyThread(threadId: string): Promise<void> {
    const thread = this.threads.find((t) => t.id === threadId)
    if (!thread) return
    await this.setMeta(threadId, (meta) => ({ ...meta, verified: undefined }))
    await this.sendControl(thread, { ctl: CTL_VERIFIED }, true)
  }

  // ---- replying -----------------------------------------------------------------

  /**
   * Seal a payload to a thread and push it to the sender at once: on every
   * relay's mailbox topic for the thread (live, a fraction of a second), and
   * over Live Wire too if they are connected. With `persist` it is also
   * appended to the thread's mailbox file in the repository, where a sender
   * who was away finds it; that commit happens in the background.
   */
  private async push(thread: Thread, envelope: Uint8Array): Promise<boolean> {
    const topic = threadTopic(mailboxTopic(thread.tagKey))
    const relays = this.bufferSpecs().filter((spec): spec is Extract<BufferSpec, { kind: 'ntfy' }> => spec.kind === 'ntfy')
    const results = await Promise.allSettled(relays.map((spec) => publish(spec.url, topic, envelope)))
    const conn = [...this.listening].find((c) => this.conns.get(c) === thread.id)
    if (conn !== undefined && this.server) void this.server.pushReply(conn, envelope).catch(() => false)
    return results.some((result) => result.status === 'fulfilled') || conn !== undefined
  }

  private async sendControl(thread: Thread, fields: Partial<Payload>, persist: boolean): Promise<void> {
    const epoch = this.epochs.at(nowSeconds())
    const envelope = this.owner.sealReply(thread.sid, thread.replyPk, epoch, { id: randomBytes(16), ts: Date.now(), ...fields })
    await this.push(thread, envelope).catch(() => false)
    if (persist) await this.appendToMailbox(thread, epoch, envelope).catch(() => undefined)
  }

  /**
   * Change one mailbox file. Changes to the same file run one after another,
   * and only the read and the queuing are serialised: the commit that
   * carries them is awaited outside, so replies are not held up by it.
   */
  private editMailbox(path: string, edit: (current: Uint8Array) => Uint8Array | undefined): Promise<void> {
    const publisher = this.publisher
    if (!publisher) return Promise.reject(new Error('publishing needs a GitHub token'))
    let committed!: Promise<void>
    const queued = this.mailboxes.then(async () => {
      const current = (await publisher.get(path)) ?? new Uint8Array()
      const next = edit(current)
      committed = next === undefined ? Promise.resolve() : next.length ? publisher.put(path, next) : publisher.remove(path)
    })
    this.mailboxes = queued.catch(() => undefined)
    return queued.then(() => committed)
  }

  private appendToMailbox(thread: Thread, epoch: number, envelope: Uint8Array): Promise<void> {
    const eid = toHex(envelopeId(envelope))
    return this.editMailbox(mailboxPath(thread.tagKey, epoch), (current) => {
      // Already there (a retry after a commit that did land): leave it.
      if (mailboxSplit(current).some((item) => toHex(envelopeId(item)) === eid)) return undefined
      return mailboxAppend(current, envelope)
    })
  }

  async reply(threadId: string, text: string, files: File[], onProgress?: (done: number) => void): Promise<void> {
    const thread = this.threads.find((t) => t.id === threadId)
    if (!thread) return
    const refs: FileRef[] = []
    for (const [n, file] of files.entries()) {
      const { staged, ref } = await stageFile(file, this.chunks, (done) => onProgress?.((n + done) / files.length))
      const stored: StoredFile = { ...staged, thread: threadId }
      const root = toHex(ref.root)
      this.outgoing.set(root, stored)
      await this.kv.set(`outfile:${root}`, this.owner.wrap('outfile', record.enc(stored)))
      refs.push(ref)
    }

    const payload: Payload = {
      id: randomBytes(16),
      ts: Date.now(),
      text: text.trim() || undefined,
      files: refs.length ? refs : undefined,
    }
    const epoch = this.epochs.at(nowSeconds())
    const envelope = this.owner.sealReply(thread.sid, thread.replyPk, epoch, payload)
    const message: OwnerMessage = {
      id: toHex(payload.id),
      thread: threadId,
      dir: 'out',
      ts: payload.ts,
      text: payload.text,
      files: payload.files,
      state: 'sending',
      envelope,
      eid: toHex(envelopeId(envelope)),
      epoch,
      saved: false,
    }
    this.list(threadId).push(message)
    thread.lastTs = payload.ts
    thread.preview = payload.text?.slice(0, 80) ?? `📎 ${refs.map((r) => r.name).join(', ')}`
    this.sortThreads()
    await this.saveThread(thread)
    await this.saveMessage(message)
    this.changed()
    if (refs.length) this.ensureReceiver()
    await this.deliver(thread, message)
  }

  /** Push a reply live and keep it in the repository; each part retried until done. */
  private async deliver(thread: Thread, message: OwnerMessage): Promise<void> {
    const envelope = message.envelope
    if (!envelope) return
    if (message.state === 'sending' || message.state === 'failed') {
      const pushed = await this.push(thread, envelope).catch(() => false)
      message.state = pushed ? 'sent' : 'failed'
      message.note = pushed ? undefined : 'No relay took it; it is tried again on its own.'
      await this.saveMessage(message)
      this.changed()
    }
    if (!message.saved && this.publisher) {
      try {
        await this.appendToMailbox(thread, message.epoch!, envelope)
        message.saved = true
        // Sent and saved: the envelope has no further use here.
        if (message.state === 'sent') message.envelope = undefined
      } catch (err) {
        message.note = `Not saved to ${this.repoName} yet: ${errorText(err)}`
      }
      await this.saveMessage(message)
      this.changed()
    }
  }

  /** Replies that did not get everywhere: tried again on every tick. */
  private async redeliver(): Promise<void> {
    for (const thread of this.threads) {
      for (const message of this.list(thread.id)) {
        if (message.dir === 'out' && (message.state === 'failed' || message.state === 'sending' || !message.saved) && message.envelope) {
          await this.deliver(thread, message)
        }
      }
    }
  }

  // ---- deleting -------------------------------------------------------------------

  /**
   * Delete messages of a thread here, and everywhere the repository keeps
   * them: replies out of the thread's mailbox file, drops out of the
   * harvest vault. The envelopes stay on the relays until their retention
   * (twelve hours on ntfy.sh) ends; they are listed as purged so no device
   * shows them again. With `tell`, the sender is asked to delete them too.
   */
  async deleteMessage(threadId: string, messageId: string): Promise<void> {
    const thread = this.threads.find((t) => t.id === threadId)
    if (!thread) return
    await this.removeMessages(thread, [messageId], true)
  }

  private async removeMessages(thread: Thread, ids: string[], tell: boolean): Promise<void> {
    const list = this.list(thread.id)
    const doomed = list.filter((message) => ids.includes(message.id))
    for (const message of doomed) {
      list.splice(list.indexOf(message), 1)
      await this.forgetMessage(message)
    }
    await this.purge(thread, doomed)
    thread.preview = list.at(-1)?.text?.slice(0, 80) ?? ''
    await this.saveThread(thread)
    this.changed()
    if (tell) {
      for (const id of ids) await this.sendControl(thread, { ctl: CTL_DELETE, replyTo: fromHex(id) }, true)
    }
  }

  /** Delete a whole conversation, here and for the sender. */
  async deleteThread(threadId: string): Promise<void> {
    const thread = this.threads.find((t) => t.id === threadId)
    if (!thread) return
    await this.clearThread(thread, Date.now(), true)
  }

  private async clearThread(thread: Thread, until: number, tell: boolean): Promise<void> {
    const list = this.list(thread.id)
    const doomed = list.filter((message) => message.ts <= until)
    for (const message of doomed) await this.forgetMessage(message)
    this.messages.set(thread.id, list.filter((message) => message.ts > until))
    await this.setMeta(thread.id, (meta) => ({ ...meta, clearedAt: Math.max(until, meta.clearedAt ?? 0) }))
    await this.purge(thread, doomed)
    // Every mailbox file of the thread goes; the current one keeps only the
    // notice that tells a sender who was away to delete their copy.
    const [first, last] = this.epochs.live(nowSeconds())
    for (let epoch = first; epoch <= last; epoch++) {
      if (epoch === last && tell) continue
      void this.editMailbox(mailboxPath(thread.tagKey, epoch), (current) => (current.length ? new Uint8Array() : undefined)).catch(() => undefined)
    }
    if (tell) {
      const envelope = this.owner.sealReply(thread.sid, thread.replyPk, last, { id: randomBytes(16), ts: until, ctl: CTL_DELETE })
      await this.push(thread, envelope).catch(() => false)
      void this.editMailbox(mailboxPath(thread.tagKey, last), () => mailboxAppend(new Uint8Array(), envelope)).catch(() => undefined)
    }
    if (!this.messages.get(thread.id)?.length) {
      this.threads = this.threads.filter((t) => t !== thread)
      this.messages.delete(thread.id)
      await this.kv.del(`thread:${thread.id}`)
    }
    this.changed()
  }

  /** This device's copy of a message, its key and its files. */
  private async forgetMessage(message: OwnerMessage): Promise<void> {
    await this.kv.del(messageKey(message))
    for (const ref of message.files ?? []) {
      const root = toHex(ref.root)
      this.expected.delete(root)
      const out = this.outgoing.get(root)
      if (out) {
        this.outgoing.delete(root)
        await this.kv.del(`outfile:${root}`)
        await this.chunks.remove(out.store)
      } else {
        await this.chunks.remove(root)
      }
    }
  }

  /** Remove the repository's copies of `messages` and remember them as purged. */
  private async purge(thread: Thread, messages: OwnerMessage[]): Promise<void> {
    const until = (epoch: number | undefined): number => this.epochs.shredAt(epoch ?? this.epochs.at(nowSeconds()))
    const replies = new Map<number, Set<string>>()
    for (const message of messages) {
      if (!message.eid) continue
      this.secrets.purged.set(message.eid, until(message.epoch))
      if (message.dir === 'in') {
        void this.vaultWriter?.remove(`drops/e${message.epoch}/${message.eid}.bin`).catch(() => undefined)
      } else if (message.epoch !== undefined) {
        let set = replies.get(message.epoch)
        if (!set) replies.set(message.epoch, (set = new Set()))
        set.add(message.eid)
      }
    }
    for (const [epoch, eids] of replies) {
      void this.editMailbox(mailboxPath(thread.tagKey, epoch), (current) => {
        const kept = mailboxSplit(current).filter((item) => !eids.has(toHex(envelopeId(item))))
        return kept.reduce((file, item) => mailboxAppend(file, item), new Uint8Array())
      }).catch(() => undefined)
    }
    if (messages.length) {
      await this.saveLocal()
      void this.tick()
    }
  }

  // ---- files and invites ----------------------------------------------------------

  async save(ref: FileRef): Promise<void> {
    await saveFile(ref, this.chunks)
  }

  /** A link that marks whoever opens it as verified under `label`. */
  inviteLink(label: string): string {
    const invite = this.owner.mintInvite(label, nowSeconds() + INVITE_LIFETIME)
    return `${location.origin}${location.pathname}#i=${b64u.enc(invite)}`
  }
}

const messageKey = (message: OwnerMessage): string => `msg:${message.thread}:${pad(message.ts, 15)}:${message.id}`

const epochPublicCache = new Map<string, Uint8Array>()

/** The public half of an epoch key, from its seed. */
function epochPublic(seed: Uint8Array): Uint8Array {
  const tag = toHex(seed)
  const known = epochPublicCache.get(tag)
  if (known) return known
  const pk = new XWingSecret(seed).public
  epochPublicCache.set(tag, pk)
  return pk
}

/** Ours, plus any passkey slot only the repository's copy has. */
function mergeSlots(ours: VaultFile['slots'], theirs: VaultFile['slots']): VaultFile['slots'] {
  const known = new Set(ours.map((slot) => (slot.kind === 'passkey' ? slot.cred : '')))
  return [...ours, ...theirs.filter((slot) => slot.kind === 'passkey' && !known.has(slot.cred))]
}
