// The owner's key vault: data/owner-vault.enc on the data branch.
//
// It holds everything the inbox needs to run on any device: the root key
// (identity, signing, receiver), the epoch secrets still alive, and the
// settings. It is public, like everything on the data branch, so it is
// sealed under a random vault key, and that key is wrapped once per way of
// unlocking it ("slots", as in LUKS): always a passphrase, through argon2id;
// optionally passkeys, through the WebAuthn PRF extension.
//
// What this costs: a copy of the vault plus the passphrase opens every epoch
// secret that copy holds. Epoch keys are still destroyed on schedule (the
// vault is rewritten without them and the branch history squashed), but a
// copy someone kept from before stays as strong as the passphrase. Hence the
// slow KDF and the length rule below.
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { b64u, concat, kdf, OwnerKeys, randomBytes, unwrap, utf8, wrap } from '../core'

export const VAULT_PATH = 'owner-vault.enc'
export const MIN_PASSPHRASE = 12

/** RFC 9106's second recommended setting, with one lane for JavaScript. */
const ARGON = { m: 64 * 1024, t: 3, p: 1 }

export interface VaultSettings {
  name: string
  /** Base URL of an ntfy-protocol relay; empty for none. */
  ntfy: string
  waku: boolean
  /** Run the Live Wire receiver (downloads the WebAssembly module). */
  live: boolean
  /** Unix ms of the last change, so two devices agree on the newer one. */
  updated: number
}

/** What the owner decided about one thread, kept with the keys so every device agrees. */
export interface ThreadMeta {
  /** The owner's name for this sender. */
  name?: string
  /** Set when the owner verified the sender: the label and the signed credential (b64u). */
  verified?: { label: string; cred: string }
  blocked?: boolean
  /** Messages up to this time (Unix ms) were deleted, the thread with them. */
  clearedAt?: number
  /** Unix ms of the last change, so two devices agree on the newer one. */
  updated: number
}

export interface VaultSecrets {
  root: Uint8Array
  /** Epoch number to its random seed. */
  epochs: Map<number, Uint8Array>
  settings: VaultSettings
  /** By thread id (hex). */
  threads: Map<string, ThreadMeta>
  /**
   * Envelopes the owner deleted (eid hex) until their epoch's secret is
   * gone: never shown again, and removed wherever they turn up.
   */
  purged: Map<string, number>
}

type PassphraseSlot = { kind: 'passphrase'; kdf: 'argon2id'; m: number; t: number; p: number; salt: string; key: string }
type PasskeySlot = { kind: 'passkey'; cred: string; key: string }
export type Slot = PassphraseSlot | PasskeySlot

export interface VaultFile {
  v: 1
  /** The identity this vault unlocks; binds every slot and the body to it. */
  oik: string
  slots: Slot[]
  body: string
}

interface Body {
  v: 1
  root: string
  epochs: { e: number; seed: string }[]
  settings: VaultSettings
  /** Absent in vaults written before threads were kept here. */
  threads?: Record<string, ThreadMeta>
  /** eid hex to Unix seconds after which it can be forgotten. */
  purged?: Record<string, number>
}

export class WrongPassphrase extends Error {
  constructor() {
    super('That passphrase does not open this inbox.')
    this.name = 'WrongPassphrase'
  }
}

const label = (what: string, oik: Uint8Array): Uint8Array => concat(utf8.enc(`sayso/v1/vault/${what}`), oik)

/** Why a new passphrase is not good enough, or `undefined`. */
export function passphraseProblem(passphrase: string): string | undefined {
  if ([...passphrase].length < MIN_PASSPHRASE) {
    return `Use at least ${MIN_PASSPHRASE} characters. The vault is public, so a short passphrase can be guessed offline.`
  }
  if (new Set(passphrase).size < 5) return 'That passphrase repeats too few characters to be hard to guess.'
  return undefined
}

/** Five groups of five letters and digits: about 125 bits. */
export function suggestPassphrase(): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
  const bytes = randomBytes(25)
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length])
  return [0, 5, 10, 15, 20].map((i) => chars.slice(i, i + 5).join('')).join('-')
}

async function passphraseKek(passphrase: string, slot: PassphraseSlot): Promise<Uint8Array> {
  return argon2idAsync(utf8.enc(passphrase.normalize('NFKC')), b64u.dec(slot.salt), {
    m: slot.m,
    t: slot.t,
    p: slot.p,
    dkLen: 32,
  })
}

const passkeyKek = (prf: Uint8Array): Uint8Array => kdf('sayso/v1/vault/passkey', prf)

function encodeBody(secrets: VaultSecrets): Uint8Array {
  const body: Body = {
    v: 1,
    root: b64u.enc(secrets.root),
    epochs: [...secrets.epochs].sort(([a], [b]) => a - b).map(([e, seed]) => ({ e, seed: b64u.enc(seed) })),
    settings: secrets.settings,
    threads: Object.fromEntries([...secrets.threads].sort(([a], [b]) => (a < b ? -1 : 1))),
    purged: Object.fromEntries([...secrets.purged].sort(([a], [b]) => (a < b ? -1 : 1))),
  }
  return utf8.enc(JSON.stringify(body))
}

/** A new vault for `secrets`, opened by `passphrase`. Returns the file and its vault key. */
export async function createVault(secrets: VaultSecrets, passphrase: string): Promise<{ file: VaultFile; key: Uint8Array }> {
  const oik = new OwnerKeys(secrets.root).oik
  const key = randomBytes(32)
  const file: VaultFile = { v: 1, oik: b64u.enc(oik), slots: [], body: '' }
  file.slots.push(await passphraseSlot(key, oik, passphrase))
  return { file: sealBody(file, key, secrets), key }
}

async function passphraseSlot(key: Uint8Array, oik: Uint8Array, passphrase: string): Promise<PassphraseSlot> {
  const slot: PassphraseSlot = { kind: 'passphrase', kdf: 'argon2id', ...ARGON, salt: b64u.enc(randomBytes(16)), key: '' }
  slot.key = b64u.enc(wrap(await passphraseKek(passphrase, slot), label('slot', oik), key))
  return slot
}

/** The vault key, from the passphrase. Slow on purpose (argon2id, 64 MiB). */
export async function unlockWithPassphrase(file: VaultFile, passphrase: string): Promise<Uint8Array> {
  const oik = b64u.dec(file.oik)
  for (const slot of file.slots) {
    if (slot.kind !== 'passphrase') continue
    try {
      return unwrap(await passphraseKek(passphrase, slot), label('slot', oik), b64u.dec(slot.key))
    } catch {
      // Not this slot.
    }
  }
  throw new WrongPassphrase()
}

/** The credential ids of the passkeys that can open this vault. */
export const passkeyCredentials = (file: VaultFile): Uint8Array[] =>
  file.slots.filter((slot): slot is PasskeySlot => slot.kind === 'passkey').map((slot) => b64u.dec(slot.cred))

/** The vault key, from a passkey's PRF output. */
export function unlockWithPasskey(file: VaultFile, credential: Uint8Array, prf: Uint8Array): Uint8Array {
  const oik = b64u.dec(file.oik)
  const id = b64u.enc(credential)
  for (const slot of file.slots) {
    if (slot.kind !== 'passkey' || slot.cred !== id) continue
    try {
      return unwrap(passkeyKek(prf), label('slot', oik), b64u.dec(slot.key))
    } catch {
      break
    }
  }
  throw new Error('That passkey does not open this inbox.')
}

export function addPasskey(file: VaultFile, key: Uint8Array, credential: Uint8Array, prf: Uint8Array): VaultFile {
  const oik = b64u.dec(file.oik)
  const slot: PasskeySlot = { kind: 'passkey', cred: b64u.enc(credential), key: b64u.enc(wrap(passkeyKek(prf), label('slot', oik), key)) }
  return { ...file, slots: [...file.slots.filter((s) => !(s.kind === 'passkey' && s.cred === slot.cred)), slot] }
}

/** Replace every passphrase slot with one for `passphrase`. */
export async function changePassphrase(file: VaultFile, key: Uint8Array, passphrase: string): Promise<VaultFile> {
  const slot = await passphraseSlot(key, b64u.dec(file.oik), passphrase)
  return { ...file, slots: [slot, ...file.slots.filter((s) => s.kind !== 'passphrase')] }
}

export function openBody(file: VaultFile, key: Uint8Array): VaultSecrets {
  const oik = b64u.dec(file.oik)
  const body = JSON.parse(utf8.dec(unwrap(key, label('body', oik), b64u.dec(file.body)))) as Body
  const secrets: VaultSecrets = {
    root: b64u.dec(body.root),
    epochs: new Map(body.epochs.map(({ e, seed }) => [e, b64u.dec(seed)])),
    settings: body.settings,
    threads: new Map(Object.entries(body.threads ?? {})),
    purged: new Map(Object.entries(body.purged ?? {})),
  }
  // The body is bound to the identity by its label; check the root agrees.
  const derived = b64u.enc(new OwnerKeys(secrets.root).oik)
  if (derived !== file.oik) throw new Error('the key vault is damaged: its root does not match its identity')
  return secrets
}

/** The same vault with a new body (a fresh nonce every time). */
export function sealBody(file: VaultFile, key: Uint8Array, secrets: VaultSecrets): VaultFile {
  return { ...file, body: b64u.enc(wrap(key, label('body', b64u.dec(file.oik)), encodeBody(secrets))) }
}

export const encodeVault = (file: VaultFile): Uint8Array => utf8.enc(JSON.stringify(file))

export function decodeVault(bytes: Uint8Array): VaultFile {
  let file: VaultFile
  try {
    file = JSON.parse(utf8.dec(bytes)) as VaultFile
  } catch {
    throw new Error('the key vault came back unreadable')
  }
  if (file?.v !== 1 || typeof file.oik !== 'string' || !Array.isArray(file.slots) || typeof file.body !== 'string') {
    throw new Error('the key vault came back unreadable')
  }
  return file
}

/**
 * Two devices' views of the vault, merged: every epoch either knows (the
 * repository's copy wins when both made one, since that is the one that may
 * have been published), none that is due for destruction, and the newer
 * settings.
 */
export function mergeSecrets(
  local: VaultSecrets,
  remote: VaultSecrets,
  shredded: (epoch: number) => boolean,
  now: number = Math.floor(Date.now() / 1000),
): VaultSecrets {
  const epochs = new Map<number, Uint8Array>()
  for (const [e, seed] of [...local.epochs, ...remote.epochs]) if (!shredded(e)) epochs.set(e, seed)
  for (const [e, seed] of remote.epochs) if (!shredded(e)) epochs.set(e, seed)
  const threads = new Map(remote.threads)
  for (const [id, meta] of local.threads) {
    const theirs = threads.get(id)
    if (!theirs || meta.updated > theirs.updated) threads.set(id, meta)
  }
  const purged = new Map<string, number>()
  for (const [eid, until] of [...local.purged, ...remote.purged]) {
    if (until > now) purged.set(eid, Math.max(until, purged.get(eid) ?? 0))
  }
  return {
    root: remote.root,
    epochs,
    settings: local.settings.updated > remote.settings.updated ? local.settings : remote.settings,
    threads,
    purged,
  }
}

/** Whether two views hold the same epochs and settings. */
export function sameSecrets(a: VaultSecrets, b: VaultSecrets): boolean {
  if (a.epochs.size !== b.epochs.size || JSON.stringify(a.settings) !== JSON.stringify(b.settings)) return false
  const sorted = (map: Map<string, unknown>): string => JSON.stringify([...map].sort(([x], [y]) => (x < y ? -1 : 1)))
  if (sorted(a.threads) !== sorted(b.threads) || sorted(a.purged) !== sorted(b.purged)) return false
  for (const [e, seed] of a.epochs) {
    const other = b.epochs.get(e)
    if (!other || b64u.enc(other) !== b64u.enc(seed)) return false
  }
  return true
}
