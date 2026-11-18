// owner.json: the one signed document on the data branch (spec section 10).
// Who the owner is, which GitHub repository vouches for them, the inbox
// parameters, the receivers, the relays, and the epoch keys to seal to.
import { b64u, utf8 } from '../core/bytes'
import type { Owner } from '../crypto'
import { verifyDoc } from '../crypto/ident'
import { NetworkError, timed } from '../net'

export interface Receiver {
  kind: 'dashboard' | 'courier'
  /** iroh endpoint id. */
  node: string
}

/** A public store-and-forward network senders may leave envelopes on. */
export type BufferSpec = { kind: 'ntfy'; url: string } | { kind: 'waku' }

export interface OwnerProfile {
  v: 1
  issued: number
  name: string
  /**
   * The GitHub account that published this, and the repository it was
   * published to. Only someone who can write to that repository can publish
   * here, which is what anchors the owner to it.
   */
  github?: { login: string; repo: string }
  epoch_len: number
  grace: number
  ttl: number
  receivers: Receiver[]
  pow: { alg: 1; bits: number }
  buffers: BufferSpec[]
  /** Epochs before this one are destroyed. */
  shredded_before: number
  epochs: { e: number; pk: string }[]
}

/** The file: the body is kept as text so its bytes are exactly what was signed. */
export interface SignedDoc {
  key: string
  sig: string
  body: string
}

export const OWNER_PATH = 'owner.json'

export function signOwner(owner: Owner, body: OwnerProfile): Uint8Array {
  const text = JSON.stringify(body)
  const doc: SignedDoc = { key: b64u.enc(owner.oik), sig: b64u.enc(owner.signDoc(utf8.enc(text))), body: text }
  return utf8.enc(JSON.stringify(doc))
}

/** What came of reading owner.json. */
export type Opened =
  | { status: 'ok'; key: Uint8Array; body: OwnerProfile }
  /** Well-formed, but not signed by the expected key: a different owner. */
  | { status: 'bad-signature' }
  /** Not a signed document at all: an error page, a proxy's interstitial, a cut-off file. */
  | { status: 'unreadable' }

/**
 * Verify owner.json and parse its body. `expected` is the pinned owner
 * identity; without it the document's own key is used, which is only
 * acceptable for the very first contact.
 *
 * Only a document that parses and fails its signature is `bad-signature`.
 * Anything that does not even parse says nothing about the owner, only
 * about the network, and is `unreadable`.
 */
export function openOwner(bytes: Uint8Array | string, expected?: Uint8Array): Opened {
  let doc: SignedDoc
  let body: Uint8Array
  let sig: Uint8Array
  let own: Uint8Array
  try {
    doc = JSON.parse(typeof bytes === 'string' ? bytes : utf8.dec(bytes)) as SignedDoc
    if (typeof doc.body !== 'string') return { status: 'unreadable' }
    body = utf8.enc(doc.body)
    sig = b64u.dec(doc.sig)
    own = b64u.dec(doc.key)
  } catch {
    return { status: 'unreadable' }
  }
  const key = expected ?? own
  if (!verifyDoc(key, body, sig)) {
    // A document that does not verify even under its own key is damaged,
    // not a sign of a different owner.
    return expected && verifyDoc(own, body, sig) ? { status: 'bad-signature' } : { status: 'unreadable' }
  }
  try {
    const parsed = JSON.parse(doc.body) as OwnerProfile
    return parsed.v === 1 && Array.isArray(parsed.epochs) ? { status: 'ok', key, body: parsed } : { status: 'unreadable' }
  } catch {
    return { status: 'unreadable' }
  }
}

/** Does the profile name this repository? GitHub names are case-insensitive. */
export const anchoredTo = (profile: OwnerProfile, repo?: { owner: string; name: string }): boolean =>
  !!repo && !!profile.github && profile.github.repo.toLowerCase() === `${repo.owner}/${repo.name}`.toLowerCase()

/**
 * Read a file from the site's copy of the data branch: bytes, or
 * `undefined` when it does not exist. A network failure throws a
 * `NetworkError`; it never looks like a missing file.
 *
 * The query string changes every 20 seconds. A CDN in front of the site
 * (Cloudflare, for one) may cache these files, `.bin` mailboxes and their
 * 404s included, for hours; a fresh query reaches the origin instead.
 */
export async function fetchData(base: string, path: string, http: typeof fetch = timed('this site')): Promise<Uint8Array | undefined> {
  const fresh = Math.floor(Date.now() / 20_000).toString(36)
  const res = await http(`${base}${path}?v=${fresh}`, { cache: 'no-store' })
  if (res.status === 404) return undefined
  if (!res.ok) throw new NetworkError(`this site answered HTTP ${res.status} for ${path}`, res.status)
  return new Uint8Array(await res.arrayBuffer())
}
