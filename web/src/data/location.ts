// Where this deployment keeps its data.
//
// Senders read the public data from the same site that served the page: the
// deploy workflow copies the data branch into the site under `data/`. That
// keeps reading possible wherever the page itself loads. (Networks exist
// that serve GitHub Pages and the GitHub API but refuse
// raw.githubusercontent.com.) The owner's dashboard reads and writes
// through the GitHub API instead, which sees changes at once.

import { NetworkError, timed } from '../net'
import { inlineData, type SiteConfig } from './inline'

export interface Repo {
  owner: string
  name: string
  /** Public data written by the dashboard: signed documents and mailboxes. */
  dataBranch: string
  /** Sealed drops filed by the harvest job. */
  vaultBranch: string
  /** GitHub API base URL, without a trailing slash. */
  api: string
}

export interface DataLocation {
  /** Stable name of this inbox, for naming browser storage. Never changes. */
  id: string
  /** URL prefix that data-branch paths are appended to, for reading. */
  base: string
  /** True when data lives in the local stand-ins instead of GitHub. */
  local: boolean
  /** Local stand-ins only: URL prefix of the vault. */
  localVault?: string
  repo?: Repo
  /** The ntfy relay a new inbox starts with. */
  ntfy: string
}

const LOCAL: DataLocation = { id: 'local', base: '/__data/', localVault: '/__vault/', local: true, ntfy: '/__ntfy' }
const NTFY = 'https://ntfy.sh'
/** A relay on this same site (the local stand-ins) or any https one. */
const RELAY = /^(https:\/\/[a-z0-9.-]+(:\d+)?|\/[a-z0-9_/-]+)$/i

const GITHUB_API = 'https://api.github.com'
/** Only https, or a same-site path for the local stand-ins. */
const API = /^(https:\/\/[a-z0-9.-]+|\/[a-z0-9_/-]+)$/i

function fromRepo(owner: string, name: string, api = GITHUB_API, ntfy = NTFY): DataLocation {
  return {
    ntfy: RELAY.test(ntfy) ? ntfy : NTFY,
    // GitHub names are case-insensitive; storage names must not depend on how
    // a link happened to spell them.
    id: `${owner}/${name}`.toLowerCase(),
    base: './data/',
    local: false,
    repo: { owner, name, dataBranch: 'main', vaultBranch: 'sayso-vault', api: API.test(api) ? api.replace(/\/+$/, '') : GITHUB_API },
  }
}

const REPO_NAME = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/

const REMEMBERED = 'sayso.location'

function fromConfig(config: SiteConfig): DataLocation | undefined {
  if (config.local) return LOCAL
  if (config.repo && REPO_NAME.test(config.repo)) {
    const [owner, name] = config.repo.split('/')
    return fromRepo(owner, name, config.api, config.ntfy)
  }
  return undefined
}

/**
 * The location written into the page itself, or else the one found on an
 * earlier visit: either way nothing waits on the network to learn which
 * repository this is.
 * Browser storage may be unavailable; then there is simply nothing remembered.
 */
export function rememberedLocation(): DataLocation | undefined {
  if (import.meta.env.DEV) return undefined
  const inline = inlineData().config
  if (inline) {
    const where = fromConfig(inline)
    if (where) return where
  }
  try {
    const saved = JSON.parse(localStorage.getItem(REMEMBERED) ?? 'null') as SiteConfig | null
    if (saved?.local) return LOCAL
    if (saved?.repo && REPO_NAME.test(saved.repo)) {
      const [owner, name] = saved.repo.split('/')
      return fromRepo(owner, name, saved.api, saved.ntfy)
    }
  } catch {
    // Unreadable or unavailable: nothing remembered.
  }
  return undefined
}

function remember(where: DataLocation | 'unconfigured'): void {
  try {
    if (where === 'unconfigured') localStorage.removeItem(REMEMBERED)
    else {
      const saved: SiteConfig = where.local
        ? { local: true }
        : { repo: `${where.repo!.owner}/${where.repo!.name}`, api: where.repo!.api, ntfy: where.ntfy }
      localStorage.setItem(REMEMBERED, JSON.stringify(saved))
    }
  } catch {
    // Not remembering only costs the next visit a request.
  }
}

/**
 * Where this deployment keeps its data, or `'unconfigured'` when it cannot
 * be told (no `sayso.config.json`, and not on `*.github.io`).
 *
 * Throws a `NetworkError` when the configuration could not be read. That is
 * a reason to try again, never a reason to say the site is unconfigured.
 */
export async function locateData(http: typeof fetch = timed('this site', { timeoutMs: 20_000 })): Promise<DataLocation | 'unconfigured'> {
  if (import.meta.env.DEV) return LOCAL
  const where = await lookUp(http)
  remember(where)
  return where
}

async function lookUp(http: typeof fetch): Promise<DataLocation | 'unconfigured'> {
  const res = await http('./sayso.config.json', { cache: 'no-cache' })
  let config: SiteConfig = {}
  if (res.ok) {
    try {
      config = (await res.json()) as SiteConfig
    } catch {
      // An HTML page where JSON should be: a proxy or CDN interstitial.
      throw new NetworkError('this site sent something other than its configuration; it may be behind a check page')
    }
  } else if (res.status !== 404) {
    throw new NetworkError(`this site answered HTTP ${res.status} for its configuration`, res.status)
  }
  const configured = fromConfig(config)
  if (configured) return configured

  // https://<owner>.github.io/<repo>/ - or the user site, whose repository
  // is named after the host.
  const host = /^([a-z0-9-]+)\.github\.io$/i.exec(location.hostname)
  if (!host) return 'unconfigured'
  const first = location.pathname.split('/').filter(Boolean)[0]
  return fromRepo(host[1], first ?? `${host[1]}.github.io`)
}
