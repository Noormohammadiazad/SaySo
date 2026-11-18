// Reading the vault: sealed drops the harvest job filed while the owner was
// away. The vault is written by the repository's own workflow; the dashboard
// only reads it, through the GitHub API.
import { b64 } from '../core/bytes'
import { timed } from '../net'
import type { DataLocation } from './location'

export interface VaultEntry {
  /** `drops/e<epoch>/<eid>.bin`: also what the dashboard remembers it by. */
  path: string
  /** How `get` finds it: the blob id on GitHub, the path locally. */
  ref: string
}

export interface Vault {
  list(): Promise<VaultEntry[]>
  get(entry: VaultEntry): Promise<Uint8Array | undefined>
}

const isDrop = (path: string): boolean => /^drops\/e\d+\/[0-9a-f]{64}\.bin$/.test(path)

export function openVault(where: DataLocation, token?: string, fetcher: typeof fetch = fetch): Vault {
  const http = timed(where.local ? 'the local vault' : 'GitHub', { timeoutMs: 30_000, fetcher })

  if (where.local) {
    const base = where.localVault!
    return {
      async list() {
        const res = await http(base + '?list', { cache: 'no-store' })
        const paths = res.ok ? ((await res.json()) as string[]) : []
        return paths.filter(isDrop).map((path) => ({ path, ref: path }))
      },
      async get(entry) {
        const res = await http(base + entry.ref, { cache: 'no-store' })
        return res.ok ? new Uint8Array(await res.arrayBuffer()) : undefined
      },
    }
  }

  const repo = where.repo!
  const api = `${repo.api}/repos/${repo.owner}/${repo.name}`
  const headers = {
    accept: 'application/vnd.github+json',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  }
  return {
    async list() {
      // One request for the whole tree. The token is optional on a public
      // repository but lifts the anonymous rate limit.
      const res = await http(`${api}/git/trees/${repo.vaultBranch}?recursive=1`, { cache: 'no-store', headers })
      if (res.status === 404 || res.status === 409) return [] // No vault yet, or an empty one.
      if (!res.ok) throw new Error(`could not list the vault: HTTP ${res.status}`)
      const tree = (await res.json()) as { tree: { path: string; type: string; sha: string }[] }
      return tree.tree
        .filter((entry) => entry.type === 'blob' && isDrop(entry.path))
        .map((entry) => ({ path: entry.path, ref: entry.sha }))
    },
    async get(entry) {
      // By blob id: content-addressed, so it cannot be stale or swapped.
      const res = await http(`${api}/git/blobs/${entry.ref}`, { cache: 'no-store', headers })
      if (res.status === 404) return undefined
      if (!res.ok) throw new Error(`could not read ${entry.path}: HTTP ${res.status}`)
      const blob = (await res.json()) as { content: string; encoding: string }
      return blob.encoding === 'base64' ? b64.dec(blob.content) : undefined
    },
  }
}
