import { b64, utf8 } from '../core/bytes'
import { timed } from '../net'
import { Conflict, type Publisher } from './index'
import { rotatedWorkflowName, WORKFLOW_DIR } from './rotate'
import { TokenProblem } from './token'

export interface Target {
  owner: string
  name: string
  branch: string
  /** API base URL; https://api.github.com unless a stand-in replaces it. */
  api?: string
  /** Where the files live in the branch: `data/` on main, nothing on the vault. */
  prefix: string
  /**
   * Move the workflow to a new file name in the same commit. On main every
   * commit starts a run, and a new path makes it run #1; this is also what
   * redeploys the page after a data change, with no other trigger.
   */
  rotateWorkflow: boolean
}

export interface Options {
  /** The token's account; commits are authored as `<login>@users.noreply.github.com`. */
  login?: string
  /** Writes this close together go into one commit. */
  batchMs?: number
  /** ... but none waits longer than this. */
  maxDelayMs?: number
  timeoutMs?: number
}

interface TreeEntry {
  path: string
  mode: string
  type: string
  sha: string
}

interface Change {
  /** `undefined` removes the file. */
  bytes?: Uint8Array
  /** Required current blob id: a string, `null` for absent, `undefined` for no check. */
  expect?: string | null
  waiters: { resolve: () => void; reject: (err: unknown) => void }[]
}

const isWorkflow = (path: string): boolean => path.startsWith(WORKFLOW_DIR) && /\.ya?ml$/.test(path) && !path.slice(WORKFLOW_DIR.length).includes('/')

/**
 * Writes one branch through the GitHub REST API with the owner's own token.
 *
 * Every commit has no parent and the branch is moved onto it with force: the
 * branch always holds exactly one commit, the current state, and nothing
 * removed from it stays reachable from it. Writes are gathered for a moment
 * and committed together, so a reply and the files it touches are one
 * commit, and on main one workflow run.
 *
 * GitHub's REST API cannot move a branch only if it is still where it was
 * (a forced update has no lease), so before moving it the head is read again
 * and the commit is rebuilt if anyone moved it meanwhile. That narrows a
 * race between two writers to one round trip; it does not close it.
 */
export class GithubPublisher implements Publisher {
  private readonly repo: string
  private readonly http: typeof fetch
  private readonly pending = new Map<string, Change>()
  private timer?: ReturnType<typeof setTimeout>
  private firstQueued?: number
  private queue: Promise<unknown> = Promise.resolve()
  private login?: string
  private readonly texts = new Map<string, string>()
  private readonly batchMs: number
  private readonly maxDelayMs: number

  constructor(
    private readonly target: Target,
    private readonly token: string,
    options: Options = {},
    http: typeof fetch = fetch,
  ) {
    // Every call has a deadline, so a stalled request cannot hold anything up for good.
    this.http = timed('GitHub', { timeoutMs: options.timeoutMs ?? 30_000, fetcher: http })
    this.repo = `${target.api ?? 'https://api.github.com'}/repos/${target.owner}/${target.name}`
    this.login = options.login
    this.batchMs = options.batchMs ?? 2_000
    this.maxDelayMs = options.maxDelayMs ?? 10_000
  }

  // ---- reads ------------------------------------------------------------------

  /** `path` is under the repository (`/git/...`), unless `absolute`. */
  private call(path: string, init: RequestInit = {}, absolute = false): Promise<Response> {
    return this.http(absolute ? path : this.repo + path, {
      ...init,
      cache: 'no-store',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${this.token}`,
        'x-github-api-version': '2022-11-28',
        ...(init.body ? { 'content-type': 'application/json' } : {}),
      },
    })
  }

  private async json<T>(method: string, path: string, body?: unknown, absolute = false): Promise<T> {
    const res = await this.call(path, { method, body: body === undefined ? undefined : JSON.stringify(body) }, absolute)
    if (!res.ok) throw new Error(`GitHub ${method} ${path.split('?')[0]}: HTTP ${res.status}`)
    return res.json() as Promise<T>
  }

  private get ref(): string {
    return `heads/${this.target.branch}`
  }

  /** The commit the branch points at, or `undefined` if there is no branch. */
  private async head(): Promise<string | undefined> {
    const res = await this.call(`/git/ref/${this.ref}`)
    if (res.status === 404 || res.status === 409) return undefined
    if (!res.ok) throw new Error(`GitHub: could not read the ${this.target.branch} branch: HTTP ${res.status}`)
    return ((await res.json()) as { object: { sha: string } }).object.sha
  }

  private async entries(head: string): Promise<{ tree: string; files: TreeEntry[] }> {
    const commit = await this.json<{ tree: { sha: string } }>('GET', `/git/commits/${head}`)
    const listing = await this.json<{ tree: TreeEntry[]; truncated: boolean }>('GET', `/git/trees/${commit.tree.sha}?recursive=1`)
    if (listing.truncated) throw new Error(`the ${this.target.branch} branch has too many files to change through the API`)
    return { tree: commit.tree.sha, files: listing.tree.filter((entry) => entry.type === 'blob') }
  }

  private async blob(sha: string): Promise<Uint8Array> {
    const blob = await this.json<{ content: string }>('GET', `/git/blobs/${sha}`)
    return b64.dec(blob.content)
  }

  private async entry(path: string): Promise<{ sha: string; size: number; content?: string } | undefined> {
    const full = encodeURI(this.target.prefix + path)
    const res = await this.call(`/contents/${full}?ref=${encodeURIComponent(this.target.branch)}`)
    if (res.status === 404) return undefined
    if (!res.ok) throw new Error(`GitHub: could not read ${path}: HTTP ${res.status}`)
    const found = (await res.json()) as { sha: string; size: number; content?: string } | unknown[]
    return Array.isArray(found) ? undefined : found
  }

  private async fetchFile(path: string): Promise<{ bytes: Uint8Array; version: string } | undefined> {
    const entry = await this.entry(path)
    if (!entry) return undefined
    // Files over 1 MB come back without content; fetch the blob itself.
    const bytes = entry.content || entry.size === 0 ? b64.dec(entry.content ?? '') : await this.blob(entry.sha)
    return { bytes, version: entry.sha }
  }

  async get(path: string): Promise<Uint8Array | undefined> {
    const queued = this.pending.get(path)
    if (queued) return queued.bytes
    return (await this.serial(() => this.fetchFile(path)))?.bytes
  }

  async read(path: string): Promise<{ bytes: Uint8Array; version: string } | undefined> {
    if (this.pending.has(path)) await this.settled()
    return this.serial(() => this.fetchFile(path))
  }

  async list(prefix: string): Promise<string[]> {
    const found = await this.serial(async () => {
      const head = await this.head()
      if (!head) return []
      return (await this.entries(head)).files.map((entry) => entry.path)
    })
    const paths = new Set(
      found.filter((path) => path.startsWith(this.target.prefix)).map((path) => path.slice(this.target.prefix.length)),
    )
    for (const [path, change] of this.pending) {
      if (change.bytes) paths.add(path)
      else paths.delete(path)
    }
    return [...paths].filter((path) => path.startsWith(prefix)).sort()
  }

  // ---- writes -------------------------------------------------------------------

  put(path: string, bytes: Uint8Array): Promise<void> {
    return this.enqueue(path, { bytes })
  }

  remove(path: string): Promise<void> {
    return this.enqueue(path, {})
  }

  write(path: string, bytes: Uint8Array, version: string | undefined): Promise<void> {
    return this.enqueue(path, { bytes, expect: version ?? null })
  }

  settled(): Promise<void> {
    clearTimeout(this.timer)
    this.timer = undefined
    return this.flush()
  }

  private enqueue(path: string, change: Omit<Change, 'waiters'>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const previous = this.pending.get(path)
      // A later write to the same path replaces the earlier one; both callers
      // learn the outcome of the commit that carries the later.
      const waiters = [...(previous?.waiters ?? []), { resolve, reject }]
      const expect = change.expect !== undefined ? change.expect : previous?.expect
      this.pending.set(path, { bytes: change.bytes, expect, waiters })
      this.firstQueued ??= Date.now()
      clearTimeout(this.timer)
      const wait = Math.max(0, Math.min(this.batchMs, this.firstQueued + this.maxDelayMs - Date.now()))
      this.timer = setTimeout(() => {
        this.timer = undefined
        void this.flush().catch(() => undefined)
      }, wait)
    })
  }

  private serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task)
    this.queue = run.catch(() => undefined)
    return run
  }

  private flush(): Promise<void> {
    return this.serial(async () => {
      if (!this.pending.size) return
      const batch = new Map(this.pending)
      this.pending.clear()
      this.firstQueued = undefined
      try {
        await this.commit(batch)
        for (const change of batch.values()) for (const waiter of change.waiters) waiter.resolve()
      } catch (err) {
        for (const change of batch.values()) for (const waiter of change.waiters) waiter.reject(err)
        throw err
      }
    })
  }

  private async identity(): Promise<{ name: string; email: string }> {
    this.login ??= (await this.json<{ login: string }>('GET', `${this.target.api ?? 'https://api.github.com'}/user`, undefined, true)).login
    return { name: this.login, email: `${this.login}@users.noreply.github.com` }
  }

  private async text(sha: string): Promise<string> {
    let known = this.texts.get(sha)
    if (known === undefined) this.texts.set(sha, (known = utf8.dec(await this.blob(sha))))
    return known
  }

  /** One parentless commit with every change in `batch`, and the branch moved onto it. */
  private async commit(batch: Map<string, Change>): Promise<void> {
    const who = await this.identity()
    // Blobs depend only on the bytes: made once, whatever the retries.
    const blobs = new Map<string, string>()
    for (const [path, change] of batch) {
      if (!change.bytes) continue
      const made = await this.json<{ sha: string }>('POST', '/git/blobs', { content: b64.enc(change.bytes), encoding: 'base64' })
      blobs.set(path, made.sha)
    }
    for (let attempt = 0; attempt < 4; attempt++) {
      const head = await this.head()
      const { tree, files } = head ? await this.entries(head) : { tree: undefined, files: [] as TreeEntry[] }
      const current = new Map(files.map((entry) => [entry.path, entry]))

      for (const [path, change] of [...batch]) {
        if (change.expect === undefined) continue
        const have = current.get(this.target.prefix + path)?.sha ?? null
        if (have !== change.expect) {
          for (const waiter of change.waiters) waiter.reject(new Conflict(path))
          batch.delete(path)
        }
      }
      const changes: { path: string; mode: string; type: 'blob'; sha: string | null }[] = []
      for (const [path, change] of batch) {
        const full = this.target.prefix + path
        if (change.bytes) {
          if (current.get(full)?.sha !== blobs.get(path)) changes.push({ path: full, mode: '100644', type: 'blob', sha: blobs.get(path)! })
        } else if (current.has(full)) {
          changes.push({ path: full, mode: '100644', type: 'blob', sha: null })
        }
      }
      // Nothing that would change a file: no commit, no run.
      if (!changes.length) return

      if (this.target.rotateWorkflow) {
        const workflows = files.filter((entry) => isWorkflow(entry.path))
        if (workflows.length === 1) {
          const [workflow] = workflows
          const next = rotatedWorkflowName(workflow.path, await this.text(workflow.sha))
          changes.push({ path: workflow.path, mode: workflow.mode, type: 'blob', sha: null })
          changes.push({ path: next, mode: workflow.mode, type: 'blob', sha: workflow.sha })
        }
      }

      const made = await this.json<{ sha: string }>('POST', '/git/trees', {
        ...(tree ? { base_tree: tree } : {}),
        tree: tree ? changes : changes.filter((change) => change.sha !== null),
      })
      const names = [...batch.keys()]
      const message = `Update inbox data: ${names.slice(0, 4).join(', ')}${names.length > 4 ? ` and ${names.length - 4} more` : ''}`
      const commit = await this.json<{ sha: string }>('POST', '/git/commits', {
        message,
        tree: made.sha,
        parents: [],
        author: who,
        committer: who,
      })
      // The branch must still be where it was read; otherwise build again on it.
      if ((await this.head()) !== head) continue
      const res = head
        ? await this.call(`/git/refs/${this.ref}`, { method: 'PATCH', body: JSON.stringify({ sha: commit.sha, force: true }) })
        : await this.call('/git/refs', { method: 'POST', body: JSON.stringify({ ref: `refs/${this.ref}`, sha: commit.sha }) })
      if (res.ok) return
      const why = ((await res.json().catch(() => ({}))) as { message?: string }).message ?? ''
      if (/workflow/i.test(why) || (this.target.rotateWorkflow && (res.status === 403 || res.status === 404))) {
        throw new TokenProblem(
          `GitHub refused to update ${this.target.branch} (HTTP ${res.status}). The token needs "Workflows: Read and write" as well as "Contents: Read and write": every save renames the workflow file.`,
        )
      }
      throw new Error(`GitHub: could not move ${this.target.branch}: HTTP ${res.status}${why ? ` (${why})` : ''}`)
    }
    throw new Error(`the ${this.target.branch} branch kept changing while this was being saved; it is tried again`)
  }

  /** Delete the branch. Used by the self-test to clean up after itself. */
  async deleteBranch(): Promise<void> {
    const res = await this.call(`/git/refs/${this.ref}`, { method: 'DELETE' })
    if (!res.ok && res.status !== 404 && res.status !== 422) {
      throw new Error(`GitHub: could not delete ${this.target.branch}: HTTP ${res.status}`)
    }
  }

  /** How many commits the branch has. */
  async historyLength(): Promise<number> {
    const commits = await this.json<unknown[]>('GET', `/commits?sha=${encodeURIComponent(this.target.branch)}&per_page=100`)
    return commits.length
  }
}
