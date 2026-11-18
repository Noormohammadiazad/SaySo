// An in-memory model of the parts of the GitHub REST API Sayso uses,
// faithful enough to catch a wrong call sequence: objects are immutable and
// named by id, a contents write needs the current blob id, a branch only
// moves through its ref, a tree can be built on a base tree with files
// removed by `sha: null`, and a token without the workflow permission cannot
// move a branch to a commit that changes a workflow file.
import { b64 } from '../core/bytes'
import { hash, toHex } from '../crypto/prims'

interface Entry {
  path: string
  mode: string
  type: string
  sha: string
}

export interface Person {
  name: string
  email: string
}

interface Commit {
  tree: string
  parents: string[]
  message: string
  author?: Person
  committer?: Person
}

/** One move of a branch, as a test or the preview server sees it. */
export interface Push {
  branch: string
  sha: string
  parents: number
  workflows: string[]
  files: string[]
}

const INLINE_LIMIT = 1_000_000
const WORKFLOWS = /^\.github\/workflows\/[^/]+\.ya?ml$/

/** Git orders tree entries by byte value, not by locale. */
const byPath = (a: Entry, b: Entry): number => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)

export class FakeGithub {
  readonly blobs = new Map<string, Uint8Array>()
  readonly trees = new Map<string, Entry[]>()
  readonly commits = new Map<string, Commit>()
  readonly refs = new Map<string, string>()
  readonly calls: string[] = []
  readonly pushes: Push[] = []
  readonly dispatches: { event_type: string; client_payload?: unknown }[] = []
  /** The API base it answers on; a stand-in server mounts it elsewhere. */
  readonly base: string
  /** The account the token belongs to. */
  login: string
  /** Answer writes with 403, like a token with read-only access. */
  readOnly = false
  /** Whether the token may change workflow files ("Workflows: write"). */
  workflowScope = true
  /** Called after every move of a branch. */
  onPush?: (push: Push) => void
  private next = 1

  constructor(
    private readonly repo: string,
    private readonly token: string,
    options: { base?: string; login?: string } = {},
  ) {
    this.base = options.base ?? 'https://api.github.com'
    this.login = options.login ?? repo.split('/')[0]
  }

  private id(kind: string): string {
    return `${kind}${String(this.next++).padStart(6, '0')}`.padEnd(40, '0')
  }

  /** Blobs are named by their content, as in git. */
  private store(bytes: Uint8Array): string {
    const sha = `b${toHex(hash(bytes)).slice(0, 39)}`
    this.blobs.set(sha, bytes)
    return sha
  }

  /** Make `branch` one commit holding `files`, as a push from a clone would. */
  seed(branch: string, files: Record<string, string | Uint8Array>): string {
    const entries: Entry[] = Object.entries(files).map(([path, content]) => {
      const sha = this.store(typeof content === 'string' ? new TextEncoder().encode(content) : content)
      return { path, mode: '100644', type: 'blob', sha }
    })
    const tree = this.id('t')
    this.trees.set(tree, entries.sort(byPath))
    const commit = this.id('c')
    this.commits.set(commit, { tree, parents: [], message: 'seed' })
    this.refs.set(`heads/${branch}`, commit)
    return commit
  }

  /** Every commit reachable from a branch, newest first. */
  history(branch: string): string[] {
    const out: string[] = []
    let at = this.refs.get(`heads/${branch}`)
    while (at) {
      out.push(at)
      at = this.commits.get(at)?.parents[0]
    }
    return out
  }

  files(branch: string): Map<string, Uint8Array> {
    const head = this.refs.get(`heads/${branch}`)
    const out = new Map<string, Uint8Array>()
    if (!head) return out
    for (const entry of this.trees.get(this.commits.get(head)!.tree)!) out.set(entry.path, this.blobs.get(entry.sha)!)
    return out
  }

  head(branch: string): Commit | undefined {
    const sha = this.refs.get(`heads/${branch}`)
    return sha ? this.commits.get(sha) : undefined
  }

  private workflowsOf(commit: string | undefined): string {
    if (!commit) return ''
    return this.trees
      .get(this.commits.get(commit)!.tree)!
      .filter((entry) => WORKFLOWS.test(entry.path))
      .map((entry) => `${entry.path}:${entry.sha}`)
      .join(',')
  }

  /** Move a ref, as GitHub would let this token. `undefined` when allowed. */
  private move(name: string, sha: string): Response | undefined {
    if (!this.workflowScope && this.workflowsOf(this.refs.get(name)) !== this.workflowsOf(sha)) {
      return new Response(
        JSON.stringify({ message: 'refusing to allow a Personal Access Token to create or update workflow without `workflow` scope' }),
        { status: 403, headers: { 'content-type': 'application/json' } },
      )
    }
    this.refs.set(name, sha)
    const commit = this.commits.get(sha)!
    const entries = this.trees.get(commit.tree)!
    const push: Push = {
      branch: name.replace(/^heads\//, ''),
      sha,
      parents: commit.parents.length,
      workflows: entries.filter((entry) => WORKFLOWS.test(entry.path)).map((entry) => entry.path),
      files: entries.map((entry) => entry.path),
    }
    this.pushes.push(push)
    this.onPush?.(push)
    return undefined
  }

  readonly fetch: typeof fetch = async (input, init = {}) => {
    const url = new URL(String(input))
    const method = init.method ?? 'GET'
    const prefix = `/repos/${this.repo}`
    const reply = (status: number, body: unknown = {}): Response =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

    const base = new URL(this.base)
    if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname.replace(/\/$/, ''))) return reply(404)
    const route = url.pathname.slice(base.pathname.replace(/\/$/, '').length)
    const headers = new Headers(init.headers)
    if (headers.get('authorization') !== `Bearer ${this.token}`) return reply(401)
    if (route === '/user' && method === 'GET') return reply(200, { login: this.login })
    if (!route.startsWith(prefix)) return reply(404)
    if (this.readOnly && method !== 'GET') return reply(403, { message: 'Resource not accessible by personal access token' })
    const path = decodeURIComponent(route.slice(prefix.length))
    this.calls.push(`${method} ${path}`)
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    let match: RegExpExecArray | null

    if (path === '/dispatches' && method === 'POST') {
      this.dispatches.push(body)
      return new Response(null, { status: 204 })
    }
    if ((match = /^\/git\/ref\/(.+)$/.exec(path)) && method === 'GET') {
      const sha = this.refs.get(match[1])
      return sha ? reply(200, { ref: `refs/${match[1]}`, object: { sha } }) : reply(404)
    }
    if (path === '/git/refs' && method === 'POST') {
      const name = String(body.ref).replace(/^refs\//, '')
      if (this.refs.has(name)) return reply(422)
      if (!this.commits.has(body.sha)) return reply(422)
      const refused = this.move(name, body.sha)
      if (refused) return refused
      return reply(201, { ref: body.ref, object: { sha: body.sha } })
    }
    if ((match = /^\/git\/refs\/(.+)$/.exec(path))) {
      const current = this.refs.get(match[1])
      if (!current) return reply(method === 'DELETE' ? 422 : 404)
      if (method === 'DELETE') {
        this.refs.delete(match[1])
        return new Response(null, { status: 204 })
      }
      if (method === 'PATCH') {
        if (!this.commits.has(body.sha)) return reply(422)
        // Without force, GitHub only fast-forwards.
        const descends = (() => {
          let at: string | undefined = body.sha
          while (at) {
            if (at === current) return true
            at = this.commits.get(at)?.parents[0]
          }
          return false
        })()
        if (!descends && !body.force) return reply(422, { message: 'Update is not a fast forward' })
        const refused = this.move(match[1], body.sha)
        if (refused) return refused
        return reply(200, { object: { sha: body.sha } })
      }
    }
    if (path === '/git/blobs' && method === 'POST') {
      const sha = this.store(body.encoding === 'base64' ? b64.dec(body.content) : new TextEncoder().encode(body.content))
      return reply(201, { sha })
    }
    if ((match = /^\/git\/blobs\/(.+)$/.exec(path)) && method === 'GET') {
      const blob = this.blobs.get(match[1])
      return blob ? reply(200, { sha: match[1], encoding: 'base64', content: b64.enc(blob) }) : reply(404)
    }
    if (path === '/git/trees' && method === 'POST') {
      const changes = body.tree as (Omit<Entry, 'sha'> & { sha: string | null })[]
      const entries = new Map<string, Entry>()
      if (body.base_tree) {
        const base = this.trees.get(body.base_tree)
        if (!base) return reply(422)
        for (const entry of base) entries.set(entry.path, { ...entry })
      }
      for (const change of changes) {
        if (change.sha === null) {
          if (!entries.delete(change.path)) return reply(422, { message: `${change.path} is not in the base tree` })
        } else {
          if (!this.blobs.has(change.sha)) return reply(422)
          entries.set(change.path, { path: change.path, mode: change.mode, type: 'blob', sha: change.sha })
        }
      }
      if (!entries.size) return reply(422)
      const sha = this.id('t')
      this.trees.set(sha, [...entries.values()].sort(byPath))
      return reply(201, { sha })
    }
    if ((match = /^\/git\/trees\/(.+)$/.exec(path)) && method === 'GET') {
      const tree = this.trees.get(match[1])
      return tree ? reply(200, { sha: match[1], tree, truncated: false }) : reply(404)
    }
    if (path === '/git/commits' && method === 'POST') {
      if (!this.trees.has(body.tree)) return reply(422)
      const sha = this.id('c')
      this.commits.set(sha, { tree: body.tree, parents: body.parents ?? [], message: body.message, author: body.author, committer: body.committer })
      return reply(201, { sha })
    }
    if ((match = /^\/git\/commits\/(.+)$/.exec(path)) && method === 'GET') {
      const commit = this.commits.get(match[1])
      return commit
        ? reply(200, { sha: match[1], tree: { sha: commit.tree }, parents: commit.parents.map((sha) => ({ sha })), message: commit.message })
        : reply(404)
    }
    if (path === '/commits' && method === 'GET') {
      return reply(200, this.history(url.searchParams.get('sha') ?? '').map((sha) => ({ sha })))
    }
    if ((match = /^\/contents\/(.+)$/.exec(path))) {
      const file = match[1]
      const branch = method === 'GET' ? url.searchParams.get('ref')! : String(body.branch)
      const head = this.refs.get(`heads/${branch}`)
      if (!head) return reply(404)
      const tree = this.trees.get(this.commits.get(head)!.tree)!
      const existing = tree.find((entry) => entry.path === file)
      if (method === 'GET') {
        if (!existing) return reply(404)
        const blob = this.blobs.get(existing.sha)!
        const content = blob.length > INLINE_LIMIT ? '' : b64.enc(blob)
        return reply(200, { sha: existing.sha, size: blob.length, content, encoding: 'base64' })
      }
    }
    return reply(404)
  }
}
