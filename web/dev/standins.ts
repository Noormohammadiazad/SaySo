// Local stand-ins for everything a deployed Sayso reaches over the network,
// so the whole system runs on one machine with no account:
//
//   /__data/   the data branch            -> .dev-data/
//   /__vault/  the vault branch           -> .dev-vault/
//   /__ntfy/   an ntfy-protocol buffer    -> .dev-buffer/
//
// They are mounted by `vite dev` always, and by `vite preview` only when
// SAYSO_LOCAL=1, which also makes the built page use them (see
// src/data/location.ts). Nothing here is part of the deployed site.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { appendFile, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Connect, Plugin } from 'vite'
import { FakeGithub } from '../src/test/fake-github'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')

type Handler = (req: IncomingMessage, res: ServerResponse) => Promise<void>

const SAFE_PATH = /^[A-Za-z0-9._/-]+$/

async function body(req: IncomingMessage): Promise<Buffer> {
  const parts: Buffer[] = []
  for await (const part of req) parts.push(part as Buffer)
  return Buffer.concat(parts)
}

function send(res: ServerResponse, status: number, data?: string | Buffer, type = 'application/octet-stream'): void {
  res.statusCode = status
  res.setHeader('cache-control', 'no-store')
  if (data !== undefined) res.setHeader('content-type', type)
  res.end(data)
}

async function listFiles(root: string, prefix = ''): Promise<string[]> {
  const entries = await readdir(join(root, prefix), { withFileTypes: true }).catch(() => [])
  const out: string[] = []
  for (const entry of entries) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) out.push(...(await listFiles(root, path)))
    else out.push(path)
  }
  return out.sort()
}

/** A directory of files: GET, PUT, DELETE by path; `GET /?list` names them all. */
function files(root: string): Handler {
  return async (req, res) => {
    const [rawPath, query] = (req.url ?? '/').split('?')
    const path = decodeURIComponent(rawPath).replace(/^\/+/, '')
    if (req.method === 'GET' && path === '' && query === 'list') {
      return send(res, 200, JSON.stringify(await listFiles(root)), 'application/json')
    }
    if (!SAFE_PATH.test(path) || path.split('/').includes('..')) return send(res, 400)
    const file = join(root, path)
    if (req.method === 'GET') {
      const data = await readFile(file).catch(() => undefined)
      return data ? send(res, 200, data) : send(res, 404)
    }
    if (req.method === 'PUT') {
      await mkdir(dirname(file), { recursive: true })
      await writeFile(file, await body(req))
      return send(res, 204)
    }
    if (req.method === 'DELETE') {
      await rm(file, { recursive: true, force: true })
      return send(res, 204)
    }
    send(res, 405)
  }
}

interface NtfyMessage {
  id: string
  time: number
  event: 'message'
  topic: string
  message: string
}

/** Messages after `since`: an ntfy id, a Unix time, a duration (`12h`) or `all`. */
function after(lines: string[], since: string): string[] {
  if (since === 'all') return lines
  const duration = /^(\d+)([smhd])$/.exec(since)
  if (duration) {
    const seconds = Number(duration[1]) * { s: 1, m: 60, h: 3600, d: 86_400 }[duration[2] as 's' | 'm' | 'h' | 'd']
    const from = Math.floor(Date.now() / 1000) - seconds
    return lines.filter((line) => (JSON.parse(line) as NtfyMessage).time >= from)
  }
  if (/^\d+$/.test(since)) return lines.filter((line) => (JSON.parse(line) as NtfyMessage).time >= Number(since))
  const at = lines.findIndex((line) => (JSON.parse(line) as NtfyMessage).id === since)
  return at < 0 ? lines : lines.slice(at + 1)
}

/**
 * The slice of the ntfy HTTP API that Sayso uses: publish a text message to
 * a topic, poll a topic as one JSON object per line, and subscribe to it as
 * Server-Sent Events. Like the real service it refuses to keep a message
 * over 4096 bytes as a message, and sends a keepalive while a subscription
 * is quiet.
 */
function ntfy(root: string): Handler {
  let counter = 0
  const listeners = new Map<string, Set<ServerResponse>>()
  return async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://local')
    const [topic, action] = url.pathname.replace(/^\/+/, '').split('/')
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(topic ?? '')) return send(res, 400)
    const file = join(root, `${topic}.ndjson`)
    const backlog = async (): Promise<string[]> => (await readFile(file, 'utf8').catch(() => '')).split('\n').filter(Boolean)

    if (req.method === 'POST' && !action) {
      const message = (await body(req)).toString('utf8')
      if (Buffer.byteLength(message) > 4096) return send(res, 413, '{"error":"message too large"}', 'application/json')
      const entry: NtfyMessage = {
        id: `${Date.now().toString(36)}${(counter++).toString(36).padStart(4, '0')}`,
        time: Math.floor(Date.now() / 1000),
        event: 'message',
        topic,
        message,
      }
      await mkdir(root, { recursive: true })
      await appendFile(file, JSON.stringify(entry) + '\n')
      for (const listener of listeners.get(topic) ?? []) listener.write(`data: ${JSON.stringify(entry)}\n\n`)
      return send(res, 200, JSON.stringify(entry), 'application/json')
    }

    if (req.method === 'GET' && action === 'json') {
      const lines = after(await backlog(), url.searchParams.get('since') ?? 'all')
      return send(res, 200, lines.map((line) => line + '\n').join(''), 'application/x-ndjson')
    }

    if (req.method === 'GET' && action === 'sse') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' })
      const event = (name: string): string =>
        `event: ${name}\ndata: ${JSON.stringify({ id: `${name}${Date.now()}`, time: Math.floor(Date.now() / 1000), event: name, topic })}\n\n`
      res.write(event('open'))
      for (const line of after(await backlog(), url.searchParams.get('since') ?? 'all')) res.write(`data: ${line}\n\n`)
      let set = listeners.get(topic)
      if (!set) listeners.set(topic, (set = new Set()))
      set.add(res)
      const keepalive = setInterval(() => res.write(event('keepalive')), 25_000)
      req.on('close', () => {
        clearInterval(keepalive)
        set.delete(res)
      })
      return
    }
    send(res, 405)
  }
}

function guard(handler: Handler): Connect.NextHandleFunction {
  return (req, res) => {
    handler(req, res).catch(() => send(res, 500))
  }
}

function mount(middlewares: Connect.Server, announce: boolean): void {
  // Tells the built page (not `vite dev`, which knows already) to use the
  // stand-ins instead of GitHub.
  if (announce) {
    middlewares.use('/sayso.config.json', (_req, res) => send(res, 200, '{"local":true}', 'application/json'))
  }
  middlewares.use('/__data', guard(files(join(repo, '.dev-data'))))
  middlewares.use('/__vault', guard(files(join(repo, '.dev-vault'))))
  middlewares.use('/__ntfy', guard(ntfy(join(repo, '.dev-buffer'))))
}

/**
 * `vite preview` with SAYSO_FAKE_GITHUB set to a test token: the built site
 * as GitHub Pages serves it after a deploy, with GitHub itself played by the
 * in-memory model the unit tests use. The owner signs in with that token
 * against a repository named tester/inbox; nothing leaves this machine.
 *
 *   /__github/  the GitHub REST API   (FakeGithub, in memory; main starts
 *               with a README and one workflow, as a fork would)
 *   /data/      main's data/, as the deploy publishes it, current at once
 *   /           the page with its data written in, as inline-data.mjs does
 *   /__ntfy/    an ntfy relay, with live (SSE) subscriptions -> .dev-buffer/
 *   /__fake/state  every branch move so far, for checking the commit policy
 */
function mountFakeGithub(middlewares: Connect.Server, token: string): void {
  const repoName = 'tester/inbox'
  const github = new FakeGithub(repoName, token, { base: 'http://fake/__github', login: 'tester' })
  github.seed('main', {
    'README.md': '# tester/inbox\n',
    '.github/workflows/sayso-20260101-000000.yml': 'name: Sayso\non: push\n',
  })
  const dist = join(repo, 'web/dist')

  middlewares.use(
    '/__fake/state',
    guard(async (_req, res) => {
      const branches = Object.fromEntries(
        [...github.refs.keys()].map((ref) => {
          const branch = ref.replace(/^heads\//, '')
          const head = github.head(branch)
          return [branch, { commits: github.history(branch).length, author: head?.author, message: head?.message, files: [...github.files(branch).keys()] }]
        }),
      )
      send(res, 200, JSON.stringify({ pushes: github.pushes, dispatches: github.dispatches.length, branches }), 'application/json')
    }),
  )
  middlewares.use(
    '/__github',
    guard(async (req, res) => {
      const method = req.method ?? 'GET'
      const data = method === 'GET' || method === 'HEAD' ? undefined : (await body(req)).toString('utf8')
      const headers: Record<string, string> = {}
      for (const [name, value] of Object.entries(req.headers)) if (typeof value === 'string') headers[name] = value
      const answer = await github.fetch(`http://fake/__github${req.url ?? '/'}`, { method, headers, body: data })
      send(res, answer.status, Buffer.from(await answer.arrayBuffer()), answer.headers.get('content-type') ?? 'application/json')
    }),
  )
  middlewares.use(
    '/data',
    guard(async (req, res) => {
      const path = decodeURIComponent((req.url ?? '/').split('?')[0]).replace(/^\/+/, '')
      const file = github.files('main').get(`data/${path}`)
      return file ? send(res, 200, Buffer.from(file)) : send(res, 404)
    }),
  )
  middlewares.use('/__ntfy', guard(ntfy(join(repo, '.dev-buffer'))))
  middlewares.use((req, res, next) => {
    const path = (req.url ?? '/').split('?')[0]
    if (path !== '/' && path !== '/index.html') return next()
    const owner = github.files('main').get('data/owner.json')
    const inline = {
      config: { repo: repoName, api: '/__github', ntfy: '/__ntfy' },
      at: Date.now(),
      ...(owner ? { owner: new TextDecoder().decode(owner) } : {}),
    }
    const json = JSON.stringify(inline).replace(/</g, '\\u003c')
    const html = readFileSync(join(dist, 'index.html'), 'utf8').replace(
      /<script id="sayso-data" type="application\/json">[\s\S]*?<\/script>/,
      () => `<script id="sayso-data" type="application/json">${json}</script>`,
    )
    send(res, 200, html, 'text/html; charset=utf-8')
  })
}

export function standins(): Plugin {
  return {
    name: 'sayso-standins',
    configureServer(server) {
      mount(server.middlewares, false)
    },
    configurePreviewServer(server) {
      const fake = process.env.SAYSO_FAKE_GITHUB
      if (fake) mountFakeGithub(server.middlewares, fake)
      else if (process.env.SAYSO_LOCAL === '1') mount(server.middlewares, true)
    },
  }
}
