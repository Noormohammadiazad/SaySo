// Checking the owner's GitHub token before anything else is done with it.
//
// Signing in to the dashboard takes two things: this token, which proves
// the person can write to the repository the inbox lives in, and the
// passphrase (or a passkey) that opens the key vault. Neither is enough
// alone.
import type { Repo } from '../data/location'
import { timed } from '../net'

export class TokenProblem extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TokenProblem'
  }
}

export interface Grant {
  /** The GitHub account the token belongs to. */
  login: string
}

/**
 * Who the token belongs to, and proof that it can write to `repo`: it
 * creates a blob, which needs "Contents: write" but changes no branch (an
 * unreferenced blob is garbage-collected). That is the same permission
 * publishing and redeploying need.
 */
export async function checkToken(repo: Repo, token: string, http: typeof fetch = timed('GitHub', { timeoutMs: 30_000 })): Promise<Grant> {
  if (!/^[A-Za-z0-9_]{20,255}$/.test(token)) {
    throw new TokenProblem('That does not look like a GitHub token. Paste the whole token, starting with github_pat_ or ghp_.')
  }
  const headers = {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${token}`,
    'x-github-api-version': '2022-11-28',
  }
  const user = await http(`${repo.api}/user`, { headers, cache: 'no-store' })
  if (user.status === 401) throw new TokenProblem('GitHub rejected this token: it is wrong, expired or revoked.')
  if (!user.ok) throw new TokenProblem(`GitHub could not check this token (HTTP ${user.status}).`)
  const { login } = (await user.json()) as { login: string }

  const where = `${repo.owner}/${repo.name}`
  const probe = await http(`${repo.api}/repos/${repo.owner}/${repo.name}/git/blobs`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ content: '', encoding: 'utf-8' }),
    cache: 'no-store',
  })
  if (probe.status === 404) {
    throw new TokenProblem(`This token cannot see ${where}. A fine-grained token has to include this repository.`)
  }
  if (probe.status === 403) {
    throw new TokenProblem(`This token can read ${where} but not write to it. Give it "Contents: Read and write".`)
  }
  if (!probe.ok) throw new TokenProblem(`GitHub refused a test write to ${where} (HTTP ${probe.status}).`)
  return { login }
}
