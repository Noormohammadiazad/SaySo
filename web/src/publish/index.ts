// Writing the repository's data. Only the owner's dashboard does this.
import type { DataLocation } from '../data/location'
import { GithubPublisher } from './github'
import { LocalPublisher } from './local'

/** A write was refused because the file changed since it was read. */
export class Conflict extends Error {
  constructor(path: string) {
    super(`${path} changed since it was read`)
    this.name = 'Conflict'
  }
}

/**
 * The data files, by path under data/. Writes are gathered and committed
 * together: each returns once the commit that carries it is in place.
 */
export interface Publisher {
  /** Current content, read past any cache; `undefined` if absent. */
  get(path: string): Promise<Uint8Array | undefined>
  put(path: string, bytes: Uint8Array): Promise<void>
  remove(path: string): Promise<void>
  /** Current content and its version, for a later `write`. */
  read(path: string): Promise<{ bytes: Uint8Array; version: string } | undefined>
  /**
   * Write only if the file is still at `version` (absent, for `undefined`);
   * otherwise throw `Conflict` and change nothing.
   */
  write(path: string, bytes: Uint8Array, version: string | undefined): Promise<void>
  /** Every path that starts with `prefix`. */
  list(prefix: string): Promise<string[]>
  /** Commit what is gathered now instead of after the batching delay. */
  settled(): Promise<void>
}

export interface Who {
  /** The GitHub account the token belongs to: commits are made as this account. */
  login?: string
}

/** `undefined` when the deployment needs a token and none was provided. */
export function openPublisher(where: DataLocation, token?: string, who: Who = {}): Publisher | undefined {
  if (where.local) return new LocalPublisher(where.base)
  if (where.repo && token) {
    const { owner, name, api } = where.repo
    return new GithubPublisher({ owner, name, api, branch: 'main', prefix: 'data/', rotateWorkflow: true }, token, { login: who.login })
  }
  return undefined
}

/**
 * The harvest job's vault branch, for removing what the owner deleted. It
 * has no workflow and no prefix; a removal there starts no run.
 */
export function openVaultWriter(where: DataLocation, token?: string, who: Who = {}): Publisher | undefined {
  if (where.local) return new LocalPublisher(where.localVault!)
  if (where.repo && token) {
    const { owner, name, api, vaultBranch } = where.repo
    return new GithubPublisher({ owner, name, api, branch: vaultBranch, prefix: '', rotateWorkflow: false }, token, { login: who.login })
  }
  return undefined
}
