// The same publisher against the real GitHub API, on a scratch branch that
// is deleted afterwards. Runs only where a token is provided: in the
// workflow's selftest job, or by hand with
//
//   SAYSO_LIVE_GITHUB=1 GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/name npx vitest run github.live
import { afterAll, describe, expect, it } from 'vitest'
import { utf8 } from '../core/bytes'
import { GithubPublisher } from './github'
import { Conflict } from './index'

const { SAYSO_LIVE_GITHUB, GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REPOSITORY_OWNER } = process.env
const enabled = Boolean(SAYSO_LIVE_GITHUB && GITHUB_TOKEN && GITHUB_REPOSITORY)

// Asked to run but unable to: that must fail, not pass by skipping.
if (SAYSO_LIVE_GITHUB && !enabled) {
  throw new Error('SAYSO_LIVE_GITHUB is set, but GITHUB_TOKEN or GITHUB_REPOSITORY is missing')
}

describe.skipIf(!enabled)('GithubPublisher against GitHub', () => {
  const [owner, name] = (GITHUB_REPOSITORY ?? '/').split('/')
  const branch = `sayso-selftest-${Date.now().toString(36)}`
  // A scratch branch with no workflow file: nothing to rename, no run.
  const publisher = new GithubPublisher(
    { owner, name, branch, prefix: 'data/', rotateWorkflow: false },
    GITHUB_TOKEN ?? '',
    // The workflow's own token belongs to no account; name the owner instead.
    { login: GITHUB_REPOSITORY_OWNER ?? owner, batchMs: 200 },
  )

  afterAll(async () => {
    await publisher.deleteBranch()
  })

  it('creates the branch as one commit, writes, reads and replaces', async () => {
    await publisher.put('owner.json', utf8.enc('{"v":1}'))
    expect(utf8.dec((await publisher.get('owner.json'))!)).toBe('{"v":1}')
    await Promise.all([publisher.put('owner.json', utf8.enc('{"v":1,"n":2}')), publisher.put('mail/e9/a.bin', utf8.enc('a'))])
    expect(utf8.dec((await publisher.get('owner.json'))!)).toBe('{"v":1,"n":2}')
    expect(await publisher.list('mail/')).toEqual(['mail/e9/a.bin'])
    expect(await publisher.historyLength()).toBe(1)
  }, 90_000)

  it('writes only over the version it read, and removes', async () => {
    const seen = (await publisher.read('owner.json'))!
    await publisher.write('owner.json', utf8.enc('{"v":1,"n":3}'), seen.version)
    await expect(publisher.write('owner.json', utf8.enc('stale'), seen.version)).rejects.toBeInstanceOf(Conflict)
    await publisher.remove('mail/e9/a.bin')
    expect(await publisher.get('mail/e9/a.bin')).toBeUndefined()
    expect(await publisher.historyLength()).toBe(1)
  }, 90_000)
})
