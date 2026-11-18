import { describe, expect, it } from 'vitest'
import { utf8 } from '../core/bytes'
import { FakeGithub } from '../test/fake-github'
import { GithubPublisher } from './github'
import { Conflict } from './index'
import { rotatedWorkflowName } from './rotate'

const TOKEN = 'token-for-tests'
const WORKFLOW = '.github/workflows/sayso-20261118-170100.yml'

function world(options: { rotate?: boolean } = {}) {
  const github = new FakeGithub('someone/inbox', TOKEN, { login: 'someone' })
  github.seed('main', { 'README.md': '# code', [WORKFLOW]: 'name: Sayso\non: push\n' })
  const publisher = new GithubPublisher(
    { owner: 'someone', name: 'inbox', branch: 'main', prefix: 'data/', rotateWorkflow: options.rotate ?? true },
    TOKEN,
    { batchMs: 20, maxDelayMs: 100 },
    github.fetch,
  )
  return { github, publisher }
}

describe('GithubPublisher', () => {
  it('commits a batch of writes as one parentless commit, renaming the workflow', async () => {
    const { github, publisher } = world()
    await Promise.all([
      publisher.put('owner.json', utf8.enc('{"v":1}')),
      publisher.put('mail/e7/a.bin', utf8.enc('a')),
      publisher.put('mail/e7/b.bin', utf8.enc('b')),
    ])
    expect(github.pushes).toHaveLength(1)
    const [push] = github.pushes
    expect(push.parents).toBe(0)
    expect(github.history('main')).toHaveLength(1)
    // The code is untouched; the workflow moved to a later name; the data is under data/.
    expect(push.files).toContain('README.md')
    expect(push.workflows).toHaveLength(1)
    expect(push.workflows[0]).not.toBe(WORKFLOW)
    expect(push.workflows[0] > WORKFLOW).toBe(true)
    expect(push.workflows[0]).toMatch(/^\.github\/workflows\/sayso-\d{8}-\d{6}\.yml$/)
    expect(utf8.dec(github.files('main').get('data/owner.json')!)).toBe('{"v":1}')
    // Made as the token's account, at its noreply address.
    const head = github.head('main')!
    expect(head.author).toEqual({ name: 'someone', email: 'someone@users.noreply.github.com' })
    expect(head.committer).toEqual(head.author)
    expect(head.message).not.toMatch(/co-authored|signed-off|generated/i)
    expect(github.dispatches).toHaveLength(0)
  })

  it('keeps one commit through many saves, each under a new workflow name', async () => {
    const { github, publisher } = world()
    for (const n of [1, 2, 3]) {
      await publisher.put(`mail/e7/${n}.bin`, utf8.enc(String(n)))
    }
    expect(github.pushes).toHaveLength(3)
    expect(github.history('main')).toHaveLength(1)
    const names = github.pushes.map((push) => push.workflows[0])
    expect(new Set(names).size).toBe(3)
    expect([...names].sort()).toEqual(names)
    expect([...github.files('main').keys()].filter((path) => path.startsWith('data/'))).toEqual([
      'data/mail/e7/1.bin',
      'data/mail/e7/2.bin',
      'data/mail/e7/3.bin',
    ])
  })

  it('reads what it wrote, lists, and removes', async () => {
    const { github, publisher } = world()
    await publisher.put('mail/e7/a.bin', utf8.enc('a'))
    expect(utf8.dec((await publisher.get('mail/e7/a.bin'))!)).toBe('a')
    expect(await publisher.list('mail/')).toEqual(['mail/e7/a.bin'])
    await publisher.remove('mail/e7/a.bin')
    expect(await publisher.get('mail/e7/a.bin')).toBeUndefined()
    expect(github.files('main').has('data/mail/e7/a.bin')).toBe(false)
    expect(github.history('main')).toHaveLength(1)
  })

  it('makes no commit when nothing changes', async () => {
    const { github, publisher } = world()
    await publisher.put('owner.json', utf8.enc('same'))
    await publisher.put('owner.json', utf8.enc('same'))
    await publisher.remove('missing.bin')
    expect(github.pushes).toHaveLength(1)
  })

  it('writes only over the version it read', async () => {
    const { github, publisher } = world()
    await publisher.write('owner-vault.enc', utf8.enc('first'), undefined)
    await expect(publisher.write('owner-vault.enc', utf8.enc('also first'), undefined)).rejects.toBeInstanceOf(Conflict)
    const seen = (await publisher.read('owner-vault.enc'))!
    await publisher.write('owner-vault.enc', utf8.enc('second'), seen.version)
    await expect(publisher.write('owner-vault.enc', utf8.enc('stale'), seen.version)).rejects.toBeInstanceOf(Conflict)
    expect(utf8.dec(github.files('main').get('data/owner-vault.enc')!)).toBe('second')
  })

  it('rebuilds on a branch someone else moved meanwhile, keeping their files', async () => {
    const { github, publisher } = world()
    const original = github.fetch
    let once = true
    const racingFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      // Just after the commit is made, another writer moves main.
      if (once && init?.method === 'POST' && String(input).endsWith('/git/commits')) {
        once = false
        const answer = await original(input, init)
        github.seed('main', { 'README.md': '# code', [WORKFLOW]: 'name: Sayso\n', 'data/theirs.bin': 'x' })
        return answer
      }
      return original(input, init)
    }) as typeof fetch
    const racing = new GithubPublisher(
      { owner: 'someone', name: 'inbox', branch: 'main', prefix: 'data/', rotateWorkflow: true },
      TOKEN,
      { batchMs: 5 },
      racingFetch,
    )
    await racing.put('mine.bin', utf8.enc('y'))
    const files = github.files('main')
    expect(files.has('data/theirs.bin')).toBe(true)
    expect(files.has('data/mine.bin')).toBe(true)
    void publisher
  })

  it('says in words when the token may not touch workflow files', async () => {
    const { github, publisher } = world()
    github.workflowScope = false
    await expect(publisher.put('owner.json', utf8.enc('x'))).rejects.toThrow('"Workflows: Read and write"')
    expect(github.history('main')).toHaveLength(1)
    expect(github.files('main').has('data/owner.json')).toBe(false)
  })

  it('writes a branch without a workflow, and creates it when missing', async () => {
    const github = new FakeGithub('someone/inbox', TOKEN)
    const vault = new GithubPublisher(
      { owner: 'someone', name: 'inbox', branch: 'sayso-vault', prefix: '', rotateWorkflow: false },
      TOKEN,
      { batchMs: 5 },
      github.fetch,
    )
    await vault.put('drops/e7/x.bin', utf8.enc('x'))
    await vault.put('drops/e7/y.bin', utf8.enc('y'))
    await vault.remove('drops/e7/x.bin')
    expect(github.history('sayso-vault')).toHaveLength(1)
    expect([...github.files('sayso-vault').keys()]).toEqual(['drops/e7/y.bin'])
  })
})

describe('rotatedWorkflowName', () => {
  it('is later than now and than the current name, from the name: slug', () => {
    const at = new Date('2026-11-18T17:01:00Z')
    expect(rotatedWorkflowName('.github/workflows/old.yml', 'name: My Inbox!\n', at)).toBe('.github/workflows/my-inbox-20261118-170100.yml')
    // The current name is ahead of the clock: one second after it.
    expect(rotatedWorkflowName('.github/workflows/sayso-20261118-170100.yml', 'name: Sayso', at)).toBe(
      '.github/workflows/sayso-20261118-170101.yml',
    )
  })
})
