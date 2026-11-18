import { describe, expect, it } from 'vitest'
import type { Repo } from '../data/location'
import { FakeGithub } from '../test/fake-github'
import { checkToken } from './token'

const TOKEN = 'github_pat_' + 'x'.repeat(40)
const REPO: Repo = { owner: 'someone', name: 'inbox', dataBranch: 'sayso-data', vaultBranch: 'sayso-vault', api: 'https://api.github.com' }

describe('checkToken', () => {
  it('names the account and proves write access without touching a branch', async () => {
    const github = new FakeGithub('someone/inbox', TOKEN, { login: 'someone' })
    expect(await checkToken(REPO, TOKEN, github.fetch)).toEqual({ login: 'someone' })
    expect(github.calls).toEqual(['POST /git/blobs'])
    expect(github.refs.size).toBe(0)
  })

  it('says what is wrong with a token in words', async () => {
    const github = new FakeGithub('someone/inbox', TOKEN)
    await expect(checkToken(REPO, 'github_pat_' + 'y'.repeat(40), github.fetch)).rejects.toThrow('rejected this token')
    await expect(checkToken(REPO, 'hello', github.fetch)).rejects.toThrow('does not look like a GitHub token')
    await expect(checkToken({ ...REPO, name: 'other' }, TOKEN, github.fetch)).rejects.toThrow('cannot see someone/other')
    github.readOnly = true
    await expect(checkToken(REPO, TOKEN, github.fetch)).rejects.toThrow('"Contents: Read and write"')
  })
})
