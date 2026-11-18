import { describe, expect, it } from 'vitest'
import { b64 } from '../core/bytes'
import type { DataLocation } from './location'
import { openVault } from './vault'

const EID = 'ab'.repeat(32)
const GITHUB: DataLocation = {
  id: 'someone/inbox',
  base: './data/',
  local: false,
  ntfy: 'https://ntfy.sh',
  repo: { owner: 'someone', name: 'inbox', dataBranch: 'sayso-data', vaultBranch: 'sayso-vault', api: 'https://api.github.com' },
}

describe('vault reader', () => {
  it('lists only drops from the vault branch and reads them by blob id through the API', async () => {
    const seen: { url: string; auth: string | null }[] = []
    const http: typeof fetch = async (input, init = {}) => {
      const url = String(input)
      seen.push({ url, auth: new Headers(init.headers).get('authorization') })
      if (url.includes('/git/trees/')) {
        return Response.json({
          tree: [
            { path: 'README.txt', type: 'blob', sha: 'r1' },
            { path: 'drops', type: 'tree', sha: 't1' },
            { path: 'drops/e7', type: 'tree', sha: 't2' },
            { path: `drops/e7/${EID}.bin`, type: 'blob', sha: 'blob1' },
            { path: 'drops/e7/notes.txt', type: 'blob', sha: 'n1' },
            { path: `drops/e7/${EID}.part`, type: 'blob', sha: 'p1' },
          ],
        })
      }
      if (url.endsWith('/git/blobs/blob1')) {
        return Response.json({ encoding: 'base64', content: b64.enc(new Uint8Array([1, 2, 3])) })
      }
      return new Response('{}', { status: 404 })
    }
    const vault = openVault(GITHUB, 'owner-token', http)

    const entries = await vault.list()
    expect(entries).toEqual([{ path: `drops/e7/${EID}.bin`, ref: 'blob1' }])
    expect(seen[0].url).toBe('https://api.github.com/repos/someone/inbox/git/trees/sayso-vault?recursive=1')
    expect(seen[0].auth).toBe('Bearer owner-token')

    expect(await vault.get(entries[0])).toEqual(new Uint8Array([1, 2, 3]))
    expect(seen[1].url).toBe('https://api.github.com/repos/someone/inbox/git/blobs/blob1')
    expect(seen[1].auth).toBe('Bearer owner-token')
    // Nothing goes to raw.githubusercontent.com, which some networks refuse.
    expect(seen.every((call) => call.url.startsWith('https://api.github.com/'))).toBe(true)

    expect(await vault.get({ path: `drops/e7/${EID}.bin`, ref: 'gone' })).toBeUndefined()
  })

  it('treats a missing vault branch as an empty vault, and other failures as failures', async () => {
    const status = (code: number): typeof fetch => async () => new Response('{}', { status: code })
    expect(await openVault(GITHUB, undefined, status(404)).list()).toEqual([])
    await expect(openVault(GITHUB, undefined, status(403)).list()).rejects.toThrow(/HTTP 403/)
    await expect(openVault(GITHUB, undefined, status(500)).get({ path: 'p', ref: 'x' })).rejects.toThrow(/HTTP 500/)
  })

  it('reads the local stand-in the same way', async () => {
    const http: typeof fetch = async (input) =>
      String(input).endsWith('?list')
        ? Response.json([`drops/e7/${EID}.bin`, 'other.txt'])
        : new Response('', { status: 404 })
    const local: DataLocation = { id: 'local', base: '/__data/', localVault: '/__vault/', local: true, ntfy: '/__ntfy' }
    const vault = openVault(local, undefined, http)
    const entries = await vault.list()
    expect(entries).toEqual([{ path: `drops/e7/${EID}.bin`, ref: `drops/e7/${EID}.bin` }])
    expect(await vault.get(entries[0])).toBeUndefined()
  })
})
