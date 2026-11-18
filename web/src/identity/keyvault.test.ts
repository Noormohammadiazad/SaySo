import { describe, expect, it } from 'vitest'
import { b64u, OwnerKeys, randomBytes } from '../core'
import {
  addPasskey,
  changePassphrase,
  createVault,
  decodeVault,
  encodeVault,
  mergeSecrets,
  openBody,
  passkeyCredentials,
  passphraseProblem,
  sameSecrets,
  sealBody,
  suggestPassphrase,
  unlockWithPasskey,
  unlockWithPassphrase,
  WrongPassphrase,
  type VaultSecrets,
} from './keyvault'

const settings = { name: 'Ada', ntfy: 'https://ntfy.sh', waku: false, live: true, updated: 1 }
const secrets = (): VaultSecrets => ({
  root: randomBytes(32),
  epochs: new Map([
    [10, randomBytes(32)],
    [11, randomBytes(32)],
  ]),
  settings: { ...settings },
  threads: new Map(),
  purged: new Map(),
})
const PASS = 'correct horse battery staple'

describe('the key vault', () => {
  it('opens with its passphrase on a fresh device, and only with it', async () => {
    const mine = secrets()
    const { file, key } = await createVault(mine, PASS)
    // What another device downloads from the repository.
    const copy = decodeVault(encodeVault(file))
    expect(copy.oik).toBe(b64u.enc(new OwnerKeys(mine.root).oik))
    const unlocked = await unlockWithPassphrase(copy, PASS)
    expect(unlocked).toEqual(key)
    const opened = openBody(copy, unlocked)
    expect(opened.root).toEqual(mine.root)
    expect(opened.threads.size).toBe(0)
    expect([...opened.epochs.keys()]).toEqual([10, 11])
    expect(opened.settings).toEqual(settings)
    await expect(unlockWithPassphrase(copy, PASS + '!')).rejects.toBeInstanceOf(WrongPassphrase)
    // The passphrase is only ever stored as an argon2id slot.
    expect(new TextDecoder().decode(encodeVault(file))).not.toContain(PASS)
  })

  it('binds the body to its identity, so bodies cannot be swapped between vaults', async () => {
    const a = await createVault(secrets(), PASS)
    const b = await createVault(secrets(), PASS)
    expect(() => openBody({ ...a.file, body: b.file.body }, a.key)).toThrow()
    expect(() => openBody({ ...b.file, body: a.file.body }, a.key)).toThrow()
  })

  it('opens with a passkey slot, and keeps working after the passphrase changes', async () => {
    const mine = secrets()
    const { file, key } = await createVault(mine, PASS)
    const credential = randomBytes(16)
    const prf = randomBytes(32)
    const withPasskey = addPasskey(file, key, credential, prf)
    expect(passkeyCredentials(withPasskey)).toEqual([credential])
    expect(unlockWithPasskey(withPasskey, credential, prf)).toEqual(key)
    expect(() => unlockWithPasskey(withPasskey, credential, randomBytes(32))).toThrow()
    expect(() => unlockWithPasskey(withPasskey, randomBytes(16), prf)).toThrow()

    const changed = await changePassphrase(withPasskey, key, 'a whole new passphrase')
    await expect(unlockWithPassphrase(changed, PASS)).rejects.toBeInstanceOf(WrongPassphrase)
    expect(await unlockWithPassphrase(changed, 'a whole new passphrase')).toEqual(key)
    expect(unlockWithPasskey(changed, credential, prf)).toEqual(key)
  })

  it('reseals the body under a fresh nonce every time', async () => {
    const mine = secrets()
    const { file, key } = await createVault(mine, PASS)
    const again = sealBody(file, key, mine)
    expect(again.body).not.toBe(file.body)
    expect(openBody(again, key).root).toEqual(mine.root)
  })

  it('merges two devices: union of epochs, the repository wins a clash, none past its time', () => {
    const root = randomBytes(32)
    const local: VaultSecrets = {
      root,
      epochs: new Map([[5, randomBytes(32)], [6, randomBytes(32)], [7, randomBytes(32)]]),
      settings: { ...settings, name: 'old', updated: 1 },
      threads: new Map([
        ['t1', { name: 'Ada (here)', updated: 5 }],
        ['t2', { blocked: true, updated: 1 }],
      ]),
      purged: new Map([['e1', 100], ['e2', 10]]),
    }
    const remote: VaultSecrets = {
      root,
      epochs: new Map([[6, randomBytes(32)], [8, randomBytes(32)]]),
      settings: { ...settings, name: 'new', updated: 2 },
      threads: new Map([
        ['t1', { name: 'Ada (there)', updated: 3 }],
        ['t2', { blocked: false, updated: 2 }],
      ]),
      purged: new Map([['e3', 100]]),
    }
    const merged = mergeSecrets(local, remote, (e) => e < 6, 50)
    expect(merged.threads.get('t1')?.name).toBe('Ada (here)')
    expect(merged.threads.get('t2')?.blocked).toBe(false)
    expect([...merged.purged.keys()].sort()).toEqual(['e1', 'e3'])
    expect([...merged.epochs.keys()].sort()).toEqual([6, 7, 8])
    expect(merged.epochs.get(6)).toEqual(remote.epochs.get(6))
    expect(merged.epochs.get(7)).toEqual(local.epochs.get(7))
    expect(merged.settings.name).toBe('new')
    expect(sameSecrets(merged, remote)).toBe(false)
    expect(sameSecrets(merged, mergeSecrets(merged, merged, () => false, 50))).toBe(true)
  })

  it('refuses weak passphrases and suggests strong ones', () => {
    expect(passphraseProblem('short')).toMatch(/at least 12/)
    expect(passphraseProblem('aaaaaaaaaaaaaaaa')).toMatch(/repeats/)
    expect(passphraseProblem(PASS)).toBeUndefined()
    const suggested = suggestPassphrase()
    expect(suggested).toMatch(/^[a-z2-9]{5}(-[a-z2-9]{5}){4}$/)
    expect(passphraseProblem(suggested)).toBeUndefined()
  })
})
