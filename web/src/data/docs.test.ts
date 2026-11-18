import { describe, expect, it } from 'vitest'
import { Owner, randomBytes } from '../core'
import { utf8 } from '../core/bytes'
import { anchoredTo, openOwner, signOwner, type OwnerProfile } from './docs'

const profile: OwnerProfile = {
  v: 1,
  issued: 100,
  name: 'Ada',
  github: { login: 'Ada', repo: 'Ada/Inbox' },
  epoch_len: 604_800,
  grace: 172_800,
  ttl: 2_592_000,
  receivers: [],
  pow: { alg: 1, bits: 16 },
  buffers: [{ kind: 'ntfy', url: 'https://ntfy.sh' }],
  shredded_before: 0,
  epochs: [{ e: 1, pk: 'AAAA' }],
}

describe('owner.json', () => {
  it('verifies under its own key on first contact and under the pinned key after', () => {
    const owner = new Owner(randomBytes(32))
    const signed = signOwner(owner, profile)
    const first = openOwner(signed)
    expect(first.status).toBe('ok')
    expect(openOwner(utf8.dec(signed), owner.oik)).toMatchObject({ status: 'ok', body: { name: 'Ada' } })
  })

  it('tells a different owner from a damaged file', () => {
    const owner = new Owner(randomBytes(32))
    const impostor = new Owner(randomBytes(32))
    expect(openOwner(signOwner(impostor, profile), owner.oik).status).toBe('bad-signature')
    const doc = JSON.parse(utf8.dec(signOwner(owner, profile)))
    doc.body = doc.body.replace('"Ada"', '"Eve"')
    expect(openOwner(JSON.stringify(doc), owner.oik).status).toBe('unreadable')
    expect(openOwner('<html>Checking your browser…</html>').status).toBe('unreadable')
  })

  it('is anchored only to the repository it names, in any letter case', () => {
    expect(anchoredTo(profile, { owner: 'ada', name: 'inbox' })).toBe(true)
    expect(anchoredTo(profile, { owner: 'eve', name: 'inbox' })).toBe(false)
    expect(anchoredTo(profile, undefined)).toBe(false)
    expect(anchoredTo({ ...profile, github: undefined }, { owner: 'ada', name: 'inbox' })).toBe(false)
  })
})
