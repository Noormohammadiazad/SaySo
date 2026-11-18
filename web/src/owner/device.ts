// Staying signed in on one browser.
//
// After a sign-in the vault key (and the GitHub token) are kept in this
// browser's storage, encrypted with an AES key that the browser generated
// as non-extractable: page code can use it but never read it out, so a copy
// of the storage files alone does not reveal them. Signing out deletes both.
import { record } from '../core'
import type { Kv } from '../store/db'

const DEVICE_KEY = 'device-key'
const SESSION = 'session'

export interface DeviceSession {
  vaultKey: Uint8Array
  token?: string
  login?: string
}

async function deviceKey(kv: Kv, create: boolean): Promise<CryptoKey | undefined> {
  const existing = await kv.getValue<CryptoKey>(DEVICE_KEY)
  if (existing || !create) return existing
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  await kv.put(DEVICE_KEY, key)
  return key
}

export async function saveSession(kv: Kv, session: DeviceSession): Promise<void> {
  const key = (await deviceKey(kv, true))!
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, record.enc(session) as unknown as Uint8Array<ArrayBuffer>))
  const out = new Uint8Array(12 + sealed.length)
  out.set(iv)
  out.set(sealed, 12)
  await kv.set(SESSION, out)
}

export async function loadSession(kv: Kv): Promise<DeviceSession | undefined> {
  const [key, sealed] = await Promise.all([deviceKey(kv, false), kv.get(SESSION)])
  if (!key || !sealed) return undefined
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12) }, key, sealed.slice(12))
    return record.dec<DeviceSession>(new Uint8Array(plain))
  } catch {
    return undefined
  }
}

export async function clearSession(kv: Kv): Promise<void> {
  await kv.del(SESSION)
  await kv.del(DEVICE_KEY)
}
