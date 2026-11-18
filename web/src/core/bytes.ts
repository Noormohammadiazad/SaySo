// Byte helpers with no dependency on the WebAssembly core, so modules that
// only talk to the network can be used, and tested, without loading it.

export const b64u = {
  enc(bytes: Uint8Array): string {
    let text = ''
    for (let i = 0; i < bytes.length; i += 0x8000) {
      text += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
    }
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  },
  dec(text: string): Uint8Array {
    const raw = atob(text.replace(/-/g, '+').replace(/_/g, '/'))
    const out = new Uint8Array(raw.length)
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
    return out
  },
}

/** Standard base64 with padding, as the GitHub API speaks it. */
export const b64 = {
  enc(bytes: Uint8Array): string {
    const text = b64u.enc(bytes).replace(/-/g, '+').replace(/_/g, '/')
    return text + '='.repeat((4 - (text.length % 4)) % 4)
  },
  dec: (text: string): Uint8Array => b64u.dec(text.replace(/\s/g, '').replace(/=+$/, '')),
}

export const utf8 = {
  enc: (text: string): Uint8Array => new TextEncoder().encode(text),
  dec: (bytes: Uint8Array): string => new TextDecoder().decode(bytes),
}

export const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, i) => value === b[i])

export const nowSeconds = (): number => Math.floor(Date.now() / 1000)

/** JSON that keeps Uint8Array fields, for records stored on this device. */
export const record = {
  enc: (value: unknown): Uint8Array =>
    utf8.enc(JSON.stringify(value, (_key, v) => (v instanceof Uint8Array ? { $b: b64u.enc(v) } : v))),
  dec: <T>(bytes: Uint8Array): T =>
    JSON.parse(utf8.dec(bytes), (_key, v) =>
      v && typeof v === 'object' && typeof v.$b === 'string' ? b64u.dec(v.$b) : v,
    ) as T,
}
