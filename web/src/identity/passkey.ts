// Deriving a 32-byte secret from a passkey with the WebAuthn PRF extension.
//
// The passkey is scoped to this site's host, and synced passkeys follow the
// user across devices, so the same secret comes back on every device with no
// account and nothing stored by the page.

const SALTS = {
  sender: 'sayso/v1/prf/sender',
  /** Opens a passkey slot of the owner's key vault. */
  vault: 'sayso/v1/prf/owner-vault',
} as const

export type Role = keyof typeof SALTS

type PrfInputs = { prf: { eval: { first: BufferSource } } }
type PrfOutputs = { prf?: { enabled?: boolean; results?: { first?: BufferSource } } }

const random = (length: number): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(length))

async function salt(role: Role): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(SALTS[role]))
}

function secretOf(credential: Credential | null): Uint8Array | undefined {
  const outputs = (credential as PublicKeyCredential | null)?.getClientExtensionResults() as PrfOutputs | undefined
  const first = outputs?.prf?.results?.first
  if (!first) return undefined
  const bytes = first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer)
  return bytes.length === 32 ? bytes.slice() : undefined
}

export function passkeysSupported(): boolean {
  return typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

/** Ask for an existing passkey on this site and derive the secret from it. */
export async function passkeySecret(role: Role): Promise<Uint8Array | undefined> {
  return (await passkeyWithId(role))?.secret
}

/**
 * Like `passkeySecret`, and says which passkey answered. `allow` limits the
 * prompt to those credentials (the vault's passkey slots).
 */
export async function passkeyWithId(role: Role, allow?: Uint8Array[]): Promise<{ id: Uint8Array; secret: Uint8Array } | undefined> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      rpId: location.hostname,
      userVerification: 'required',
      allowCredentials: allow?.map((id) => ({ type: 'public-key' as const, id: id as Uint8Array<ArrayBuffer> })),
      extensions: { prf: { eval: { first: await salt(role) } } } as PrfInputs,
    },
  })) as PublicKeyCredential | null
  const secret = secretOf(credential)
  return credential && secret ? { id: new Uint8Array(credential.rawId), secret } : undefined
}

/**
 * Create a passkey for this site and derive the secret from it. Some
 * authenticators only evaluate the PRF on a later sign-in, so this may show
 * a second prompt; a failure there says so, because the passkey itself now
 * exists.
 */
export async function createPasskey(role: Role, label: string): Promise<Uint8Array | undefined> {
  return (await createPasskeyWithId(role, label))?.secret
}

/** Like `createPasskey`, and returns the new passkey's credential id. */
export async function createPasskeyWithId(role: Role, label: string): Promise<{ id: Uint8Array; secret: Uint8Array } | undefined> {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: random(32),
      rp: { name: 'Sayso', id: location.hostname },
      user: { id: random(16), name: label, displayName: label },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { prf: { eval: { first: await salt(role) } } } as PrfInputs,
    },
  })
  const outputs = (credential as PublicKeyCredential | null)?.getClientExtensionResults() as PrfOutputs | undefined
  if (!credential || (!outputs?.prf?.enabled && !outputs?.prf?.results)) return undefined
  const id = new Uint8Array((credential as PublicKeyCredential).rawId)
  const secret = secretOf(credential)
  if (secret) return { id, secret }
  // Some browsers refuse a new prompt while the last one is still closing.
  await new Promise((resolve) => setTimeout(resolve, 400))
  try {
    const second = await passkeyWithId(role, [id])
    return second && { id, secret: second.secret }
  } catch (err) {
    throw new PasskeyStepError('second', err)
  }
}

/** The passkey was made, but the prompt to read a key from it failed. */
class PasskeyStepError extends Error {
  constructor(
    readonly stage: 'second',
    readonly original: unknown,
  ) {
    super('the second passkey prompt did not finish')
    this.name = 'PasskeyStepError'
  }
}

/**
 * What to tell someone whose passkey prompt failed. Browsers word these
 * differently (and Firefox and Safari report a cancelled prompt as "The
 * operation was aborted."), so this goes by the error's name.
 */
export function passkeyProblem(err: unknown): string {
  const second = err instanceof PasskeyStepError
  const original = second ? err.original : err
  const name = (original as { name?: string } | null)?.name
  const reason =
    name === 'NotAllowedError' || name === 'AbortError' || name === 'TimeoutError'
      ? 'The passkey prompt was closed, timed out, or is not allowed on this page.'
      : name === 'InvalidStateError'
        ? 'This device already has a passkey for this inbox.'
        : name === 'NotSupportedError' || name === 'SecurityError'
          ? "This browser can't use a passkey here."
          : `The passkey did not work (${original instanceof Error ? original.message : String(original)}).`
  return second ? `Your passkey was created, but reading a key from it failed. ${reason}` : reason
}
