// Invites (spec section 8): bearer credentials the owner hands out so a
// sender's thread shows as verified.
import { asBytes, asMap, asText, asUint, decodeExact, encode, type CborValue } from './cbor'
import { SIG_LEN, verify, type OwnerKeys } from './keys'
import { ascii, concat, expired, malformed, tooLarge, type Bytes } from './prims'

export const INVITE_ID_LEN = 16
export const MAX_LABEL = 64
const CONTEXT = /* @__PURE__ */ ascii('sayso/v1/invite')

export interface InviteInfo {
  id: Bytes
  label: string
  notAfter: number
}

const byteLength = (text: string): number => new TextEncoder().encode(text).length

/** Sign an invite. `id` must be 16 fresh random bytes. */
export function mintInvite(owner: OwnerKeys, id: Bytes, label: string, notAfter: number): Bytes {
  if (byteLength(label) > MAX_LABEL) throw tooLarge()
  const body = encode(
    new Map<number, CborValue>([
      [1, id],
      [2, label],
      [3, notAfter],
    ]),
  )
  return concat(owner.sign(concat(CONTEXT, body)), body)
}

/** Check an invite presented at `now` against the owner identity. */
export function verifyInvite(oik: Bytes, invite: Bytes, now: number): InviteInfo {
  if (invite.length < SIG_LEN) throw malformed('invite')
  const body = invite.subarray(SIG_LEN)
  verify(oik, concat(CONTEXT, body), invite.subarray(0, SIG_LEN))
  let parsed: InviteInfo
  try {
    const map = asMap(decodeExact(body, 'invite'), 'invite')
    const notAfter = asUint(map.get(3), 'invite')
    parsed = {
      id: asBytes(map.get(1), 'invite', INVITE_ID_LEN),
      label: asText(map.get(2), 'invite'),
      notAfter: typeof notAfter === 'bigint' ? Number.MAX_SAFE_INTEGER : notAfter,
    }
  } catch {
    throw malformed('invite')
  }
  if (byteLength(parsed.label) > MAX_LABEL) throw malformed('invite')
  if (now > parsed.notAfter) throw expired()
  return parsed
}
