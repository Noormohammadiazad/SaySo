// Verified senders (spec section 8): a credential the owner signs for one
// sender identity, at any time after that sender first wrote.
import { asBytes, asMap, asText, asUint, decodeExact, encode, type CborValue } from './cbor'
import { verify } from './ident'
import type { OwnerKeys } from './keys'
import { ascii, concat, equal, invalid, malformed, tooLarge, type Bytes } from './prims'

export const MAX_LABEL = 64
const CONTEXT = /* @__PURE__ */ ascii('sayso/v1/verified')

export interface Verification {
  sid: Bytes
  label: string
  /** Unix seconds. */
  issued: number
}

const byteLength = (text: string): number => new TextEncoder().encode(text).length

export function mintVerification(owner: OwnerKeys, sid: Bytes, label: string, issued: number): Bytes {
  if (byteLength(label) > MAX_LABEL) throw tooLarge()
  const body = encode(
    new Map<number, CborValue>([
      [1, sid],
      [2, label],
      [3, issued],
    ]),
  )
  return concat(owner.sign(concat(CONTEXT, body)), body)
}

/** Check a verification against the owner identity and the sender it must name. */
export function checkVerification(oik: Bytes, credential: Bytes, sid: Bytes): Verification {
  if (credential.length < 64) throw malformed('verification')
  const body = credential.subarray(64)
  verify(oik, concat(CONTEXT, body), credential.subarray(0, 64))
  let parsed: Verification
  try {
    const map = asMap(decodeExact(body, 'verification'), 'verification')
    const issued = asUint(map.get(3), 'verification')
    parsed = {
      sid: asBytes(map.get(1), 'verification', 32),
      label: asText(map.get(2), 'verification'),
      issued: typeof issued === 'bigint' ? Number.MAX_SAFE_INTEGER : issued,
    }
  } catch {
    throw malformed('verification')
  }
  if (byteLength(parsed.label) > MAX_LABEL) throw malformed('verification')
  if (!equal(parsed.sid, sid)) throw invalid('verification is for another sender')
  return parsed
}
