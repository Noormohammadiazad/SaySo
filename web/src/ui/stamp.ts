import { stampSearch } from '../crypto/stamp'

/**
 * Find a stamp for an envelope, yielding to the page between batches so the
 * interface stays responsive.
 */
export async function mintStamp(eid: Uint8Array, bits: number): Promise<Uint8Array> {
  const batch = 50_000
  for (let start = 0; ; start += batch) {
    const stamp = stampSearch(eid, bits, start, batch)
    if (stamp) return stamp
    await new Promise((resolve) => setTimeout(resolve))
  }
}
