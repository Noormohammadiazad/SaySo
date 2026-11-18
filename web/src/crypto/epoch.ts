// Epochs and the TTL state machine (spec section 3). Times are Unix seconds.
import { invalid } from './prims'

/** How far a sender's clock may run ahead of an epoch's start. */
export const CLOCK_SKEW = 3600
/** How many upcoming epochs the owner keeps published. */
export const LOOKAHEAD = 4

export type EpochState = 'scheduled' | 'active' | 'grace' | 'retained' | 'shredded'

const U32_MAX = 0xffff_ffff

export class Epochs {
  constructor(
    readonly epochLen: number,
    readonly grace: number,
    readonly ttl: number,
  ) {
    if (epochLen < 3600) throw invalid('epoch length under one hour')
    if (grace > ttl) throw invalid('grace longer than ttl')
    if (ttl > 10 * 365 * 86_400) throw invalid('ttl over ten years')
  }

  /** The epoch that contains `now`. */
  at(now: number): number {
    return Math.min(Math.floor(now / this.epochLen), U32_MAX)
  }

  start(e: number): number {
    return e * this.epochLen
  }

  /** The moment the secret of epoch `e` must be destroyed. */
  shredAt(e: number): number {
    return this.start(e) + this.epochLen + this.ttl
  }

  state(e: number, now: number): EpochState {
    const start = this.start(e)
    const end = start + this.epochLen
    if (now < start) return 'scheduled'
    if (now < end) return 'active'
    if (now < end + this.grace) return 'grace'
    if (now < end + this.ttl) return 'retained'
    return 'shredded'
  }

  private startsWithinSkew(e: number, now: number): boolean {
    const start = this.start(e)
    return now < start && start - now <= CLOCK_SKEW
  }

  senderMaySeal(e: number, now: number): boolean {
    const state = this.state(e, now)
    return state === 'active' || (state === 'scheduled' && this.startsWithinSkew(e, now))
  }

  receiverAccepts(e: number, now: number): boolean {
    const state = this.state(e, now)
    return state === 'active' || state === 'grace' || (state === 'scheduled' && this.startsWithinSkew(e, now))
  }

  /** `[first, last]`: every epoch up to now whose secret still exists. */
  live(now: number): [number, number] {
    const span = this.epochLen + this.ttl
    const oldest = now < span ? 0 : Math.floor((now - span) / this.epochLen) + 1
    return [oldest, this.at(now)]
  }

  /** `[first, last]`: the epochs the owner keeps public keys published for. */
  published(now: number): [number, number] {
    const current = this.at(now)
    const graceEpochs = Math.ceil(this.grace / this.epochLen)
    return [Math.max(0, current - graceEpochs), Math.min(U32_MAX, current + LOOKAHEAD)]
  }
}
