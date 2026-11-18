// Shapes of what the Live Wire module (../wire) hands to JavaScript.

/** One request from a connected sender, from `WireServer.next()`. */
export type WireEvent =
  | { type: 'opened' | 'closed' | 'listening'; conn: number }
  | { type: 'seen'; conn: number; eid: Uint8Array }
  | { type: 'drop'; conn: number; id: number; stamp: Uint8Array; envelope: Uint8Array }
  | { type: 'putBegin'; conn: number; id: number; root: Uint8Array; chunks: number; totalCipher: number }
  | { type: 'putChunk'; conn: number; id: number; root: Uint8Array; index: number; cipher: Uint8Array }
  | { type: 'putEnd'; conn: number; id: number; root: Uint8Array }
  | { type: 'getBegin'; conn: number; id: number; root: Uint8Array }
  | { type: 'getChunk'; conn: number; id: number; root: Uint8Array; index: number }

/** Wire refusal codes (`SaysoError.code` when `kind` is `refused`). */
export const Refusal = {
  Malformed: 1,
  WeakStamp: 2,
  EpochNotAccepted: 3,
  TooLarge: 4,
  NotFound: 5,
  Busy: 6,
} as const

export interface SaysoError extends Error {
  kind: 'timeout' | 'connect' | 'closed' | 'protocol' | 'refused' | 'core' | 'input' | 'changed'
  code?: number
}

export const isSaysoError = (err: unknown): err is SaysoError =>
  err instanceof Error && err.name === 'SaysoError'
