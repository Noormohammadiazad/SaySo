// Files (spec section 5): padding, chunk encryption, and the Merkle tree
// that lets any party verify and resume a transfer without the key.
import { open, seal } from './aead'
import { ascii, CoreError, concat, invalid, kdf, malformed, randomBytes, TAG_LEN, tooLarge, u64be, type Bytes } from './prims'

/** Plaintext bytes per chunk. */
export const CHUNK = 1 << 20
export const MAX_CIPHER_CHUNK = CHUNK + TAG_LEN
export const MIN_PADDED = 4096
/** The most chunks a file may have on the wire (`sayso-wire`). */
export const MAX_FILE_CHUNKS = 2 ** 18

/**
 * Padmé: round `len` up so that at most about 12% is added and the result
 * reveals only O(log log len) bits of the true length.
 */
export function padme(len: number): number {
  if (len < 2) return len
  const n = BigInt(len)
  const e = n.toString(2).length - 1
  const s = e.toString(2).length
  const mask = (1n << BigInt(e - s)) - 1n
  return Number((n + mask) & ~mask)
}

export class FilePlan {
  private constructor(
    /** True size in bytes. */
    readonly size: number,
    /** Size after zero padding. */
    readonly padded: number,
    readonly chunks: number,
  ) {}

  static forSize(size: number): FilePlan {
    if (!Number.isSafeInteger(size) || size < 0) throw tooLarge()
    const padded = Math.max(padme(size), MIN_PADDED)
    return new FilePlan(size, padded, Math.ceil(padded / CHUNK))
  }

  /** Rebuild the plan from a `File` entry, refusing sizes a sender would not produce. */
  static fromParts(size: number, padded: number): FilePlan {
    const plan = FilePlan.forSize(size)
    if (plan.padded !== padded) throw invalid('file padding')
    return plan
  }

  private check(i: number): void {
    if (!Number.isInteger(i) || i < 0 || i >= this.chunks) throw invalid('chunk index')
  }

  /** Plaintext bytes in chunk `i`, padding included. */
  plainLen(i: number): number {
    this.check(i)
    return Math.min(this.padded - i * CHUNK, CHUNK)
  }

  /** Bytes of the real file in chunk `i`. */
  dataLen(i: number): number {
    this.check(i)
    return Math.max(0, Math.min(this.size - i * CHUNK, CHUNK))
  }

  get totalCipher(): number {
    return this.padded + this.chunks * TAG_LEN
  }
}

const nonceFor = (i: number): Bytes => concat(new Uint8Array(4), u64be(i))
const aadFor = (chunks: number): Bytes => concat(ascii('sayso/v1/chunk'), u64be(chunks))

export function encryptChunk(key: Bytes, plan: FilePlan, i: number, data: Bytes): Bytes {
  if (data.length !== plan.dataLen(i)) throw invalid('chunk length')
  const plain = new Uint8Array(plan.plainLen(i))
  plain.set(data)
  return seal(key, nonceFor(i), aadFor(plan.chunks), plain)
}

export function decryptChunk(key: Bytes, plan: FilePlan, i: number, cipher: Bytes): Bytes {
  const dataLen = plan.dataLen(i)
  const plain = open(key, nonceFor(i), aadFor(plan.chunks), cipher)
  if (plain.length !== plan.plainLen(i)) throw invalid('chunk length')
  return plain.slice(0, dataLen)
}

export const leaf = (cipher: Bytes): Bytes => kdf('sayso/v1/merkle/leaf', cipher)

function subtree(leaves: Bytes[]): Bytes {
  if (leaves.length === 1) return leaves[0]
  // RFC 6962 shape: split at the largest power of two below n.
  let split = 1
  while (split * 2 < leaves.length) split *= 2
  return kdf('sayso/v1/merkle/node', subtree(leaves.slice(0, split)), subtree(leaves.slice(split)))
}

/** The root that names a file; binds the leaf count and the total length. */
export function merkleRoot(leaves: Bytes[], totalCipher: number): Bytes {
  if (!leaves.length) throw invalid('file without chunks')
  return kdf('sayso/v1/merkle/root', u64be(leaves.length), u64be(totalCipher), subtree(leaves))
}

export interface SealedFile {
  root: Bytes
  key: Bytes
  size: number
  paddedSize: number
  /** Concatenated 32-byte leaves, for the wire manifest. */
  leaves: Bytes
  totalCipher: number
}

/** The file changed between the two passes; sending it would reuse a nonce. */
export class FileChanged extends CoreError {
  override readonly kind = 'changed' as never
  constructor() {
    super('the file changed while it was being sent')
  }
}

/**
 * Encrypts one file chunk by chunk under a fresh random key. `encrypt` is
 * deterministic; a second pass over a chunk whose bytes changed is refused.
 */
export class FileSealer {
  readonly plan: FilePlan
  private readonly key = randomBytes(32)
  private readonly leaves: (Bytes | undefined)[]

  constructor(size: number) {
    this.plan = FilePlan.forSize(size)
    if (this.plan.chunks > MAX_FILE_CHUNKS) throw tooLarge()
    this.leaves = new Array(this.plan.chunks)
  }

  get chunks(): number {
    return this.plan.chunks
  }

  dataLen(index: number): number {
    return this.plan.dataLen(index)
  }

  encrypt(index: number, data: Bytes): Bytes {
    const cipher = encryptChunk(this.key, this.plan, index, data)
    const hashed = leaf(cipher)
    const first = this.leaves[index]
    if (first && toKey(first) !== toKey(hashed)) throw new FileChanged()
    this.leaves[index] = hashed
    return cipher
  }

  seal(): SealedFile {
    if (this.leaves.some((l) => !l) || this.leaves.length !== this.plan.chunks) throw malformed('file: not every chunk was encrypted')
    const leaves = this.leaves as Bytes[]
    const total = this.plan.totalCipher
    return {
      root: merkleRoot(leaves, total),
      key: this.key.slice(),
      size: this.plan.size,
      paddedSize: this.plan.padded,
      leaves: concat(...leaves),
      totalCipher: total,
    }
  }
}

const toKey = (bytes: Bytes): string => String.fromCharCode(...bytes)

/** Decrypts the chunks of a received file. */
export class FileOpener {
  readonly plan: FilePlan
  constructor(
    private readonly key: Bytes,
    size: number,
    paddedSize: number,
  ) {
    this.plan = FilePlan.fromParts(size, paddedSize)
  }

  get chunks(): number {
    return this.plan.chunks
  }

  get totalCipher(): number {
    return this.plan.totalCipher
  }

  decrypt(index: number, cipher: Bytes): Bytes {
    return decryptChunk(this.key, this.plan, index, cipher)
  }
}
