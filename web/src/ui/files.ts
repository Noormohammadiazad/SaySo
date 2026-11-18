// Encrypting a file for sending, and turning received chunks back into a file.
import { FileOpener, FileSealer, randomBytes, toHex } from '../core'
import type { FileRef } from '../core'
import type { ChunkStore } from '../store/chunks'
import { formatBytes } from './format'

const CHUNK = 1 << 20

/**
 * A file that was encrypted once and whose encrypted chunks sit in a chunk
 * store, ready to be uploaded now or after a reload. Everything here is safe
 * to keep: the key is not part of it.
 */
export interface StagedFile {
  /** Where the chunks are in the chunk store. */
  store: string
  root: Uint8Array
  /** Concatenated 32-byte leaves. */
  leaves: Uint8Array
  totalCipher: number
  chunks: number
}

/**
 * Encrypt a file chunk by chunk into `chunks`. The file is read once; the
 * upload later reads the stored ciphertext, so the original may change or
 * disappear in the meantime.
 */
export async function stageFile(
  file: File,
  chunks: ChunkStore,
  onProgress?: (done: number) => void,
  signal?: AbortSignal,
): Promise<{ staged: StagedFile; ref: FileRef }> {
  const sealer = new FileSealer(file.size)
  const room = await chunks.room()
  // Ciphertext is the padded size plus a tag per chunk: under 13% over.
  if (file.size * 1.13 + CHUNK > room) {
    throw new Error(
      `Not enough browser storage to queue ${file.name}: it needs about ${formatBytes(file.size)}, and ${formatBytes(room)} is free.`,
    )
  }
  const store = toHex(randomBytes(16))
  try {
    for (let index = 0; index < sealer.chunks; index++) {
      signal?.throwIfAborted()
      const start = Math.min(index * CHUNK, file.size)
      const data = new Uint8Array(await file.slice(start, start + sealer.dataLen(index)).arrayBuffer())
      await chunks.write(store, index, sealer.encrypt(index, data))
      onProgress?.((index + 1) / sealer.chunks)
    }
    const sealed = sealer.seal()
    return {
      staged: {
        store,
        root: sealed.root,
        leaves: sealed.leaves,
        totalCipher: sealed.totalCipher,
        chunks: sealer.chunks,
      },
      ref: {
        name: file.name.slice(0, 200),
        mime: (file.type || 'application/octet-stream').slice(0, 100),
        size: sealed.size,
        root: sealed.root,
        key: sealed.key,
        paddedSize: sealed.paddedSize,
      },
    }
  } catch (err) {
    await chunks.remove(store)
    throw err
  }
}

type SavePicker = (options: { suggestedName: string }) => Promise<FileSystemFileHandle>

/**
 * Decrypt a stored file and hand it to the user. Streams to disk where the
 * browser can (so size is not limited by memory); otherwise builds it in
 * memory and triggers a download. `store` is where its chunks are.
 */
export async function saveFile(ref: FileRef, chunks: ChunkStore, store: string = toHex(ref.root)): Promise<void> {
  const opener = new FileOpener(ref.key, ref.size, ref.paddedSize)
  try {
    const plain = async (index: number): Promise<Uint8Array<ArrayBuffer>> => {
      const cipher = await chunks.read(store, index)
      if (!cipher) throw new Error('this file is not fully on this device yet')
      return opener.decrypt(index, cipher) as Uint8Array<ArrayBuffer>
    }

    const picker = (window as unknown as { showSaveFilePicker?: SavePicker }).showSaveFilePicker
    if (picker) {
      let handle: FileSystemFileHandle
      try {
        handle = await picker({ suggestedName: ref.name })
      } catch {
        return // The user closed the dialog.
      }
      const out = await handle.createWritable()
      for (let index = 0; index < opener.chunks; index++) await out.write(await plain(index))
      await out.close()
      return
    }

    const parts: Uint8Array<ArrayBuffer>[] = []
    for (let index = 0; index < opener.chunks; index++) parts.push(await plain(index))
    const url = URL.createObjectURL(new Blob(parts, { type: ref.mime }))
    const link = document.createElement('a')
    link.href = url
    link.download = ref.name
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 60_000)
  } finally {
    // Nothing to free: the TypeScript core holds no WebAssembly memory.
  }
}
