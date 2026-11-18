// Encrypted file chunks on this device, in the browser's private file system
// (OPFS), one directory per file root. Falls back to memory where OPFS is
// missing, which limits file size to what fits in RAM.

export interface ChunkStore {
  /** False when chunks live in memory and are lost with the page. */
  readonly persistent: boolean
  /** Bytes this store can still take, as far as the browser will say. */
  room(): Promise<number>
  /** How many chunks are stored contiguously from index 0. */
  have(root: string, upTo: number): Promise<number>
  write(root: string, index: number, bytes: Uint8Array): Promise<void>
  read(root: string, index: number): Promise<Uint8Array | undefined>
  remove(root: string): Promise<void>
}

class OpfsChunks implements ChunkStore {
  readonly persistent = true

  constructor(private readonly dir: FileSystemDirectoryHandle) {}

  async room(): Promise<number> {
    const { quota = 0, usage = 0 } = await navigator.storage.estimate()
    return Math.max(0, quota - usage)
  }

  private file(root: string, create: boolean): Promise<FileSystemDirectoryHandle> {
    return this.dir.getDirectoryHandle(root, { create })
  }

  async have(root: string, upTo: number): Promise<number> {
    let dir: FileSystemDirectoryHandle
    try {
      dir = await this.file(root, false)
    } catch {
      return 0
    }
    let count = 0
    while (count < upTo) {
      try {
        await dir.getFileHandle(String(count))
        count++
      } catch {
        break
      }
    }
    return count
  }

  async write(root: string, index: number, bytes: Uint8Array): Promise<void> {
    const dir = await this.file(root, true)
    // Write under a temporary name first so a half-written chunk is never
    // counted as present.
    const handle = await dir.getFileHandle(`${index}.part`, { create: true })
    const writable = await handle.createWritable()
    await writable.write(bytes as Uint8Array<ArrayBuffer>)
    await writable.close()
    const done = await dir.getFileHandle(String(index), { create: true })
    const out = await done.createWritable()
    await out.write(await handle.getFile())
    await out.close()
    await dir.removeEntry(`${index}.part`)
  }

  async read(root: string, index: number): Promise<Uint8Array | undefined> {
    try {
      const dir = await this.file(root, false)
      const file = await (await dir.getFileHandle(String(index))).getFile()
      return new Uint8Array(await file.arrayBuffer())
    } catch {
      return undefined
    }
  }

  async remove(root: string): Promise<void> {
    await this.dir.removeEntry(root, { recursive: true }).catch(() => undefined)
  }
}

/** What a page may reasonably hold in memory when there is no OPFS. */
const MEMORY_BUDGET = 256 << 20

class MemoryChunks implements ChunkStore {
  readonly persistent = false
  private readonly files = new Map<string, Map<number, Uint8Array>>()

  async room(): Promise<number> {
    let used = 0
    for (const file of this.files.values()) for (const chunk of file.values()) used += chunk.length
    return Math.max(0, MEMORY_BUDGET - used)
  }

  async have(root: string, upTo: number): Promise<number> {
    const file = this.files.get(root)
    let count = 0
    while (file && count < upTo && file.has(count)) count++
    return count
  }

  async write(root: string, index: number, bytes: Uint8Array): Promise<void> {
    let file = this.files.get(root)
    if (!file) this.files.set(root, (file = new Map()))
    file.set(index, bytes)
  }

  async read(root: string, index: number): Promise<Uint8Array | undefined> {
    return this.files.get(root)?.get(index)
  }

  async remove(root: string): Promise<void> {
    this.files.delete(root)
  }
}

export async function openChunks(name: string): Promise<ChunkStore> {
  try {
    const top = await navigator.storage.getDirectory()
    const dir = await top.getDirectoryHandle(name, { create: true })
    // Probe: some browsers expose OPFS but not writable streams on the main thread.
    const probe = await dir.getFileHandle('.probe', { create: true })
    await (await probe.createWritable()).close()
    await dir.removeEntry('.probe')
    return new OpfsChunks(dir)
  } catch {
    return new MemoryChunks()
  }
}
