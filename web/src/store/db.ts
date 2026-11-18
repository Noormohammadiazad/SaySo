// A tiny key-value store over IndexedDB. Values are bytes (anything secret
// is wrapped by the core before it gets here), plus the odd `CryptoKey`.

function wait<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

export class Kv {
  private constructor(private readonly db: IDBDatabase) {}

  static async open(name: string): Promise<Kv> {
    const request = indexedDB.open(name, 1)
    request.onupgradeneeded = () => request.result.createObjectStore('kv')
    return new Kv(await wait(request))
  }

  private store(mode: IDBTransactionMode): IDBObjectStore {
    // Writes are keys and queued messages: ask for them to be on disk before
    // the write counts as done, not merely handed to the operating system.
    return this.db.transaction('kv', mode, { durability: mode === 'readwrite' ? 'strict' : 'default' }).objectStore('kv')
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    return wait(this.store('readonly').get(key))
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    await wait(this.store('readwrite').put(value, key))
  }

  /** Any value IndexedDB can store, such as a non-extractable `CryptoKey`. */
  async getValue<T>(key: string): Promise<T | undefined> {
    return wait(this.store('readonly').get(key)) as Promise<T | undefined>
  }

  async put(key: string, value: unknown): Promise<void> {
    await wait(this.store('readwrite').put(value, key))
  }

  async del(key: string): Promise<void> {
    await wait(this.store('readwrite').delete(key))
  }

  /** Every entry whose key starts with `prefix`, in key order. */
  async scan(prefix: string): Promise<[string, Uint8Array][]> {
    const range = IDBKeyRange.bound(prefix, prefix + '￿')
    const store = this.store('readonly')
    const [keys, values] = await Promise.all([wait(store.getAllKeys(range)), wait(store.getAll(range))])
    return keys.map((key, i) => [String(key), values[i] as Uint8Array])
  }
}

/**
 * Ask the browser not to evict this site's storage under pressure. Browsers
 * may say no (some only agree for installed or frequently used sites);
 * returns whether storage is now protected.
 */
export async function keepStorage(): Promise<boolean> {
  try {
    return (await navigator.storage.persisted()) || (await navigator.storage.persist())
  } catch {
    return false
  }
}
