// Build step: ship the WebAssembly core as small gzip parts.
//
// The page's loader (src/wire/load.ts) fetches the parts one by one and
// retries any that stall, which a single 1.2 MB download cannot do. The
// parts are gzip-compressed here, because servers do not compress files of
// unknown type, and named after the module's hash, so they can be cached
// forever.
//
// The list of parts reaches the page through the virtual module
// `virtual:sayso-wasm-parts`. During `vite dev` it is `null` and the loader
// fetches the whole module instead.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import type { Plugin } from 'vite'

const VIRTUAL = 'virtual:sayso-wasm-parts'
const RESOLVED = '\0' + VIRTUAL
/**
 * Small enough to finish before a bad link freezes the connection: on one
 * such network, fresh connections stalled after about 73 KB.
 */
const PART_SIZE = 48 * 1024

const module = resolve(dirname(fileURLToPath(import.meta.url)), '../src/wire/pkg/sayso_wasm_bg.wasm')

export function wasmParts(): Plugin {
  let building = false
  return {
    name: 'sayso-wasm-parts',
    configResolved(config) {
      building = config.command === 'build'
    },
    resolveId(id) {
      return id === VIRTUAL ? RESOLVED : undefined
    },
    load(id) {
      if (id !== RESOLVED) return undefined
      if (!building) return 'export default null'

      const wasm = readFileSync(module)
      const sha256 = createHash('sha256').update(wasm).digest('hex')
      const gz = gzipSync(wasm, { level: 9 })
      const parts: { name: string; size: number }[] = []
      for (let at = 0, i = 0; at < gz.length; at += PART_SIZE, i++) {
        const source = gz.subarray(at, at + PART_SIZE)
        // Named after its own bytes: a CDN may keep a file for hours, and a
        // name must never stand for two different contents. (Naming parts
        // after the module once served old, larger parts under new names.)
        const own = createHash('sha256').update(source).digest('hex').slice(0, 20)
        const name = `sayso-${own}-${i}.bin`
        // Beside the script that loads them: assets/wasm/.
        this.emitFile({ type: 'asset', fileName: `assets/wasm/${name}`, source })
        parts.push({ name, size: source.length })
      }
      return `export default ${JSON.stringify({ size: wasm.length, sha256, parts })}`
    },
  }
}
