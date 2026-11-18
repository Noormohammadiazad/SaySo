// Live Wire: the only part of Sayso that still needs the WebAssembly module
// (iroh's QUIC over relays). Nothing loads it at startup. It is fetched the
// first time a live transfer is needed: a sender with files queued or an
// attachment to fetch, or an owner turning on the live receiver. After that
// the browser keeps it, so later visits start it at once.
import parts from 'virtual:sayso-wasm-parts'
import wholeUrl from './pkg/sayso_wasm_bg.wasm?url'
import { loadWasmBytes } from './load'

export type Wire = typeof import('./pkg/sayso_wasm.js')
export type { WireClient, WireServer } from './pkg/sayso_wasm.js'
type Progress = (fraction: number | undefined, stalls: number) => void

let ready: Promise<Wire> | undefined
const listeners = new Set<Progress>()

/**
 * The Live Wire module, downloading it on first use. Calls share one
 * download; a failed one is forgotten, so calling again tries again.
 */
export function loadWire(onProgress?: Progress): Promise<Wire> {
  if (onProgress) listeners.add(onProgress)
  ready ??= (async () => {
    // The parts sit in assets/wasm/, beside the script this ends up in. (A
    // variable keeps the bundler from treating this as an asset to resolve.)
    const here = import.meta.url
    const [glue, bytes] = await Promise.all([
      import('./pkg/sayso_wasm.js'),
      loadWasmBytes(parts, wholeUrl, {
        resolve: (name) => new URL(`wasm/${name}`, here).href,
        onProgress: (fraction, stalls) => listeners.forEach((listener) => listener(fraction, stalls)),
      }),
    ])
    await glue.default({ module_or_path: bytes as Uint8Array<ArrayBuffer> })
    return glue
  })()
  const attempt = ready
  attempt.then(
    () => onProgress && listeners.delete(onProgress),
    () => {
      if (onProgress) listeners.delete(onProgress)
      if (ready === attempt) ready = undefined
    },
  )
  return attempt
}
