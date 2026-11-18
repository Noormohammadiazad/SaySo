declare module 'virtual:sayso-wasm-parts' {
  import type { WasmParts } from './wire/load'
  /** The WebAssembly core as gzip parts; `null` during `vite dev`. */
  const parts: WasmParts | null
  export default parts
}
