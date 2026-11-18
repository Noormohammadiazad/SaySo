import preact from '@preact/preset-vite'
import { defineConfig } from 'vitest/config'
import { standins } from './dev/standins'
import { chaos } from './dev/chaos'
import { wasmParts } from './dev/wasm-parts'

export default defineConfig({
  // Relative asset paths, so the build works under https://<owner>.github.io/<repo>/.
  base: './',
  // Like GitHub Pages: a missing file is a 404, not the page. (The app routes
  // by #hash, so it needs no fallback.)
  appType: 'mpa',
  plugins: [preact(), chaos(), standins(), wasmParts()],
  // terser squeezes the first-load script under its budget (scripts/check-size.mjs).
  build: { target: 'es2022', minify: 'terser', terserOptions: { compress: { passes: 2 }, format: { comments: false } } },
  server: { port: 5183, strictPort: true },
  preview: { port: 5184, strictPort: true },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
})
