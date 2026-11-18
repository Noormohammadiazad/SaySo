// Builds crates/sayso-wasm for the browser into web/src/wire/pkg:
// cargo compiles to WebAssembly, then wasm-bindgen writes the JavaScript and
// TypeScript glue.
//
// Release builds are then shrunk with wasm-opt (the `binaryen` dev dependency).
//
// Two things need care:
// - wasm-bindgen's command-line tool must be the exact version of the
//   wasm-bindgen crate in Cargo.lock; it is installed here when it is not.
// - One dependency (ring) compiles C for WebAssembly, which needs an archiver
//   that understands wasm objects. Apple's `ar` does not, so unless the
//   caller already chose one we use the `llvm-ar` from Rust's `llvm-tools`.
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repo = resolve(web, '..')
const out = resolve(web, 'src/wire/pkg')
const dev = process.argv.includes('--dev')

const capture = (cmd, ...args) => execFileSync(cmd, args, { encoding: 'utf8' }).trim()
const run = (cmd, args, env = process.env) => {
  const result = spawnSync(cmd, args, { stdio: 'inherit', cwd: repo, env })
  if (result.status !== 0) process.exit(result.status ?? 1)
}

// ---- the wasm-bindgen tool, pinned to the lockfile ----
const lock = readFileSync(join(repo, 'Cargo.lock'), 'utf8')
const wanted = /name = "wasm-bindgen"\nversion = "([^"]+)"/.exec(lock)?.[1]
if (!wanted) {
  console.error('wasm-bindgen is not in Cargo.lock; run `cargo fetch` first.')
  process.exit(1)
}
let installed
try {
  installed = capture('wasm-bindgen', '--version').split(' ')[1]
} catch {
  // Not installed.
}
if (installed !== wanted) {
  console.log(`Installing wasm-bindgen-cli ${wanted} (found ${installed ?? 'none'})`)
  run('cargo', ['install', 'wasm-bindgen-cli', '--version', wanted, '--locked'])
}

// ---- compile ----
const env = { ...process.env }
if (!env.AR_wasm32_unknown_unknown) {
  const host = /host: (\S+)/.exec(capture('rustc', '-vV'))[1]
  const ar = join(capture('rustc', '--print', 'sysroot'), 'lib/rustlib', host, 'bin', 'llvm-ar')
  if (existsSync(ar)) {
    env.AR_wasm32_unknown_unknown = ar
  } else if (process.platform === 'darwin') {
    console.error('llvm-ar not found. Run: rustup component add llvm-tools')
    process.exit(1)
  }
}
env.CC_wasm32_unknown_unknown ??= 'clang'

const target = 'wasm32-unknown-unknown'
run('cargo', ['build', '-p', 'sayso-wasm', '--target', target, ...(dev ? [] : ['--release'])], env)

// ---- generate bindings ----
const wasm = join(repo, 'target', target, dev ? 'debug' : 'release', 'sayso_wasm.wasm')
run('wasm-bindgen', [wasm, '--out-dir', out, '--target', 'web', ...(dev ? ['--debug'] : [])])

// ---- shrink ----
// Release only: optimise for size and drop names, debug info and the
// producers section. This has to come after wasm-bindgen, which needs the
// sections a cargo-level `strip = true` would remove.
if (!dev) {
  const bound = join(out, 'sayso_wasm_bg.wasm')
  const before = statSync(bound).size
  run(join(web, 'node_modules/.bin/wasm-opt'), [bound, '-o', bound, '-Oz', '--strip-debug', '--strip-producers'])
  const after = statSync(bound).size
  console.log(`wasm-opt: ${(before / 1e6).toFixed(2)} MB -> ${(after / 1e6).toFixed(2)} MB`)
}
