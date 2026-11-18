// Moves the one workflow in .github/workflows/ to a file name it has never
// had: <slug of its name:>-<UTC date>-<UTC time>.yml, always later than the
// current one. Contents are left untouched.
//
// GitHub numbers a workflow's runs by its file path, so a path that never
// existed starts again at run #1. Run this first, on every push:
//
//     npm run rotate:workflow
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, renameSync } from 'node:fs'
import { join } from 'node:path'

const DIR = '.github/workflows'
const git = (...args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()

const files = readdirSync(DIR).filter((name) => !name.startsWith('.'))
if (files.length !== 1) {
  console.error(`${DIR} must hold exactly one workflow; it holds ${files.length}: ${files.join(', ') || 'none'}.`)
  process.exit(1)
}
const [current] = files
const declared = /^name:\s*['"]?(.+?)['"]?\s*$/m.exec(readFileSync(join(DIR, current), 'utf8'))?.[1]
if (!declared) {
  console.error(`${current} has no top-level name: to build its file name from.`)
  process.exit(1)
}
const slug = declared.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')

const stampOf = (date) => date.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)
const dateOf = (stamp) => new Date(`${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`)

// Every workflow path this clone has ever seen, so none comes back.
let seen = new Set()
try {
  seen = new Set(git('log', '--all', '--format=', '--name-only', '--', DIR).split('\n').filter(Boolean).map((p) => p.split('/').pop()))
} catch {
  // Not a git repository yet, or no history: nothing seen.
}
seen.add(current)

let when = new Date()
const previous = /-(\d{8}-\d{6})\.ya?ml$/.exec(current)?.[1]
if (previous && stampOf(when) <= previous) when = new Date(dateOf(previous).getTime() + 1000)
let next = `${slug}-${stampOf(when)}.yml`
while (seen.has(next)) {
  when = new Date(when.getTime() + 1000)
  next = `${slug}-${stampOf(when)}.yml`
}

const from = join(DIR, current)
const to = join(DIR, next)
let tracked = true
try {
  git('ls-files', '--error-unmatch', from)
} catch {
  tracked = false
}
// git mv stages the move, so git status shows it as a rename.
if (tracked) execFileSync('git', ['mv', from, to], { stdio: 'inherit' })
else renameSync(from, to)
console.log(`${from} -> ${to}`)
