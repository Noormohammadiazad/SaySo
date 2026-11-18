// The repository's rules, checked before every commit and on every push:
//
//     npm run verify
//
// - .github/workflows/ holds exactly one workflow, under a rotated name
//   (see rotate-workflow.mjs), and locally that name is new in this change;
// - main is one root commit, by one identity, author and committer alike;
// - no commit message carries assistant attribution or trailers;
// - no tracked or about-to-be-added file names an AI assistant or vendor
//   (data/ is ciphertext the dashboard writes, and is not read);
// - locally, data/ is exactly what main has on GitHub: the dashboard
//   commits it there, and a push of this clone replaces main whole;
// - no refs/original/* and no branch but main.
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const DIR = '.github/workflows'
const CI = !!process.env.GITHUB_ACTIONS

// The names this repository must not mention, stored ROT13-encoded so that
// this file passes its own check.
const rot13 = (s) => s.replace(/[a-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - 97 + 13) % 26) + 97))
const NAMES = ['pynhqr', 'nagubcvp', 'pbcvybg', 'pungtcg', 'bcranv'].map(rot13)
const TRAILERS = ['co-authored', 'signed-off', 'generated with', '\u{1F916}']

const failures = []
const fail = (message) => failures.push(message)
const git = (...args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'pipe'] })

// The one identity: the repository owner's account at its GitHub noreply
// address. The dashboard commits as the same.
const owner =
  process.env.GITHUB_REPOSITORY_OWNER ??
  // git@github.com:owner/repo, https://github.com/owner/repo, ssh://git@ssh.github.com:443/owner/repo
  /github\.com(?::\d+)?[:/]([^/]+)\/[^/]+$/.exec((() => {
    try {
      return git('remote', 'get-url', 'origin').trim()
    } catch {
      return ''
    }
  })())?.[1]
if (!owner) {
  console.error('npm run verify: cannot tell the repository owner (no GITHUB_REPOSITORY_OWNER, no GitHub origin)')
  process.exit(1)
}
const IDENTITY = `${owner} <${owner}@users.noreply.github.com>`
const hasHead = (() => {
  try {
    git('rev-parse', '--verify', '-q', 'HEAD')
    return true
  } catch {
    return false
  }
})()

// ---- one workflow, under a rotated name ------------------------------------
const workflows = readdirSync(DIR).filter((name) => !name.startsWith('.'))
if (workflows.length !== 1) {
  fail(`${DIR} must hold exactly one workflow; it holds ${workflows.length}: ${workflows.join(', ')}`)
} else {
  const [file] = workflows
  const declared = /^name:\s*['"]?(.+?)['"]?\s*$/m.exec(readFileSync(join(DIR, file), 'utf8'))?.[1] ?? ''
  const slug = declared.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  if (!new RegExp(`^${slug}-\\d{8}-\\d{6}\\.yml$`).test(file)) {
    fail(`${DIR}/${file} is not under a rotated name (${slug}-<date>-<time>.yml); run npm run rotate:workflow`)
  }
  // "This push renames it": compared with what was last pushed, so it holds
  // both before and after the change is committed.
  const pushed = (() => {
    try {
      git('rev-parse', '--verify', '-q', 'refs/remotes/origin/main')
      return 'refs/remotes/origin/main'
    } catch {
      return undefined // Never pushed: nothing to compare with.
    }
  })()
  if (!CI && pushed) {
    const before = git('ls-tree', '--name-only', pushed, `${DIR}/`).split('\n').filter(Boolean)
    if (before.includes(`${DIR}/${file}`)) fail(`${DIR}/${file} is the name already pushed; run npm run rotate:workflow`)
    // With exactly one workflow before, the change must show as a rename.
    if (before.length === 1 && !before.includes(`${DIR}/${file}`)) {
      const staged = git('diff', '--cached', '-M', '--name-status', pushed, '--', DIR)
      if (!staged.split('\n').some((line) => /^R\d*\t/.test(line) && line.endsWith(`\t${DIR}/${file}`))) {
        fail(`the change does not show ${before[0]} renamed to ${DIR}/${file}; rotate with npm run rotate:workflow (it uses git mv)`)
      }
    }
  }
}

// ---- who will commit ---------------------------------------------------------
if (!CI) {
  const name = git('config', 'user.name').trim()
  const email = git('config', 'user.email').trim()
  if (`${name} <${email}>` !== IDENTITY) fail(`git config identity is "${name} <${email}>", not "${IDENTITY}"`)
}

// ---- history: one root commit, one identity, clean messages ------------------
if (hasHead) {
  const identities = [...new Set(git('log', '--format=%an <%ae> | %cn <%ce>').split('\n').filter(Boolean))]
  if (identities.length !== 1 || identities[0] !== `${IDENTITY} | ${IDENTITY}`) {
    fail(`commits must all be by ${IDENTITY} as author and committer; found: ${identities.join('; ')}`)
  }
  const count = Number(git('rev-list', '--count', 'HEAD').trim())
  const parents = git('rev-list', '--parents', '-n', '1', 'HEAD').trim().split(' ').length - 1
  if (count !== 1 || parents !== 0) fail(`main must be one root commit; HEAD has ${count} commits and ${parents} parent(s)`)
  const messages = git('log', '--format=%B').toLowerCase()
  for (const word of NAMES) {
    if (messages.includes(word)) fail(`a commit message names an AI assistant or vendor (${rot13(word)} in ROT13)`)
  }
  for (const word of TRAILERS) {
    if (messages.includes(word)) fail(`a commit message carries an attribution trailer or marker ("${word}")`)
  }
}

// ---- refs ----------------------------------------------------------------------
const refs = git('for-each-ref', '--format=%(refname)').split('\n').filter(Boolean)
if (refs.some((ref) => ref.startsWith('refs/original/'))) fail('refs/original/* is left over from a rewrite; delete it')
let branch = ''
try {
  branch = git('symbolic-ref', '-q', '--short', 'HEAD').trim()
} catch {
  // Detached HEAD (a CI checkout of a commit): no current branch.
}
// main, and the branch an orphan rebuild is being made on; nothing else.
const extra = refs.filter((ref) => ref.startsWith('refs/heads/') && ref !== 'refs/heads/main' && ref !== `refs/heads/${branch}`)
if (extra.length) fail(`branches besides main: ${extra.join(', ')}`)

// ---- files: tracked, and untracked ones git add -A would pick up ---------------
const files = git('ls-files', '-z', '--cached', '--others', '--exclude-standard').split('\0').filter(Boolean)
for (const path of files) {
  if (path.startsWith('data/')) continue
  let bytes
  try {
    bytes = readFileSync(path)
  } catch {
    continue // Deleted in the working tree.
  }
  if (bytes.includes(0)) continue // Binary.
  const text = bytes.toString('utf8').toLowerCase()
  for (const word of NAMES) {
    if (text.includes(word)) fail(`${path} names an AI assistant or vendor (${rot13(word)} in ROT13)`)
  }
}

// ---- data/ is main's, not this clone's -------------------------------------------
if (!CI) {
  let remote = []
  try {
    remote = git('ls-tree', '-r', 'refs/remotes/origin/main', '--', 'data').split('\n').filter(Boolean)
  } catch {
    remote = [] // Never pushed.
  }
  const want = new Map(remote.map((line) => [line.split('\t')[1], line.split(' ')[2].split('\t')[0]]))
  const have = new Map()
  for (const path of files.filter((p) => p.startsWith('data/'))) {
    try {
      have.set(path, git('hash-object', path).trim())
    } catch {
      // Deleted in the working tree.
    }
  }
  const differs = [...new Set([...want.keys(), ...have.keys()])].filter((path) => want.get(path) !== have.get(path))
  // Before main has any data/, this clone may bring it (moving an inbox in).
  if (differs.length && want.size) {
    fail(`data/ differs from origin/main in ${differs.length} file(s) (${differs.slice(0, 3).join(', ')}): the dashboard writes it there. Run npm run sync:data`)
  }
}

if (failures.length) {
  console.error(`npm run verify: ${failures.length} problem(s)\n${failures.map((f) => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log(`npm run verify: ok (${files.length} files, ${hasHead ? 'history checked' : 'no commit yet'}${CI ? ', CI' : ''})`)
