// Makes data/ in this clone exactly what main has on GitHub. The owner's
// dashboard commits data/ (owner.json, the key vault, mailboxes) straight to
// main, and a push from here replaces main whole: run this first, so the push
// carries the dashboard's latest data instead of an older copy.
//
//     npm run sync:data
import { execFileSync } from 'node:child_process'
import { rmSync } from 'node:fs'

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })

git('fetch', '--quiet', 'origin', 'main')
const listing = git('ls-tree', '-r', '--name-only', 'refs/remotes/origin/main', '--', 'data').split('\n').filter(Boolean)
git('rm', '-r', '-q', '--cached', '--ignore-unmatch', 'data')
rmSync('data', { recursive: true, force: true })
if (listing.length) git('checkout', 'refs/remotes/origin/main', '--', 'data')
console.log(`data/: ${listing.length} file(s) from origin/main`)
