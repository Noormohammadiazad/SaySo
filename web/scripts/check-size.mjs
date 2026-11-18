// Fails the build when what a first visit downloads before it can show the
// page grows past the budget: the entry script and stylesheet the HTML
// names, gzip-compressed as a server sends them.
//
//     node scripts/check-size.mjs [dist] [budget KiB]
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'

const dist = process.argv[2] ?? 'dist'
const budget = Number(process.argv[3] ?? 50) * 1024
const html = readFileSync(join(dist, 'index.html'), 'utf8')
const files = [...html.matchAll(/(?:src|href)="\.\/(assets\/[^"]+\.(?:js|css))"/g)].map((m) => m[1])
let total = gzipSync(html, { level: 9 }).length
const rows = [`  index.html ${total}`]
for (const file of files) {
  const size = gzipSync(readFileSync(join(dist, file)), { level: 9 }).length
  rows.push(`  ${file} ${size}`)
  total += size
}
console.log(rows.join('\n'))
const kib = (n) => `${(n / 1024).toFixed(1)} KiB`
if (total > budget) {
  console.error(`First load is ${kib(total)} gzipped, over the ${kib(budget)} budget.`)
  process.exit(1)
}
console.log(`First load: ${kib(total)} gzipped (budget ${kib(budget)}).`)
