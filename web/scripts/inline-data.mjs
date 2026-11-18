// Writes the site's configuration and the owner's signed owner.json into the
// built index.html, for the deploy workflow:
//
//     node web/scripts/inline-data.mjs <dist> <owner/repo>
//
// Run after the data branch was copied to <dist>/data. With this the page
// needs no request of its own before it can show, verified, who it delivers
// to: on networks where every new request can stall for seconds, that is
// the difference between a page that is there and one that is loading.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const [dist, repo] = process.argv.slice(2)
if (!dist || !/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repo ?? '')) {
  console.error('usage: inline-data.mjs <dist> <owner/repo>')
  process.exit(2)
}

const data = { config: { repo }, at: Date.now() }
const ownerPath = join(dist, 'data', 'owner.json')
if (existsSync(ownerPath)) {
  const text = readFileSync(ownerPath, 'utf8').trim()
  try {
    const doc = JSON.parse(text)
    const body = JSON.parse(doc.body)
    if (typeof doc.key !== 'string' || typeof doc.sig !== 'string') throw new Error('not a signed document')
    // The browser verifies the signature; here only the claim is compared,
    // to say so in the log when it names another repository.
    const named = body.github?.repo
    if (named && named.toLowerCase() !== repo.toLowerCase()) {
      console.log(`::warning title=owner.json names another repository::It was published for ${named}; senders here will not see it as verified.`)
    }
    data.owner = text
  } catch (err) {
    console.log(`::warning title=owner.json not inlined::${err.message}`)
  }
}

// Safe inside <script>: no "</script>", no line separators JavaScript dislikes.
const json = JSON.stringify(data).replace(/[<\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
const page = join(dist, 'index.html')
const html = readFileSync(page, 'utf8')
const block = /<script id="sayso-data" type="application\/json">[\s\S]*?<\/script>/
if (!block.test(html)) {
  console.error('index.html has no sayso-data block')
  process.exit(1)
}
writeFileSync(page, html.replace(block, () => `<script id="sayso-data" type="application/json">${json}</script>`))
console.log(`Inlined the configuration for ${repo}${data.owner ? ' and owner.json' : ''}: ${json.length} bytes.`)
