# Sayso architecture

Sayso lets anyone send end-to-end encrypted messages and large files to the
owner of a GitHub repository, and get replies, from a static page on GitHub
Pages. There is no backend and no secret in the page.

## The one hard problem

A static page cannot accept writes, and GitHub accepts writes only from
signed-in accounts. A page cannot sign a visitor into GitHub either: the OAuth
endpoints refuse cross-origin browser calls. So something else has to catch an
anonymous sender's ciphertext and hold it until the owner is around. Sayso
answers with three tiers, tried in order, all carrying the same sealed
envelope.

## Tiered transport

The sender seals once (see [PROTOCOL.md](PROTOCOL.md)), then the orchestrator
picks a lane. Envelopes are named by their hash, so delivering the same one
through two lanes is harmless: the owner keeps one copy.

| Tier | Catcher | Used when | Carries | Sender may close the tab |
|---|---|---|---|---|
| 0. Live relay | the owner's open dashboard, subscribed to the inbox topic; the sender's page, subscribed to its thread's mailbox topic | always, for every message, reply and control notice | sealed envelopes; replies are also kept in the repository | at once: measured 0.2 to 0.3 s end to end through a local relay |
| 1. Live Wire | the owner's open dashboard, or a courier that is already awake | there is a file to move (the module loads only then) | files of any size, nothing stored in transit | after the upload |
| 2. Buffer | public relays (Waku, ntfy), then the vault | the owner's dashboard is closed | messages of up to about 120 KB, and the announcement of files still to come | once the first relay accepts: measured 0.3 s on ntfy, 5 s on Waku from a cold start |
| 3. Courier | a GitHub Actions job running a receiver | no receiver answers and there is a file to move | files, written to Releases in the vault | after the handover |

### Tier 1: Live Wire (milestone 1)

Sender and receiver both run an iroh endpoint. In a browser iroh is relay-only:
traffic goes through a public relay as end-to-end encrypted QUIC. Sayso lists
the public relays itself (`sayso_wire::RELAYS`), the same servers as iroh's
defaults but written without the trailing dot iroh uses. On the network this
was built on, a browser could not open a WebSocket to the dotted names at all. The sender
dials the receiver ids listed in the signed manifest; a receiver that is not
online simply does not answer, and the dial times out.

It is loaded only for files: when a sender queues one, or when a drop that
announces one reaches the dashboard, which then starts its receiver.

### Tier 0: live over the relays

Both sides hold an ntfy Server-Sent Events subscription while their page is
open. The owner's is on the inbox topic, where senders leave drops; a drop
shows in the dashboard a fraction of a second after it is sent, with no
polling and no "check now". The sender's is on the thread's mailbox topic,
`"sm" + hex(KDF("sayso/v1/mbox-topic", tag_key)[0..20])`: unlinkable to anyone
without the tag key, and the same in every epoch. The owner pushes every
reply there the moment it is sealed, then commits a copy to the thread's
mailbox file in the background for a sender who was away. Acknowledgements
(a drop reached the owner), deletions and verifications travel the same
way, as control payloads.

A subscription that goes quiet for 75 seconds (ntfy sends a keepalive every
45) is reopened from the last message it saw; a reconnect also reads the
harvest vault, which may hold what a relay no longer does.

### Messenger lifecycle

- **Verify a sender at any time.** From a conversation's menu the owner
  names the sender and signs a verification credential bound to their
  identity key (PROTOCOL.md section 8). It is kept in the key vault and sent
  to the sender, whose page shows it. Invites still verify ahead of time.
- **Rename, block, unblock.** Names and blocks are the owner's alone, kept in
  the key vault so every device agrees. A blocked sender's new messages are
  not kept and not acknowledged.
- **Delete for both sides.** Either side can delete a message, or the whole
  conversation, with a signed control payload (`ctl: 2`). The dashboard
  removes its copies from the repository too: replies out of the mailbox
  file, drops out of the harvest vault. It lists the envelope ids as purged
  in the vault, so no device shows them again and copies the harvest job
  files later are removed on sight. Copies on public relays expire with the
  relay (twelve hours on ntfy.sh).

### Tier 2: Buffer (milestone 2)

A relay is anything that accepts an anonymous write and gives it back later:
`put(item)` for senders, `drain(cursor)` for the owner. The manifest lists the
relays an owner collects from. Two kinds exist:

- **ntfy.** A plain HTTP publish and poll service, `ntfy.sh` or self-hosted.
  It keeps messages twelve hours and caps them at 4 KB, so an item is split
  into parts. On by default.
- **Waku.** A peer-to-peer network whose store nodes keep messages. One
  message holds a whole item. It needs a large SDK, loaded only when used.
  Off by default: on some networks it never connects. The owner can turn it
  on in Settings.

No public network promises retention, which is why two kinds exist. A relay
that fails or stalls is skipped for ten minutes rather than waited on again
each time. A sender
writes to all of them at once and is finished when the first accepts; the
others complete in the background and the message shows on how many relays it
landed. The owner drops repeats by envelope id.

Three collectors move items onward:

1. **The dashboard**, whenever it is open, reads every relay directly.
2. **The harvest job** of the workflow in `.github/workflows/` runs every
   four hours in the owner's repository. It polls the ntfy relays and files what
   passes the public checks in the vault branch, so a message outlives the
   relay's twelve hours. It runs `ops/harvest.sh`, which uses the `sayso-ops`
   tool for everything except network and git.
3. **The dashboard again**, reading the vault.

The harvest job does not read Waku: that needs the JavaScript SDK, and the
dashboard collects from Waku itself. How long Waku's public store nodes keep
a message is not documented; a message that exists only there depends on the
owner opening the dashboard in time.

A message with files uses both lanes: the envelope, which names the files,
goes to the relays at once, and the files follow over Live Wire when both
sides are online.

### Tier 3: Courier, with on-demand wake-up (milestone 3)

The courier is the Live Wire receiver built as a native binary. It holds no
decryption key: it checks stamps and chunk hashes and writes ciphertext to the
vault. It starts two ways:

- **On schedule.** The sender waits with the tab open and sees a countdown.
- **Instant wake-up.** The sender clicks through to a pre-filled GitHub issue
  and submits it with their own account. The `issues` event starts the courier.

Three things about wake-up that the design accounts for:

1. It takes tens of seconds, not five: a runner has to be assigned and boot.
2. It is public and permanent. The issue shows which GitHub account asked this
   owner's courier to wake, and public event archives keep that after the
   issue is deleted. The page says so before the sender clicks.
3. Anyone with an account can trigger it. The workflow never reads the issue's
   text, runs in one concurrency group, and ignores a wake while a courier is
   up.

### What waits in the sender's browser

There is no background transfer after the tab closes. A service worker is
stopped shortly after its page goes away and cannot hold an iroh connection.
Instead, everything a sender has queued is kept in the browser: the sealed
envelope in IndexedDB, and each file as encrypted chunks in the origin
private file system. The file is read and encrypted once, when it is
attached; after that the original is not needed. When the sender returns
and the owner is online, the upload continues from the first chunk the
receiver does not have, without asking for the file again.

The price is disk space: a queued file is stored a second time, encrypted,
until it is delivered. A file larger than the browser's free quota is
refused with a message saying so.

## Trust

- Payloads are sealed to the owner's current epoch key in the sender's browser.
  Relays, buffers, the courier and GitHub see ciphertext only.
- Senders pin the owner identity key on first contact and can compare its
  fingerprint out of band. The signed owner.json also names the GitHub
  account and repository that published it; the page shows the owner as
  verified on GitHub when that is the repository the page belongs to, since
  only someone who can write there could have published it.
- The owner is the person who holds both a GitHub token that can write to
  the repository and the passphrase (or a passkey) of the key vault in it.
  Neither alone opens the dashboard.
- Deleting from a public repository is not erasure, so the TTL is enforced by
  destroying the epoch's secret key: the dashboard rewrites the vault without
  it and squashes the branch history. Section 12 of PROTOCOL.md says what an
  old copy of the vault still allows.
- The limits are listed at the end of [PROTOCOL.md](PROTOCOL.md).

## Where data lives

One repository holds the code, the data and the harvest vault. Every branch
is exactly one commit with no parent: the current state, nothing else.

```
<owner>/<repo>
├─ main                     source, the workflow, and data/:
│  ├─ (GitHub Pages)        the built page with data/ in it, deployed by the workflow
│  └─ data/
│     ├─ owner.json            signed: owner identity, GitHub account, parameters,
│     │                     receivers, relays, epoch public keys
│     ├─ owner-vault.enc    the key vault: root, live epoch secrets, settings,
│     │                     what the owner decided about each thread; sealed
│     │                     under the passphrase (argon2id) and any passkeys
│     ├─ mail/e<epoch>/<addr>.bin   sealed replies and notices for a sender
│     └─ blob/e<epoch>/<root>/<i>   reserved: chunks of files attached to replies
└─ sayso-vault              orphan branch, written by the harvest job
   └─ drops/e<epoch>/<eid>.bin      sealed envelopes collected from the relays
```

Milestone 3 adds Releases (tag `e<epoch>`, up to 2 GiB per asset) for file
chunks the courier receives, and the option of a separate private repository
for the vault so inbound ciphertext is never public.

Everything that expires is grouped by epoch, so expiry is one directory and
one release. Because every commit has no parent, a removed file (an expired
epoch, a deleted message, an older vault with a destroyed epoch secret in
it) is unreachable from its branch at once. GitHub may keep the unreachable
objects for a while, and earlier clones still have them, so this is
hygiene; the guarantee is the destroyed key.

The dashboard writes through the GitHub Git Data API: blobs, a tree on the
current one, a commit with `parents: []`, and the branch moved onto it with
`force: true`, as the account of the token at its noreply address. Writes
made within two seconds of each other share one commit. On `main` the same
commit renames the workflow file (`<slug>-<UTC date>-<UTC time>.yml`), so
the push starts a run numbered #1, which verifies and redeploys the page;
the dashboard sends no `repository_dispatch`. The harvest job pushes the
vault the same way, with a lease. A developer's push replaces `main` whole,
so `npm run sync:data` brings `data/` from GitHub first, and `npm run verify`
refuses a clone whose `data/` differs from it.

### How data reaches readers

Senders read the public data from the site that served the page:
`<site>/data/owner.json`, `<site>/data/mail/...`. The workflow's deploy
job copies `data/` into the site on every deploy, and every dashboard
commit is a push that starts one. One path, with no fallback, so a sender
never sees two copies of different age. Live replies do not wait for it.

This is deliberate. Some networks serve GitHub Pages and the GitHub API but
refuse `raw.githubusercontent.com` outright; the network this was built on
is one of them. Serving data from the page's own site means that if the page
loaded, its data loads too.

The owner's dashboard does not wait for deploys: it reads and writes the
branches through the GitHub API with the owner's token.

The deploy workflow also writes the repository's name and the current
owner.json into `index.html` itself (`web/scripts/inline-data.mjs`), so a
first visit verifies and shows the owner with no request beyond the page and
its script, and writes `sayso.config.json` with the repository's name for
older pages. `data/deploy.json` records what the last deploy contained.

A reply left in a mailbox therefore reaches a sender after a deploy, not at
once. Live replies are not affected.

## Code layout

```
crates/
  sayso-core/      formats and cryptography; no I/O, no async, no clock
  sayso-wire/      the wire protocol over iroh; builds natively and for wasm32
  sayso-ops/       the harvest and expiry tool the repository's workflow runs
  sayso-wasm/      the JavaScript-facing API of core and wire (cargo + wasm-bindgen)
  sayso-courier/   the native receiver for tier 3 (milestone 3, not yet written)
ops/               harvest.sh, run by the workflow, and its test
web/               the page: sender view, with the dashboard as a separate chunk
  scripts/         builds the wasm package; writes data into the page; size budget
  dev/             local stand-ins: data, vault, a live relay, and a fake GitHub
  src/crypto/      the core in TypeScript (@noble), checked against Rust vectors
  src/core/        re-exports the core with byte helpers
  src/wire/        Live Wire: the wasm package and its resilient loader, lazy
  src/data/        finds the branches; reads owner.json and the harvest vault
  src/buffer/      the relays: Waku and ntfy behind one interface
  src/identity/    the key vault, and secrets derived from passkeys
  src/store/       IndexedDB records and encrypted file chunks (OPFS)
  src/publish/     parentless commits through the GitHub API (or the local stand-in)
  src/ui/          design system: tokens, kit, overlays, FA/EN strings, themes
  src/sender/      sender view and its session logic, including lane selection
  src/owner/       dashboard: receiver, collector, epoch key lifecycle, replies
  src/ui/          shared components and helpers
  src/test/        in-memory GitHub and ntfy for unit tests
docs/
.github/workflows/ one workflow: verify, deploy to Pages, harvest, self-test
scripts/           rotate:workflow and verify, run before every push
```

The reference core is Rust (`sayso-core`): the harvest job, the courier and
the wire protocol use it. The page runs a TypeScript port of the parts it
needs (`web/src/crypto`, on the audited @noble libraries), because the Rust
core only reached the browser inside a 2.7 MB WebAssembly module, and on a
slow link a first visit spent minutes downloading it before it could show
anything. The port is held to the reference byte for byte:
`cargo run -p sayso-wire --example vectors` writes every key derivation,
encoding and envelope from fixed inputs, the TypeScript tests must reproduce
them, and CI fails if the vectors are out of date. Only Live Wire (iroh's
QUIC over relays) still needs the WebAssembly module, and the page loads it
when a live transfer needs it.

## Milestones

1. Done. Shared core, Live Wire, sender view and dashboard.
2. Done. Buffer lane, harvest job, mailbox publishing through the GitHub API,
   persistent outbox, history compaction.
   Then: live relays both ways, delivery receipts, verification at any time,
   deletion for both sides, one-commit branches, the Persian/English
   interface.
3. Courier, wake-up, vault releases for large files.
4. Verified-sender proofs beyond invites. Done early: owner sign-in on any
   device (GitHub token + vault passphrase or passkey).

## Known weak points

- **Throughput through the public iroh relays** has measured between 0.1 and
  0.8 MB/s between two browser tabs. That is fine for documents and slow for
  anything in the gigabytes; the courier of milestone 3 is where a faster
  path has to come from.
- **The Waku SDK** has had no release since December 2025, and its libp2p
  dependency carries a published advisory about accepting forged peer
  records. In Sayso that can cost availability of the Waku relay, not
  confidentiality: everything on a relay is sealed. It is loaded only when
  the Waku relay is used, and an owner can switch that relay off.
- **No lease on a forced branch update.** GitHub's REST API cannot move a
  branch only if it is still where it was read. The dashboard reads the head
  again just before moving it and rebuilds if it moved, which narrows a race
  with another writer (a second dashboard, a developer's push) to one round
  trip without closing it. The key vault merges on every sync, so a lost
  vault write heals; a reply's repository copy could be lost, while its live
  delivery stands.
- **Every dashboard save is a workflow run.** Each commit to `main` starts
  one run (#1, under a new file name): verify, which skips the build when
  only `data/` changed, then a deploy, about a minute of Actions time each.
  Writes within two seconds share a commit. The scheduled harvest runs on
  the current file and counts up (#2, #3...) until the next push renames
  it: the workflow token cannot rename workflow files, so a scheduled run
  cannot start at #1.
- **The token needs "Workflows: Read and write"** besides "Contents: Read
  and write", because every save renames the workflow file. Such a token
  can also change what the workflow does: keep it to this one repository,
  in this one browser.
- **A sender can delete the whole conversation on the owner's side.**
  That is what deletion for both sides means; the owner can block a sender
  who abuses it. Neither side can delete what the other keeps elsewhere
  (screenshots, copies), nor a relay's copy before it expires.
- **Two dashboards open at once share one live address.** Every device
  derives the same receiver key from the root, and the relay keeps one
  connection per key. Messages left on the relays reach both; a live
  transfer reaches whichever holds the relay connection. A receiver key per
  device, listed in owner.json, would fix it.
- **Messages a dashboard received live** (and the files that came with
  them) are kept in that browser only. Another device sees what the relays
  and the harvest job still hold, not those, and not the replies sent from
  elsewhere.
- **Reply attachments** reach a sender only while both sides are online.
- **ntfy.sh allows 250 messages per IP address per day.** A short drop
  takes 2 of them, the largest 49. Behind shared or carrier-grade NAT the
  budget is shared with strangers; the Waku relay is the other path.
- **Page weight.** A first visit downloads the page with owner.json written
  in (about 12 KB once there is an owner), a 42 KB script and a 2 KB
  stylesheet (gzip), and right after them a 16 KB chunk with the sealing
  code. CI fails the build when the first three pass 50 KB. The 1.2 MB of
  WebAssembly for Live Wire comes only when a file is sent or fetched live,
  or when the dashboard's live receiver is on; the Waku SDK (about 250 KB)
  only when the Waku relay is used. On the network this was built on,
  requests to the site sometimes froze after a few tens of KB and sometimes
  waited about 10.5 seconds for their first byte. The WebAssembly loader is
  built for both (25 parts of 48 KB named by their hash, 30 s for a first
  byte and 8 s of silence while data flows, two at a time, alternating
  connection pools, no fixed limit while parts keep arriving, checked
  against its SHA-256 and kept in the Cache API), and before this change a
  first visit there spent about 6 minutes in it before showing anything.

  Measured on sayso.ir from that network on 2026-11-18, with nothing
  cached: the sender view's first screen at 0.95 s (page 0.33 s, script
  0.38 s). At other moments the same network held the page itself for 10
  to 34 seconds, or froze the connection so the dashboard's chunk never
  arrived; no code in the page can shorten that, so the page now says
  after 10 seconds that the connection seems stuck and offers a reload,
  which got through on the next try.
- **A CDN in front of the site.** Cloudflare caches `.bin` files, the
  mailboxes among them, and caches 404s too. Senders add a query string that
  changes every 20 seconds to every data read, which gets past that; a Cache
  Rule that bypasses the cache for `/data/*` is the cleaner fix.
- **Tested browsers.** Chromium and Firefox (Gecko) have run the whole flow
  (live messages and receipts both ways included)
  against a local stand-in for GitHub: a first visit, sending, and the owner
  signing in on a fresh profile with a token and the passphrase. Safari
  (WebKit) has not been run, and no real passkey has been used.

## Starting up without the network

Nothing the network does should stop the page from opening.

- **Nothing to download first.** The sender view verifies the owner from
  the owner.json written into the page (or the copy kept from the last
  visit) and shows them at once: about 0.1 s after navigation on a local
  server, in Chromium and in Firefox. Only a page deployed before the inbox
  existed has to fetch owner.json, and that step retries on its own, 2
  seconds later, then 4, up to a minute.
- **Sending needs no live connection.** A message is sealed, stamped and
  left on the relays (0.2 to 0.4 s locally). Only files, and an owner with
  no relay, wait for Live Wire.
- **Signing in is the dashboard's only network step.** A browser that
  signed in before opens from its own copy of the vault, then catches up
  with the repository in the background. Publishing, collecting and the
  receiver report their state in the header and in banners.
- **Failures say where.** A step that fails names itself and its cause,
  and the sign-in form says what was wrong with the token or the
  passphrase in words.
- **Every request has a deadline**, including its body. Nothing reports a
  bare "The operation was aborted.".
- **A passkey that fails stays in the form**, and the passphrase still works.

To try the built page against a bad network locally, `vite preview` takes
`SAYSO_CHAOS`; see `web/dev/chaos.ts`. To try the GitHub-backed flow with no
account, `SAYSO_FAKE_GITHUB=<any test token> vite preview` serves the page
as Pages would, with GitHub played in memory (`web/dev/standins.ts`).
