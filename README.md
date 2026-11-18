# Sayso

End-to-end encrypted messages and files to the owner of a GitHub repository,
from a static page on GitHub Pages. No backend, no accounts, no secret in the
page.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how it works and where data lives
- [docs/PROTOCOL.md](docs/PROTOCOL.md): the exact formats and cryptography

## Status

Milestones 1 and 2 of 4 are built.

- **Both online:** messages and files of any size go straight from the
  sender's browser to the owner's dashboard, and replies come straight back.
- **Owner away:** a message is sealed and left on public relays; a scheduled
  workflow files it in the repository; the dashboard collects it later.
  Files wait, encrypted, in the sender's browser and upload when both sides
  are online, without being selected again.
- **Live both ways:** messages, replies, delivery receipts and deletions
  arrive in a fraction of a second over the relays, with no polling.
- **Sender away:** replies also wait in a mailbox file in the repository.
- **Messenger basics:** verify a sender at any time, rename, block, and
  delete a message or a whole conversation for both sides.
- **Persian and English**, right-to-left included, light and dark.
- **Any device:** the owner signs in with a GitHub token for the repository
  and the passphrase of the key vault kept in it (or a passkey added to it).
- **Light:** a sender's first visit loads about 45 KB (gzip) and shows the
  owner, verified, without waiting on any request; the 1.2 MB WebAssembly
  module for live transfers loads only when one starts.

Not built yet: receiving files while the owner is away (milestone 3).

This has not had a security review. Do not rely on it for anything that
matters yet.

## Deploy your own

1. Fork or push this repository to GitHub. It must be public for Pages on a
   free plan.
2. **Settings > Pages > Source: GitHub Actions.** Then run the workflow in
   `.github/workflows/` from the Actions tab (task "deploy"), or push any
   commit.
3. Make a fine-grained personal access token: **Settings > Developer
   settings > Fine-grained tokens**, repository access "Only select
   repositories" with this one repository, permissions **Contents: Read and
   write** and **Workflows: Read and write**, nothing else. With it the
   dashboard commits your public keys, your key vault and replies under
   `data/` on `main`, each save one parentless commit that also renames the
   workflow file (so the run it starts is #1, and it redeploys the page),
   and reads the harvest vault. It is checked with GitHub when you sign in
   and kept only in that browser.
4. Open `https://<you>.github.io/<repo>/#/owner`, paste the token, choose a
   passphrase and create the inbox. The keys are sealed with the passphrase
   (argon2id) into `data/owner-vault.enc` on `main`. That file is
   public, so use a long passphrase you use nowhere else; the form can
   suggest one. On any other device, sign in with a token and the same
   passphrase, or add a passkey under Settings and use that instead.
5. Share the page's address. A custom domain set under Settings > Pages
   works as is. Behind Cloudflare, add a Cache Rule that bypasses the cache
   for `/data/*`, so replies are not held back by Cloudflare's copy.

The repository has one workflow, in `.github/workflows/`. Every push runs
its `verify` job and then `deploy`; its `harvest` job runs every four hours
on its own; and run by hand with the task "selftest", it checks the
dashboard's GitHub code against the real API on a scratch branch.

## Develop

Needs Rust (the toolchain file selects the version, the WebAssembly target and
`llvm-tools`), Node 22 and a C compiler that can target WebAssembly (`clang`).

```bash
cargo test
```

```bash
cd web && npm install && npm run wasm:dev && npm test && npm run dev
```

Then open <http://localhost:5183/#/owner> to create a test inbox and
<http://localhost:5183/> in another tab to write to it. In development the
data branch, the vault and a relay are local folders (`.dev-data/`,
`.dev-vault/`, `.dev-buffer/`) served by stand-ins in `web/dev/`.

### Repository conventions

`main` is one root commit, by one identity. Before every push, from the
repository root:

```bash
npm run rotate:workflow
```

```bash
npm run sync:data
```

```bash
npm run verify
```

The first gives the workflow a file name it has never had (GitHub numbers
runs per file path); the second brings `data/` from GitHub, where the
dashboard commits it, so the push does not replace it with an older copy;
the third checks the workflow, the history, the identity, `data/` and the
files. Then the change is folded into the one commit
(`git commit --amend`) and pushed with `--force-with-lease`. The workflow
runs `npm run verify` again on every push.

To try the production bundle against the same stand-ins:

```bash
cd web && npm run build && npm run preview:local
```

## License

The Vazirmatn font in `web/src/assets/fonts/` is by the Vazirmatn Project
Authors under the SIL Open Font License 1.1 (`OFL.txt` beside it). The rest
is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
