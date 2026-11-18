#!/usr/bin/env bash
# Exercises ops/harvest.sh against a throwaway git remote: first run, a
# repeat, and an expiry. Needs a signed owner.json and matching relay output,
# both of which a local `npm run dev` session leaves behind:
#
#   ops/test-harvest.sh .dev-data/owner.json relay.ndjson
set -euo pipefail

manifest="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
poll="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
repo="$(cd "$(dirname "$0")/.." && pwd)"
ops="$repo/target/release/sayso-ops"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
quiet() { "$@" >/dev/null 2>&1; }

quiet git init --bare "$scratch/remote.git"
quiet git init -b main "$scratch/clone"
cd "$scratch/clone"
git config user.name test && git config user.email test@example.invalid
git remote add origin "$scratch/remote.git"
echo code >file && git add file && quiet git commit -m code && quiet git push origin main

# The identity is pinned: in a workflow GITHUB_REPOSITORY_OWNER would name the real owner.
run() { SAYSO_LOGIN=test SAYSO_OPS="$ops" SAYSO_POLL_FILE="$poll" "$repo/ops/harvest.sh"; }
# Run the script to completion, then look for `$1` in what it printed.
# (Piping straight into `grep -q` would close the pipe at the first match and
# kill the script mid-run.)
says() {
  local out
  out="$(run)" || fail "harvest.sh exited with an error"
  printf '%s\n' "$out" | grep -q "$1"
}
vault_files() { git --git-dir="$scratch/remote.git" ls-tree -r --name-only sayso-vault 2>/dev/null || true; }
vault_commits() { git --git-dir="$scratch/remote.git" rev-list --count sayso-vault; }

echo "1. no inbox yet"
says "No inbox yet" || fail "should say there is no inbox"
[ -z "$(vault_files)" ] || fail "must not create a vault without an owner.json"

mkdir -p data && cp "$manifest" data/owner.json
git add data/owner.json && quiet git commit -m data && quiet git push origin main

echo "2. first harvest creates the vault"
says "stored=[1-9]" || fail "should store at least one drop"
drops="$(vault_files | grep -c '^drops/e[0-9]*/[0-9a-f]\{64\}\.bin$' || true)"
[ "$drops" -ge 1 ] || fail "vault has no drops"
[ "$(vault_commits)" = 1 ] || fail "vault should start with one commit"
author="$(git --git-dir="$scratch/remote.git" log -1 --format='%an <%ae> | %cn <%ce>' sayso-vault)"
[ "$author" = "test <test@users.noreply.github.com> | test <test@users.noreply.github.com>" ] || fail "vault commit made as '$author'"
git --git-dir="$scratch/remote.git" merge-base main sayso-vault >/dev/null 2>&1 && fail "vault must share no history with the code"

echo "3. the same relay output again changes nothing"
head_before="$(git --git-dir="$scratch/remote.git" rev-parse sayso-vault)"
says "Nothing new" || fail "should report nothing new"
[ "$(git --git-dir="$scratch/remote.git" rev-parse sayso-vault)" = "$head_before" ] || fail "branch moved"

# Commit a change straight to the vault branch, as if history had gone on.
poke() {
  quiet git fetch origin sayso-vault
  git worktree add --quiet --detach "$scratch/poke" FETCH_HEAD
  (cd "$scratch/poke" && "$@")
  git -C "$scratch/poke" add -A && quiet git -C "$scratch/poke" commit -m "test: $1"
  quiet git -C "$scratch/poke" push origin HEAD:refs/heads/sayso-vault
  git worktree remove --force "$scratch/poke"
}

echo "4. a new drop on an existing vault replaces it with one commit"
poke rm -rf drops
[ -z "$(vault_files | grep '^drops/' || true)" ] || fail "test setup: drops should be gone"
says "Vault updated" || fail "should report an update"
[ "$(vault_files | grep -c '^drops/e[0-9]*/[0-9a-f]\{64\}\.bin$')" = "$drops" ] || fail "the drop was not filed again"
[ "$(vault_commits)" = 1 ] || fail "expected one parentless commit, got $(vault_commits)"

plant_expired() { mkdir -p drops/e1 && echo old >"drops/e1/$(printf 'a%.0s' $(seq 64)).bin"; }
poke plant_expired
[ "$(vault_commits)" = 2 ] || fail "test setup: expected two commits before expiry"

echo "5. expiry deletes old epochs and leaves one commit"
says "Removed 1 expired" || fail "should report the expiry"
vault_files | grep -q '^drops/e1/' && fail "expired epoch still in the vault"
[ "$(vault_files | grep -c '^drops/e[0-9]*/[0-9a-f]\{64\}\.bin$')" = "$drops" ] || fail "current drops were lost"
[ "$(vault_commits)" = 1 ] || fail "history was not squashed"
planted="$(printf 'a%.0s' $(seq 64))"
git --git-dir="$scratch/remote.git" log --all --name-only --format= | grep -q "$planted" && fail "expired file still reachable from a branch"

echo "6. far in the future every epoch has expired"
SAYSO_NOW=4102444800 run >/dev/null
vault_files | grep -q '^drops/' && fail "drops survived their expiry"
[ "$(vault_commits)" = 1 ] || fail "history was not squashed"

echo "ok: harvest script"
