#!/usr/bin/env bash
# Collect buffered drops into the vault branch, and drop expired epochs.
#
# Run from a checkout of the repository, by the workflow's harvest job or
# by hand. It reads the owner's signed data/owner.json from main, polls each
# ntfy relay it lists, files what passes sayso-ops' checks under
# drops/e<epoch>/ on the vault branch, and pushes.
#
# The vault branch is always exactly one commit with no parent, the current
# state, pushed with a lease: nothing removed from it (expired epochs, drops
# the owner deleted) stays reachable from it.
#
#   SAYSO_OPS        path to the sayso-ops binary   (default: target/release/sayso-ops)
#   SAYSO_REMOTE     git remote to read and push    (default: origin)
#   SAYSO_POLL_FILE  read relay output from this file instead of the network (tests)
#   SAYSO_NOW        Unix time to run at instead of the clock (tests)
set -euo pipefail

ops="${SAYSO_OPS:-target/release/sayso-ops}"
remote="${SAYSO_REMOTE:-origin}"
code_branch="main"
vault_branch="sayso-vault"
work="$(mktemp -d)"
vault="$work/vault"
manifest="$work/owner.json"

cleanup() {
  git worktree remove --force "$vault" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

note() { echo "::notice title=$1::$2"; }

# ---- the owner's document ---------------------------------------------------
if ! git fetch --quiet --depth=1 "$remote" "$code_branch" 2>/dev/null ||
  ! git show FETCH_HEAD:data/owner.json >"$manifest" 2>/dev/null; then
  note "No inbox yet" "$code_branch has no data/owner.json. Create the inbox in the dashboard first."
  exit 0
fi

# ---- the vault as it is now -----------------------------------------------
before=""
if git fetch --quiet "$remote" "$vault_branch" 2>/dev/null; then
  before="$(git rev-parse FETCH_HEAD)"
  git worktree add --quiet --detach "$vault" "$before"
else
  # First run: the vault starts as a branch with no history in common with the code.
  git worktree add --quiet --detach "$vault"
  git -C "$vault" checkout --quiet --orphan "$vault_branch"
  git -C "$vault" rm -rf --quiet . >/dev/null 2>&1 || true
  echo "Sayso vault: sealed drops filed by the harvest job. Do not edit by hand." >"$vault/README.txt"
fi

# ---- harvest ----------------------------------------------------------------
if [ -n "${SAYSO_POLL_FILE:-}" ]; then
  "$ops" harvest "$manifest" "$vault" <"$SAYSO_POLL_FILE"
else
  "$ops" plan "$manifest" | while IFS= read -r url; do
    host="$(printf '%s' "$url" | cut -d/ -f3)"
    if curl --silent --show-error --fail --max-time 60 --proto '=https' "$url" >"$work/poll.ndjson"; then
      echo "$host: $("$ops" harvest "$manifest" "$vault" <"$work/poll.ndjson")"
    else
      echo "::warning title=Relay unreachable::Could not read $host; it will be tried again on the next run."
    fi
  done
fi

# ---- expiry -----------------------------------------------------------------
expired="$("$ops" expire "$manifest" "$vault" | sed 's/^expired=//')"

# ---- commit and push ----------------------------------------------------------
git -C "$vault" add --all
if [ -n "$before" ] && git -C "$vault" diff --cached --quiet; then
  echo "Nothing new."
  exit 0
fi

# The repository's one identity (npm run verify checks it on main): the
# owner's account at its GitHub noreply address.
owner="${SAYSO_LOGIN:-${GITHUB_REPOSITORY_OWNER:-$(git config user.name || echo sayso)}}"
export GIT_AUTHOR_NAME="$owner" GIT_AUTHOR_EMAIL="$owner@users.noreply.github.com"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

message="Vault: harvest"
[ "$expired" -gt 0 ] && message="Vault: harvest, $expired expired epoch(s) removed"
# One commit, no parent: the branch holds only what is current.
commit="$(git -C "$vault" commit-tree "$(git -C "$vault" write-tree)" -m "$message")"
if [ -z "$before" ]; then
  git -C "$vault" push --quiet "$remote" "$commit:refs/heads/$vault_branch"
else
  # The lease makes the push fail, rather than clobber, if the branch moved
  # since it was fetched; the next run tries again.
  git -C "$vault" push --quiet --force-with-lease="refs/heads/$vault_branch:$before" "$remote" "$commit:refs/heads/$vault_branch"
fi
[ "$expired" -gt 0 ] && echo "Removed $expired expired epoch(s)."
echo "Vault updated."
