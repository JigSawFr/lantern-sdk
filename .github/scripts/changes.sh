#!/usr/bin/env bash
# Which parts of the repository a run has to check, from the files it
# changes: one line `<part>=true|false` per part, for $GITHUB_OUTPUT
# (ci.yml's `changes` job). Every part runs when the list cannot be known
# (a scheduled or manual run, a new branch, a failed fetch) or when the CI
# itself changes.
#
#   changes.sh <event> [<before>]
#
# For a pull request, the checkout is GitHub's merge commit (two commits
# deep): its first parent is the base branch, so HEAD^1..HEAD is the pull
# request's change. For a push, <before> is the commit the branch was on.
set -euo pipefail

event=$1
before=${2:-}
parts=(cpp c python typescript workflows)

all() {
  for part in "${parts[@]}"; do echo "$part=true"; done
  exit 0
}

case "$event" in
  pull_request)
    files=$(git diff --name-only HEAD^1 HEAD) || all
    ;;
  push)
    if [ -z "$before" ] || [ "$before" = 0000000000000000000000000000000000000000 ]; then all; fi
    git fetch --quiet --depth=1 origin "$before" || all
    files=$(git diff --name-only "$before" HEAD) || all
    ;;
  *)
    all
    ;;
esac

echo "Files changed:" >&2
echo "$files" | sed 's/^/  /' >&2

# What every part shares: the CI's own entry, scripts and actions
if grep -qE '^\.github/(workflows/ci\.yml|scripts/|actions/)' <<< "$files"; then all; fi

# What each part is made of, as its workflow's header says: its folder, the
# specification (the submodule), the files every library shares (the
# submodules' list, the licences), the malicious test server its tests run,
# and its workflow
shared='^(spec|\.gitmodules|REUSE\.toml)$|^LICENSES/'
declare -A pattern=(
  [cpp]="^cpp/|^python/tools/hostile_server\.py$|^\.github/workflows/cpp\.yml$|$shared"
  [c]="^c/|^cpp/|^\.github/workflows/c\.yml$|$shared"
  [python]="^python/|^\.github/workflows/python\.yml$|$shared"
  [typescript]="^typescript/|^python/tools/hostile_server\.py$|^python/src/lantern/|^\.github/workflows/typescript\.yml$|$shared"
  [workflows]='^\.github/'
)
for part in "${parts[@]}"; do
  if grep -qE "${pattern[$part]}" <<< "$files"; then echo "$part=true"; else echo "$part=false"; fi
done
