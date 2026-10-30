#!/usr/bin/env bash
# Rebuild the release's files and compare them (RELEASING.md, SECURITY.md).
#
#   tools/reproduce.sh twice PART...   build each PART twice, in two fresh
#                                      folders, and fail if a file differs
#   tools/reproduce.sh release vX.Y.Z [PART...]
#                                      build PART (default: python npm source)
#                                      at that tag and compare each file with
#                                      the release's SHA256SUMS
#
# PART: python npm source cpp c (tools/release_build.sh says what each needs).
# REPRODUCE_KEEP=DIR keeps the first build's files there.
# The Python package and the npm tarball are the same bytes from any
# machine with the tools the release names in its build-info files (the
# Python ones are pinned by hash in tools/release-requirements.txt; Node's
# version shows in build-info-npm.txt). The native archives are the same
# bytes with the same compiler: the release's are built with GCC 15 on
# GitHub's ubuntu-26.04 image.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO=${LANTERN_REPO:-JigSawFr/lantern-sdk}
mode=${1:-}
shift || true
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

case "$mode" in
  twice)
    [ $# -gt 0 ] || set -- python npm source
    "$ROOT/tools/release_build.sh" -o "$WORK/one" "$@" > /dev/null
    "$ROOT/tools/release_build.sh" -o "$WORK/two" "$@" > /dev/null
    if [ -n "${REPRODUCE_KEEP:-}" ]; then
      mkdir -p "$REPRODUCE_KEEP"
      cp "$WORK"/one/* "$REPRODUCE_KEEP/"
    fi
    status=0
    for file in "$WORK"/one/*; do
      name=$(basename "$file")
      case "$name" in build-info-*) continue ;; esac
      if cmp -s "$file" "$WORK/two/$name"; then
        echo "same      $(sha256sum "$file" | cut -d' ' -f1)  $name"
      else
        echo "DIFFERENT $name"
        status=1
      fi
    done
    exit $status
    ;;
  release)
    tag=${1:?"reproduce.sh release vX.Y.Z [PART...]"}
    shift
    [ $# -gt 0 ] || set -- python npm source
    git -C "$ROOT" rev-parse --verify --quiet "$tag^{commit}" > /dev/null \
      || git -C "$ROOT" fetch --quiet origin "refs/tags/$tag:refs/tags/$tag"
    curl -fsSL -o "$WORK/SHA256SUMS" "https://github.com/$REPO/releases/download/$tag/SHA256SUMS"
    LANTERN_REF=$tag LANTERN_VERSION=${tag#v} "$ROOT/tools/release_build.sh" -o "$WORK/built" "$@" > /dev/null
    status=0
    for file in "$WORK"/built/*; do
      name=$(basename "$file")
      case "$name" in build-info-*) continue ;; esac
      want=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$WORK/SHA256SUMS")
      have=$(sha256sum "$file" | cut -d' ' -f1)
      if [ -z "$want" ]; then
        echo "not in the release  $name"
      elif [ "$want" = "$have" ]; then
        echo "same      $have  $name"
      else
        echo "DIFFERENT $name: built $have, released $want"
        status=1
      fi
    done
    exit $status
    ;;
  *)
    sed -n '2,18p' "$0"
    exit 2
    ;;
esac
