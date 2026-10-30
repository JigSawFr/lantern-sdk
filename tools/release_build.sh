#!/usr/bin/env bash
# The release's files, built reproducibly (RELEASING.md): the same commit,
# SOURCE_DATE_EPOCH and tools give the same bytes, wherever the checkout is.
#
#   tools/release_build.sh [-o OUT] PART...
#
# PART is one or more of:
#   python  the sdist and wheel of lantern-protocol, and their SBOM
#           (needs a Python with tools/release-requirements.txt installed: $PYTHON)
#   npm     the npm tarball of lantern-protocol, as published (without
#           "private"), and its SBOM (needs Node and npm)
#   source  lantern-sdk-VERSION.tar.gz, git archive of the commit
#   cpp     the C++ library installed for this machine (static library,
#           headers, CMake package Lantern), and its SBOM
#   c       the C API installed for this machine (shared and static
#           libraries, headers, CMake packages LanternC and Lantern), and its SBOM
#
# Environment:
#   LANTERN_REF        the commit to build (default HEAD); it is exported with
#                      git archive, so nothing uncommitted reaches the build
#   SOURCE_DATE_EPOCH  every timestamp (default: that commit's time)
#   LANTERN_VERSION    the version in the names of source, cpp and c's files
#                      (default: cpp/CMakeLists.txt's)
#   PYTHON             the Python with the release's tools (default python3)
#   CC, CXX            the compilers (the release uses GCC 15 on ubuntu-26.04)
#
# Each part also writes the tools it used to OUT/build-info-PART.txt.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$PWD/dist
parts=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT=$2; shift 2 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    python|npm|source|cpp|c) parts+=("$1"); shift ;;
    *) echo "release_build.sh: unknown part $1" >&2; exit 2 ;;
  esac
done
[ ${#parts[@]} -gt 0 ] || { echo "release_build.sh: which part? (python npm source cpp c)" >&2; exit 2; }

REF=${LANTERN_REF:-HEAD}
COMMIT=$(git -C "$ROOT" rev-parse --verify "$REF^{commit}")
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct "$COMMIT")}
VERSION=${LANTERN_VERSION:-$(git -C "$ROOT" show "$COMMIT:cpp/CMakeLists.txt" \
  | sed -n 's/^ *VERSION \([0-9][0-9.]*\) # x-release-please-version.*/\1/p')}
PYTHON=${PYTHON:-python3}
ARCH=linux-$(uname -m)
export TZ=UTC LC_ALL=C
umask 022

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/src"
git -C "$ROOT" archive --format=tar "$COMMIT" | tar -x -C "$WORK/src"

# OUT/build-info-PART.txt: the commit, the epoch, and what the tools say
info() { # info COMMAND... (each one a command whose output says a version)
  {
    echo "commit: $COMMIT"
    echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
    for command in "$@"; do
      bash -c "$command" | head -n 1
    done
  } > "$OUT/build-info-$part.txt"
}
native_tools=("cmake --version" "echo ninja \$(ninja --version)" "\"\${CXX:-c++}\" --version")

# A folder as a .tar.gz that depends on nothing but its files
pack() { # pack DIR NAME OUTFILE
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu \
    -C "$1" -cf - "$2" | gzip -n -9 > "$3"
}

# The native parts: Release, no TLS adapter (their libcurl and mbedTLS are
# the app's to choose), the build folder's path kept out of the binaries
native() { # native SOURCE_DIR NAME CMAKE_ARGS...
  local dir=$1 name=$2
  shift 2
  local flags="-ffile-prefix-map=$WORK=."
  cmake -S "$WORK/src/$dir" -B "$WORK/build-$dir" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DLANTERN_CURL=OFF -DLANTERN_MBEDTLS=OFF -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" "$@" > /dev/null
  cmake --build "$WORK/build-$dir" > /dev/null
  cmake --install "$WORK/build-$dir" --prefix "$WORK/pkg-$dir/$name" > /dev/null
  pack "$WORK/pkg-$dir" "$name" "$OUT/$name.tar.gz"
  echo "$OUT/$name.tar.gz"
}

for part in "${parts[@]}"; do
  case "$part" in
    python)
      "$PYTHON" -c "import build, hatchling, cyclonedx_py" 2>/dev/null || {
        echo "release_build.sh: $PYTHON lacks the release's tools:" \
          "pip install --require-hashes -r tools/release-requirements.txt" >&2
        exit 1
      }
      # Without isolation: the build backend is the one installed, pinned by hash
      (cd "$WORK/src/python" && "$PYTHON" -m build --no-isolation --outdir "$WORK/py" . > /dev/null)
      cp "$WORK"/py/* "$OUT/"
      wheel=$(cd "$WORK/py" && ls -- *.whl)
      version=${wheel#lantern_protocol-}
      version=${version%%-*}
      # The SBOM: the wheel installed alone, with what it requires (nothing,
      # for the core: the extras are the app's choice)
      "$PYTHON" -m venv --without-pip "$WORK/py-env"
      "$PYTHON" -m pip --python "$WORK/py-env/bin/python" install --quiet --no-cache-dir "$WORK"/py/*.whl
      sbom="$OUT/lantern-protocol-$version.pypi.cdx.json"
      "$PYTHON" -m cyclonedx_py environment --pyproject "$WORK/src/python/pyproject.toml" --mc-type library \
        --output-reproducible --output-format JSON --spec-version 1.6 -o "$sbom" "$WORK/py-env/bin/python"
      python3 "$ROOT/tools/sbom.py" normalize "$sbom" --name lantern-protocol --version "$version" \
        --purl "pkg:pypi/lantern-protocol@$version"
      info "'$PYTHON' --version" "'$PYTHON' -m build --version | cut -d' ' -f1-2" \
        "'$PYTHON' -c 'import importlib.metadata as m; print(\"hatchling\", m.version(\"hatchling\"))'"
      ls "$OUT"/lantern_protocol-"$version"* "$sbom"
      ;;
    npm)
      (
        cd "$WORK/src/typescript"
        npm ci --ignore-scripts --no-audit --no-fund > /dev/null
        npx --no-install tsc -p tsconfig.build.json
        # Published: "private" keeps it from being published by mistake from a
        # checkout; the release's tarball is the one without it
        npm pkg delete private
        mkdir -p "$WORK/npm"
        npm pack --pack-destination "$WORK/npm" > /dev/null
        version=$(node -p "require('./package.json').version")
        npm sbom --sbom-format cyclonedx --sbom-type library --omit dev --package-lock-only \
          > "$WORK/npm/lantern-protocol-$version.npm.cdx.json"
        python3 "$ROOT/tools/sbom.py" normalize "$WORK/npm/lantern-protocol-$version.npm.cdx.json" \
          --name lantern-protocol --version "$version" --purl "pkg:npm/lantern-protocol@$version"
      )
      cp "$WORK"/npm/* "$OUT/"
      info "echo node \$(node --version)" "echo npm \$(npm --version)" \
        "cd '$WORK/src/typescript' && echo typescript \$(npx --no-install tsc --version)"
      ls "$OUT"/lantern-protocol-*
      ;;
    source)
      # The libraries' sources; the specification (the spec submodule) is
      # not in it: everything generated from it is committed
      git -C "$ROOT" archive --format=tar --prefix="lantern-sdk-$VERSION/" "$COMMIT" \
        | gzip -n -9 > "$OUT/lantern-sdk-$VERSION.tar.gz"
      info "git --version" "gzip --version"
      echo "$OUT/lantern-sdk-$VERSION.tar.gz"
      ;;
    cpp)
      native cpp "lantern-cpp-$VERSION-$ARCH" -DLANTERN_BUILD_TESTS=OFF -DLANTERN_BUILD_EXAMPLES=OFF
      python3 "$ROOT/tools/sbom.py" native cpp --version "$VERSION" -o "$OUT/lantern-cpp-$VERSION.cdx.json"
      info "${native_tools[@]}"
      ;;
    c)
      native c "lantern-c-$VERSION-$ARCH" -DLANTERN_C_BUILD_TESTS=OFF -DLANTERN_C_BUILD_EXAMPLES=OFF
      python3 "$ROOT/tools/sbom.py" native c --version "$VERSION" -o "$OUT/lantern-c-$VERSION.cdx.json"
      info "${native_tools[@]}"
      ;;
  esac
done
