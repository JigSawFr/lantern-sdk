# Releasing

One version for the whole SDK, in every language, with notes by language.
A release is made by [release-please](https://github.com/googleapis/release-please)
from the Conventional Commits on `main`, and built, attested and published
by this repository's workflows: nobody builds or uploads anything by hand.

## The version

The SDK has one [semantic version](https://semver.org/), the same for the
C++ library, the C API, the Python package and the npm package. It is the
SDK's own: it does not follow the specification's drafts, which each
library states on its own (`lantern::spec_draft`, `LANTERN_SPEC_DRAFT`,
`lantern.SPEC_DRAFT`, its README), and which the release notes list. The
first release is **0.5.0**, when every library follows draft 0.5; until
1.0.0, a change that breaks an API raises the minor version (0.5.0 to
0.6.0), anything else the patch version.

Where it is written, all by release-please (`release-please-config.json`,
`extra-files`):

| Language | Where |
|---|---|
| C++ | `cpp/CMakeLists.txt`, `project(Lantern VERSION …)`: the CMake package `Lantern` and its version file |
| C | `c/include/lantern/lantern.h`, `LANTERN_VERSION_STRING` (between the markers), which `lantern_version_string()` returns and `c/CMakeLists.txt` reads for the package `LanternC` |
| Python | `python/src/lantern/_version.py`, `__version__`, which hatchling reads for the package's version |
| TypeScript | `typescript/package.json`, and `VERSION` in `typescript/src/client/client.ts` (the User-Agent) |

Each of these lines carries an `x-release-please-version` marker (or sits
between `x-release-please-start-version` and `x-release-please-end`): a
new place that states the version gets one, and an entry in
`extra-files`. Two files are made from them on the release pull request
by `release-please.yml`, since release-please cannot write them:
`typescript/package-lock.json` (its copy of the version) and
`c/abi/lantern.abi` (which records the header's version string).
`python3 tools/release_versions.py` lists them all; the release refuses to
start unless each states the tag's version.

`LANTERN_C_API_VERSION` and `LANTERN_C_ABI_VERSION` are not the SDK's
version: they follow the C API's own policy (`c/README.md`).

## The flow

1. Pull requests are merged into `main` as one squashed commit whose title
   is a Conventional Commit with a scope (`feat(cpp): …`, `fix(python): …`).
2. On every push to `main`, `release-please.yml` keeps a pull request
   **`chore(main): release X.Y.Z`** up to date: `CHANGELOG.md`, the version
   in every language, then the lock file and the ABI dump brought along.
   The usual checks run on it, and `release-check.yml` builds every part
   of the release twice.
3. Merging that pull request creates the tag `vX.Y.Z` and its GitHub
   release, which starts **`release.yml`**:
   - `meta`: the tag is a version, and every language states it;
   - `python`: the sdist and the wheel, built without isolation with the
     tools pinned by hash in `tools/release-requirements.txt`, and their
     SBOM (cyclonedx-py);
   - `npm`: the npm tarball as it will be published (without
     `"private": true`, which only keeps a checkout from being published by
     mistake), and its SBOM (`npm sbom`);
   - `native`: the source archive (`git archive`), and the C++ library and
     the C API built and installed for Linux x86_64 with GCC 15 (static
     and shared libraries, headers, CMake packages; without the TLS
     adapters, whose libcurl or mbedTLS is the app's), with their SBOMs
     (`tools/sbom.py`, from `cpp/THIRD_PARTY_NOTICES.md`: Monocypher inside
     the library, doctest for its tests only);
   - `attest`: `SHA256SUMS`, then GitHub's attestations, signed through
     Sigstore: SLSA build provenance for every file, and each SBOM linked
     to the files it describes; the files attached to the release, and its
     notes rewritten by language (`tools/release_notes.py`);
   - `pypi`: the sdist and the wheel published to PyPI by trusted publishing
     (OIDC), with their PEP 740 attestations, in the `pypi` environment;
   - `npm-publish`: the tarball published to npm with its provenance, by
     trusted publishing, in the `npm` environment.

Every file is built from the tag's commit, with every timestamp at that
commit's time (`SOURCE_DATE_EPOCH`): see [Reproducing](#reproducing).

No cosign signature: the attestations are Sigstore's already, and
`SHA256SUMS` is itself attested. `gh attestation verify` checks them
([SECURITY.md](SECURITY.md#verifying-a-release)).

## Cutting a release

1. Look at the open `chore(main): release X.Y.Z` pull request: its version,
   and `CHANGELOG.md`'s entries (they are the merged pull requests' titles:
   one that reads badly is fixed by editing that pull request's title, then
   running `release-please.yml` again from the Actions tab).
2. Optionally, a summary written by hand: `.github/release-notes/X.Y.Z.md`,
   merged before the release pull request; it goes above the notes.
3. Check that the libraries follow the drafts they should: the release
   notes show each one's.
4. Merge the release pull request (squash, its title as it is). Then
   follow `release.yml` in the Actions tab; the `pypi` and `npm`
   environments may ask for an approval.

Another version than the computed one: a commit on `main` whose message
has the footer `Release-As: X.Y.Z`.

A failed run: re-run the failed jobs from the Actions tab. Or start
`release.yml` by hand (*Run workflow*, from the tag: *Use workflow from ›
Tags › vX.Y.Z*, and the same tag below): the files are built,
attested and attached again; with **publish**, PyPI and npm too (they
refuse a version they already have, so only the missing one goes out).

## Reproducing

```sh
tools/reproduce.sh twice python npm source   # built twice here, compared
tools/reproduce.sh release v0.5.0            # built at the tag, compared with the release's SHA256SUMS
```

`tools/release_build.sh` is the recipe both use, and the one the release
runs. The Python package needs the tools of
`tools/release-requirements.txt` (`pip install --require-hashes -r
tools/release-requirements.txt` in a virtual environment, then
`PYTHON=that/bin/python`); the npm tarball needs Node and npm, and the
release's `build-info-npm.txt` says which. The native archives come out
the same with the same compiler (GCC 15 on GitHub's ubuntu-26.04 image,
`build-info-cpp.txt`). `release-check.yml` checks every part on each pull
request that touches a library, the tools or this release chain (called by
`ci.yml`, behind its `all green` check).

The build tools are raised by hand: `hatchling` in
`python/pyproject.toml` and `tools/release-requirements.in`, then
`tools/release-requirements.txt` compiled again (the command is in the
`.in` file).

## Setting it up

What the maintainer does once, before the first release, in this order.

1. **The release GitHub App.** A GitHub App of the account (the one the
   other projects use, or a new one), installed on this repository, with
   *Contents: read and write* and *Pull requests: read and write*. In the
   repository's *Settings › Secrets and variables › Actions*: the variable
   `RELEASE_APP_CLIENT_ID` (or `RELEASE_APP_ID`) and the secret
   `RELEASE_APP_PRIVATE_KEY`. Without them `release-please.yml` does
   nothing. A ruleset that protects `v*` tags lists the app as a bypass.
   Releases are not made immutable (*Settings › General*): the files are
   attached after release-please has published the release.
2. **The environments**, in *Settings › Environments*: `pypi` and `npm`,
   each limited to the tags `v*` (*Deployment branches and tags*), with
   the maintainer as required reviewer if each publication should wait for
   an approval.
3. **PyPI**: on <https://pypi.org/manage/account/publishing/>, a *pending
   publisher* for the project `lantern-protocol`: owner `JigSawFr`,
   repository `lantern-sdk`, workflow `release.yml`, environment `pypi`.
   The first release creates the project; no token, ever.
4. **npm, the first version.** npm trusts a workflow only for a package
   that exists, so 0.5.0 goes out with a token: a *granular access token*
   on npmjs.com (*Access Tokens › Generate New Token*), read and write on
   packages, expiring in a week, saved as the secret `NPM_TOKEN` of the
   `npm` environment (not of the repository).
5. **npm, after the first version**: in the package's settings on
   npmjs.com, *Trusted Publisher › GitHub Actions*: organization or user
   `JigSawFr`, repository `lantern-sdk`, workflow `release.yml`,
   environment `npm`; then *Publishing access*: *Require two-factor
   authentication and disallow tokens*. Revoke the token, and delete the
   `NPM_TOKEN` secret: the next releases publish by OIDC alone.
