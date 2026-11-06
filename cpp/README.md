# Lantern for C++

The C++23 client library of the [Lantern protocol](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme),
for the consoles and the apps built with [Aurore](https://github.com/JigSawFr/Aurore):
`Lantern::lantern`, and two optional TLS transports, `Lantern::curl` and
`Lantern::mbedtls`. It follows the specification's **draft 0.11**
(`spec/`, pinned as a submodule of this repository).

**Status: draft 0.11, the client whole.** Pairing with a device key, signed
requests, invitations, the routes that write and the administration API,
over TLS with the server's key pinned; events, grants with mirrors and
peers, sync, end-to-end encrypted saves, static libraries, and, since
draft 0.7, differential updates (a newer package put together from the
chunks of an older one) and canonical JSON as RFC 8785 writes it, and, since
draft 0.9, variants of one game and packages a device cannot use (`requires`,
`includes`, the `format` filter, `formats` and `satisfies`), and, since
draft 0.11, a TLS floor of 1.2 in both transports and `is_valid_server_uid()`
(a `uid` is a lower case UUID, version 4 or 7). Of a
server, a peer's side, and the first slices of a server core
(Lantern Core, read-only, with its changes, sections, titles, homebrew and
cheat sets, and the
tokens, pairing and signed requests that give a device its access: see
[Server core](#server-core); the other families come in later steps); the C API is in [`../c/`](../c/README.md).

## What it does

- **Pairing** (SPEC.md § 5.2): the device flow, with `verify_complete` for
  a QR code the app draws next to the code and the server's short
  fingerprint; an Ed25519 **device key** made from the app's random source
  (§ 5.4), whose polls are signed; an **invitation**'s code or link
  (§ 5.5), approved at once. The token, the key and the pinned server key
  go to a `CredentialStore` the app implements, as homebrew pins do, and
  come back from it by the server's `uid`.
- **Signed requests** (§ 5.4, RFC 9421): every request that carries a
  bound token signed by the `RequestSigner` the client fills,
  `DeviceSigner`, exactly as § 5.4 writes it: the label `lantern`,
  `"@method" "@target-uri" "authorization"`, then `"content-digest"` with a
  body (and its `Content-Digest`), `created`, a new nonce from the app's
  random source, `keyid` and `alg`. Its bytes are those of
  `spec/vectors/signatures.json`, which the unit tests pass byte for byte,
  and a server's check (`check_signature`) refuses each of the vectors'
  refused requests with its code. The device's clock is set by the
  server's `Date` (Annex B.9); a signature refused as `signature_expired`
  is signed again with the server's clock, once (L-5.4-8); a 401 for a
  signature says, from `Accept-Signature`, when only pairing again mends
  it. A token and a signature go to the server's origin alone (§ 2). A
  signature refused as `signature_replayed` is signed again too, once,
  with a new nonce.
- **The server's key** (§ 5.3): a `ServerTrust` the transport asks for
  each connection, with the leaf certificate's SPKI: the CA store decides,
  or a pin does, whatever the certificate; before pairing, any key is taken
  and recorded, to show its short form next to the code, then pinned for
  the polls. No token goes over a connection nobody verified.
- **The read side of the protocol**: the handshake and its `features`, the
  apps' listing with its cursors, what a device is missing, `changes`,
  `sections`, titles (one, many, their changes), homebrew (the listing, an
  entry, the updates of what is installed), cheat sets and their text, with
  `Lantern-Platform` on every call.
- **The routes that write**: save backups (§ 9) listed, downloaded,
  removed, sent in one request with their `Content-Digest` and § 9.2's
  headers, or resumably (§ 9.3): `POST` the upload, `PATCH` chunks with
  `Upload-Offset`, `HEAD` to resume after a cut or a `409` (its
  `Lantern-Chunk-Size` gives the chunks back to an app that kept the
  upload's address alone: `Client::upload_head()`), the whole archive's
  SHA-256 checked by the server; cheat sets written, replaced and
  removed (§ 10); requests made, listed and withdrawn (§ 11).
- **The administration API** (§ 5.7): accounts, devices, the pairings
  waiting (each with its code and key, to compare with the console's
  screen), invitations, and deleting an account, its name typed again.
- **Events** (§ 18, `events.hpp`): the stream of Server-Sent Events, read
  as the transport hands the body over by a parser of our own (lines and
  events bounded, `retry`, `id`, heartbeats, fuzzed), resumed with
  `Last-Event-ID`; each event the client knows, of a schema it reads, goes
  to the app, the others are skipped; long polling with `wait` for a
  console that cannot keep a connection open. The library has no timers:
  `event_silence_limit()` gives the transport's read timeout, and
  `reconnect_delay()` how long to wait before connecting again.
- **Mirrors and peers** (§ 19, `peers.hpp`): a file taken from a mirror
  or a paired console of the LAN is checked by the server's size and
  SHA-256 like any, with nothing of the server's sent to it but a grant to
  a peer, plain HTTP on a private network only; grants asked of the server
  and checked on a peer's side as § 19.3 writes them (the canonical
  payload, strict Ed25519); peers found by the discovery datagram; and
  `PeerGate`, a peer's side without networking of its own (below).
- **Sync** (§ 20, `sync.hpp`): wishes and what a console has installed,
  read and written only once the app set the user's consent (`installed`
  by name), the account's `generation` kept so that data deleted is never
  written back, `If-Match` for a write all or nothing (`412`), and
  § 20.4's merge rule with its canonical JSON, for an app that keeps a copy.
- **Encrypted save backups** (§ 9.4, `encrypted_save.hpp`):
  `lantern-save-e2e-1`, XChaCha20-Poly1305 from Monocypher (the IETF
  construction, which the vectors check byte for byte), HKDF-SHA-256 over
  our HMAC-SHA-256, 64 KiB chunks streamed both ways with one chunk in
  memory, an upload that resumes by encrypting again to the same bytes,
  the recovery phrase and the QR text, and every secret wiped.
- **Static libraries** (§ 21, `static_library.hpp`): a library read as
  files, over HTTP(S) or through the app's own file I/O, its pages
  chained, its files checked, and what a server would answer computed on
  the device (what is missing, homebrew updates). `find_library()` looks
  for one at an address in § 21.3's order: the origin's
  `/.well-known/lantern` (a server's handshake, not a static library's),
  then `<address>/lantern.json`.
- **Variants and packages a device cannot use** (§ 6.1 to § 6.3,
  `variants.hpp`): an app's `requires` tokens and `includes`; the listing's
  `format` filter (`AppsQuery::format`); `formats` and `satisfies` of what
  is missing (`MissingRequest`, `std::optional` so that an empty array,
  which leaves out every app, differs from none), applied by
  `StaticLibrary::missing` as a server does, the versions an installed app
  includes counted as installed (L-6.3-4). `install_decision()` says whether
  a client installs an app (`Install::install`, or `unavailable` with
  reasons: its format, a token it lacks, an update an installed app already
  `included()`, L-6.1-3 to L-6.1-5), and `prefer_variant()` picks the
  variant among those of one `app_id` and `version_code` (Annex B.15: the
  fewest `requires`, the smallest `size`, the smaller `id`). The unit tests
  pass `vectors/app-requires.json`; the integration tests list the
  reference server's `[LZ4]` variants.
- **Discovery** (§ 4.1): the datagram to UDP 47115, the replies read
  bounded and with the `schema` rule, each server once, through a
  `UdpSocket` the app gives (`adapters/posix` has one); with `peers`, the
  consoles that share their files too (§ 19.5). **DNS-SD** (`_lantern._tcp`
  and `_lantern-peer._tcp`, `browse_dnssd()`, `lantern/dnssd.hpp`) over the
  same `UdpSocket`: one question to `224.0.0.251:5353` from a port of the
  app's own, which responders answer straight back (RFC 6762 § 6.7), so no
  group is joined; an instance whose answer came without its port or TXT is
  asked for them once, and a server's advertisement is held to the rules of
  its datagram reply. IPv4 only.
- **Deprecation** (§ 3.4): each `Deprecation` and `Sunset` a server sends
  goes to the app's `DeprecationLog`.
- **Downloads that are checked**: `Range` and `If-Range` to resume, the
  SHA-256 computed as the bytes come, `Repr-Digest`, `Content-Range` and
  `Content-Length` checked against the listing. Nothing is done until the
  whole file's digest matches; the hash's state can be saved with a partial
  file and taken up after a restart.
- **The `schema` rule** (SPEC.md § 3.2): every reader gives an empty
  optional for a document of a newer schema, never an error; a document
  without `schema` is an error; unknown fields are skipped; `rewrite()`
  rewrites a document and keeps the keys it does not know, and refuses to
  write over a newer one.
- **Homebrew, as § 8 asks a client**: manifest paths checked (no `..`, no
  absolute data path, no drive letter, backslash, colon, quote or control
  character, nothing outside the profile's roots), an install plan that
  splits the paths that need no consent from those that do, the package for
  the device's architecture, ed25519 signatures (Monocypher) over the
  canonical bytes of § 8.4, key pinning through a store the app keeps, a
  port's data checked before it launches, and § 8.7's offer, warn or refuse.
- **The platform profiles** of Annex A: ids (checked by hand, no
  `<regex>`), `version_code`, formats, roots, architectures.
- **The TLS transports**, optional targets: `Lantern::curl` (libcurl and
  the TLS it was built with) and `Lantern::mbedtls` (mbedTLS 2.28 or 3, for
  the consoles), both pinning through `ServerTrust`.

## Server core

`lantern/server.hpp`: what answers the protocol's routes, with no HTTP
framework and no socket of its own, as `PeerGate` is for a peer. Three slices so
far: **Lantern Core, read-only**, **tokens, pairing and signatures**, and the
library's **changes, sections, titles, homebrew and cheat sets**.

- the handshake at `/.well-known/lantern` and `<base>/v1` (§ 4.2), which lists
  only what the server serves: `features` says `library`, `titles`, `changes`,
  `sections`, `homebrew` and `cheats` when the library offers them (the last for
  a caller with the scope `cheats`, which anonymous callers hold on a public
  server), and `pairing` and `signatures`
  when the server has accounts, and nothing else; the account is
  the caller's (`anonymous`, `active` or `frozen`, its scopes, whether its
  token is bound), `limits.page_size` is the largest page;
- the platforms (§ 4.3), the listing of apps (§ 6.2) with `platform`, `type`,
  `format`, `title_id`, `q`, the sorts `name`, `added` and `release`,
  `page_size` and cursors that are sealed (HMAC-SHA-256, a secret drawn from
  the app's `RandomSource`) and neither skip nor repeat an app, and
  what a device is missing (§ 6.3), computed by the same `missing_apps()` as
  a client does over a static library;
- the files (§ 6.6): `Range`, `If-Range`, 206, 416 with `Content-Range`,
  `Repr-Digest` of the whole file on every answer, HEAD, a strong ETag; a
  file is read piece by piece through a `FileReader`, never held whole;
- `ETag` and `If-None-Match` (304), `Vary` and `Cache-Control` (§ 14),
  errors as `application/problem+json` (§ 12), request documents read with
  the `schema` rule (§ 3.2), I-JSON and § 13's bounds (§ 2.3), a parameter
  given twice refused (§ 2.4);
- browsers (§ 2.5): CORS for the origins the app allows, with preflights
  answered without a token, and `Strict-Transport-Security` over HTTPS (§ 2).

```cpp
lantern::MemoryLibrary library("/api/lantern");          // or the app's own lantern::Library
library.add_app(draft, package_bytes);                   // size and SHA-256 from the bytes
lantern::ServerOptions options;
options.uid  = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";   // a lower case UUID, version 4 or 7
options.name = "Lea's shelf";
options.cors_origins = origins;                          // {"https://app.example.org"}
auto server = lantern::Server::create(library, options, random, clock);

// In the app's HTTP server, for each request it parsed:
lantern::ServerRequest request;                          // method, decoded path and query, headers, body, scheme, target, remote
const lantern::ServerResponse response = server->handle(request);
// response.status, response.headers, response.body, or response.file: the
// bytes [offset, offset + length) of file->reader, to read as they are sent
```

`Library` is the app's: its platforms, its apps (every variant, at least those
a filter keeps; the server applies the filter itself) and the file of a name.
`MemoryLibrary` is a complete one, for tests and demos; it refuses an app that
breaks § 6.1 or its platform's profile. `Server::handle()` may be called from
several threads when the library's and the account store's methods can be.
`parse_target()` splits and decodes a request target for an adapter;
`problem_response()` answers what an adapter cannot read.

### Changes, sections, titles, homebrew and cheat sets

A `Library` offers these families by overriding methods that, by default,
offer none, so that a library written for the first slice keeps working:

- **Titles** (§ 7): `offers_titles()` and `titles(languages)`, every title (the
  server narrows by platform and id itself): `GET <base>/v1/titles/{title_id}`
  (404 for an unknown one, 400 when several platforms have the id and the client
  named none), `GET <base>/v1/titles?ids=` for 1 to 100 ids at once (each id in
  `titles` or in `unknown`, once), and the images of `GET <base>/v1/media/{name}`,
  which `media(name)` reads, served only if a title shows them, with
  `Cache-Control: public, max-age=31536000, immutable` (`private` with a
  token). `languages` is the request's `Accept-Language`, as written; a library
  with texts in several languages picks the best (§ 2.2).
- **Changes** (§ 6.4, § 7.3): `journal()` returns a `Journal` (its `position()`
  with an `epoch`, the position now and the oldest it answers from; the apps
  added and removed, the titles changed and removed, since a position). The
  server seals each position into a `since` token (HMAC-SHA-256, like the
  cursors, of a kind of its own for the apps' and the titles' changes):
  without `since`, `GET <base>/v1/changes` gives no app and the token of now;
  a token the server never gave is a `400`, one of another epoch or older than
  the journal a `410`. `GET <base>/v1/titles/changes` follows the same rules,
  with `more` for a journal that gives part of them; without a journal, it
  gives a token that no one can use (`410`). No `wait` yet: it comes with
  the events.
- **Sections** (§ 6.5): `offers_sections()` and `sections(languages)`; the
  server leaves out the apps of another platform and the ids the library does
  not have, and a shelf left empty.
- **Homebrew** (§ 8): `offers_homebrew()` and `homebrew(languages)`, every entry
  with the manifests of its packages. `GET <base>/v1/homebrew` is a page sorted
  by name with `platform`, `q`, `kind` (a kind the library does not know is
  read as `app`, § 8.1) and `genre`, and no manifest; `GET .../homebrew/{id}`
  gives the entry with them (404 for an unknown id, 400 when several platforms
  have it and the client named none); `POST .../homebrew/updates` (a platform
  required) pages the entries newer than the builds installed. The packages
  are files, served by `file(name)` like an app's. The signature (§ 8.4) is the
  author's: the library holds it, the server serves it as it is, and
  `MemoryLibrary::add_homebrew()` refuses one that does not verify.
- **Cheat sets** (§ 10): `offers_cheats()`, `cheats()` and `cheat_file(id)`;
  `GET <base>/v1/cheats` (filters `platform`, `title_id`, `build_id`) and
  `GET .../cheats/{id}`, the set's text as a file, need the scope `cheats`.
  A library that returns true from `writes_cheats()` also takes `POST`, `PUT`
  and `DELETE` from tokens with `cheats.write`: the server checks the set
  (§ 10, § 13, Annex A: the platform's build_id and text format, 1 MiB at most,
  409 for a set that exists) and calls `write_cheat()` and `delete_cheat()`
  one request at a time. A library that does not answers 405. A body above
  1 MiB needs an adapter that takes it: `ListenOptions::max_body`, 3 MiB for
  the largest set once escaped.

`MemoryLibrary` serves them once told to: `add_title()` (refuses what § 7.1
and Annex A do not allow), `add_media()` (an image on the server's origin,
named by its SHA-256), `add_section()`, `add_homebrew()` (the entry and the
bytes of its packages, whose `size`, `sha256` and `manifest_sha256` must be
right; it refuses what § 8 and the profile do not allow: paths, roots,
architectures, signatures, a port's data, requirements), `add_cheat()` and
`accept_cheat_writes()`, `keep_journal(n)` for the last `n` changes (call it
before the first one), and `remove_app()`, `remove_title()`, `remove_section()`,
`remove_homebrew()` and `remove_cheat()`; the journal records the apps and the
titles.

```cpp
library.keep_journal();
auto icon = library.add_media(png_bytes, "png");         // an Image: url and sha256
lantern::Title title;
title.platform = "switch"; title.title_id = "0100AB1200010000"; title.name = "Lumen Drift";
title.icon = *icon;
library.add_title(title);
library.add_section("new", "New this month", app_ids);
```

### Tokens, pairing and signatures

Give the server an `AccountStore` (`lantern/accounts.hpp`) and it takes
`Authorization: Bearer` tokens, pairs devices and checks signed requests:

```cpp
lantern::MemoryAccountStore accounts;                    // or the app's own lantern::AccountStore
accounts.add_account("lea", {"library", "saves"});       // an account and its scopes (§ 5.7)
options.accounts = &accounts;
options.require_auth = false;                            // true: a private server, 401 without a token
options.spki = sha256_of_the_tls_key;                    // the approval page shows its short form (§ 5.3)

// The app's approval page, once the user is signed in there (§ 5.2):
server->approve_pairing(typed_code, "lea");              // the scopes asked for that the account holds
```

- **Tokens** (§ 5.1): 256 random bits, `et_` and base64url. The store keeps
  the SHA-256 of a token, never the token; the server hashes what it is sent
  and asks the store for the device by that hash, which the memory store
  compares in constant time. A device's scopes are cut back to its account's at
  every request. An unknown, revoked or expired token, another scheme and an
  empty token give `401` with `WWW-Authenticate: Bearer` (and
  `error="invalid_token"` when a token was sent); a valid token without the
  scope, `403 forbidden`; one of a frozen account, `403 account_frozen`.
  `options.token_lifetime` makes new tokens expire. A server without accounts
  takes no token at all. Secrets are never written to an error, and the
  library keeps no log.
- **Pairing** (§ 5.2): `POST <base>/v1/pairing` gives a code of the specified
  alphabet (8 symbols, 40 bits, in groups of 4), the approval address with the
  code in it (`verify_complete`), and a poll address of 192 random bits;
  `GET` on it answers `202` while waiting, then the token once, then `410`. A
  code lives 10 minutes at most; the polls are counted from the last one
  answered (`429 slow_down` with the seconds left); pairing requests per
  address and wrong invitation codes per address are limited
  (`options.pairing_requests`, `invitation_attempts`). A key of small order
  or that does not decode is a `400` (L-5.4-12). `Server::waiting_pairing()`,
  `approve_pairing()` and `refuse_pairing()` are the app's side: approval
  never goes through the device.
- **The approval page** (§ 5.3): `GET <verify>` (`/pair`) shows the code and
  the short fingerprint of `options.spki`, and approves nothing. An app with a
  page of its own gives `options.verify` an absolute address.
- **Signed requests** (§ 5.4): a request with a bound token carries a
  signature of `@method`, `@target-uri`, `authorization` and, with a body,
  `content-digest`, checked in the specified order (`signature_required`,
  `signature_invalid`, `signature_expired`, `signature_replayed`) and answered
  with `Accept-Signature`; a body that does not match its `Content-Digest` is a
  `422 digest_mismatch`. The window (`options.skew`, 300 s) and the replay
  memory (a nonce is kept per key for twice the window, in `options.nonce_limit`
  entries; full, the server answers `429` rather than forget) are read from the
  `Clock` given to `Server::create()`. A pairing made with a key polls with
  requests signed by it. `options.bound_only` refuses tokens without a key.

`AccountStore` is the app's own store behind a few methods (accounts, devices
by token hash, pairings); each must be atomic and safe from several threads.
`MemoryAccountStore` is a complete one, for tests and demos. The `random`
given to `Server::create()` must outlive the server: it draws the tokens, the
codes and the poll addresses.

`adapters/posix/server_posix.hpp` is a blocking HTTP/1.1 listener for the demo
and the conformance run: one connection at a time, `Connection: close`, a body
of `Content-Length` bytes, plain HTTP on loopback by default. It is not for an
app, and has no TLS. `lantern_demo_server [port] [--private]` (`examples/`)
serves a small fictional library through it, with the accounts of
`examples/demo_accounts.hpp` (mira, noor and the token of mira's console,
bound to a key made from a fixed phrase), and prints its URL; the conformance
suite runs against it:

```sh
build/dev/examples/lantern_demo_server 8080 &
python3 ../spec/conformance/run.py http://127.0.0.1:8080/ --origin https://app.example.org
```

`ctest -R conformance` plays the suite three times, each against a demo of its
own: anonymously, with the console's token and its device key, and with the
token against `--private`. No check fails; the two warnings are plain HTTP on
loopback and JSON that is not compressed; with the token the run reaches
**Lantern Core**, +titles, +homebrew and +cheats (a set written, replaced and
deleted); anonymously the suite leaves out the signed requests it has no key
for and the writing of a set. `ctest -R server` plays the library read by this library's own
client over the listener, `ctest -R unit` the server's cases in memory.

Not in this slice, and so not offered by the handshake: invitations (§ 5.5; a
code in a pairing request is unknown) and the administration API, so rating
caps (§ 5.6) too (so no set or entry is hidden by a cap); saves, requests, events,
peers, sync and discovery; chunks and differential updates for the homebrew
packages (§ 22); compression of the JSON (§ 2.1: the
library can read gzip, not write it); a `release` sort that means anything (it
needs titles: every app is without a release for now). Text search folds ASCII
case only, not Unicode's.

## Building

CMake 3.28 or later, Ninja, and a C++23 compiler with `std::expected`:
GCC 13 or later, clang 19 or later with libstdc++, or clang 17 or later
with libc++, MSVC 19.36 or later, Xcode 15 or later. (clang 18 with
libstdc++ 13 has no `std::expected`.)

```sh
cd cpp
cmake --workflow --preset dev        # configure, build, run the tests
```

| Preset | What |
|---|---|
| `dev` | Debug, the tests and the example, hardened |
| `release` | Optimised, the tests and the example, hardened |
| `noexcept` | Everything, tests included, with `-fno-exceptions -fno-rtti`, hardened |
| `asan` | AddressSanitizer and UndefinedBehaviorSanitizer |
| `ubsan` | UndefinedBehaviorSanitizer alone, every report fatal |
| `tsan` | ThreadSanitizer |
| `coverage` | clang's source-based coverage (`CC=clang CXX=clang++`); the profiles go to `build/coverage/profiles/` |
| `fuzz` | The libFuzzer targets (clang: `CC=clang CXX=clang++`) |

Hardened (`LANTERN_HARDENING`, `cmake/LanternHardening.cmake`, GCC and
clang): the stack protector, stack clash and control-flow protection, full
RELRO; `_FORTIFY_SOURCE=3` when optimised; in Debug, the standard
library's own checks (`_GLIBCXX_ASSERTIONS`, libc++'s debug hardening
mode) and uninitialised variables filled with a pattern. Off by default,
so an app that adds this folder keeps its own flags.

`-DLANTERN_WERROR=ON` makes warnings errors, as the CI does. The tests need
the `spec/` submodule (`git submodule update --init`); the integration
tests also need Python 3, which runs the specification's reference server,
and the TLS adapters' tests need `openssl`, which makes a self-signed
certificate for the run. The integration tests also run every scenario of
`python/tools/hostile_server.py`, the repository's malicious server, when
it is there; its TLS scenarios need Python's `cryptography`.

| Option | What |
|---|---|
| `LANTERN_CURL` | `Lantern::curl`, over libcurl 7.85 or later: `AUTO` (built when found), `ON` (required) or `OFF` |
| `LANTERN_MBEDTLS` | `Lantern::mbedtls`, over mbedTLS 2.28 or 3: `AUTO`, `ON` or `OFF` |

Both are `AUTO` when this folder is the project built for the machine it
runs on, `OFF` otherwise: an app that adds this folder, or a cross build,
asks for one with `ON`. The library itself needs neither.

### Before pushing

The CI (`.github/workflows/cpp.yml`, through `ci.yml`) checks all of these; run what you can:

```sh
cd cpp
cmake --preset dev -DLANTERN_WERROR=ON && cmake --build --preset dev && ctest --preset dev
python3 tools/gen_types.py --check     # the generated types match spec/schemas
git ls-files '*.cpp' '*.hpp' ':!:third_party/**' ':!:src/generated/**' ':!:include/lantern/types.hpp' \
  | xargs clang-format --dry-run --Werror   # clang-format 18 (pip install clang-format==18.1.8)
run-clang-tidy -p build/dev 'cpp/src/[^g].*\.cpp$' 'cpp/adapters/.*\.cpp$'   # clang-tidy 22 (pip install clang-tidy)
reuse lint                             # at the repository's root
actionlint                             # at the repository's root, for .github/workflows
```

## In an app

### As a submodule

Lantern's C++ library needs nothing but `cpp/`; `spec/` serves its tests
and its generator only, and `python/tools/hostile_server.py` its
integration tests. A sparse checkout keeps the rest out:

```sh
git submodule add https://github.com/JigSawFr/lantern-sdk library/lantern-sdk
git -C library/lantern-sdk sparse-checkout set cpp
```

```cmake
set(LANTERN_MBEDTLS ON)                       # or LANTERN_CURL, for its transport
add_subdirectory(library/lantern-sdk/cpp)
target_link_libraries(my_app PRIVATE Lantern::lantern Lantern::mbedtls)
```

Added this way, it builds the library alone, and the adapters asked for:
no tests, no example, no install rules of its own unless `LANTERN_INSTALL`
is set.

### Installed

```sh
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release -DLANTERN_BUILD_TESTS=OFF
cmake --build build && cmake --install build --prefix /opt/lantern
```

```cmake
find_package(Lantern 0.5 REQUIRED)
target_link_libraries(my_app PRIVATE Lantern::lantern Lantern::curl)   # the adapters installed with it
```

## The transport

The library has no networking of its own: it speaks HTTP through the
app's `lantern::Transport` (`transport.hpp`), which sends one request and
hands the answer to a `ResponseHandler` as it comes: the status, each
header, then the body in chunks. The transport does TLS (and pins a
server's key, § 5.3), follows no redirect and adds no header but `Host`
and its framing.

```cpp
class MyTransport final : public lantern::Transport
{
  public:
    lantern::Result<void> send(const lantern::Request& request, lantern::ResponseHandler& handler) override
    {
        // request.method, request.url, request.headers, request.body
        // ...then, as the answer comes:
        //   if (!handler.on_status(status)) return {};
        //   if (!handler.on_header(name, value)) return {};
        //   if (!handler.on_body(chunk)) return {};
        // A handler that returns false wants the transfer stopped.
        // A connection that could not be made, or was cut:
        //   return lantern::fail(lantern::Category::transport, "…");
        return {};
    }
};
```

Two transports come with the library, each an optional target:

- **`Lantern::curl`** (`adapters/curl`): libcurl and the TLS library it
  was built with (OpenSSL, GnuTLS, Schannel, Secure Transport), for
  desktops and phones. The app calls `curl_global_init()` once; one
  transport is one easy handle, its connection kept between requests.
- **`Lantern::mbedtls`** (`adapters/mbedtls`): mbedTLS 2.28 or 3 over
  POSIX sockets (the Switch's libnx and the 3DS's libctru have them), one
  request per connection; its randomness is the app's `RandomSource`, so
  no entropy module of the platform is needed. The CI builds it for the
  Switch and the 3DS with devkitPro's `switch-mbedtls` and `3ds-mbedtls`.

```cpp
lantern::ServerTrust trust;                   // the server's key (SPEC.md § 5.3)
lantern::mbedtls::Options options;
options.random = &random;                     // the platform's generator
options.trust  = &trust;
options.ca_pem = bundled_cas;                 // or nothing: pinned keys only
auto transport = lantern::mbedtls::MbedTlsTransport::create(options);
```

Each asks the `ServerTrust` once per connection, with the SPKI of the
certificate the server showed (libcurl's `CURLOPT_CERTINFO` before the
request is sent; mbedTLS's verification callback): with a pin, the pin
decides and the CA store is not asked; in its CA mode, the chain and the
name must verify; before pairing, any key is taken and recorded. A key
refused is `Category::refused`.

`adapters/posix` is a blocking HTTP/1.1 client over POSIX sockets, plain
HTTP to a loopback address only, `/dev/urandom` and a UDP socket, built
for the tests and the examples and never installed.

A `RequestSigner` (`ClientConfig::signer`) sees every request's method,
target, headers and body digest and may add headers. The client's own,
`DeviceSigner`, signs with the device key (below); an app's runs after
it.

**The TLS floor** (SPEC.md § 2, L-2-9): neither transport offers a protocol
older than TLS 1.2. `Lantern::curl` sets `CURLOPT_SSLVERSION` to
`CURL_SSLVERSION_TLSv1_2` (a minimum; no maximum), `Lantern::mbedtls` sets
`MBEDTLS_SSL_VERSION_TLS1_2` as the configuration's minimum; each reports it
as `minimum_tls()`. A transport of the app's own must do the same.

## Pairing and signed requests

`examples/pair_device.cpp`, in short:

```cpp
config.random = &random;                      // device key and nonces
config.trust  = &trust;                       // the transport's ServerTrust
auto client   = lantern::Client::create(transport, config);
client->handshake();
if (!client->sign_in(store).value_or(false))  // nothing kept for this uid
{
    trust.allow_unverified();                 // a LAN server, self-signed
    lantern::PairingOptions options;
    options.device = "Lea's Switch";
    options.scopes = scopes;                  // {"library", "saves"}
    auto pairing   = client->start_pairing(options);
    // Show pairing->code.code, a QR code of pairing->code.verify_complete,
    // and pairing->fingerprint_view(), side by side (Annex B.6)
    while (client->poll_pairing(*pairing, &store) == lantern::PollState::waiting)
        sleep(pairing->wait);
}
client->apps();                               // signed with the device key
```

An invitation's link gives its code and the server's whole fingerprint:

```cpp
const auto link = lantern::parse_invitation_link(scanned);
if (link->spki)
    trust.pin(*link->spki);                   // pinned without asking the user to compare
options.invitation = link->code;              // approved at once: the first poll gives the token
```

## Events

```cpp
struct Shown final : lantern::EventHandler
{
    bool on_event(const lantern::StreamEvent& event) override
    {
        if (event.kind == lantern::EventKind::request)
            notify(lantern::read_request_event(event.data));   // "Frostline Tales is there"
        return true;                                           // false closes the stream
    }
};
lantern::EventStreamState state;              // kept: last_id resumes after a restart
for (;;)
{
    const auto ended = client->events(state, shown);           // until the server or the network ends it
    if (!ended && ended.error().effective_code() == lantern::Code::gone)
        read_library_again();                 // a position too old: read again, then go on
    sleep(state.reconnect_delay());           // retry at least, more after each failure (L-18.1-9)
}
```

The transport's read timeout is `client->event_silence_limit()`: twice the
server's heartbeat. A console that sleeps asks
`wait_changes(state.last_id_view(), 0)` on waking, then opens its stream
again (Annex B.10).

## Mirrors and peers

```cpp
// A mirror of the app's (§ 19.2), then the server: what a mirror served
// that fails the app's size and SHA-256 is dropped
client->download_with_mirrors(app.mirrors, {app.file, app.size, app.sha256}, state, sink);

// A peer found by discovery (DiscoveryOptions::peers, on_peer), with a grant
const auto grant = client->grant(app.sha256);             // scope library
if (client->peer_holds(found.endpoint, **grant).value_or(false))
    client->download_from_peer(found.endpoint, **grant, {app.file, app.size, app.sha256}, state, sink);
```

A console that shares its files answers with `PeerGate`: the app's HTTP
server gives it each request (method, target, `Lantern-Grant`, `Range`,
the client's address), sends the status and headers it answers, then
streams the bytes of the file it names from its own storage, and calls
`release()` once done. The gate checks the grant against the servers the
console paired with (`GrantKey`: uid and `peers.key`), serves only the
files `HeldFiles` says it holds whole, its own networks only, `slots`
downloads at once and a few requests a second per address; it holds no
socket, as the library holds none.

## Sync

```cpp
// After asking the user (§ 20.1, Annex B.12), kept per profile and server
client->set_sync_consent({.sync = true, .installed = false}, kept_generation);
const auto state = client->sync_state();      // refused: sync off, ask again (the data was deleted)
lantern::SyncItem wish;
wish.key = *lantern::wish_key("switch", "0100ABCD00010000");
lantern::write_wish(chosen, wish.value);
lantern::format_sync_time(now_ms + client->clock_offset() * 1000, wish.updated);
client->sync_write(lantern::sync_wishes, std::span(&wish, 1));
keep(client->sync_consent(), client->sync_generation());
```

## Encrypted saves

```cpp
auto key = lantern::SaveKey::generate(random);   // once; kept as a device key is
show_once(key->phrase());                         // "96PA-S67D-…", and key->qr_text()
const auto header = lantern::make_save_header(*key, random);   // kept to resume
auto source = lantern::EncryptingSource::create(*key, *header, archive, archive_size);
lantern::UploadRequest request;
source->describe(request);                        // size, sha256, encryption {scheme, key_id}
client->upload_resumable(title_id, request, *source, progress);

lantern::DecryptingSink opening(*key, file);      // chunk by chunk, each once it opened
client->download_save(save, state, opening);
if (opening.finish())
    restore(file);                                // only now
```

## Differential updates

```cpp
std::vector<lantern::Seed> seeds { lantern::Seed(older_package) };   // bytes the app holds
lantern::DeltaOptions options;                                        // peers, mirrors, the gap between ranges
auto report = client.download_with_seeds({ app.file, app.size, app.sha256 }, *app.chunks, seeds, sink, options);
// report->from_seeds, report->from_ranges, report->whole_file (read whole after a failure)
```

Resuming an interrupted run is the app's: keep the bytes already written (a
verified prefix) and pass them as one more seed. The chunks found there are
not read again, and are still checked (SPEC.md Annex B.4); a stale or foreign
prefix shares nothing and is harmless.

## Static libraries

```cpp
auto files   = lantern::HttpStaticFiles::create(transport, "https://lea.example.org/library/", "MyShelf/1.0");
auto library = lantern::StaticLibrary::open(*files);   // or the app's own StaticFiles: a USB key
const auto page    = (*library)->apps("switch");        // then its `next`: "2", "3", …
const auto missing = (*library)->missing("switch", request);   // § 6.3, computed here
```

## Errors

Nothing throws: the library builds and runs with `-fno-exceptions
-fno-rtti`. A call that can fail returns `lantern::Result<T>`, a
`std::expected<T, lantern::Error>`; a call that reads a document returns
`lantern::Read<T>`, a `Result<std::optional<T>>` whose optional is empty
for a document of a newer schema.

An `Error` has:

- a `category()`: `protocol` (the server answered with an error),
  `transport`, `invalid_response`, `limit`, `integrity`, `signature`,
  `refused` (a server key refused among them, a grant a peer refuses, sync
  without consent), `unsupported`, `usage`, `storage` or `memory`;
- for a server's error, its `status()`, the `code()` of its problem+json
  (`Code::unknown` for a code of a later version, with `code_text()`),
  and `effective_code()`, the code to act on: the server's, or the one its
  status implies (§ 12); draft 0.4's `key_required`, `signature_required`,
  `signature_invalid`, `signature_expired` and `signature_replayed`, and
  draft 0.5's `precondition_failed` (412) included;
- `detail()` and `title()`, for people, bounded and without control
  characters, and `retry_after()`.

## Memory

Every allocation goes through a `std::pmr::memory_resource` the app gives
(`ClientConfig::decode.memory`; the default resource otherwise), and each
document read stays within `json::Limits::max_memory`, checked before each
allocation: a document that needs more is `Category::memory`, not a crash.
On a console, a `std::pmr::monotonic_buffer_resource` over a static buffer
of that size does. Documents are bounded by § 13 (32 MiB, depth 16,
4 KiB strings), which an app may lower.

## An example

`examples/read_library.cpp`, in short:

```cpp
lantern::ClientConfig config;
config.origin     = "https://shelf.example.org";
config.user_agent = "MyShelf/1.0";
config.platform   = "switch";
auto client = lantern::Client::create(transport, config);
if (!client)
    return report(client.error());

const auto server = client->handshake();      // name, base path, features
if (!server || !*server)
    return 1;

lantern::AppsQuery query;
for (std::string cursor;;)                    // every page, by its cursor
{
    query.cursor    = cursor;
    const auto page = client->apps(query);
    if (!page || !*page)
        break;
    for (const lantern::App& app : (*page)->items)
        show(app);
    if ((*page)->next.empty())
        break;
    cursor = (*page)->next;
}

const lantern::App& app = chosen;             // one of the listing's
lantern::DownloadState state;                 // keep it to resume
const auto done = client->download({app.file, app.size, app.sha256}, state, sink);
if (done)
    install(sink);                            // only now: the SHA-256 matched
```

## Choices

- **`std::pmr` for memory.** It is in the standard library of every Aurore
  toolchain (devkitA64, devkitARM and VitaSDK's libstdc++; the NDK's,
  Xcode's, Emscripten's and the PS4's libc++; MSVC's), it needs neither
  exceptions nor RTTI, and it keeps allocators out of the types. Since a
  resource cannot fail without throwing, the library counts what it asks
  for against a budget first.
- **Our own JSON.** A pull tokenizer that does not allocate (a string with
  escapes is decoded into a scratch buffer), so the generated readers bind
  documents straight into structs; a DOM on top for what has no struct.
  Bounded by § 13, strict RFC 8259, UTF-8 checked (overlong forms,
  surrogates), fuzzed. A response's body is read whole, up to the limit,
  then parsed: the `schema` is read first wherever it is, so a newer
  document is never bound.
- **Generated types.** `tools/gen_types.py` turns `spec/schemas/v1` into
  structs and binders (`include/lantern/types.hpp`, `src/generated/`),
  committed; the CI fails when they are stale. Values a later version may
  add (a `kind`, a genre, a GPU name) are kept as strings; `requires.min`
  and unknown members of `requires` are kept raw, for § 8.7.
- **doctest** for the tests: one header, vendored, fast to build, and it
  runs with `-fno-exceptions`, which the CI tests.
- **A push transport** (a handler called as the answer comes) rather than
  a response object: it fits libcurl's callbacks and a blocking socket
  alike, allocates nothing, and lets a download stream to storage.
- **Monocypher** for ed25519, small and audited, behind checks of our own:
  a public key or an R of small order, a non-canonical encoding (y ≥ p) and
  an S ≥ L are refused before Monocypher's equation, so the forgeries a
  cofactorless check lets through (a small-order key, R and S = 0) never
  verify.
- **Strict RFC 9421, as § 5.4 writes it.** One form, built and checked
  whole, rather than a general Structured Fields engine; a server's check
  takes nothing else (another order, another label, a parameter more).
- **The certificate read by the library.** A bounded DER walk to the
  SPKI, fuzzed, so that libcurl's and mbedTLS's adapters pin the same
  bytes, and `spec/vectors/spki.json` tests both.
- **No randomness of its own.** A key or a nonce from a generator that is
  not cryptographic is no key at all, and each platform has its own; the
  app gives one (`RandomSource`).

## Not there yet

- **DNS-SD over IPv6** (`ff02::fb`), and an answer that wants the multicast
  group joined: the question is one-shot, over IPv4.
- **Compression** (§ 2.1) beyond gzip: the client asks for `gzip` on its JSON
  calls (never on a file or a stream) and reads it with `gunzip()`
  (`lantern/inflate.hpp`, no dependency, the limits of § 13 applying once
  decompressed); `zstd` and `br` need a decoder of their own, which a
  platform brings by an adapter later.
- **The mbedTLS adapter's connections**: one per request; keeping them is
  for a later version.
- **Annex B's retries** (backoff with jitter, `Retry-After` as a floor):
  the errors carry what they need, the app retries.
- The rest of the server core (see [Server core](#server-core)): tokens,
  pairing, signatures, accounts, saves,
  requests, administration, events, peers, sync and discovery, and
  compressed JSON. The C API is in [`../c/`](../c/README.md).

## Layout

| Path | What |
|---|---|
| `include/lantern/` | The public headers; `lantern.hpp` includes them all |
| `src/` | The library; `src/generated/` from `tools/gen_types.py` |
| `adapters/curl/`, `adapters/mbedtls/` | The TLS transports, `Lantern::curl` and `Lantern::mbedtls` |
| `adapters/http1/` | HTTP/1.1 over a byte stream, and POSIX TCP, for the mbedTLS and loopback adapters |
| `adapters/posix/` | The loopback HTTP adapter, `/dev/urandom`, a UDP socket and the demo's HTTP listener (`server_posix.hpp`), tests and examples only |
| `third_party/` | Monocypher and doctest, as published (`THIRD_PARTY_NOTICES.md`) |
| `tests/unit/`, `tests/integration/` | doctest; the integration tests start `spec/server`, its peer and a static export, over HTTPS too for the adapters, and every scenario of `python/tools/hostile_server.py` |
| `tests/fuzz/` | libFuzzer targets and their seed corpus |
| `tests/consumer/` | An app using the library, both ways |
| `examples/` | `read_library` and `pair_device`, the examples above; `lantern_demo_server`, the server core over a fictional library |
