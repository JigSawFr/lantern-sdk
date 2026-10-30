# Lantern for C++

The C++23 client library of the [Lantern protocol](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme),
for the consoles and the apps built with [Aurore](https://github.com/JigSawFr/Aurore):
`Lantern::lantern`, and two optional TLS transports, `Lantern::curl` and
`Lantern::mbedtls`. It follows the specification's **draft 0.4**
(`spec/`, pinned as a submodule of this repository).

**Status: draft 0.4, the client whole.** Pairing with a device key, signed
requests, invitations, the routes that write and the administration API,
over TLS with the server's key pinned; a server core and a C API are for
later (see [Not there yet](#not-there-yet)).

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
  it. A token and a signature go to the server's origin alone (§ 2).
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
  `Upload-Offset`, `HEAD` to resume after a cut or a `409`, the whole
  archive's SHA-256 checked by the server; cheat sets written, replaced and
  removed (§ 10); requests made, listed and withdrawn (§ 11).
- **The administration API** (§ 5.7): accounts, devices, the pairings
  waiting (each with its code and key, to compare with the console's
  screen), invitations.
- **Discovery** (§ 4.1): the datagram to UDP 47115, the replies read
  bounded and with the `schema` rule, each server once, through a
  `UdpSocket` the app gives (`adapters/posix` has one).
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
| `dev` | Debug, the tests and the example |
| `release` | Optimised, the tests and the example |
| `noexcept` | Everything, tests included, with `-fno-exceptions -fno-rtti` |
| `asan` | AddressSanitizer and UndefinedBehaviorSanitizer |
| `ubsan` | UndefinedBehaviorSanitizer alone, every report fatal |
| `tsan` | ThreadSanitizer |
| `fuzz` | The libFuzzer targets (clang: `CC=clang CXX=clang++`) |

`-DLANTERN_WERROR=ON` makes warnings errors, as the CI does. The tests need
the `spec/` submodule (`git submodule update --init`); the integration
tests also need Python 3, which runs the specification's reference server,
and the TLS adapters' tests need `openssl`, which makes a self-signed
certificate for the run.

| Option | What |
|---|---|
| `LANTERN_CURL` | `Lantern::curl`, over libcurl 7.85 or later: `AUTO` (built when found), `ON` (required) or `OFF` |
| `LANTERN_MBEDTLS` | `Lantern::mbedtls`, over mbedTLS 2.28 or 3: `AUTO`, `ON` or `OFF` |

Both are `AUTO` when this folder is the project built for the machine it
runs on, `OFF` otherwise: an app that adds this folder, or a cross build,
asks for one with `ON`. The library itself needs neither.

### Before pushing

The CI (`.github/workflows/cpp.yml`) checks all of these; run what you can:

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
and its generator only. A sparse checkout keeps the rest out:

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
find_package(Lantern 0.4 REQUIRED)
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

## Errors

Nothing throws: the library builds and runs with `-fno-exceptions
-fno-rtti`. A call that can fail returns `lantern::Result<T>`, a
`std::expected<T, lantern::Error>`; a call that reads a document returns
`lantern::Read<T>`, a `Result<std::optional<T>>` whose optional is empty
for a document of a newer schema.

An `Error` has:

- a `category()`: `protocol` (the server answered with an error),
  `transport`, `invalid_response`, `limit`, `integrity`, `signature`,
  `refused` (a server key refused among them), `unsupported`, `usage`,
  `storage` or `memory`;
- for a server's error, its `status()`, the `code()` of its problem+json
  (`Code::unknown` for a code of a later version, with `code_text()`),
  and `effective_code()`, the code to act on: the server's, or the one its
  status implies (§ 12); draft 0.4's `key_required`, `signature_required`,
  `signature_invalid`, `signature_expired` and `signature_replayed`
  included;
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

- **DNS-SD** (`_lantern._tcp`, § 4.1): the datagram only.
- **Compression** (§ 2.1): the client sends no `Accept-Encoding` and gets
  JSON as it is.
- **The mbedTLS adapter's connections**: one per request; keeping them is
  for a later version.
- **Annex B's retries** (backoff with jitter, `Retry-After` as a floor):
  the errors carry what they need, the app retries.
- **A malicious test server** for clients is the repository's, shared
  between languages; `tests/integration/run_server.py --hostile-server`
  runs the integration tests' case against it once it exists.
- A server core, and a C API.

## Layout

| Path | What |
|---|---|
| `include/lantern/` | The public headers; `lantern.hpp` includes them all |
| `src/` | The library; `src/generated/` from `tools/gen_types.py` |
| `adapters/curl/`, `adapters/mbedtls/` | The TLS transports, `Lantern::curl` and `Lantern::mbedtls` |
| `adapters/http1/` | HTTP/1.1 over a byte stream, and POSIX TCP, for the mbedTLS and loopback adapters |
| `adapters/posix/` | The loopback HTTP adapter, `/dev/urandom` and a UDP socket, tests and examples only |
| `third_party/` | Monocypher and doctest, as published (`THIRD_PARTY_NOTICES.md`) |
| `tests/unit/`, `tests/integration/` | doctest; the integration tests start `spec/server`, over HTTPS too for the adapters |
| `tests/fuzz/` | libFuzzer targets and their seed corpus |
| `tests/consumer/` | An app using the library, both ways |
| `examples/` | `read_library` and `pair_device`, the examples above |
