# Lantern for C++

The C++23 client library of the [Lantern protocol](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme),
for the consoles and the apps built with [Aurore](https://github.com/JigSawFr/Aurore):
`Lantern::lantern`. It follows the specification's **draft 0.3**
(`spec/`, pinned as a submodule of this repository).

**Status: the read side of draft 0.3.** Draft 0.4 is being written and
changes tokens and pairing; until it is out, this library takes a bearer
token from the app and does not pair (see [Not there yet](#not-there-yet)).

## What it does

- **The read side of the protocol**: the handshake and its `features`, the
  apps' listing with its cursors, what a device is missing, `changes`,
  `sections`, titles (one, many, their changes), homebrew (the listing, an
  entry, the updates of what is installed), cheat sets and their text, with
  `Lantern-Platform` on every call.
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
tests also need Python 3, which runs the specification's reference server.

### Before pushing

The CI (`.github/workflows/cpp.yml`) checks all of these; run what you can:

```sh
cd cpp
cmake --preset dev -DLANTERN_WERROR=ON && cmake --build --preset dev && ctest --preset dev
python3 tools/gen_types.py --check     # the generated types match spec/schemas
git ls-files '*.cpp' '*.hpp' ':!:third_party/**' ':!:src/generated/**' ':!:include/lantern/types.hpp' \
  | xargs clang-format --dry-run --Werror   # clang-format 18 (pip install clang-format==18.1.8)
run-clang-tidy -p build/dev 'cpp/src/[^g].*\.cpp$' 'cpp/adapters/.*\.cpp$'
reuse lint                             # at the repository's root
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
add_subdirectory(library/lantern-sdk/cpp)
target_link_libraries(my_app PRIVATE Lantern::lantern)
```

Added this way, it builds the library alone: no tests, no example, no
install rules of its own unless `LANTERN_INSTALL` is set.

### Installed

```sh
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release -DLANTERN_BUILD_TESTS=OFF
cmake --build build && cmake --install build --prefix /opt/lantern
```

```cmake
find_package(Lantern 0.3 REQUIRED)
target_link_libraries(my_app PRIVATE Lantern::lantern)
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

`adapters/posix` is a blocking HTTP/1.1 client over POSIX sockets, plain
HTTP to a loopback address only, built for the tests and the example and
never installed. TLS adapters (libcurl, mbedTLS) are for a later version.

A `RequestSigner` (`ClientConfig::signer`) sees every request's method,
target, headers and body digest and may add headers: the hook for draft
0.4's device-bound tokens (RFC 9421). Nothing uses one yet.

## Errors

Nothing throws: the library builds and runs with `-fno-exceptions
-fno-rtti`. A call that can fail returns `lantern::Result<T>`, a
`std::expected<T, lantern::Error>`; a call that reads a document returns
`lantern::Read<T>`, a `Result<std::optional<T>>` whose optional is empty
for a document of a newer schema.

An `Error` has:

- a `category()`: `protocol` (the server answered with an error),
  `transport`, `invalid_response`, `limit`, `integrity`, `signature`,
  `refused`, `unsupported`, `usage`, `storage` or `memory`;
- for a server's error, its `status()`, the `code()` of its problem+json
  (`Code::unknown` for a code of a later version, with `code_text()`),
  and `effective_code()`, the code to act on: the server's, or the one its
  status implies (§ 12);
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

## Not there yet

- **TLS adapters** (libcurl and mbedTLS for the consoles, the platform's
  own elsewhere): a later version. The POSIX adapter here is plain HTTP on
  loopback, for tests.
- **Pairing and tokens**, beyond `set_bearer_token()`: draft 0.4 changes
  them (device-bound keys, RFC 9421 signatures, invitations); the
  `RequestSigner` hook is where they will go. Server key pinning by SPKI
  (§ 5.3) comes with them.
- **The routes that write**: saves (and their resumable upload), cheat
  sets, requests.
- **Discovery** (UDP datagrams, DNS-SD), a server core, and a C API.

## Layout

| Path | What |
|---|---|
| `include/lantern/` | The public headers; `lantern.hpp` includes them all |
| `src/` | The library; `src/generated/` from `tools/gen_types.py` |
| `adapters/posix/` | The loopback HTTP adapter, tests and example only |
| `third_party/` | Monocypher and doctest, as published (`THIRD_PARTY_NOTICES.md`) |
| `tests/unit/`, `tests/integration/` | doctest; the integration tests start `spec/server` |
| `tests/fuzz/` | libFuzzer targets and their seed corpus |
| `tests/consumer/` | An app using the library, both ways |
| `examples/` | `read_library`, the example above |
