# Lantern for C

The C API of the [Lantern protocol](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme)'s
client library: a thin, stable C ABI over the C++23 library of
[`cpp/`](../cpp/README.md), for Swift (iOS, macOS), Kotlin (Android,
through JNI) and any language with a C FFI. One header,
`include/lantern/lantern.h` (C11 or later, and C++), and one library,
`Lantern::c` (shared) or `Lantern::c_static`. It follows the
specification's **draft 0.5** (C API version 2).

**Status: draft 0.5, the C++ client whole.** The handshake, pairing with a
device key, signed requests, invitations, the library and its cursors,
`missing`, `changes`, titles, homebrew (manifest and path checks, install
plans, signatures and pins, ports' data, requirements), cheat sets, verified
downloads, saves (single and resumable), requests, the administration API
(deleting an account included), LAN discovery, and the server key's
fingerprint; and since draft 0.5, events (a stream, or long polling),
grants, mirrors and peers (a peer's gate included), sync with its consent,
end-to-end encrypted saves, and static libraries: each a C function.

## Building

CMake 3.28 or later, Ninja, a C11 compiler and the C++23 compiler `cpp/`
asks for (GCC 13, clang 19 with libstdc++ or 17 with libc++, MSVC 19.36,
Xcode 15).

```sh
cd c
cmake --workflow --preset dev        # configure, build, run the tests
```

| Preset | What |
|---|---|
| `dev` | Debug, the tests and the example |
| `release` | Optimised, the tests |
| `noexcept` | The C++ inside with `-fno-exceptions -fno-rtti`, as on a console |
| `asan` | AddressSanitizer and UndefinedBehaviorSanitizer |
| `ubsan` | UndefinedBehaviorSanitizer alone, every report fatal |

Built on its own, `c/` adds `../cpp` as a subdirectory, with its libcurl
and mbedTLS transports when it finds them (`LANTERN_CURL`,
`LANTERN_MBEDTLS`: `AUTO`, `ON` or `OFF`, as in `cpp/`). An app that adds
`cpp/` itself first keeps its `Lantern::lantern`; `-DLANTERN_C_CPP=PACKAGE`
takes an installed one (`find_package(Lantern)`).

| Option | What |
|---|---|
| `LANTERN_C_SHARED` | `Lantern::c`, the shared library (`ON`, but on a console) |
| `LANTERN_C_BUILD_TESTS` | The tests (on when `c/` is the project built for this machine) |
| `LANTERN_C_INSTALL` | Install rules and the CMake package `LanternC` |
| `LANTERN_WERROR` | Warnings are errors, as the CI builds |

The tests need the `spec/` submodule (`git submodule update --init`) and
Python 3, which writes the specification's vectors as a C header and runs
its reference server for the integration tests.

### Before pushing

The CI (`.github/workflows/c.yml`, through `ci.yml`) checks all of these; run what you can:

```sh
cd c
cmake --preset dev -DLANTERN_WERROR=ON && cmake --build --preset dev && ctest --preset dev
python3 tools/gen_c.py --check          # the documents' accessors match the C++ types
python3 tools/abi_dump.py --check       # the ABI is the one kept in abi/lantern.abi
git ls-files '*.c' '*.h' '*.cpp' '*.hpp' ':!:src/generated/**' ':!:include/lantern/lantern_documents.h' \
  | xargs clang-format --dry-run --Werror      # clang-format 18, with .clang-format
run-clang-tidy -config-file .clang-tidy -p build/dev 'c/src/[^g].*\.cpp$'   # clang-tidy 22
```

## In an app

```cmake
add_subdirectory(library/lantern-sdk/c)            # or find_package(LanternC 0.5)
target_link_libraries(my_app PRIVATE Lantern::c)   # or Lantern::c_static
```

`liblantern_c.so.1` (`lantern_c.dll`, `liblantern_c.1.dylib`) exports the
functions of `lantern.h` and nothing else; the C++ library and its standard
library are inside, hidden. `Lantern::c_static` is a C++ library inside: a
C program links it with the C++ runtime (CMake does, `LINKER_LANGUAGE CXX`).

### Apple: an XCFramework

Not built by the CI; the recipe, from a Mac with Xcode:

```sh
for sdk in iphoneos iphonesimulator macosx; do
  cmake -S c -B build/$sdk -G Xcode -DCMAKE_SYSTEM_NAME=$([ $sdk = macosx ] && echo Darwin || echo iOS) \
    -DCMAKE_OSX_SYSROOT=$sdk -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" -DCMAKE_OSX_DEPLOYMENT_TARGET=16.0 \
    -DLANTERN_C_SHARED=OFF -DLANTERN_C_BUILD_TESTS=OFF -DLANTERN_CURL=OFF -DLANTERN_MBEDTLS=OFF
  cmake --build build/$sdk --config Release
  # One archive: the C API and the C++ library under it
  libtool -static -o build/$sdk/liblantern.a build/$sdk/Release*/liblantern_c.a build/$sdk/cpp/Release*/liblantern.a
done
xcodebuild -create-xcframework \
  -library build/iphoneos/liblantern.a -headers c/include \
  -library build/iphonesimulator/liblantern.a -headers c/include \
  -library build/macosx/liblantern.a -headers c/include \
  -output Lantern.xcframework
```

`bindings/swift` is a Swift package over the library, with a module map
(`module CLantern`): an example of a binding, built and tested by the CI on
macOS against the library installed (see its `Package.swift`). An app on
iOS brings its own transport (URLSession) and keeps credentials in the
keychain through the callbacks below.

### Android: JNI

`bindings/kotlin` is a sketch: `Lantern.kt` (a client over the app's HTTP
stack, errors as exceptions) and `lantern_jni.c`, its JNI side, one native
method per C call. The CI builds the JNI library with the NDK for
`arm64-v8a`, and with the desktop's JDK in the Linux jobs; the Kotlin file
is not compiled (that is an app's Gradle build), and nothing of it is
published.

```sh
cmake -S c/bindings/kotlin/src/main/c -B build/jni -G Ninja -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"
cmake --build build/jni                     # liblantern_jni.so, for jniLibs/arm64-v8a
```

## The rules every function keeps

### Errors

A function that can fail returns a `lantern_status`: `LANTERN_OK` (0), or a
negative `LANTERN_ERROR_*`, one per category of the C++ library's errors
(`PROTOCOL` when the server answered with an error, `TRANSPORT`,
`INVALID_RESPONSE`, `LIMIT`, `INTEGRITY`, `SIGNATURE`, `REFUSED`,
`UNSUPPORTED`, `USAGE`, `STORAGE`, `MEMORY`). Its last argument is a
`lantern_error*`, which may be NULL; when given, it is filled on failure and
cleared on success:

| Member | What |
|---|---|
| `status` | The category |
| `http_status` | The HTTP status, 0 for a local error |
| `code`, `effective_code` | § 12's code as the server wrote it (`LANTERN_CODE_UNKNOWN` for a later version's), and the one to act on (the server's, or what its status implies) |
| `code_text` | The code exactly as written |
| `title`, `detail` | For people: bounded, NUL-terminated, without control characters |
| `retry_after` | Seconds, on a 429 or a 503 |

`LANTERN_ABSENT` (1) is not an error: a document of a newer `schema` than
the library reads (§ 3.2). Its `*out` is NULL, and the app treats the
feature as unavailable. Nothing throws, nothing aborts but an allocator
that returns NULL (below); a NULL where an object is needed is
`LANTERN_ERROR_USAGE`.

### Strings

- **Given to the library**: UTF-8, NUL-terminated `const char*`, borrowed
  for the call; NULL is the empty string. Where a size goes with a text
  (`lantern_read_*`, `lantern_check_device_path`, a transport's headers), the
  size decides and no NUL is needed.
- **Given by the library**: a `lantern_str` (`data`, `size`), UTF-8, also
  NUL-terminated at `data[size]`, `data` never NULL. It is borrowed from the
  object it came from and lives as long as that object (a document, a plan,
  the request a transport was given). A text the library makes for the app
  is a `lantern_string*`, owned, freed with `lantern_string_free()`.

### Ownership

| What | Who frees it |
|---|---|
| An object given through `**out` (a document, a client, a pairing, a plan, a key, a string) | The caller, with its `lantern_*_free()`; each takes NULL |
| A `const T*` a function returns (a nested document, `lantern_client_server()`, `lantern_pairing_get_key()`) | Nobody: borrowed from its owner, valid while the owner lives and is not changed |
| A `lantern_str` | Nobody: borrowed |
| Objects the app passes in (transport, random, clock, trust, stores, sinks) | The app, after everything that holds them: a client holds its transport, random source, clock, trust and log |
| Structs the app passes by pointer (configurations, queries, requests) | The app; the library copies what it keeps |

A document holds a reference to the allocator it was made with, not to the
client: it may outlive the client it came from.

### Memory

Every allocation goes through a `lantern_allocator` (`allocate`,
`deallocate`, a `user` context), given in the client's configuration or to
each function that makes an object, or, when none is given, through the
C++ default resource (`operator new`). It matches the C++ library's
`std::pmr` design: the app's allocator becomes the `memory_resource` of
every document read, and each read stays within `lantern_limits.max_memory`
(SPEC.md § 13), counted before each allocation, so that a document too
large is `LANTERN_ERROR_MEMORY`, not an allocation that fails. An allocator
that returns NULL anyway ends the program (`abort()`), as a C++ allocation
without exceptions does. The allocator is copied; whatever it allocates
from must outlive every object made with it.

### Threads

A `lantern_client` is **not** thread-safe: one thread at a time uses it
(calls may move from one thread to another when the app serializes them).
Two clients are independent and may run at once on two threads, sharing
nothing but an allocator (which must then be thread-safe) and documents.
A document is immutable once given: any number of threads may read it at
once; it is freed once, by one of them, after the others are done. A
callback is called on the thread that called the library, during that call
and never later; a transport's `send()` blocks until the answer is there,
so an app calls the client off its main thread. A `lantern_trust` is used
by the client and its transport, on the client's thread.

## The ABI policy

- **Versions.** `LANTERN_C_API_VERSION` (the header) and
  `lantern_version()` (the library) go up by one with each release that adds
  to the API; an app compiled against version N checks
  `lantern_version() >= N` before it calls what N added.
  `LANTERN_C_ABI_VERSION` is the shared library's SONAME
  (`liblantern_c.so.1`) and its symbols' version node (`LANTERN_C_1`): it
  goes up only when something is removed or changes meaning, which the
  library avoids.
- **Append only.** Functions, constants and enum values are added, never
  removed nor changed. Every enum is a fixed-size `int32_t` typedef with
  explicit values.
- **`struct_size` first.** Every struct passed by pointer begins with
  `size_t struct_size`, set by the caller to the size it was compiled with
  (`LANTERN_INIT(type)` does, the rest zero). A later version only appends
  members, and reads or writes no further than `struct_size`: an old app's
  shorter struct keeps its defaults (zero is always the default), and an
  output struct of an old app gets only what it has room for.
- **Frozen arrays.** Structs passed in arrays (`lantern_header`,
  `lantern_installed_app`, `lantern_version_fact`…) and `lantern_pin`,
  `lantern_datagram`, `lantern_str` never change; a new member makes a new
  struct and new functions.
- **Opaque everything else.** Clients, documents, plans and callbacks
  objects are opaque pointers, made and freed by the library, read through
  functions.
- **Checked.** `tools/abi_dump.py` writes the ABI as text, every
  function's prototype, constant, typedef and struct member, into
  `abi/lantern.abi`. The CI fails when the headers differ from it, says
  whether the change breaks the ABI or only adds to it, and that the right
  version went up; the shared library must export exactly the functions it
  lists. A change to the ABI is a change to that file, reviewed with it.

## Documents: accessors, and the `schema` rule

The protocol's documents are opaque, read through generated accessor
functions, not exposed as C structs:

```c
const lantern_app* app = lantern_apps_page_get_items_at(page, 0);
lantern_str name       = lantern_app_get_name(app);
uint64_t size          = 0;
bool has_size          = lantern_app_get_size(app, &size);
const lantern_title_players* players = lantern_title_get_players(title);  /* NULL when absent */
```

Why accessors: SPEC.md § 3.2 lets a document gain members without a new
`schema`, and the C++ structs gain them with it. A C struct of a document
would change size with each, and every array of them its stride: each
addition would break the ABI. An accessor is one more function, appended;
an old app never sees the new member and keeps working, as § 3.2 asks of a
reader. They are also what keeps a member a later schema makes optional
from changing a signature: every number, boolean and SHA-256 is read as
`bool get(const T*, X* out)`, false when absent; a string is empty when
absent; an object is NULL. An array has `_count()` and `_at(index)`.
`tools/gen_c.py` generates them from `cpp/tools/gen_types.py`'s own model of
`spec/schemas`, so that each reads the very member the C++ binder fills;
the CI fails when they are stale.

The rule itself is the C++ library's: a document of a newer `schema` is
`LANTERN_ABSENT`, never an error and never bound; one without `schema` is
`LANTERN_ERROR_INVALID_RESPONSE`; unknown members are skipped. Each
document also has a reader from text, `lantern_read_<document>(text, size,
limits, allocator, &out, &error)`, for one an app kept.

What the app keeps to resume after a restart, a download's state and an
upload's progress, is saved by the library as a JSON document with
`schema` 1 (`lantern_download_state_save()`, `lantern_upload_progress_save()`)
and read back with the same rule: a newer one is `LANTERN_ABSENT` (the
download starts over) and is never written over (`save()` then refuses
with `LANTERN_ABSENT`); a member a later version added is kept when the
state is saved again.

## Callbacks

Each callback interface is an opaque object made from a struct of function
pointers and a `user` context the library passes back, with an optional
`release(user)` called when the object is freed. A callback returns
`LANTERN_OK` or an error status, and may say why with `lantern_error_set()`
where it is given a `lantern_error`.

| Object | For |
|---|---|
| `lantern_transport` | HTTP: URLSession, OkHttp, a console's sockets; `send()` gets the request and pushes the answer with `lantern_response_status()`, `_header()`, `_body()` |
| `lantern_random` | Cryptographic bytes: a device key and a nonce per signed request; `lantern_random_create_system()` takes the system's |
| `lantern_clock` | The time a signature says, corrected by the server's `Date` |
| `lantern_credential_store` | The token, the device key's seed and the pinned server key, by server uid: the keychain, the keystore |
| `lantern_pin_store` | Homebrew authors' keys (§ 8.4) |
| `lantern_deprecation_log` | Each `Deprecation` a server sends (§ 3.4) |
| `lantern_download_sink`, `lantern_upload_source` | Where a download goes, where an upload reads |
| `lantern_data_probe` | What a port finds of its data on the device (§ 8.6) |
| `lantern_udp_socket` | Discovery's datagrams (§ 4.1), servers' and peers' |
| `lantern_event_callbacks` | Each event of a stream (§ 18), for the call of `lantern_client_events()` only |
| `lantern_held_files_callbacks` | What a console that shares holds whole, for its `lantern_peer_gate` (§ 19.4) |
| `lantern_static_files` | A static library's files (§ 21): the app's own (a USB key, an SD card), pushed into the sink it is lent with `lantern_download_sink_write()`; or `lantern_static_files_create_http()` |

The library's own transports, `lantern_transport_create_curl()` (libcurl
and its TLS) and `lantern_transport_create_mbedtls()` (mbedTLS, for the
consoles), are there when the build has them (`lantern_has_transport()`);
their functions always are, and give `LANTERN_ERROR_UNSUPPORTED` otherwise.
A transport of the app's that does TLS itself checks the server's key with
`lantern_trust_accept_certificate(trust, leaf_der, size, ca_verified)` once
per connection, and shows `lantern_pairing_get_fingerprint()` (or
`lantern_short_form()` of a pinned SPKI) next to a pairing code.

## Draft 0.5

Each family maps onto the C++ client's, with the rules above:

- **Events (§ 18).** `lantern_client_events()` reads the stream through
  `lantern_event_callbacks` until the server ends it, a callback returns
  false, or the transport is cut: the transport's read timeout is what
  notices a silent stream, `lantern_client_event_silence_limit()` (twice the
  heartbeat). A `lantern_event_stream_state` keeps the last id, the server's
  `retry` and the failures in a row (`_reconnect_delay_ms()`); a 410 forgets
  the position. `lantern_client_wait_changes()` is the long poll. Each
  event's document is read with `lantern_read_<kind>_event()` and the schema
  rule (`LANTERN_ABSENT`: ignore it).
- **Grants, mirrors and peers (§ 19).** `lantern_client_grant()`, then
  `lantern_client_peer_holds()` and `_download_from_peer()` with the grant
  alone; `_download_from_mirror()` and `_download_with_mirrors()`, nothing
  of the server's sent, every byte checked by the server's document. A
  peer's own check is `lantern_verify_grant()`; a console that shares runs
  a `lantern_peer_gate` (synchronous, no networking of its own: the app's
  HTTP server asks it, then streams the file it names, and gives the slot
  back). Discovery finds peers with `lantern_discovery_options.peers` and
  `on_peer`.
- **Sync (§ 20).** Nothing before `lantern_client_set_sync_consent()`, which
  the app keeps per profile and server with `lantern_client_sync_generation()`;
  `installed` only with its own consent; a generation that changed turns
  sync off (`LANTERN_ERROR_REFUSED`). Items are written as
  `lantern_sync_item_input`, their values made with `lantern_write_wish()`
  and `lantern_write_installed()`, read back with `lantern_read_wish()` and
  `lantern_read_installed()`; `lantern_sync_merge_items()` is § 20.4's rule
  for an app that keeps a copy.
- **Encrypted saves (§ 9.4).** A `lantern_save_key` (generated, or from its
  recovery phrase or QR text; a secret, never sent), a header per backup
  (`lantern_make_save_header()`, kept to resume), then
  `lantern_encrypting_source_create()` as the upload source of
  `lantern_client_upload_resumable()` (`_describe()` fills the request's
  size, SHA-256 and `encryption`), and `lantern_decrypting_sink_create()` as
  the download sink of `lantern_client_download_save()`: nothing is the
  archive until `lantern_decrypting_sink_finish()` succeeds.
- **Static libraries (§ 21).** `lantern_static_library_open()` over
  `lantern_static_files`, then its pages, titles, homebrew, cheats and
  files; `missing` and homebrew updates computed on the device
  (`lantern_app_list`, `lantern_homebrew_list`).

Version 2 of the API only added to version 1: functions, the families
`LANTERN_FAMILY_EVENTS` to `_ENCRYPTED_SAVES`, `LANTERN_CODE_PRECONDITION_FAILED`
(20: the C++ library put it among its codes, the C API's values do not
move), and members appended to `lantern_save_info`, `lantern_upload_request`
and `lantern_discovery_options` (`abi/lantern.abi` shows each).

## An example

`examples/read_library.c`, built with the tests, in full: the server's
name, every page of its library by its cursor, and its first app,
downloaded and checked.

```c
/* Reads a Lantern server's library, page by page, and downloads its first
 * app, checked, over libcurl: c/README.md's example.
 *   read_library https://shelf.example.org [TOKEN SEED_HEX] */
#include <lantern/lantern.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static lantern_status write_file(void* user, const uint8_t* bytes, size_t size)
{
    return fwrite(bytes, 1, size, (FILE*)user) == size ? LANTERN_OK : LANTERN_ERROR_STORAGE;
}

/* The server sends the file from its start again */
static lantern_status restart_file(void* user)
{
    return fseek((FILE*)user, 0, SEEK_SET) == 0 ? LANTERN_OK : LANTERN_ERROR_STORAGE;
}

static int report(const char* what, const lantern_error* error)
{
    fprintf(stderr, "%s: %s (%s, HTTP %u, %s)\n", what, error->detail, lantern_status_name(error->status),
        (unsigned)error->http_status, error->code_text);
    return EXIT_FAILURE;
}

static bool seed_of(const char* hex, uint8_t seed[32])
{
    return lantern_digest_from_hex(hex, seed); /* 64 lower-case hex digits, as a digest */
}

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 4)
    {
        fprintf(stderr, "usage: %s ORIGIN [TOKEN SEED_HEX]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (lantern_version() < LANTERN_C_API_VERSION)
    {
        fprintf(stderr, "liblantern_c is older than its header\n");
        return EXIT_FAILURE;
    }
    lantern_error error          = LANTERN_INIT(lantern_error);
    lantern_trust* trust         = NULL;
    lantern_transport* transport = NULL;
    lantern_random* random       = NULL;
    lantern_client* client       = NULL;
    lantern_handshake* server    = NULL;
    lantern_apps_page* first     = NULL;
    int status                   = EXIT_FAILURE;

    /* libcurl's TLS, the server's key checked by the trust (SPEC.md 5.3) */
    lantern_curl_options options = LANTERN_INIT(lantern_curl_options);
    if (lantern_trust_create(NULL, &trust, &error) != LANTERN_OK
        || lantern_curl_global_init(&error) != LANTERN_OK)
        goto done;
    options.trust = trust;
    if (lantern_transport_create_curl(&options, NULL, &transport, &error) != LANTERN_OK
        || lantern_random_create_system(NULL, &random, &error) != LANTERN_OK)
        goto done;

    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = argv[1];
    config.user_agent            = "ReadLibrary/1.0";
    config.platform              = "switch";
    config.transport             = transport;
    config.random                = random;
    config.trust                 = trust;
    if (lantern_client_create(&config, &client, &error) != LANTERN_OK)
        goto done;
    if (argc == 4)
    {
        /* A token bound to a device key (SPEC.md 5.4): every request is signed */
        uint8_t seed[32];
        lantern_device_key* key = NULL;
        if (!seed_of(argv[3], seed) || lantern_device_key_from_seed(seed, NULL, &key, &error) != LANTERN_OK)
            goto done;
        const lantern_status set = lantern_client_set_credentials(client, argv[2], key, &error);
        lantern_device_key_free(key); /* the client keeps a copy */
        if (set != LANTERN_OK)
            goto done;
    }

    const lantern_status shake = lantern_client_handshake(client, &server, &error);
    if (shake == LANTERN_ABSENT)
    {
        fprintf(stderr, "a server of a newer protocol: update the app\n");
        goto done;
    }
    if (shake != LANTERN_OK)
        goto done;
    printf("%s\n", lantern_handshake_get_name(server).data);

    /* Every page, by its cursor; the first page is kept for its first app */
    char cursor[512] = "";
    do
    {
        lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
        query.cursor             = cursor;
        lantern_apps_page* page  = NULL;
        if (lantern_client_apps(client, &query, &page, &error) != LANTERN_OK)
            goto done;
        for (size_t i = 0; i < lantern_apps_page_get_items_count(page); ++i)
        {
            const lantern_app* app = lantern_apps_page_get_items_at(page, i);
            printf("  %s (%s)\n", lantern_app_get_name(app).data, lantern_app_get_app_id(app).data);
        }
        snprintf(cursor, sizeof(cursor), "%s", lantern_apps_page_get_next(page).data);
        if (first == NULL)
            first = page;
        else
            lantern_apps_page_free(page);
    } while (cursor[0] != '\0');

    const lantern_app* app = lantern_apps_page_get_items_at(first, 0);
    if (app == NULL)
    {
        status = EXIT_SUCCESS;
        goto done;
    }
    /* The file, its size and SHA-256 as the listing gave them */
    lantern_download_target target = LANTERN_INIT(lantern_download_target);
    target.url                     = lantern_app_get_file(app).data;
    lantern_app_get_size(app, &target.size);
    lantern_app_get_sha256(app, target.sha256);
    FILE* file = fopen("first-app.part", "wb");
    if (file == NULL)
        goto done;
    lantern_download_callbacks callbacks = LANTERN_INIT(lantern_download_callbacks);
    callbacks.user                       = file;
    callbacks.write                      = write_file;
    callbacks.restart                    = restart_file;
    lantern_download_sink* sink          = NULL;
    lantern_download_state* state        = NULL;
    lantern_status got                   = lantern_download_sink_create(&callbacks, NULL, &sink, &error);
    if (got == LANTERN_OK)
        got = lantern_download_state_create(NULL, &state, &error);
    if (got == LANTERN_OK)
        got = lantern_client_download(client, &target, state, sink, &error);
    lantern_download_sink_free(sink);
    lantern_download_state_free(state);
    fclose(file);
    /* Only now, with the SHA-256 checked, is the file the app's */
    if (got == LANTERN_OK && rename("first-app.part", "first-app.bin") == 0)
        status = EXIT_SUCCESS;

done:
    if (status != EXIT_SUCCESS && error.status != LANTERN_OK)
        report("lantern", &error);
    lantern_apps_page_free(first);
    lantern_handshake_free(server);
    lantern_client_free(client);
    lantern_transport_free(transport);
    lantern_random_free(random);
    lantern_trust_free(trust);
    return status;
}
```

Pairing, in short (`lantern_client_start_pairing()`, then
`lantern_client_poll_pairing()` every `lantern_pairing_get_wait()` seconds
until `LANTERN_POLL_PAIRED`, the token and the device key then kept through
the app's `lantern_credential_store`, and `lantern_client_sign_in()` on the
next start), and every other call, are in `tests/integration/`, against
the reference server.

## Tests

- **Unit** (`tests/unit/`, C11, a small harness of their own): every family
  of functions, against a scripted server of callbacks serving the
  specification's examples; the `schema` rule for every document reader
  (absent, newer, an unknown member); `spec/vectors` (signatures byte for
  byte, refused requests with their codes, SPKI fingerprints, paths, and
  draft 0.5's grants, sync-merge, static-layout and encrypted-saves) written
  as a C header by `tests/support/vectors.py`; an allocator that counts,
  back to zero; structs of an older header. Linked once against the shared
  library (what it exports is enough) and once against the static one.
- **Integration** (`tests/integration/`): the C API against the
  specification's reference server on loopback, started by
  `cpp/tests/integration/run_server.py`, through a transport of callbacks:
  pairing approved by an admin, signed requests and the clock's
  correction, invitations, saves whole and resumable, cheat sets, requests,
  downloads cut and resumed, homebrew, discovery; and draft 0.5's events and
  long polling, a grant and the reference peer's file, a mirror, the peer's
  discovery, sync, an encrypted backup sent resumably and opened back, an
  account deleted, and the library as a static library over HTTP and from
  its folder.
- **The header** compiled alone as C11, C17 and C++23 with every warning,
  and **the ABI** (`tools/abi_dump.py --check`, with the library's exports).
- ASan and UBSan builds (`asan`, `ubsan` presets), and clang-tidy with
  `.clang-tidy` (`cpp/.clang-tidy`'s checks, the C ABI's arrays aside).

## Not there yet

- An app's own `RequestSigner` (`ClientConfig::signer` in C++): the client
  signs with its device key itself, which is what an app needs.
- What the C++ library leaves for later (DNS-SD, compression, Annex B's
  retries), and its server-side pieces beyond `lantern_check_signature()`.
- The Swift and Kotlin bindings are examples, not packages: an app copies
  the pattern, or a later binding builds on it.

## Layout

| Path | What |
|---|---|
| `include/lantern/lantern.h` | The API; it includes `lantern_documents.h`, generated |
| `src/` | The library, C++ over `cpp/`; `src/generated/` from `tools/gen_c.py` |
| `abi/lantern.abi` | The ABI as kept, from `tools/abi_dump.py` |
| `examples/` | The example above |
| `tests/` | Unit and integration tests, in C |
| `bindings/swift`, `bindings/kotlin` | The bindings' sketches |
