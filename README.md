# Lantern SDK

Client and server libraries for the
[Lantern protocol](https://github.com/JigSawFr/lantern), the open,
versioned REST/JSON protocol between console homebrews and the library
servers people run at home for their own games. Its specification lives at
[lantern.boreale.dev](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme).

**Status: not started.** The libraries begin once the specification's
draft 0.3 is out; nothing here is usable yet.

## What it will hold

One repository for both sides of the protocol, in several languages, each
sharing the same types, generated from the specification's schemas (the
specification is pinned here as a submodule):

| Folder | Language | Side |
|---|---|---|
| [`cpp/`](cpp/README.md) | C++23 | The client of the consoles and of apps built with [Aurore](https://github.com/JigSawFr/Aurore), and a server core; every platform Aurore runs on. The client of draft 0.5: pairing with a device key, signed requests, the routes that write, administration, events, grants with mirrors and peers (and a peer's side), sync, end-to-end encrypted saves, static libraries, discovery, and TLS transports over libcurl and mbedTLS; tested against every scenario of the malicious test server |
| [`python/`](python/README.md) | Python | Client and server, with Flask and FastAPI integration (`lantern-protocol`): draft 0.5, the whole client (pairing with a device key, signed requests, writes, discovery, events, mirrors and peers, sync, encrypted saves, static libraries) and a server toolkit at Lantern Core +titles +homebrew +cheats +admin +events +peers +sync; a minimal peer, the generator of static libraries (Lantern Static); the malicious test server for clients (`python/tools/hostile_server.py`) |
| [`typescript/`](typescript/README.md) | TypeScript | Client in the browser and Node, and a server toolkit for Node (`lantern-protocol`): draft 0.5, the whole client (pairing with a WebCrypto device key, signed requests, writes, pinning in Node, discovery, events over fetch streams, grants, mirrors and peers, sync, end-to-end encrypted saves, static libraries) with no runtime dependency, and a server toolkit at Lantern Core +titles +homebrew +cheats +admin +events +peers +sync, on `node:http` or any framework of web Requests (Hono), with a peer server and the `lantern-static` generator |
| [`c/`](c/README.md) | C | A thin, stable C ABI over the C++ library, for Swift and Kotlin (JNI): draft 0.4, the whole client, its documents read through accessors generated from the schemas, the app's HTTP stack, random source, keychain and stores as callbacks, an ABI kept and checked; a Swift package and a JNI sketch as examples |

Every server in it passes the specification's conformance suite, and every
client passes a deliberately malicious test server, in CI, for every
language.

## Releases

One version for the whole SDK, the same in every language, with notes by
language: the C++ library and the C API as source and as CMake packages
built for Linux x86_64, the Python package `lantern-protocol` on PyPI and
the npm package `lantern-protocol`, all on
[the releases page](https://github.com/JigSawFr/lantern-sdk/releases). Every
file is built by this repository's CI from the tag, reproducibly, with its
SBOM, and attested (SLSA build provenance, through Sigstore); the packages
are published by trusted publishing, without any token.
[SECURITY.md](SECURITY.md#verifying-a-release) says how to check a file,
[RELEASING.md](RELEASING.md) how a release is made.

## Licence

[MIT](LICENSES/MIT.txt). Every file says its licence
([REUSE](https://reuse.software/)).

## Contact

Issues and pull requests on this repository: see
[CONTRIBUTING.md](CONTRIBUTING.md). A change to the protocol itself is
proposed in [the specification's repository](https://github.com/JigSawFr/lantern).
A security flaw is reported privately, as [SECURITY.md](SECURITY.md) says.
Everyone follows the [code of conduct](CODE_OF_CONDUCT.md).
