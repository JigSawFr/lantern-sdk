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
| `typescript/` | TypeScript | Client in the browser and Node, server for Node |
| `c/` | C | A thin API over the C++ library, for Swift and Kotlin |

Every server in it passes the specification's conformance suite, and every
client passes a deliberately malicious test server, in CI, for every
language.

## Licence

[MIT](LICENSES/MIT.txt). Every file says its licence
([REUSE](https://reuse.software/)).

## Contact

Issues and pull requests on this repository: see
[CONTRIBUTING.md](CONTRIBUTING.md). A change to the protocol itself is
proposed in [the specification's repository](https://github.com/JigSawFr/lantern).
A security flaw is reported privately, as [SECURITY.md](SECURITY.md) says.
Everyone follows the [code of conduct](CODE_OF_CONDUCT.md).
