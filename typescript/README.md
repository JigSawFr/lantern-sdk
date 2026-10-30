# lantern-protocol (TypeScript)

The TypeScript library of the [Lantern protocol](https://github.com/JigSawFr/lantern),
the open REST/JSON protocol between console homebrews and the library
servers people run at home for their own games
([lantern.boreale.dev](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme)):
a client for the browser and Node, a toolkit to add Lantern to a Node
server, and the checks both sides share. It follows the specification's
**draft 0.4**, as the [Python library](../python/README.md) does, whose
scope and names it mirrors.

**Status: early, complete for draft 0.4's client.** The client speaks every
route of the protocol: pairing with a device key, requests signed by it
(RFC 9421), the writes, LAN discovery (Node). The server toolkit pairs
devices, checks signed requests, and serves the read routes, invitations,
rating caps and the administration API; it reaches **Lantern Core +titles
+homebrew +cheats +admin** in the specification's conformance suite, through
`node:http` and through web Requests. See
[What is not there yet](#what-is-not-there-yet). Nothing is published on npm
before the first release (`"private": true` until then).

## Installing

Node 22.18 or later, or a browser of 2025 (Chrome 137, Firefox 129,
Safari 17: Ed25519 in WebCrypto). **No runtime dependency.** ESM only, typed.

```sh
npm install lantern-protocol
```

Three entries:

| Import | Where | What |
|---|---|---|
| `lantern-protocol` | browser and Node | the client over `fetch()`, the documents and their checks, signatures, pinning, profiles, homebrew rules |
| `lantern-protocol/node` | Node | `NodeLanternClient` (the server's key pinned), files (downloads through a `.part`, uploads, stores), LAN discovery |
| `lantern-protocol/server` | Node (and any runtime of web Requests, for `fetchHandler`) | `LanternApp` and its pieces |

## A client

```ts
import { homebrew as hb } from "lantern-protocol";
import { NodeLanternClient } from "lantern-protocol/node";

const client = new NodeLanternClient("https://shelf.example.org/", {
  platform: "switch",
  userAgent: "MyShelf/1.0",
  token: TOKEN,
});
const hello = await client.handshake(); // the server, the account, the families offered
for await (const app of client.iterApps({ type: "base" })) console.log(app.name, app.version_code);

// What the device is missing (SPEC.md § 6.3)
for await (const app of client.iterMissing([["0100ABCD00010000", 0]], ["update", "dlc"])) {
  await client.downloadAppTo(app, `downloads/${app.app_id}.${app.format}`);
}

const titles = await client.titles(["0100ABCD00010000", "0100EFEF00020000"]); // by 100 per request
const entry = await client.homebrewEntry("org.example.frostline");
if ((await hb.verifySignature(entry)) === false) throw new Error("a signature that does not verify");
const plan = hb.installPlan(entry); // paths free to write, and those that need consent
const pkg = hb.pickPackage(entry, "aarch64");
```

In a browser, the same calls on `LanternClient` (from `lantern-protocol`),
over `fetch()`; a download goes into a `DownloadSink` (`MemorySink`, or one
of the app's own over OPFS or IndexedDB).

- `platform` is sent as `Lantern-Platform` on every call; `platform:` on a
  call sends `?platform=` instead.
- `token` sets `Authorization: Bearer`, sent to the server's origin only,
  never to another host a document points at; so is the signature.
- Plain HTTP is refused unless the server is on a loopback address
  (SPEC.md § 2).
- A download is hashed as it arrives (SHA-256 in TypeScript in a browser,
  `node:crypto` in Node), its `Repr-Digest` checked against the document's,
  resumed with a `Range` from what the sink holds, and committed (the `.part`
  renamed) only when its size and SHA-256 are right. One that is not throws
  `IntegrityError`, and the sink is emptied.
- A server's error throws the `ProblemError` of its status (below); a
  document of a newer `schema` throws `NewerSchema`: treat it as absent.

### Pairing, and signed requests

```ts
import { FileServerStore, NodeLanternClient } from "lantern-protocol/node";

const store = new FileServerStore("servers.json"); // its owner's alone; or your keychain's
const client = new NodeLanternClient("https://192.0.2.10:8443/", { verify: false, platform: "switch" });
const pairing = await client.pair("Lea's console", ["library", "saves"]);
show(pairing.code, pairing.verify, pairing.fingerprint); // and pairing.verifyComplete as a QR code
const record = await client.waitForPairing(pairing, { store }); // the token, its key, the pinned SPKI

// Later, from what was kept:
const again = await NodeLanternClient.paired(record);
(await again.handshake()).account.bound; // true: signed with the device key
```

- `verify: false` is for a LAN server whose certificate no CA vouches for:
  the client reads its key's fingerprint (`pairing.fingerprint`) for the
  user to compare, pins it as soon as the pairing starts, and from then on
  talks only over that key (`pin:`). Another key throws `PinMismatch`
  before a byte of the request is sent: an alarm, not an error to retry.
- The device key is a WebCrypto `CryptoKey`. In a browser it is made
  **non-extractable**: the app keeps the `CryptoKey` itself in IndexedDB
  (`DeviceKey.fromCryptoKey()`), never its bytes, and the record it keeps has
  no `key`. In Node, `NodeLanternClient` makes it extractable so that a file
  store keeps its seed (`record.key`); keep that store where the system
  protects secrets.
- The clock: the client takes the offset of the server's `Date` from the
  handshake when it is off by half the server's `auth.skew` or more, and
  signs again once, with the server's `Date`, after `signature_expired`;
  once, with a new nonce, after `signature_replayed`. Any other refusal
  (`SignatureRequired`, `SignatureInvalid`, with the server's
  `Accept-Signature` in `e.acceptSignature`) means pairing again.
- An invitation's link (§ 5.5) pairs at once, and pins the key it names:
  `NodeLanternClient.fromInvitation(link, "Ines's console", ["library"])`.
- The rating cap the token carries (§ 5.6): `client.ratingCap`.

### Writing

```ts
await client.save("0100ABCD00010000", zip, { kind: "account", profile: "Lea" }); // one request, Content-Digest
await client.uploadSaveFile("0100ABCD00010000", "big.zip"); // resumable: chunks, HEAD, { resume }
await client.downloadSaveTo(save, "back.zip"); // checked against its sha256
await client.createCheat("switch", "0100ABCD00010000", text, { buildId: "4A1B…", source: "Lea" });
const request = await client.requestTitle("0100FFFF00090000");
await client.withdrawRequest(request.id);
```

`uploadSave(titleId, source)` takes any `UploadSource` (`bytesSource()`,
`blobSource()` for a `File` in a browser). With the scope `admin`, the
administration API (§ 5.7): `iterAdminUsers()`, `createUser()`,
`updateUser()`, `iterAdminDevices()`, `revokeDevice()`,
`iterAdminPairings()` (show each code next to the server's fingerprint),
`approvePairing(id, { ratingCap })`, `refusePairing()`,
`createInvitation()`, `revokeInvitation()`.

### On the LAN

```ts
import { directedBroadcast, discover } from "lantern-protocol/node";

for (const found of await discover([directedBroadcast("192.168.1.20", 24)])) console.log(found.name, found.url);
```

A reply is a hint, never a proof: the client then reads the handshake over
TLS and pairs. A browser has no UDP; DNS-SD needs an mDNS stack, which Node
has not: neither is here.

### Transports and pinning

A request is built, then given its credentials and its signer (both for the
server's origin only), then sent by a `Transport`: `FetchTransport` (the
platform's `fetch()`, which follows no redirect and sends no cookie),
`NodeTransport`, or any object with the same `send()`.

- **Node**: `NodeTransport({ pin })` makes each TLS connection with an agent
  of its own, which reads the certificate's key on `secureConnect`, before a
  byte of the request is written. Node calls `checkServerIdentity` only for
  a chain its CA store accepted (and not on a resumed session), so a LAN
  server's self-signed key never reaches it: the agent checks the key
  itself, and keeps no TLS session.
- **Browser**: pinning is impossible. A page cannot see the certificate of
  its connections, nor trust a key no CA vouches for; a browser client talks
  to servers its CA store accepts (or a LAN server behind a certificate of
  the user's own CA), and `pin`/`verify: false` throw `Unsupported`. The
  browser also decides `User-Agent` and `Accept-Encoding`, and a server on
  another origin than the page's must answer CORS (preflight included, for
  `Authorization`, `Lantern-Platform`, `Signature-Input`, `Signature` and
  `Content-Digest`).

### Ed25519

WebCrypto signs and verifies (Node 22 and the browsers above). Before any
verification, the library refuses what SPEC.md § 8.4 refuses, itself, in
BigInt arithmetic over public data: a key or an R that does not decode
canonically, or is of small order, and an S of L or more
(`vectors/ed25519-refused.json` passes). A platform without Ed25519 in its
WebCrypto gets `Unsupported`, with no fallback: the library carries no
Ed25519 of its own for secret keys. `ed25519.available()` says beforehand.

The client records what a server deprecates (`Deprecation`, `Sunset`,
§ 3.4) in `client.deprecations`, and calls `onDeprecation` once each
(`console.warn` by default); `whatFits(apps, free)` says which apps fit in
the device's free space (§ 6.3).

## What both sides check

- The documents of `spec/schemas/v1`, as types and readers generated by
  `tools/generate.ts` (`readHomebrew()`, `DOCUMENTS.apps`…). A reader checks
  the type of every field it knows and gives back the object it was given,
  so the fields it does not know stay on it and are written back.
- `read()`, `readNamed()`, `parse()`: the `schema` rule. A document of a
  newer `schema` is absent (`undefined`; the client throws `NewerSchema`),
  never an error and never written back. `homebrew.effectiveKind()` reads an
  unknown kind as `app`; `effectiveAssets()` and `effectiveGenres()` likewise.
- `validate(name, doc)`: the strict check against the JSON Schemas, without
  a dependency.
- `limits`: SPEC.md § 13, which `loadJson()` keeps to (the depth is read
  before parsing).
- `homebrew`: manifest paths, the canonical bytes of § 8.2 and § 8.4,
  signatures, install plans, architectures, ports' data (`launchCheck()`)
  and requirements (`offer()`); `profiles`: Annex A, per platform.
- `signatures`: device keys, and requests signed and checked as § 5.4 says;
  `spkiSha256()`: a certificate's key fingerprint (§ 5.3); `ratings`: rating
  caps (§ 5.6). The specification's vectors (`signatures`, `ed25519-refused`,
  `spki`, `rating-caps`, `paths`, `homebrew-signatures`, `version-codes`,
  `requires`) pass byte for byte.
- Stores (`lantern-protocol/node`): `FileServerStore` and `FileKeyPins` keep
  their files by the `schema` rule (a newer file is never written over,
  unknown keys are kept, a file is written whole or not at all).

## Adding Lantern to a Node server

```ts
import { createServer } from "node:http";
import { LanternApp, MemoryAccounts, MemoryLibrary, nodeHandler } from "lantern-protocol/server";

const library = new MemoryLibrary({ base: "/api/lantern" });
library.addAppFile({
  data: await readFile("games/frostline.nsp"),
  platform: "switch",
  title_id: "0100ABCD00010000",
  app_id: "0100ABCD00010000",
  type: "base",
  version_code: 0,
  name: "Frostline Tales",
  format: "nsp",
});
const accounts = new MemoryAccounts([{ name: "lea", scopes: ["library", "saves"] }, { name: "ada", scopes: ["library", "admin"] }]);
const app = new LanternApp(library, { uid: SERVER_UID, name: "Living room shelf", accounts, public: false, spki: MY_TLS_KEY_SHA256, secret: SECRET });
createServer(nodeHandler(app)).listen(8080);
```

A server implements `Library` over what it has (its database, its scan),
and `Accounts` over its own store; `MemoryLibrary` and `MemoryAccounts` are
complete ones, in memory. Every method may be async. Without `accounts`, an
`authenticate(request)` hook resolves the server's own tokens to an
`Account` (one with a `key` is still checked for its signature).

With **Hono**, or any framework of web Requests (Deno, Bun):

```ts
import { fetchHandler } from "lantern-protocol/server";

const lantern = fetchHandler(app, { remote: (request) => addressOf(request) });
hono.all("*", (c) => lantern(c.req.raw));
```

What `LanternApp` serves, with `accounts`:

- pairing (§ 5.2): codes of the unambiguous alphabet that expire within 10
  minutes, unguessable poll addresses, `verify_complete`, limits per address
  (`429 slow_down`); a device key that is not canonical or of small order is
  refused; `boundOnly` refuses tokens without a key (`key_required`);
- signed requests (§ 5.4): every request of a bound token is checked
  (components, parameters, the token's key, the window `skew`, a replay
  cache of nonces kept twice the window), then its body against its
  `Content-Digest`; a refusal carries `Accept-Signature`;
- the approval: the server's own page at `verify` (`pairPage`, which signs
  the user in and calls `app.desk.approve()`); without it, a page that shows
  the code and the server's fingerprint and approves nothing, approval then
  going through the administration API;
- invitations (§ 5.5), redeemed at pairing and approved at once, counted so
  that devices redeeming one together never pass its `devices`; a link that
  carries the server's `spki`;
- rating caps (§ 5.6): what is above a token's cap is left out of every
  listing and answers `404`;
- the administration API (§ 5.7): accounts, devices (never their token or
  its hash), waiting pairings, invitations;
- the handshake, `library` (filters, sorts, sealed cursors, what is missing,
  files with `ETag`, `Repr-Digest` and ranges), `changes` with a journal,
  `titles`, `homebrew`, `cheats`; problem+json for every error; `ETag` and
  `304`, `Cache-Control` and `Vary`; JSON compressed as `Accept-Encoding`
  asks (zstd, gzip); `Date` on every response.

The families it does not offer (sections, saves, requests) are at 0 in the
handshake, and their routes answer `404`. Each piece is usable on its own:
`jsonResponse()`, `problemResponse()`, `fileResponse()`, `platformOf()`,
`readDocument()`, `Cursors` and `SinceTokens` (sealed with the server's
secret, nothing kept), `checkHomebrew()`, `makePackage()`, `zipManifest()`.
`DiscoveryResponder.start(app, { httpsPort })` answers LAN discovery on UDP
47115 (local networks only, a few times a second per address).

## Errors

A server's error answer throws the `ProblemError` of its status:
`BadRequest` (400, 405, 416), `Unauthorized` and its signature refusals
(`SignatureRequired`, `SignatureInvalid`, `SignatureExpired`,
`SignatureReplayed`), `Forbidden` and `AccountFrozen`, `NotFound`,
`Conflict`, `Gone` (an expired cursor or token: read again from the start),
`TooLarge`, `Unprocessable`, `SlowDown`, `ServerError` and `Unavailable`.
`e.status` is always there; `e.code` is the code when this library knows it,
`undefined` otherwise (act on the status alone, SPEC.md § 12); `e.detail` is
bounded and without control characters; `e.retryAfter` is in seconds.

The client's own: `DocumentError` (a malformed document, or one beyond
§ 13), `NewerSchema` (treat as absent), `IntegrityError` (a download that is
not its document's), `TransportError`, `InsecureTransport` and
`PinMismatch`, `UnexpectedResponse` (a redirect, an unexpected status or
content type), `Unsupported` (what this platform cannot do). All derive from
`LanternError`.

## What is not there yet

- In the server toolkit: sections, saves, cheat writes and requests (their
  families are at 0), DNS-SD, and the routes it could mark deprecated.
- DNS-SD on the client: Node has no mDNS stack, and a browser no UDP.
- Pinning in a browser: impossible (above).
- Drawing the QR code of `verifyComplete`: the client gives its text.
- Installing: the library says what to write and where, and checks it; it
  writes nothing on a device.

## Developing

From `typescript/`, with the specification's submodule checked out
(`git submodule update --init`), and Node 22.18 or later (the tests and the
tools run as TypeScript, by Node's type stripping):

```sh
npm ci
node tools/generate.ts --check       # the types are those of spec/schemas/v1
npx biome ci .                       # lint and format
npx tsc -p tsconfig.json             # strict, exactOptionalPropertyTypes, noUncheckedIndexedAccess
npm test                             # unit tests and the specification's vectors
npm run build                        # dist/, with declarations
```

The integration tests need Python 3.11 or later: `PYTHON=python3 npm run
test:integration` runs the client against the malicious test server
(`python/tools/hostile_server.py`, every scenario, from its command line;
`cryptography` for its TLS ones), against the specification's reference
server (`test/fixtures/reference.py`: plain HTTP, and TLS with a pinned
self-signed key), and the conformance suite against the demo server
(`test/demo.ts`, through `node:http` and `fetchHandler`; the suite's
`spec/tools/requirements.txt`, and Python 3.14 to read the zstd the demo
sends). `npm run test:browser` builds `dist/` and runs it in Chromium
(Playwright; `PLAYWRIGHT_CHROMIUM` names a Chromium of your own).
Examples and tests use made-up games and names.

## Licence

[MIT](LICENSE).
