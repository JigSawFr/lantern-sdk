# lantern-protocol (TypeScript)

The TypeScript library of the [Lantern protocol](https://github.com/JigSawFr/lantern),
the open REST/JSON protocol between console homebrews and the library
servers people run at home for their own games
([lantern.boreale.dev](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme)):
a client for the browser and Node, a toolkit to add Lantern to a Node
server, and the checks both sides share. It follows the specification's
**draft 0.5**, as the [Python library](../python/README.md) does, whose
scope and names it mirrors.

**Status: early, complete for draft 0.5's client.** The client speaks every
route of the protocol: pairing with a device key, requests signed by it
(RFC 9421), the writes, LAN discovery (Node), events (a stream over fetch
and long polls), grants, mirrors and peers, sync, end-to-end encrypted
saves and static libraries. The server toolkit pairs devices, checks signed
requests, and serves the read routes, invitations, rating caps, the
administration API (deleting accounts included), events, grants and sync,
with a peer server and a static library generator beside it; it reaches
**Lantern Core +titles +homebrew +cheats +admin +events +peers +sync** in
the specification's conformance suite, through `node:http` and through web
Requests, and its static libraries reach **Lantern Static**. See
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
| `lantern-protocol/node` | Node | `NodeLanternClient` (the server's key pinned), files (downloads through a `.part`, uploads, stores), LAN discovery of servers and peers, static libraries in a folder and their generator, encrypted saves decrypted to a file |
| `lantern-protocol/server` | Node (and any runtime of web Requests, for `fetchHandler`) | `LanternApp` and its pieces, `PeerServer` |

And one command, `lantern-static` (the package's `bin`), which writes a
server's library as a static library (below).

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
`createInvitation()`, `revokeInvitation()`, and `deleteUser(name, confirm)`,
whose `confirm` is the name as the user typed it again (§ 5.7: at once and
whole, its devices, invitations, backups, requests and sync data with it).

### Events

```ts
const stream = await client.events({ since: kept.lastId }); // Last-Event-ID, when the app kept one
for await (const e of stream) {
  if (e.event === "request") notify(e.data); // ready, library, request, pairing, save, sync, shutdown
  kept.lastId = stream.lastId;
}
const later = await client.poll(kept.lastId, 60); // long polling: the changes, and the events after it
```

- A browser's `EventSource` cannot send `Authorization` nor a signature
  (§ 5.4): the stream is read over the client's transport (`fetch()`'s
  streaming body in a browser), by a bounded Server-Sent Events reader: a
  line beyond 5 KiB, or an event's data beyond § 13's 4 KiB, throws
  `DocumentError` as soon as the bound is passed, without holding the rest.
- The stream is opened again as it ends or fails: after the server's `retry`
  at least, with `Last-Event-ID`, backing off with full jitter while
  connecting fails (Annex B.2: five failures in a row end it), and when
  nothing came for twice `limits.heartbeat` (the transport's timeout).
  `shutdown` waits its `retry`; `stream.close()` ends it.
- An event of a type or a schema this library does not read is left out
  (§ 18.1); `Gone` means the id is too old: read the library again, then
  open a stream without `since`.

### Mirrors, grants and peers

```ts
const grant = await client.grant(app.sha256); // verified by the handshake's peers.key, or IntegrityError
const peers = await discoverPeers([directedBroadcast("192.168.1.20", 24)], { server: hello.uid }); // Node
await client.downloadAppTo(app, "frostline.nsp", { peers, mirrors: true, onSource: (s) => console.log(s) });
```

- A file comes from peers holding it (with a grant, two at most), then the
  app's mirrors, then the server: whatever a source serves is checked by
  the file's size and SHA-256 before anything is kept, a source that gives
  more bytes than the size is stopped, and one that fails is passed by
  (§ 19.1). Mirrors and peers get no token, no signature, no cookie; they
  are reached over a transport of their own (`elsewhere`), never the
  server's pinned one.
- A mirror is read over HTTPS, or plain HTTP at an address of a private
  network (or loopback, for testing); a grant goes over plain HTTP to a
  private network only (§ 19.2, § 19.4).
- A grant is checked before it goes to any peer: the file's, this server's
  `uid`, not expired by the client's clock (corrected by the server's
  `Date`), signed by `peers.key`, Ed25519's strict checks first
  (`peers.verifyGrant()`).

### Sync

```ts
// The app asks its user first ("Keep your wishes on Living room shelf?"), then:
client.setSyncConsent({ ...sync.syncOff(hello.uid, "Lea"), consent: ["wishes"] });
await client.syncPull("wishes"); // since the revision last read; the whole collection the first time
await client.syncPush("wishes", [sync.item("switch/0100ABCD00010000", { platform: "switch", title_id: "0100ABCD00010000" }, Date.now())]);
keep(client.syncState); // the app keeps it, per console profile and per server
```

- Nothing of `<base>/v1/sync` is read or written before the app set a
  consent, nor a collection the user did not agree to by name:
  `ConsentRequired` (§ 20.1). `installed` needs its own consent.
- A generation other than the one kept (the user deleted their data) drops
  the state's revisions, turns sync off and throws `GenerationChanged`
  (§ 20.3); so does a write answered `409`.
- `syncPush(…, { whole: true })` sends `If-Match` (a write made from the
  whole collection): `PreconditionFailed` (412) when it changed since.
  `sync.merge()` is § 20.4's rule as a server applies it (the vectors pass);
  `syncErase()` deletes what the server keeps.
- A sync state is a document of its own `schema`: `sync.readSyncState()`
  reads one by the `schema` rule.

### End-to-end encrypted saves

```ts
const key = SaveKey.generate(); // once, on the user's first device; keep it where the system keeps keys
show(key.phrase()); // 14 groups of 4 symbols, only when the user asks; key.qr() for a QR code
const backup = await EncryptedBackup.create(key, bytesSource(zip)); // or await fileSource("save.zip") in Node
try {
  await client.uploadEncryptedSave("0100ABCD00010000", backup); // resumable: chunks encrypted again as read
} finally {
  backup.wipe();
}
const archive = await e2e.decryptBytes(SaveKey.fromPhrase(typed), await client.fetchSave(save));
```

- Scheme `lantern-save-e2e-1` (§ 9.4), byte for byte against
  `vectors/encrypted-saves.json`: the key id and the wrapping key by
  HKDF-SHA-256 (WebCrypto's), the file key wrapped and the archive sealed in
  chunks of 64 KiB by XChaCha20-Poly1305. WebCrypto has no ChaCha20: the
  library carries ChaCha20, HChaCha20 and Poly1305 in TypeScript (RFC 8439,
  draft-irtf-cfrg-xchacha-03), tested against those texts' vectors and
  against `node:crypto`.
- `e2e.encrypt()` and `e2e.decrypt()` stream; a backup that does not open,
  is cut, extended or reordered throws `DecryptionError`, and the last
  chunk is known only at the end: restore only once the iteration ended
  (`decryptBytes()` in memory, `decryptSaveFile()` through a `.part` in
  Node). A new file key and wrap nonce for every backup; `EncryptedBackup`
  gives a resumed upload the same bytes again, without keeping them.
- A phrase or a QR text whose check does not match throws
  `KeyPhraseError` (case, spaces and dashes ignored).
- **Wiping.** The keys this library makes (the wrapping key, file keys,
  ChaCha20's subkeys and states, each plaintext chunk once sealed) live in
  typed arrays it zeroes once done; `SaveKey.wipe()` zeroes the save key.
  JavaScript promises no more: the engine may have copied a buffer while it
  moved it, WebCrypto keeps its own copy of the key HKDF imports until it
  is collected, a string (a phrase, a QR text) cannot be wiped, and nothing
  keeps memory from the swap.

### Static libraries

```ts
const lib = await StaticLibrary.open("https://lea.example.org/library/"); // or new FileStaticSource(folder) in Node
for await (const app of lib.apps("switch")) console.log(app.name);
const missing = await lib.missing("switch", [["0100ABCD00010000", 0]]); // § 6.3's rules, client-side
await lib.downloadApp(missing[0], sink); // checked by its size and SHA-256
```

- Documents are read as JSON whatever their `Content-Type`, by the
  `schema` rule; pages are chained as § 21.1 says; a path not below the
  root (a scheme, a leading `/`, `..`, `\`, a query) is refused, and a
  folder is never read outside itself (no link out).
- Over HTTP, § 2 holds: HTTPS, plain HTTP on loopback only.

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
  caps (§ 5.6); `peers`: grants and mirrors (§ 19); `sync`: the merge rule
  (§ 20.4); `e2e` and `chacha`: encrypted saves (§ 9.4); `staticLibrary`:
  the layout (§ 21.1). The specification's vectors (`signatures`,
  `ed25519-refused`, `spki`, `rating-caps`, `paths`, `homebrew-signatures`,
  `version-codes`, `requires`, `encrypted-saves`, `grants`, `sync-merge`,
  `static-layout`) pass byte for byte.
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
  asks (zstd, gzip); `Date` on every response;
- deleting an account (§ 5.7): `?confirm=` repeating its name, never the
  caller's own, its devices, invitations and sync data with it, at once
  (`Accounts.deleteUser`; a store without it answers 409);
- events (§ 18, on by default; `events: false` turns them off): a stream of
  Server-Sent Events, never compressed, `retry` then `ready`, every event
  after `Last-Event-ID` or `?since=` (400 for an id never given, 410 for
  one too old), a heartbeat every `limits.heartbeat` seconds,
  `limits.event_streams` per token (429 beyond), the stream of a token
  revoked or of an account frozen or deleted ended at once; long polls
  (`changes?since=&wait=`). Each caller gets what its token may read: of
  its scopes, account, platform and rating cap. LanternApp writes
  `pairing`, `sync` and (from a Library with `subscribe()`, as
  MemoryLibrary) `library`; `app.emit()` writes the server's own
  (`request`, `save`), and `app.shutdown()` sends `shutdown`;
- grants (§ 19.3, with `peers: { seed }`): the server's own Ed25519 key,
  `peers.key` in the handshake, a grant for a file the caller may read,
  404 otherwise;
- sync (§ 20, with `sync: true` or a `SyncStore` of the server's own):
  `wishes` and `installed`, § 20.4's merge item by item, an `updated` too
  far ahead taken as the server's time, `If-Match` (412), another
  generation (409), another device's `installed` (403), items of another
  form (400), `limits.sync_items` (413), deletions kept 30 days, `DELETE`
  giving a new generation; `MemorySyncStore` keeps it in memory.

The families it does not offer (sections, saves, encrypted saves,
requests) are at 0 in the handshake, and their routes answer `404`. Each piece is usable on its own:
`jsonResponse()`, `problemResponse()`, `fileResponse()`, `platformOf()`,
`readDocument()`, `Cursors` and `SinceTokens` (sealed with the server's
secret, nothing kept), `checkHomebrew()`, `makePackage()`, `zipManifest()`.
`DiscoveryResponder.start(app, { httpsPort })` answers LAN discovery on UDP
47115 (local networks only, a few times a second per address).

`PeerServer` is a console's sharing (§ 19.4): one route, a file served by
its SHA-256 to the holder of a grant that verifies by its server's
`peers.key`, to its own networks only, `slots` downloads at once and a few
requests a second per address (429 beyond), problem+json without
`WWW-Authenticate`; `peerFiles()` finds which of a folder's files are its
server's, and `discovery()` answers the datagrams that ask for peers.

### Static libraries, written

```sh
lantern-static --from https://shelf.example.org/ --out ./library --token "$TOKEN" --key device.key
python3 spec/conformance/run.py --static ./library    # Lantern Static
```

It reads the server as a client does (what the token may read is what is
written), checks every file by its SHA-256, and writes `lantern.json` and
`v1/` as § 21.1 lays them out, replacing those of an earlier export and
nothing else; the handshake last, so that a reader never sees it before its
pages. In code: `writeStatic(await libraryInput(library, { uid, name }), out)`
from a toolkit Library, or `clientInput(client)`. An image is kept only
when it is external or below the root.

## Errors

A server's error answer throws the `ProblemError` of its status:
`BadRequest` (400, 405, 416), `Unauthorized` and its signature refusals
(`SignatureRequired`, `SignatureInvalid`, `SignatureExpired`,
`SignatureReplayed`), `Forbidden` and `AccountFrozen`, `NotFound`,
`Conflict`, `Gone` (an expired cursor or token: read again from the start),
`PreconditionFailed` (a sync write's `If-Match`), `TooLarge`,
`Unprocessable`, `SlowDown`, `ServerError` and `Unavailable`.
`e.status` is always there; `e.code` is the code when this library knows it,
`undefined` otherwise (act on the status alone, SPEC.md § 12); `e.detail` is
bounded and without control characters; `e.retryAfter` is in seconds.

The client's own: `DocumentError` (a malformed document, or one beyond
§ 13), `NewerSchema` (treat as absent), `IntegrityError` (a download that is
not its document's), `TransportError`, `InsecureTransport` and
`PinMismatch`, `UnexpectedResponse` (a redirect, an unexpected status or
content type), `Unsupported` (what this platform cannot do),
`DecryptionError` and `KeyPhraseError` (encrypted saves), `ConsentRequired`
and `GenerationChanged` (sync). All derive from `LanternError`.

## What is not there yet

- In the server toolkit: sections, saves (and so `encrypted_saves`), cheat
  writes and requests (their families are at 0), DNS-SD, and the routes it
  could mark deprecated. `app.emit()` is there for a server that serves
  requests or saves itself.
- `PeerServer` over TLS (it speaks plain HTTP on a private network, as
  § 19.4 allows), and DNS-SD of peers (`_lantern-peer._tcp`).
- DNS-SD on the client: Node has no mDNS stack, and a browser no UDP.
- Pinning in a browser: impossible (above).
- Drawing the QR code of `verifyComplete` or of a save key: the client gives
  their text.
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
(`python/tools/hostile_server.py`, every scenario its `--list` gives, from
its command line; `cryptography` for its TLS ones; `LANTERN_HOSTILE` names
another checkout's script), against the specification's reference server
(`test/fixtures/reference.py`: plain HTTP, and TLS with a pinned self-signed
key; `--v05` adds draft 0.5: events, sync, encrypted saves, the reference
peer `spec/server/peer.py`, its static export), and the conformance suite
against the demo server (`test/demo.ts`, through `node:http` and
`fetchHandler`, with a PeerServer, and `lantern-static`'s output through
`--static`; the suite's `spec/tools/requirements.txt`, and Python 3.14 to
read the zstd the demo sends). `npm run test:browser` builds `dist/` and
runs it in Chromium (Playwright; `PLAYWRIGHT_CHROMIUM` names a Chromium of
your own): reading, pairing, signing, an event stream and decryption.
Examples and tests use made-up games and names.

## Licence

[MIT](LICENSE).
