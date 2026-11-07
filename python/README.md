# lantern-protocol

The Python library of the [Lantern protocol](https://github.com/JigSawFr/lantern),
the open REST/JSON protocol between console homebrews and the library
servers people run at home for their own games
([lantern.boreale.dev](https://lantern.boreale.dev/?utm_source=github&utm_medium=readme)):
a client, a toolkit to add Lantern to an existing server, the checks both
sides share, a minimal peer, the generator of static libraries, and a
malicious test server for clients. It follows the specification's **draft
0.11**.

**Status: early, complete for draft 0.11's client and server toolkit.** The client speaks every
route of the protocol: pairing with a device key, requests signed by it
(RFC 9421), the writes, LAN discovery; event streams and long polls, files
from mirrors and peers, newer versions put together from older ones by
their chunks (differential updates), sync with its user's consent, backups
encrypted on the device, and static libraries. The server toolkit offers every family
of the draft: it pairs devices, checks signed requests, serves the read
routes and sections, takes cheat sets written, keeps save backups (by
resumable upload too, and encrypted ones as sent) and requests, answers
invitations, rating caps and the administration API, events, grants and
sync, chunk indexes for differential updates, and the answers a browser's
page needs (CORS); it reaches **Lantern Core +titles +homebrew +saves
+cheats +requests +admin +events +peers +sync +encrypted_saves +deltas**,
every level of the draft,
in the specification's conformance suite, its peer passes the suite's
`--peer`, and what its generator writes, **Lantern Static**. See
[What is not there yet](#what-is-not-there-yet). Nothing is published on
PyPI before the first release.

## Installing

Python 3.11 or later. The core needs nothing but the standard library;
extras add what they say:

```sh
pip install lantern-protocol              # the core: models, checks, a stdlib client
pip install "lantern-protocol[httpx]"     # an httpx transport, and the async client
pip install "lantern-protocol[flask]"     # the Flask adapter
pip install "lantern-protocol[fastapi]"   # the FastAPI adapter
pip install "lantern-protocol[crypto]"    # ed25519 by `cryptography`, and encrypted saves (XChaCha20-Poly1305)
pip install "lantern-protocol[dnssd]"     # DNS-SD discovery and advertising (zeroconf)
```

A device that signs its requests should install `crypto`: the pure-Python
Ed25519 works everywhere but is not constant-time, which matters for a
secret key on a device someone else can time. Encrypted saves (§ 9.4) need
it: their XChaCha20-Poly1305 is the RFC 8439 ChaCha20-Poly1305 of
`cryptography` (OpenSSL's), after HChaCha20, written here (the ARX rounds of
draft-irtf-cfrg-xchacha, no table and no branch on the key) and checked
against the draft's vector and the specification's. One audited dependency
the library already offers, rather than a second binding (PyNaCl) for one
function; the key ids, phrases and QR codes need nothing but the standard
library.

The distribution is `lantern-protocol`; the package is `lantern`.

## A client

```python
import lantern
from lantern import homebrew

with lantern.LanternClient(
    "https://shelf.example.org/", platform="switch", user_agent="MyShelf/1.0", token=TOKEN
) as client:
    hello = client.handshake()  # the server, the account, the families offered
    for app in client.iter_apps(type="base"):  # every page, cursor by cursor
        print(app.name, app.version_code)

    # What the device is missing (SPEC.md § 6.3)
    for app in client.iter_missing([("0100ABCD00010000", 0)], ["update", "dlc"]):
        client.download_app(app, f"downloads/{app.app_id}.{app.format}")

    titles = client.titles(["0100ABCD00010000", "0100EFEF00020000"])  # by 100 per request

    entry = client.homebrew_entry("org.example.frostline")
    if homebrew.verify_signature(entry) is False:
        raise SystemExit("a signature that does not verify")
    plan = homebrew.install_plan(entry)  # paths free to write, and those that need consent
    package = homebrew.pick_package(entry, "aarch64")
```

- `platform` is sent as `Lantern-Platform` on every call; `platform=` on a
  call overrides it with `?platform=`.
- `token` sets `Authorization: Bearer`, sent to the server's origin only,
  never to another host a document points at.
- Plain HTTP is refused unless the server is on a loopback address
  (SPEC.md § 2).
- `download()` writes through a `.part` file, resumes it with a `Range`,
  checks `Repr-Digest` against the document's SHA-256, hashes the bytes as
  they arrive, and renames the file only when its size and SHA-256 are
  right. A file that is not raises `IntegrityError`, and its part is
  deleted.

The async client takes the same calls (the `httpx` extra):

```python
async with lantern.AsyncLanternClient("https://shelf.example.org/", platform="switch") as client:
    async for entry in client.iter_homebrew(kind="port"):
        ...
```

### Pairing, and signed requests

A device gets its token by pairing (SPEC.md § 5.2): it makes an Ed25519 key
for the server, shows a code, the server's address and the short
fingerprint of the server's key, and polls until the user approves it on
the server's side. Its token is then bound to the key, and every request is
signed by it (§ 5.4).

```python
from lantern.pinning import FileServerStore

store = FileServerStore("servers.json")  # its owner's alone; or your keychain's
client = lantern.LanternClient("https://192.0.2.10:8443/", verify=False, platform="switch")
pairing = client.pair("Lea's console", ["library", "saves"])
show(pairing.code, pairing.verify, pairing.fingerprint)  # and pairing.verify_complete as a QR code
record = client.wait_for_pairing(pairing, store=store)  # the token, its key, the pinned SPKI

# Later, from what was kept:
with lantern.LanternClient.paired(store.server(record.uid)) as client:
    client.handshake().account.bound  # True: signed with the device key
```

- `verify=False` is for a LAN server whose certificate no CA vouches for:
  the client reads its key's fingerprint (`pairing.fingerprint`) for the
  user to compare, pins it as soon as the pairing starts, and from then on
  talks only over that key (`pin=`). Another key raises `PinMismatch`
  before a byte of the request is sent: an alarm, not an error to retry
  (show both fingerprints, pair again only when the user asks).
- `pair(key=False)` asks for a bearer-only token; a server may refuse it
  (`key_required`). The private key never leaves the device: a
  `ServerStore` keeps it with the token (`FileServerStore`, or one over the
  system's keychain).
- The clock: the client takes the offset of the server's `Date` from the
  handshake when it is off by half the server's `auth.skew` or more, and
  signs again once, with the server's `Date`, after `signature_expired`;
  once, with a new nonce, after `signature_replayed`. Any other signature
  refusal (`SignatureRequired`, `SignatureInvalid`, with the server's
  `Accept-Signature` read in `e.accept_signature`) means pairing again.
- An invitation's link (§ 5.5) pairs at once, and pins the key it names:
  `LanternClient.from_invitation(link, "Ines's console", ["library"])`.
- The handshake shows the token's rating cap (§ 5.6): `client.rating_cap`.

### Writing

```python
client.save("0100ABCD00010000", archive, kind="account", profile="Lea")  # one request, Content-Digest
client.upload_save("0100ABCD00010000", "big.zip")  # resumable: chunks, HEAD, resume=
client.download_save(save, "back.zip")  # checked against its sha256
client.create_cheat("switch", "0100ABCD00010000", text, build_id="4A1B…", source="Lea")
request = client.request_title("0100FFFF00090000")
client.withdraw_request(request.id)
```

With the scope `admin`, the administration API (§ 5.7): `iter_admin_users()`,
`create_user()`, `update_user()`, `delete_user(name, confirm=…)` (the name
typed again: a slip deletes nothing; never one's own account),
`iter_admin_devices()`, `revoke_device()`, `iter_admin_pairings()` (show
each code next to the server's fingerprint), `approve_pairing(…,
rating_cap=…)`, `refuse_pairing()`, `create_invitation()`,
`revoke_invitation()`.

Each call that writes is in `AsyncLanternClient` too, awaited.

### Events

```python
for event in client.events():  # Server-Sent Events (§ 18.1); one stream per server
    if event.event == "request":
        notify(event.data)  # {"id", "platform", "title_id", "status"}; read the document itself
    keep(event.id)  # a token of /v1/changes: resume from it after a restart

found, since = client.poll_events(last_id, wait=60)  # long polling (§ 18.3), for a console that sleeps
```

The stream reads its lines within § 13's bounds (an event's data is 4 KiB
at most: a longer one raises DocumentError and closes the stream), skips
an event it does not know or of a newer schema, connects again after a cut,
after twice `limits.heartbeat` of silence or after `shutdown`, waiting the
server's `retry` at least and longer while connecting fails, and resumes
with `Last-Event-ID`. A server that no longer knows that id raises `Gone`:
read again what the app shows, and iterate again. `AsyncLanternClient`
has the same, `async for event in client.events()`.

### Mirrors and peers

```python
from lantern.discovery import PeerFinder, discover_peers

peers = PeerFinder().peers(client.hello.uid)  # discovery with "peers": true, once a minute at most
client.download_from(app, "frostline.nsz", peers=peers)  # mirrors, then peers, then the server
```

`AsyncLanternClient.download_from()` is the same, awaited. Whatever gave the
bytes, they are checked by the size and SHA-256 of the server's document
before they are kept; a source that gives more than the
size or bytes that fail is left for the next, and the server's file comes
last (§ 19.1). No token, signature or cookie goes to a mirror or a peer: a
peer gets a grant, asked for once (`client.grant()`, checked against the
handshake's `peers.key` before it leaves), and plain HTTP goes only to a
private network's address. `browse_dnssd_peers()` finds `_lantern-peer._tcp`
with the `dnssd` extra.

### Differential updates

```python
old = "downloads/frostline-1.1.0.nsz"  # what the device holds: the older version's bytes, or its path
client.download_delta(app, "downloads/frostline-1.2.0.nsz", seeds=[old], peers=peers)
print(client.last_delta)  # DeltaReport(used=True, reused=…, read=…, ranges=2, resumed=0) or why the whole file was read
index = client.chunk_index(app)  # the index `app.chunks` points at, checked; chunk_index_of(sha256, size) by hash
```

A newer file is cut into chunks by `lantern-cdc-1` (§ 22.2), and its index
(`GET <base>/v1/chunks/sha256/{hex}`, or `app.chunks.url`) lists each by its
size and SHA-256. `download_delta()` checks the index before it uses it
(its bytes against `chunks.size` and `chunks.sha256`, its schema, its
chunker, its file, its chunks: `UnusableIndex`, `lantern.chunks.read_index`),
cuts each seed the same way, takes the chunks it finds there, and reads the
others as ranges from the mirrors, the peers and then the server (§ 19),
without a credential for the first two. Each chunk is checked by its SHA-256
as it comes, the whole file by the document's before `dest` exists, never
more is written than the file's size, and never more is read of a source than
the range asked. Whatever fails (no index, a seed that changed, a source
that answers 200 to a range or sends too many or too few bytes, a chunk that
is not the one named), the whole file is read as `download_from()` does
(L-22.3-4), and `last_delta.reason` says why. A call that is killed or cut
hard (an exception the function does not catch) leaves `<dest>.part`, a
verified prefix: the next call keeps it as `<dest>.seed`, one more seed even
when you pass none, so what is there is not read again (`last_delta.resumed`
bytes); a stale or foreign part shares nothing and is harmless.
`AsyncLanternClient` has the same, awaited. The pieces are in `lantern.chunks` (the chunker, `size_for()`,
`build_index()`, `plan()`, `assemble()`; standard library only): cut at a few
megabytes a second, which is why a server cuts a file once.

A resumed upload (`upload_save(…, resume=address)`) asks HEAD for the
upload's `Lantern-Chunk-Size` and goes on in chunks of that size
(`upload_state()` gives it).

### Variants, and packages a device cannot use

```python
from lantern.variants import install_decision, prefer_variant

formats = {"nsp", "nsz"}  # the package formats this client reads
satisfies = {"fs-compression"}  # the `requires` tokens it knows and the device provides
page = client.missing(installed_ids, ["base", "update"], formats=formats, satisfies=satisfies)
for app in client.iter_apps(format="nsz"):  # an unknown format gives an empty list, never an error
    verdict, why = install_decision(app, formats, satisfies, installed=on_device)
    if verdict == "unavailable":
        print(app.name, "cannot be installed:", "; ".join(why))
best = prefer_variant(variants)  # Annex B.15: the fewest requires, then the smallest size, then the smaller id
```

An app lists the `format` it is in, the `requires` tokens a device must
provide (on the Switch `fs-compression`, `sigpatch`, `ncz-sparse`,
`ncz-lz4`), and the versions it `includes`. One game may be listed in
several variants (the same `app_id` and `version_code`). Three rules are the
client's to keep, and `lantern.variants` applies them: it MUST NOT install a
format or a `requires` token it does not know or cannot satisfy (L-6.1-3,
L-6.1-4; list it as unavailable and say why), and MUST NOT install an
update that an installed app `includes` at its version or above (L-6.1-5).
`formats` and `satisfies` of `missing()` ask the server to leave such apps
out (None sends nothing; an empty list filters everything that needs one),
but the client checks anyway. `included(app, installed)` is the L-6.1-5
test alone.

### Sync

```python
from lantern.sync import Item, SyncConsent, ms

client.sync_consent = SyncConsent(server_uid, wishes=True)  # after asking the user, per profile and server
client.sync_write(
    "wishes", [Item("switch/0100ABCD00010000", ms(now), {"platform": "switch", "title_id": "0100ABCD00010000"})]
)
items, rev = client.sync_items("wishes")  # since=rev later: the changes, deletions included
client.delete_sync()  # when the user turns sync off
```

No call of `/v1/sync` leaves without a consent for that server
(`ConsentRequired`), and `installed` needs its own, by name (§ 20.1). A
read of another `generation` than the one kept means the data was deleted
since: the client drops the consent and raises `SyncReset`, and writes
nothing back (§ 20.3). `sync_write(…, if_match=True)` writes all or nothing
against the revision last read (`PreconditionFailed`, 412, otherwise).
`lantern.sync.merge()` is § 20.4's rule, for a client's own copy.

### Encrypted saves

```python
from lantern.e2e import SaveKey

key = SaveKey.generate()  # once; kept where the system keeps keys
show_once(key.phrase())  # 14 groups of 4 symbols, to write down; key.qr() for a camera
key = SaveKey.from_phrase(typed)  # BadPhrase when its check does not match
save = client.upload_encrypted_save("0100ABCD00010000", "save.zip", key)  # resumable: last_upload, last_header
client.download_encrypted_save(save, key, "back.zip")  # RefusedBackup: nothing kept
```

`lantern-save-e2e-1` (§ 9.4): a new file key and nonce for each backup,
64 KiB chunks sealed with their index and whether they are the last, so
that a chunk cut, moved, dropped or added never opens. Only the key's id
leaves the device. A resumed upload encrypts again to the same bytes from
the archive and its header, without an encrypted copy on disk.
`save_encrypted()` sends a small one in one request.

### Static libraries

```python
from lantern.static import StaticLibrary

with StaticLibrary("https://lea.example.org/library/") as lib:  # or file:///…, or a folder
    todo = lib.missing([("0100ABCD00010000", 0)], ["update", "dlc"], platform="switch")
    lib.download(todo[0], "update.nsz")
```

A static library (§ 21) is read as files, as JSON whatever their type,
each file a document points at by a path relative to the root and checked
by its size and SHA-256; what is missing and the homebrew to update are
computed from the pages, by the server's rules.

### On the LAN

```python
from lantern.discovery import directed_broadcast, discover, browse_dnssd

for found in discover([directed_broadcast("192.168.1.20", 24)]):  # UDP 47115 (SPEC.md § 4.1)
    print(found.name, found.url)
```

A reply is a hint, never a proof: the client then reads the handshake over
TLS and pairs. DNS-SD (`_lantern._tcp`) needs an mDNS stack, which the
standard library has not: `browse_dnssd()` comes with the `dnssd` extra.

### Transports and the request pipeline

A request is built, then given its credentials and its signer (both for the
server's origin only), then sent by a transport: `StdlibTransport`
(`http.client`, the default), `HttpxTransport` or `AsyncHttpxTransport`, or
any object with the same `send()`. `LanternClient(token=…, key=…)` sets a
`BearerToken` and a `DeviceSigner`; `signer=` takes any object with
`sign(request)`. Each transport takes `verify` and `pin` (a LAN server's
key, SPEC.md § 5.3). The standard library's checks the key once the TLS
handshake is done and before it sends; httpx's, which cannot, reads the
certificate on a connection of its own, checks its key, and trusts that
certificate alone.

The client asks for compressed JSON (`Accept-Encoding: zstd, gzip` on Python
3.14, `gzip` before; § 2.1) and a response decodes it as it is read, in
`lantern.client.coding`, whichever transport brought it: a transport gives
the body as it came, httpx's included. The limits of § 13 apply to the
document once decompressed, so a body that expands without end stops at its
limit. Files and event streams are asked for as they are (`identity`). A
transport of your own gives the body undecoded.

The client records what a server deprecates (`Deprecation`, `Sunset`, §
3.4) in `client.core.deprecations` and the log `lantern`, and
`lantern.client.what_fits(apps, free)` says which apps fit in the device's
free space (`installed_size`, § 6.3).

## Examples

[`examples/`](examples/) holds files run as they are, in CI, against the demo server or from their command line (`tests/test_examples.py`): [`read_library.py`](examples/read_library.py) (handshake, apps, `missing`, a verified download), [`serve_flask.py`](examples/serve_flask.py) and [`serve_fastapi.py`](examples/serve_fastapi.py) (a server in a dozen lines), [`static_library.py`](examples/static_library.py) (written, then read).

## What both sides check

- `lantern.models`: every document of `spec/schemas/v1`, as dataclasses
  generated by `tools/generate.py`. `from_json()` keeps the fields it does
  not know (`extra`), and `to_json()` gives them back.
- `lantern.documents.read()`: the `schema` rule. A document of a newer
  `schema` is absent (`None`; the client raises `NewerSchema`), never an
  error and never written back. An unknown `kind` reads as `app`
  (`entry.effective_kind`), an unknown `assets` as `user_owned`, an unknown
  genre as `other`.
- `lantern.schema.validate(name, doc)`: the strict check against the JSON
  Schemas, without a dependency.
- `lantern.limits`: SPEC.md § 13 (document size and depth, string lengths,
  manifests, tags…), which `load_json()` keeps to.
- `lantern.digest`: streamed SHA-256, `Repr-Digest` and `Content-Digest`.
- `lantern.homebrew`: manifest paths, the canonical bytes of § 8.2 and § 8.4,
  signatures, install plans, architectures, ports' data (`launch_check()`)
  and requirements (`offer()`: offer, warn or refuse).
- `lantern.profiles`: Annex A, per platform: id forms, `version_code`,
  roots, architectures, cheat paths. Only the Switch's profile is complete.
- `lantern.pinning`: the key pinned per homebrew id (`KeyPins`), and the
  servers a client paired with (`ServerStore`), each an interface with a
  memory and a file implementation.
- `lantern.signatures`: device keys, and requests signed and checked as
  SPEC.md § 5.4 says; `lantern.spki`: a certificate's key fingerprint
  (§ 5.3); `lantern.ratings`: rating caps (§ 5.6). The specification's
  vectors (`signatures`, `ed25519-refused`, `spki`, `rating-caps`) pass byte
  for byte.
- `lantern.store`: files kept by the `schema` rule (a newer file is never
  written over; unknown keys are kept).
- `lantern.events`: the Server-Sent Events parser, bounded, and the reading
  rule of § 18.1; `lantern.grants`: grants made and checked (§ 19.3), and
  the addresses plain HTTP may reach (§ 19.2); `lantern.sync`: the merge
  rule (§ 20.4) and consent; `lantern.canonical`: canonical JSON (§ 2.3, RFC
8785: members sorted by UTF-16 code units, numbers as ECMAScript writes
them); `lantern.chunks`: differential updates (§ 22); `lantern.e2e`:
encrypted saves (§ 9.4);
  `lantern.missing`: what a device is missing, for a server and for a
  static library's reader. The vectors `encrypted-saves`, `grants`,
  `sync-merge`, `static-layout`, `canonical-json` and `chunks` pass byte
  for byte.
- Nothing is served of the platform `web` (Annex A.7): a browser installs
  nothing. `MemoryLibrary` and `LanternApp(platforms=…)` refuse it, and the
  handshake never lists it.

## Adding Lantern to a Flask app

The app implements a `Library`: its apps, titles, homebrew, cheat sets and
files (`MemoryLibrary` is one, in memory). `LanternApp` answers the routes
over it; `init_app()` mounts them.

```python
from flask import Flask
from lantern.server import Account, LanternApp, MemoryLibrary
from lantern.server.flask import init_app

library = MemoryLibrary(base="/api/lantern")
library.add_app_file(
    "games/frostline.nsp",
    platform="switch",
    title_id="0100ABCD00010000",
    app_id="0100ABCD00010000",
    type="base",
    version_code=0,
    name="Frostline Tales",
    format="nsp",
)


def authenticate(request):  # Authorization: Bearer <token>
    account = my_accounts.by_token(request.header("Authorization"))
    return Account(scopes=frozenset(account.scopes), name=account.name) if account else None


app = Flask(__name__)
init_app(app, LanternApp(library, uid=SERVER_UID, name="Living room shelf", authenticate=authenticate, secret=SECRET))
```

FastAPI is the same with `lantern.server.fastapi.include(app, lantern_app)`.

### Tokens issued by the toolkit

Rather than an `authenticate` hook over tokens of its own, a server can let
the toolkit pair devices and issue their tokens: give it an `Accounts`
store: `MemoryAccounts` for tests and demos, `SqliteAccounts` for a server
that must remember its pairings across a restart (one SQLite file, the
standard library only, readable by its owner alone, of a versioned
`schema`: a file of a newer one is not opened, nor written to), or your own
implementation of the interface over your database.

```python
from lantern.server import LanternApp, SqliteAccounts

accounts = SqliteAccounts("accounts.sqlite3")
for name, scopes in (("lea", ("library", "saves")), ("ada", ("library", "admin"))):
    if accounts.user(name) is None:
        accounts.create_user(name, scopes)
app = LanternApp(
    library,
    uid=SERVER_UID,
    name="Living room shelf",
    accounts=accounts,
    public=False,
    spki=MY_TLS_KEY_SHA256,
    secret=SECRET,
)
```

A store of your own is checked against the contract the toolkit's stores pass,
`lantern.server.contracts` (`ACCOUNTS_CONTRACT`, `REQUESTS_CONTRACT`): each
check takes a fresh, empty store and raises `AssertionError` when it behaves
otherwise.

```python
@pytest.mark.parametrize("check", ACCOUNTS_CONTRACT, ids=lambda c: c.__name__)
def test_my_accounts(check, tmp_path):
    check(MyAccounts(tmp_path / "db"))
```

It then offers `pairing` and `signatures` to every caller, and `admin` to
the accounts that hold it:

- pairing (§ 5.2): codes of the unambiguous alphabet that expire within 10
  minutes, unguessable poll addresses, `verify_complete`, limits per
  address (`429 slow_down`); a device key that is not canonical or of small
  order is refused; `bound_only=True` refuses tokens without a key
  (`key_required`);
- signed requests (§ 5.4): every request of a bound token is checked
  (components, parameters, the token's key, the window `skew`, a replay
  cache of nonces kept twice the window), then its body against its
  `Content-Digest`; a refusal carries `Accept-Signature`;
- the approval: the server's own page at `verify` (`pair_page=`, which
  signs the user in and calls `app.desk.approve()`); without it, LanternApp
  serves a page that shows the code and the server's fingerprint and
  approves nothing, and approval goes through the administration API;
- invitations (§ 5.5), redeemed at pairing and approved at once, counted
  so that devices redeeming one together never pass its `devices`; a link
  that carries the server's `spki` when no CA vouches for its key;
- rating caps (§ 5.6): what is above a token's cap is left out of every
  listing and answers `404`, as if the server had none;
- the administration API (§ 5.7): accounts, devices (never their token or
  its hash), waiting pairings, invitations; deleting an account, confirmed
  by its name, whose devices, invitations, pairings, save backups, requests
  and sync data go at once.

Draft 0.5's families, each an option of `LanternApp`:

- events (§ 18), on by default: `<base>/v1/events` (Server-Sent Events:
  `retry`, `ready`, heartbeats, `Last-Event-ID`), and long polls with
  `changes?since=&wait=`; event ids are `changes` tokens. Each caller gets
  only what it could read (scope, account, platform, rating cap); a token
  holds `event_streams` streams; a revoked token's stream ends at its next
  wake, and `app.shutdown()` sends `shutdown` to every stream. A
  MemoryLibrary tells it of its changes (`library`); a server sends its own
  with `app.emit()` or `app.library_changed()`. The Flask and FastAPI
  adapters send a stream as it comes, and free its slot once the client
  left;
- grants (§ 19.3), with `grant_seed` (the server's grant key, kept): the
  handshake's `peers`, and `<base>/v1/grants/sha256/{hex}` for the files a
  caller may read;
- sync (§ 20), with `sync=MemorySync()` (or a store of the server's own,
  `SyncStore`): collections merged by § 20.4's rule, If-Match, generations,
  deletions kept 30 days, `limits.sync_items`; a device writes its own item
  of `installed` only (`d_` and 16 hex digits, the ids MemoryAccounts
  gives).

### Differential updates, and browsers

```python
library = MemoryLibrary(base="/api/lantern", deltas=(128 << 10, 64 << 20))  # the sizes of the files it cuts
app = LanternApp(library, uid=SERVER_UID, name="Living room shelf", cors_origins=["https://app.example.org"])
```

- `deltas` (§ 22): each app and package of those sizes carries `chunks`,
  its index is cut once per SHA-256 by `lantern-cdc-1` and kept in canonical
  JSON, `GET <base>/v1/chunks/sha256/{hex}` serves its bytes to whoever may
  read the file (`404` otherwise, rating caps included), and the handshake
  offers `features.deltas`. A library of the server's own sets the family
  `"deltas"` in its `families`, `chunks` on its apps (`lantern.chunks.ref()`)
  and gives the bytes by `chunk_index(sha256)` (a `ChunkSource`). The
  static generator writes them at `v1/chunks/sha256/<hex>.json`.
- Images of the server's own origin (§ 7.1): `MemoryLibrary.add_media(FileRef, "png")` returns the name
  `<sha256>.png` of `<base>/v1/media/<name>`, which a title's `icon`, `banner` or `screenshots` gives as
  its `url` (with `sha256`). The toolkit serves it for a year, immutable, to whoever may see a title that
  shows it (a library of the server's own gives `media(name)`, a `MediaSource`).
- `cors_origins` (§ 2.5): the origins whose pages may read the server, or
  `"*"`; none by default. An allowed origin gets `Access-Control-Allow-Origin`
  (with `Vary: Origin`) and the headers a page reads on every answer, errors
  included, and its preflights (`OPTIONS` on any route of the text, without a
  token) are answered `204` with the methods and headers asked, kept ten
  minutes. `Access-Control-Allow-Credentials` is never sent and no cookie is
  ever read or set. The Flask and FastAPI adapters pass `OPTIONS` to the
  toolkit.
- An upload's `HEAD` says its `Lantern-Chunk-Size` (§ 9.3).

### Variants

```python
library.add_app_file(
    "games/frostline.nsz",
    platform="switch",
    title_id="0100ABCD00010000",
    app_id="0100ABCD00010000",
    type="base",
    version_code=0,
    name="Frostline Tales",
    format="nsz",
    requires=["fs-compression"],  # at most 8 tokens, a-z, 0-9 and -, listed once
    includes=[("0100ABCD00010800", 65536)],  # at most 16 (app_id, version_code)
)
```

The same game may be added several times as variants (the same `app_id`
and `version_code`, another `format` or `requires`): all are listed.
`GET /v1/apps?format=` keeps one format (an unknown one gives an empty list),
and `POST /v1/apps/missing` takes `formats` and `satisfies` (an array of at
most 16 words, `400` otherwise; absent is no filter, empty filters
everything), applied last. An installed app also installs what it
`includes`, so its update is not offered again (L-6.3-4). The cursors and
ETags depend on the filters. `lantern.missing.missing()` and the static
generator (`requires` and `includes` in `lantern-static.json`) follow the
same rules.

### Save backups, requests, cheat sets written, sections

```python
from lantern.server import FileSaveStore, LanternApp, MemoryRequests, SaveLimits

app = LanternApp(
    library,
    uid=SERVER_UID,
    name="Living room shelf",
    accounts=accounts,
    saves=FileSaveStore("/var/lib/shelf/saves"),  # or MemorySaveStore(), or a SaveStore of the server's own
    save_limits=SaveLimits(body=8 << 20, size=1 << 30, kept=10, chunk=1 << 20),
    requests=MemoryRequests(),  # or a RequestStore of the server's own
)
app.answer_request(request_id, "done")  # or "declined": the account's devices get the event
```

- save backups (§ 9), with `saves`, to the accounts with the scope `saves`:
  the listing, newest first per title; a save in one request, with its
  `Content-Digest` checked (`400` without, `422 digest_mismatch`), its
  `kind`, `slot`, game version, `profile` and `note` from the headers;
  resumable uploads (`POST …/uploads`, `PATCH` with `Upload-Offset`, `409`
  with the server's offset, `HEAD`, `DELETE`, the whole archive's SHA-256
  checked at the end, gone after `upload_hours`); downloads with ranges;
  deletion; the oldest dropped beyond `saves_kept_per_title`; the
  handshake's `save_body`, `save_size` and `saves_kept_per_title`. A save
  needs a platform and a title id of its form, and is a zip; the event
  `save` tells the account's devices of each one kept. `FileSaveStore`
  keeps an `index.json` with its `schema` (one of a newer schema is read
  as empty and never written over), the archives and the uploads' parts;
- encrypted backups (§ 9.4), on by default with `saves`
  (`encrypted_saves=False` refuses them with `400`): kept as sent, listed
  with their `encryption`; the server checks only that they begin with
  `LTNE2E01` and their key id, and never decrypts them;
- requests (§ 11), with `requests`, to the accounts with the scope
  `requests`: one open request per title (asked again, the same one,
  `200`), withdrawn by its account, `done` when an app of its title
  arrives in a MemoryLibrary, `done` or `declined` by `answer_request()`
  (the draft 0.5 has no route for it: the server's own pages call it), and
  the event `request` on each change; `all_requests()` lists everyone's;
- cheat sets written (§ 10), on a library that writes them (a
  `CheatWriter`, as MemoryLibrary is), to the accounts with `cheats.write`:
  `POST` (`409` for a set of the same platform, title, build and source),
  `PUT` of its text and note, `DELETE`; the platform's title id, build id
  and format (Atmosphère's and Luma3DS's codes, JSON for GoldHEN), 1 MiB at
  most. `cheat_writes=False` answers `405`;
- sections (§ 6.5), on a library that curates them (a `SectionSource`;
  `MemoryLibrary.add_section("new", "New this month", app_ids)`): each
  caller sees the apps of its platform and within its rating cap, and no
  shelf left empty.

Deleting an account erases its backups, uploads and requests with the
rest. The Flask and FastAPI adapters read bodies up to `app.body_limit`: a
save sent in one request, a chunk, a cheat set's document.

### A peer

`lantern.peer` is a paired console's sharing (§ 19.4): the files of a
folder whose size and SHA-256 are its server's apps' and packages', served
to the holders of a grant, on its own networks only, with `slots` downloads
at once and a few requests a second per address; discovery's `"peers":
true` and `_lantern-peer._tcp` (the `dnssd` extra).

```sh
python -m lantern.peer --folder /media/games --server https://shelf.example.org/ --token … --key-file device.key \
    --host 192.168.1.20 --discovery
```

### The generator of static libraries

```sh
lantern-static ./shelf --out ./site     # or python -m lantern.static; reads ./shelf/lantern-static.json
```

builds a static library (§ 21) from a folder of files and a metadata file
(its form is in `lantern/static.py`), or, in a program, from any `Library`
(`lantern.static.export(library, out, uid=…, name=…)`): the handshake with
`static`, the pages of apps, titles and homebrew per platform, each title,
entry and cheat set, every file by its SHA-256, and the chunk index of each
file the library cut (`features.deltas`). It never writes over a
`lantern.json` of a newer schema and keeps the keys it does not know of
the one it replaces; the suite's `--static` checks what it writes.

`LanternApp.handle()` needs the request's `scheme`, `target` (as sent) and
`remote` address, which the Flask and FastAPI adapters fill; behind a proxy
that ends TLS, give `scheme="https"`.

`lantern.server.discovery`: `DiscoveryResponder(app, https_port).start()`
answers LAN discovery on UDP 47115 (local networks only, a few times a
second per address); `advertise_dnssd()` advertises with DNS-SD (the
`dnssd` extra).

What `LanternApp` serves, besides what the previous section says:

- the handshake, at `/.well-known/lantern` and `<base>/v1/`, with each
  caller's features and the server's platforms;
- `library`: apps with filters, sorts and cursors, what a device is missing,
  files with `ETag`, `Repr-Digest` and ranges; `changes` with a journal;
- `titles`: one, many, and their changes;
- `homebrew`: listing (without manifests), entries, updates;
- `cheats`: sets and their text, and writing them (above);
- `sections`, `saves`, `encrypted_saves` and `requests` (above);
- problem+json for every error, `400` for a platform name that is not one,
  `422` for a request document of a newer schema, `ETag` and `304`,
  `Cache-Control` and `Vary`.

The families it does not offer (sections without a library that curates
them; saves and encrypted saves, requests and sync without their store;
pairing, signatures and admin without `accounts`; peers without a grant
key) are at 0 in the handshake, and their routes answer `404`; those that
keep an account's own data (saves, requests, sync, admin) answer `401`
without a token. JSON is compressed as `Accept-Encoding` asks
(zstd on Python 3.14, gzip before), problems say their `language`, and a
body above the adapter's limit is read and answered `413`. Each piece is usable on
its own: `json_response()`, `problem_response()`, `file_response()`,
`platform_of()`, `read_document()`, `Cursors` and `SinceTokens` (sealed with
the server's secret, nothing kept), `check_homebrew()` (what a server checks
before serving an entry), `make_package()` and `zip_manifest()`.

`authenticate(request) → Account | None` is called when a request carries
`Authorization`; `None` answers `401`. Without credentials, a caller is
anonymous: it gets `anonymous_scopes` on a `public` server, nothing on a
private one.

### TLS floor, HSTS, `uid` and immutable answers (draft 0.11)

- The client offers nothing older than TLS 1.2 on any context it builds (the standard-library and httpx
  transports, pinned and unverified contexts); a context handed to `StdlibTransport` is raised to it. A `Peer`
  given a TLS context, and the one `lantern-peer --tls-cert` builds, never negotiate below TLS 1.2 either.
- `LanternApp(..., hsts=True, hsts_max_age=31536000)` sends `Strict-Transport-Security` also when TLS ends before
  the app (a reverse proxy). Without it the header goes out when the request itself came over HTTPS, and never over
  plain HTTP. `hsts_max_age` is six months (15552000 s) or more.
- `uid` must be a random lower-case UUID of version 4 or 7 (`lantern.uid.check_uid`, `new_uid`); `LanternApp`,
  `static.export` and `Peer` raise `ValueError` on anything else, and what the toolkit generates is a version 4.
- Chunk indexes (`/v1/chunks/sha256/{hex}`) and a peer's blobs carry `Cache-Control: public|private,
  max-age=31536000, immutable` (`private` when the caller is authenticated); the ETag and 304 stay.

## Errors

A server's error answer raises the `lantern.ProblemError` of its status:
`BadRequest` (400, 405, 416), `Unauthorized` and its signature refusals
(`SignatureRequired`, `SignatureInvalid`, `SignatureExpired`,
`SignatureReplayed`), `Forbidden` and `AccountFrozen`, `NotFound`, `Conflict`, `Gone` (an expired cursor or token:
read again from the start), `TooLarge`, `Unprocessable`, `SlowDown`,
`ServerError` and `Unavailable`, and `PreconditionFailed` (412, a sync
write against a revision gone). `e.status` is always there; `e.code` is
the code when this library knows it, `None` otherwise (act on the status
alone, SPEC.md § 12); `e.detail` is bounded and without control characters;
`e.retry_after` is in seconds.

The client's own errors: `DocumentError` (a malformed document, or one
beyond § 13), `NewerSchema` (treat as absent), `IntegrityError` (a download
that is not its document's), `TransportError` and `InsecureTransport`, and
`UnexpectedResponse` (a redirect, an unexpected status or content type),
`PinMismatch` (a server's key that is not the one pinned), `ConsentRequired`
and `SyncReset` (sync, § 20), `RefusedBackup` (an encrypted backup that
does not open). All derive from `lantern.LanternError`.

## The malicious test server

`tools/hostile_server.py` serves a server that breaks one rule per
scenario, and says what a client must do: a wrong or changed TLS key,
hostile manifests (`..`, relative paths, outside the roots), a newer
`schema`, documents beyond SPEC.md § 13, a bad digest, a truncated
download, a wrong `Content-Range`, extra bytes, a forged signature of a
small-order key, signature refusals that never end, a pairing code that
points elsewhere, a redirect; and draft 0.5's: a forged or expired grant,
an event of 64 KiB, a mirror that serves other bytes, a static library of
a newer schema. `tests/test_hostile.py` proves this client
refuses each one. It is shared: any language's CI starts it from the
command line.

```sh
python tools/hostile_server.py --list                  # every scenario, and what a client must do (JSON)
python tools/hostile_server.py bad-digest --port 8099  # prints {"url", "token", "pin", "expect", …}, then serves
```

Every request it reads is logged on standard error, one JSON line each, so
that a harness checks what its client sent. The TLS scenarios need the
`cryptography` package.

## What is not there yet

- In the server toolkit: the routes it could mark deprecated
  (`Deprecation`, `Sunset`), and a store of requests on disk (a server
  gives its own `RequestStore`). Its event streams, and its locks of saves
  and requests, live in one process: a server of several processes gives
  each its own, or shares stores and a hub of its own making.
- Drawing the QR code of `verify_complete`: the client gives its text; an
  app draws it with its own toolkit (SPEC.md § 5.2 wants no image from the
  server).
- Installing: the library says what to write and where, and checks it; it
  writes nothing on a device.

## Developing

From `python/`, with the specification's submodule checked out
(`git submodule update --init`):

```sh
python -m pip install -e . --group dev
python tools/generate.py --check     # the models are those of spec/schemas/v1
ruff check . && ruff format --check .
mypy                                 # strict
python -m pytest --cov -n auto       # unit, integration and conformance tests, on every core
```

The CI installs the same environment with [uv](https://docs.astral.sh/uv/),
exactly as `uv.lock` pins it: `uv sync`, then `uv run pytest -n auto` and
the others the same way. A new dependency goes in `pyproject.toml`, then
`uv lock`.

`pytest -m integration` runs the client against the specification's
reference server (`spec/server`): over plain HTTP on loopback and over TLS
with a self-signed key, pairing, a token bound to its key, every write and
the administration API; its event stream, its peer (`spec/server/peer.py`),
sync, encrypted saves sent and read back, and its static export read from
a folder and over HTTP; and DNS-SD on loopback. `pytest -m conformance`
runs the specification's conformance suite against the demo server
(`tests/demo.py`), through Flask and FastAPI, anonymously and with a token
bound to its key, with a peer of the toolkit and LAN discovery: it reaches
Lantern Core +titles +homebrew +saves +cheats +requests +admin +events
+peers +sync +encrypted_saves +deltas, every level of the draft 0.11, the
origin of a page being allowed for the browser checks (`--origin`); and
against the static library the generator writes (`--static`): Lantern
Static. `tests/test_hostile.py` runs the client against the malicious test
server.
Examples and tests use made-up games and names.

## Licence

[MIT](LICENSE).
