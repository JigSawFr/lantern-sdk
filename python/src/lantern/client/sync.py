"""The synchronous client: every route of draft 0.5."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote

from lantern import e2e
from lantern import sync as syncing
from lantern._base import LanternError
from lantern._generated.models import (
    AdminDevice,
    AdminDevices,
    AdminPairing,
    AdminPairings,
    AdminUser,
    AdminUsers,
    App,
    AppsPage,
    Changes,
    CheatSet,
    CheatSets,
    Encryption,
    Grant,
    Handshake,
    HomebrewPage,
    InstalledApp,
    InstalledHomebrew,
    Invitation,
    InvitationCreate,
    Invitations,
    Package,
    PairingToken,
    RatingCap,
    Save,
    Saves,
    Sections,
    Sync,
    SyncCollection,
    Title,
    TitleChanges,
    TitleRequest,
    TitleRequests,
    Titles,
    UploadRequest,
)
from lantern._generated.models import Homebrew as HomebrewEntry
from lantern.client.auth import DeviceSigner, Pairing, check_pairing_code, invitation_link
from lantern.client.core import (
    ERROR_BODY,
    JSON_DOCUMENT,
    USER_AGENT,
    Call,
    ClientCore,
    chunked,
    events_of,
    item_of,
    merge_titles,
    next_cursor,
    retry_signature,
    token_record,
)
from lantern.client.download import Verifier
from lantern.client.stdlib import StdlibTransport
from lantern.client.streams import EventStream
from lantern.client.transport import BearerToken, Credentials, Request, RequestSigner, Response, Transport
from lantern.digest import Sha256, sha256_file
from lantern.discovery import FoundPeer
from lantern.errors import (
    Conflict,
    DocumentError,
    Gone,
    InsecureTransport,
    IntegrityError,
    ProblemError,
    SlowDown,
    TransportError,
    UnexpectedResponse,
)
from lantern.events import ServerEvent
from lantern.grants import plain_http_to
from lantern.http import Headers
from lantern.limits import CHEAT_SET
from lantern.pinning import ServerRecord, ServerStore
from lantern.signatures import DeviceKey

T = TypeVar("T")
I = TypeVar("I")  # noqa: E741
Progress = Callable[[int, int], None]


class LanternClient:
    """A client of one Lantern server.

        with LanternClient("https://shelf.example.org/", platform="switch",
                           user_agent="MyShelf/1.0") as client:
            hello = client.handshake()
            for app in client.iter_apps(type="base"):
                ...

    `url` is the server's address (its origin, or any URL on it); the base
    path comes from the handshake unless `base` is given. `platform` is sent
    as Lantern-Platform on every call (SPEC.md § 4.3). `token` sets
    `Authorization: Bearer` (SPEC.md § 5.1), sent to the server's origin
    only; with `key`, the device key the token is bound to, every request
    is signed (SPEC.md § 5.4). `credentials` and `signer` take any other
    step of the request pipeline (lantern.client.transport). `transport`
    defaults to the standard library's, built with `verify` and `pin` (a
    LAN server's self-signed key, SPEC.md § 5.3). `LanternClient.paired()`
    makes a client of a server the device paired with.

    Errors: a server's error answer raises the lantern.ProblemError of its
    status (NotFound, Gone…); a document of a newer schema raises NewerSchema
    (treat it as absent); a malformed one, DocumentError; a download that is
    not what its document says, IntegrityError.
    """

    def __init__(
        self,
        url: str,
        *,
        user_agent: str = USER_AGENT,
        platform: str | None = None,
        token: str | None = None,
        key: DeviceKey | None = None,
        credentials: Credentials | None = None,
        signer: RequestSigner | None = None,
        transport: Transport | None = None,
        verify: bool = True,
        pin: str | None = None,
        accept_language: str | None = None,
        base: str | None = None,
        timeout: float = 30.0,
        mirror_transport: Transport | None = None,
        peer_transport: Transport | None = None,
    ) -> None:
        if token is not None and credentials is not None:
            raise ValueError("token or credentials, not both")
        if key is not None and signer is not None:
            raise ValueError("key or signer, not both")
        if transport is not None and (pin is not None or not verify):
            raise ValueError("verify and pin set the default transport: set them on the transport given")
        self.core = ClientCore(
            url,
            user_agent=user_agent,
            platform=platform,
            credentials=BearerToken(token) if token is not None else credentials,
            signer=signer,
            accept_language=accept_language,
            base=base,
        )
        if key is not None:
            self.core.pipeline.signer = DeviceSigner(key, self.core.now)
        self.transport: Transport = transport or StdlibTransport(verify=verify, pin=pin)
        self.timeout = timeout
        #: The address of the last upload left unfinished, to resume (upload_save(resume=…)).
        self.last_upload: str | None = None
        #: The header of the last encrypted upload left unfinished, to resume it to the same bytes.
        self.last_header: bytes | None = None
        #: What the user agreed to sync with this server (SPEC.md § 20.1): no call of /v1/sync without it.
        self.sync_consent: syncing.SyncConsent | None = None
        #: The transports of mirrors (CAs checked) and peers (whose certificate nobody pins, SPEC.md § 19.4):
        #: never the server's, which carry its pin, and never a credential.
        self.mirror_transport: Transport = mirror_transport or StdlibTransport()
        self.peer_transport: Transport = peer_transport or StdlibTransport(verify=False)

    @classmethod
    def paired(cls, record: ServerRecord, **options: object) -> LanternClient:
        """A client of a server the device paired with: its token, signed with its device key when bound,
        over its pinned key when no CA vouches for it (SPEC.md § 5.3, § 5.4)."""
        key = DeviceKey.from_b64(record.key) if record.key is not None else None
        if record.spki is not None and "transport" not in options:
            options["pin"] = record.spki
        return cls(record.url, token=record.token, key=key, **options)  # type: ignore[arg-type]

    def __enter__(self) -> LanternClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.transport.close()
        self.mirror_transport.close()
        self.peer_transport.close()

    def set_token(self, token: str | None, key: DeviceKey | None = None) -> None:
        """Set or clear the token of later calls, and the device key it is bound to."""
        self.core.pipeline.credentials = BearerToken(token) if token is not None else None
        self.core.pipeline.signer = DeviceSigner(key, self.core.now) if key is not None else None

    @property
    def rating_cap(self) -> RatingCap | None:
        """The rating cap the token carries, as the last handshake showed it (SPEC.md § 5.6)."""
        return self.core.hello.account.rating_cap if self.core.hello is not None else None

    @property
    def hello(self) -> Handshake | None:
        """The last handshake read."""
        return self.core.hello

    # Plumbing.

    def _send(self, call: Call[T]) -> T:
        if not call.well_known and call.url is None and self.core.base is None:
            self.handshake()
        for attempt in range(2):
            request = self.core.request(call)
            with self.transport.send(request, timeout=call.timeout or self.timeout) as response:
                self.core.last_spki = response.spki
                ok = response.status in call.statuses
                body = response.read(JSON_DOCUMENT) if ok else _error_body(response)
                try:
                    return self.core.finish(call, response.status, response.headers, body)
                except LanternError as e:
                    if not retry_signature(self.core, e, request, attempt):
                        raise
        raise AssertionError("unreachable")

    def _pages(self, call: Call[I], items: Callable[[I], list[T]], cursor: Callable[[I], str | None]) -> Iterator[T]:
        seen: set[str] = set()
        while True:
            page = self._send(call)
            yield from items(page)
            following = next_cursor(seen, cursor(page), call.what)
            if following is None:
                return
            call = call.with_cursor(following)

    # The handshake (SPEC.md § 4.2).

    def handshake(self) -> Handshake:
        """GET /.well-known/lantern: the server, the caller's account and what it is offered."""
        return self._send(self.core.handshake())

    def offers(self, family: str) -> bool:
        """Whether the server offers `family` (`library`, `homebrew`…) to this caller, in a schema this
        library reads (the handshake is read first if it was not)."""
        if self.core.hello is None:
            self.handshake()
        return self.core.offers(family)

    # Library (SPEC.md § 6).

    def apps(
        self,
        *,
        platform: str | None = None,
        type: str | None = None,
        title_id: str | None = None,
        q: str | None = None,
        sort: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> AppsPage:
        """One page of apps; `next` is the cursor of the following page."""
        return self._send(
            self.core.apps(
                platform=platform, type=type, title_id=title_id, q=q, sort=sort, page_size=page_size, cursor=cursor
            )
        )

    def iter_apps(
        self,
        *,
        platform: str | None = None,
        type: str | None = None,
        title_id: str | None = None,
        q: str | None = None,
        sort: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[App]:
        """Every app, page by page. An expired cursor raises Gone: read the list again from its start."""
        call = self.core.apps(
            platform=platform, type=type, title_id=title_id, q=q, sort=sort, page_size=page_size, cursor=None
        )
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    def missing(
        self,
        installed: Iterable[InstalledApp | tuple[str, int]],
        want: Iterable[str] = ("update", "dlc"),
        *,
        platform: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> AppsPage:
        """What the device is missing (SPEC.md § 6.3): `installed` as (app_id, version_code)."""
        return self._send(self.core.missing(installed, want, platform=platform, page_size=page_size, cursor=cursor))

    def iter_missing(
        self,
        installed: Iterable[InstalledApp | tuple[str, int]],
        want: Iterable[str] = ("update", "dlc"),
        *,
        platform: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[App]:
        call = self.core.missing(list(installed), want, platform=platform, page_size=page_size, cursor=None)
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    def changes(self, since: str | None = None, *, platform: str | None = None) -> Changes:
        """The apps added and removed since a token (none, and the current token, without one).
        A token too old raises Gone: read the whole library again."""
        return self._send(self.core.changes(since, platform))

    def sections(self, *, platform: str | None = None) -> Sections:
        return self._send(self.core.sections(platform))

    # Events (SPEC.md § 18).

    def events(
        self,
        since: str | None = None,
        *,
        platform: str | None = None,
        reconnect: bool = True,
        sleep: Callable[[float], None] = time.sleep,
    ) -> EventStream:
        """The server's event stream (SPEC.md § 18.1), from `since` (an event id or a changes token: what
        was missed in between comes first), or from now. It connects again by itself after a cut, waiting
        the server's `retry` (lantern.client.streams); hold one per server at most (L-18.4-3)."""
        return EventStream(self, since, platform=platform, reconnect=reconnect, sleep=sleep)

    def wait_changes(self, since: str, wait: int = 60, *, platform: str | None = None) -> Changes:
        """A long poll (SPEC.md § 18.3): answered as soon as an event comes after `since`, or after `wait`
        seconds (lowered to the server's `limits.wait`); its `events` and its new `since`."""
        if self.core.base is None:
            self.handshake()
        return self._send(self.core.wait_changes(since, wait, platform, self.timeout))

    def poll_events(self, since: str, wait: int = 60, *, platform: str | None = None) -> tuple[list[ServerEvent], str]:
        """The events of a long poll, read by the rules of SPEC.md § 18.1 (one of a type this library does
        not know, or of a newer schema, is skipped), and the token to ask again with, at once."""
        changes = self.wait_changes(since, wait, platform=platform)
        return events_of(changes), changes.since

    # Grants, mirrors and peers (SPEC.md § 19).

    def grant(self, sha256: str, size: int, *, platform: str | None = None) -> Grant:
        """A grant for a file of the library (scope `library`), checked: of that file, verifying by the
        handshake's `peers.key`, not expired (IntegrityError otherwise). It goes to a peer, alone."""
        if self.core.hello is None:
            self.handshake()
        found = self._send(self.core.grant(sha256, platform))
        self.core.check_grant(found, sha256, size)
        return found

    def download_from(
        self,
        file: App | Package,
        dest: str | Path,
        *,
        mirrors: bool = True,
        peers: Sequence[FoundPeer] = (),
        platform: str | None = None,
        progress: Progress | None = None,
    ) -> Path:
        """An app's or a package's file, from its mirrors and from peers first, then from the server
        (SPEC.md § 19): whatever gave the bytes, they are checked by the size and SHA-256 of the server's
        document before they are kept (L-19.1-1), and a source that gave more than the size, or bytes
        that fail the check, is left for the next (L-19.1-3). No token, signature or cookie goes to a
        mirror or a peer; a peer gets a grant, asked for once (L-19.1-2). Plain HTTP only to a private
        network's address (L-19.2-1, L-19.4-6); at most 2 peers are tried (L-19.5-2)."""
        sources: list[tuple[str, Transport, dict[str, str]]] = []
        if mirrors:
            for m in (file.mirrors or [])[:8]:
                if plain_http_to(m.url):
                    sources.append((m.url, self.mirror_transport, {}))
        chosen = [p for p in peers if self.core.hello is None or self.core.hello.uid in p.servers][:2]
        if chosen:
            if self.core.hello is None:
                self.handshake()
            try:
                grant = self.grant(file.sha256, file.size, platform=platform)
            except (LanternError, ValueError):
                grant = None
            if grant is not None:
                for peer in chosen:
                    url = peer.blob_url(file.sha256)
                    if plain_http_to(url):
                        sources.append((url, self.peer_transport, {"Lantern-Grant": grant.grant}))
        for url, transport, headers in sources:
            try:
                return self._download_source(
                    url,
                    transport=transport,
                    headers=headers,
                    sha256=file.sha256,
                    size=file.size,
                    dest=dest,
                    progress=progress,
                )
            except (IntegrityError, TransportError, UnexpectedResponse, DocumentError, ProblemError):
                continue
        return self.download(file.file, dest, sha256=file.sha256, size=file.size, resume=False, progress=progress)

    def _download_source(
        self,
        url: str,
        *,
        transport: Transport,
        headers: dict[str, str],
        sha256: str,
        size: int,
        dest: str | Path,
        progress: Progress | None,
    ) -> Path:
        """One mirror's or peer's file: a bare request (no credential, no signature), checked as it arrives,
        kept only once whole and right."""
        if not plain_http_to(url):
            raise InsecureTransport(f"{url}: plain HTTP only to a private network's address (SPEC.md § 19.2)")
        verifier = Verifier(sha256, size, url)
        h = Headers({"User-Agent": self.core.user_agent, "Accept": "*/*", "Accept-Encoding": "identity"})
        for k, v in headers.items():
            h[k] = v
        target = Path(dest)
        part = target.with_name(target.name + ".part")
        hasher = Sha256()
        with transport.send(Request("GET", url, h), timeout=self.timeout) as response:
            if response.status != 200:
                raise self.core.error(url, response.status, response.headers, _error_body(response))
            verifier.start(response.status, response.headers, 0)
            try:
                with part.open("wb") as f:
                    for chunk in response.iter_bytes():
                        verifier.feed(hasher, chunk)
                        f.write(chunk)
                        if progress is not None:
                            progress(hasher.size, size)
                verifier.finish(hasher)
            except BaseException:
                part.unlink(missing_ok=True)
                raise
        part.replace(target)
        return target

    # Sync (SPEC.md § 20), with the user's consent alone.

    def _consent(self, collection: str | None, *, write: bool) -> syncing.SyncConsent:
        """The consent a sync call needs (L-20.1-1, L-20.1-2): ConsentRequired, before anything is sent."""
        hello = self.core.hello or self.handshake()
        return syncing.consent_for(self.sync_consent, hello.uid, collection, write=write)

    def _generation(self, consent: syncing.SyncConsent, found: str) -> None:
        """Another generation than the one kept: the data was deleted since; consent and copy are dropped,
        and nothing is written back (L-20.3-2)."""
        if not syncing.same_generation(consent, found):
            self.sync_consent = None
            raise syncing.SyncReset(consent.generation, found)

    def sync(self) -> Sync:
        """GET /v1/sync: the generation, each collection's revision, and this device's id."""
        consent = self._consent(None, write=False)
        found = self._send(self.core.sync_overview())
        self._generation(consent, found.generation)
        return found

    def sync_items(
        self, collection: str, since: int | None = None, *, page_size: int | None = None
    ) -> tuple[list[syncing.Item], int]:
        """The items of a collection (every live one, or every change after the revision `since`, deletions
        included), page by page; and the collection's revision when its first page was read. Gone when the
        server keeps no deletions that far back: read the collection whole."""
        consent = self._consent(collection, write=False)
        call = self.core.sync_read(collection, since, page_size, None)
        items: list[syncing.Item] = []
        rev: int | None = None
        seen: set[str] = set()
        while True:
            page = self._send(call)
            self._generation(consent, page.generation)
            rev = page.rev if rev is None else rev
            items += [item_of(i) for i in page.items]
            following = next_cursor(seen, page.next, "sync")
            if following is None:
                consent.revs[collection] = rev
                return items, rev
            call = call.with_cursor(following)

    def sync_write(self, collection: str, items: Sequence[syncing.Item], *, if_match: bool = False) -> SyncCollection:
        """PATCH items (SPEC.md § 20.4), each merged by the server as § 20.4's rule says; the answer gives
        each as the server then keeps it. `if_match` makes the write all or nothing against the revision
        last read (PreconditionFailed when the collection changed since: read it again). `installed` needs
        the user's consent by name; a device writes its own item there only."""
        consent = self._consent(collection, write=True)
        if consent.generation is None:
            self.sync()
        assert consent.generation is not None
        tag = None
        if if_match:
            if collection not in consent.revs:
                raise ValueError("if_match needs the collection read first (sync_items())")
            tag = f'"{consent.generation}-{consent.revs[collection]}"'
        try:
            found = self._send(self.core.sync_write(collection, consent.generation, items, tag))
        except Conflict as e:
            self.sync_consent = None  # another generation: the data was deleted since (L-20.3-2)
            raise syncing.SyncReset(consent.generation, "?") from e
        self._generation(consent, found.generation)
        return found

    def delete_sync(self, collection: str | None = None) -> None:
        """Erases what the server keeps of a collection, or of every one (SPEC.md § 20.5), at the user's
        word: when they turn sync off, it is offered whatever the consent (L-20.1-3). The consent's
        generation is dropped: the next read gives a new one."""
        self._send(self.core.sync_delete(collection))
        if self.sync_consent is not None:
            self.sync_consent.generation = None
            self.sync_consent.revs.clear()

    # Encrypted saves (SPEC.md § 9.4).

    def save_encrypted(
        self,
        title_id: str,
        archive: bytes,
        key: e2e.SaveKey,
        *,
        kind: str | None = None,
        slot: str | None = None,
        game_version_code: int | None = None,
        profile: str | None = None,
        note: str | None = None,
        platform: str | None = None,
    ) -> Save:
        """A backup encrypted on the device, in one request: its bytes and Content-Digest the encrypted
        ones, its key id in Lantern-Save-Encryption. `profile` and `note` stay in clear: leave them out
        unless the user wants them shown (L-9.4-6). The key never leaves the device (L-9.4-2)."""
        data = e2e.encrypt(key, archive)
        return self._send(
            self.core.save_post(
                title_id,
                data,
                kind=kind,
                slot=slot,
                game_version_code=game_version_code,
                profile=profile,
                note=note,
                platform=platform,
                key_id=key.key_id,
            )
        )

    def upload_encrypted_save(
        self,
        title_id: str,
        archive: str | Path,
        key: e2e.SaveKey,
        *,
        kind: str | None = None,
        slot: str | None = None,
        game_version_code: int | None = None,
        profile: str | None = None,
        note: str | None = None,
        platform: str | None = None,
        resume: str | None = None,
        header: bytes | None = None,
        progress: Progress | None = None,
    ) -> Save:
        """A backup of any size, encrypted on the device and sent by resumable upload (SPEC.md § 9.3,
        § 9.4), without an encrypted copy on disk: the encrypted bytes are made again from the archive and
        their header for each chunk. A new file key and nonce for each backup (L-9.4-3); to resume, give
        `resume` (self.last_upload) and `header` (self.last_header), which encrypt again to the same
        bytes."""
        source = Path(archive)
        if resume is None:
            header = e2e.make_header(key)
        elif header is None:
            raise ValueError("resuming an encrypted upload needs the header it began with (self.last_header)")
        size = e2e.encrypted_size(source.stat().st_size)
        if resume is None:
            hasher = Sha256()
            for piece in e2e.iter_encrypted(key, source, header):
                hasher.update(piece)
            request = UploadRequest(
                schema=1,
                size=size,
                sha256=hasher.hexdigest(),
                kind=kind,
                slot=slot,
                game_version_code=game_version_code,
                profile=profile,
                note=note,
                encryption=Encryption(scheme=e2e.SCHEME, key_id=key.key_id),
            )
            upload = self._send(self.core.upload_open(title_id, request, platform))
            address, chunk_size, offset = upload.upload, upload.chunk_size, upload.offset
        else:
            address, chunk_size = resume, 1 << 20
            offset, _ = self._send(self.core.upload_state(resume))
        if chunk_size < 1:
            raise UnexpectedResponse("upload: a chunk_size under 1")
        self.last_upload, self.last_header = address, header
        while True:
            chunk = bytearray()
            for piece in e2e.iter_encrypted(key, source, header, offset):
                chunk += piece
                if len(chunk) >= chunk_size:
                    break
            result = self._send(self.core.upload_chunk(address, offset, bytes(chunk[:chunk_size])))
            if isinstance(result, Save):
                self.last_upload = self.last_header = None
                if progress is not None:
                    progress(size, size)
                return result
            if not offset < result <= size:
                raise UnexpectedResponse(f"upload: the server's offset {result}, after {offset} of {size}")
            offset = result
            if progress is not None:
                progress(offset, size)

    def download_encrypted_save(self, save: Save, key: e2e.SaveKey, dest: str | Path) -> Path:
        """A backup encrypted on the device: its bytes checked against its sha256, then decrypted into
        `dest` only when every chunk opens (RefusedBackup otherwise, and nothing is kept, L-9.4-1)."""
        if save.encryption is None or save.encryption.scheme != e2e.SCHEME:
            raise e2e.RefusedBackup("not a backup encrypted with lantern-save-e2e-1")
        if save.encryption.key_id != key.key_id:
            raise e2e.RefusedBackup(f"a backup of the key {save.encryption.key_id}, not of {key.key_id}")
        target = Path(dest)
        sealed = target.with_name(target.name + ".lne")
        try:
            self.download_save(save, sealed, resume=False)
            return e2e.decrypt_file(key, sealed, target)
        finally:
            sealed.unlink(missing_ok=True)

    # Titles (SPEC.md § 7).

    def title(self, title_id: str, *, platform: str | None = None) -> Title:
        return self._send(self.core.title(title_id, platform))

    def titles(self, ids: Iterable[str], *, platform: str | None = None) -> Titles:
        """Many titles at once: asked for by 100 at most per request, and put together."""
        return merge_titles([self._send(self.core.titles(part, platform)) for part in chunked(ids)])

    def title_changes(self, since: str | None = None, *, platform: str | None = None) -> TitleChanges:
        return self._send(self.core.title_changes(since, platform))

    def iter_title_changes(self, since: str | None = None, *, platform: str | None = None) -> Iterator[TitleChanges]:
        """Title changes until `more` is false; the last one's `since` is the next token."""
        while True:
            changes = self.title_changes(since, platform=platform)
            yield changes
            if not changes.more or changes.since == since:
                return
            since = changes.since

    # Homebrew (SPEC.md § 8).

    def homebrew(
        self,
        *,
        platform: str | None = None,
        q: str | None = None,
        kind: str | None = None,
        genre: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> HomebrewPage:
        """One page of entries, without their manifests (read an entry for them)."""
        return self._send(
            self.core.homebrew(platform=platform, q=q, kind=kind, genre=genre, page_size=page_size, cursor=cursor)
        )

    def iter_homebrew(
        self,
        *,
        platform: str | None = None,
        q: str | None = None,
        kind: str | None = None,
        genre: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[HomebrewEntry]:
        call = self.core.homebrew(platform=platform, q=q, kind=kind, genre=genre, page_size=page_size, cursor=None)
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    def homebrew_entry(self, homebrew_id: str, *, platform: str | None = None) -> HomebrewEntry:
        """An entry, with its manifests."""
        return self._send(self.core.homebrew_entry(homebrew_id, platform))

    def homebrew_updates(
        self,
        installed: Iterable[InstalledHomebrew | tuple[str, int]],
        *,
        platform: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> HomebrewPage:
        """The entries newer than what is installed: `installed` as (id, build)."""
        return self._send(self.core.homebrew_updates(installed, platform=platform, page_size=page_size, cursor=cursor))

    def iter_homebrew_updates(
        self,
        installed: Iterable[InstalledHomebrew | tuple[str, int]],
        *,
        platform: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[HomebrewEntry]:
        call = self.core.homebrew_updates(list(installed), platform=platform, page_size=page_size, cursor=None)
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    # Cheats (SPEC.md § 10).

    def cheats(
        self, *, title_id: str | None = None, build_id: str | None = None, platform: str | None = None
    ) -> CheatSets:
        return self._send(self.core.cheats(title_id=title_id, build_id=build_id, platform=platform))

    def cheat_text(self, cheat: CheatSet) -> str:
        """A set's text, checked against its size and SHA-256 (1 MiB at most)."""
        if cheat.size > CHEAT_SET:
            raise DocumentError(f"cheat set {cheat.id}: {cheat.size} bytes, above {CHEAT_SET}")
        if self.core.base is None:
            self.handshake()
        data = self.fetch(self.core.cheat_url(cheat.id), sha256=cheat.sha256, size=cheat.size)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DocumentError(f"cheat set {cheat.id}: not UTF-8 text") from e

    # Pairing (SPEC.md § 5.2 to § 5.5).

    def pair(
        self,
        device: str,
        scopes: Sequence[str],
        *,
        key: DeviceKey | None | bool = True,
        invitation: str | None = None,
    ) -> Pairing:
        """Asks to pair: makes a device key (`key=True`, a new one; a DeviceKey
        given; or False for a bearer-only token), sends it with the device's
        name, the scopes asked for and an invitation's code when there is one,
        and gives what the device shows. The key of the server's connection is
        pinned from then on when no CA vouched for it."""
        if self.core.hello is None:
            self.handshake()
        device_key = DeviceKey.generate() if key is True else key if isinstance(key, DeviceKey) else None
        doc = self._send(self.core.pairing(device, scopes, device_key, invitation))
        check_pairing_code(doc, self.core.root)
        spki = self.core.last_spki
        self._pin_seen(spki)
        poll = self.core.on_origin(doc.poll, "pairing poll")
        return Pairing(doc, device_key, spki, poll, interval=float(doc.interval))

    def _pin_seen(self, spki: str | None) -> None:
        """A key seen without a CA to vouch for it is the one polls and calls go over from then on (L-5.3-4)."""
        transport = self.transport
        if spki is not None and getattr(transport, "verify", True) is False and getattr(transport, "pin", 0) is None:
            transport.pin = spki  # type: ignore[attr-defined]

    def poll_pairing(self, pairing: Pairing) -> PairingToken | None:
        """One poll: the token's document once approved (then the client uses it), None while waiting.
        Gone when refused, expired or already collected."""
        signer = DeviceSigner(pairing.key, self.core.now) if pairing.key is not None else None
        token = self._send(self.core.poll(pairing.poll_url, signer))
        if token is not None:
            self.set_token(token.token, pairing.key if token.bound is not False else None)
        return token

    def wait_for_pairing(
        self,
        pairing: Pairing,
        *,
        store: ServerStore | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> ServerRecord:
        """Polls every `interval` until the user approves (or refuses: Gone), within the code's life; then
        keeps the server in `store` and gives its record. A 429 slows the polls down (RFC 8628 § 3.5)."""
        interval = pairing.interval
        while True:
            if pairing.expired:
                raise Gone(410)
            try:
                token = self.poll_pairing(pairing)
            except SlowDown as e:
                interval = max(interval + 5, float(e.retry_after or 0))
                token = None
            if token is not None:
                self.handshake()
                record = token_record(self.core, pairing, token)
                if store is not None:
                    store.save(record)
                return record
            sleep(interval)

    @classmethod
    def from_invitation(
        cls, link: str, device: str, scopes: Sequence[str], *, store: ServerStore | None = None, **options: object
    ) -> tuple[LanternClient, ServerRecord]:
        """Redeems an invitation's link (SPEC.md § 5.5): the key it names is pinned without asking the user,
        and the pairing is approved at once."""
        found = invitation_link(link)
        if found.spki is not None and "transport" not in options:
            options["pin"] = found.spki
        client = cls(found.url, **options)  # type: ignore[arg-type]
        pairing = client.pair(device, scopes, invitation=found.code)
        return client, client.wait_for_pairing(pairing, store=store, sleep=lambda s: time.sleep(min(s, 1.0)))

    # Saves (SPEC.md § 9).

    def saves(self, *, title_id: str | None = None, platform: str | None = None) -> Saves:
        """The account's backups, newest first per title."""
        return self._send(self.core.saves(title_id, platform))

    def save(
        self,
        title_id: str,
        data: bytes,
        *,
        kind: str | None = None,
        slot: str | None = None,
        game_version_code: int | None = None,
        profile: str | None = None,
        note: str | None = None,
        platform: str | None = None,
    ) -> Save:
        """A save of at most limits.save_body bytes, in one request with its Content-Digest (SPEC.md § 9.2)."""
        return self._send(
            self.core.save_post(
                title_id,
                data,
                kind=kind,
                slot=slot,
                game_version_code=game_version_code,
                profile=profile,
                note=note,
                platform=platform,
            )
        )

    def upload_save(
        self,
        title_id: str,
        path: str | Path,
        *,
        kind: str | None = None,
        slot: str | None = None,
        game_version_code: int | None = None,
        profile: str | None = None,
        note: str | None = None,
        platform: str | None = None,
        resume: str | None = None,
        progress: Progress | None = None,
    ) -> Save:
        """A save of any size, by resumable upload (SPEC.md § 9.3): opened, then sent in chunks of the
        server's `chunk_size`, each with its Content-Digest; `resume` is the address of an upload opened
        before, which goes on from where HEAD says. A lost connection raises TransportError: call again
        with the same `resume` (`self.last_upload`)."""
        source = Path(path)
        size = source.stat().st_size
        digest = sha256_file(source).hexdigest()
        if resume is None:
            request = UploadRequest(
                schema=1,
                size=size,
                sha256=digest,
                kind=kind,
                slot=slot,
                game_version_code=game_version_code,
                profile=profile,
                note=note,
            )
            upload = self._send(self.core.upload_open(title_id, request, platform))
            address, chunk_size, offset = upload.upload, upload.chunk_size, upload.offset
        else:
            address, chunk_size = resume, 1 << 20
            offset, _ = self._send(self.core.upload_state(resume))
        if chunk_size < 1:
            raise UnexpectedResponse("upload: a chunk_size under 1")
        self.last_upload = address
        with source.open("rb") as f:
            while True:
                f.seek(offset)
                chunk = f.read(chunk_size)
                result = self._send(self.core.upload_chunk(address, offset, chunk))
                if isinstance(result, Save):
                    self.last_upload = None
                    if progress is not None:
                        progress(size, size)
                    return result
                if not offset < result <= size:
                    raise UnexpectedResponse(f"upload: the server's offset {result}, after {offset} of {size}")
                offset = result
                if progress is not None:
                    progress(offset, size)

    def upload_offset(self, upload: str) -> tuple[int, int | None]:
        """Where an upload stands: its Upload-Offset and Upload-Length (HEAD)."""
        return self._send(self.core.upload_state(upload))

    def abandon_upload(self, upload: str) -> None:
        self._send(self.core.delete(upload, "upload"))

    def download_save(
        self, save: Save, dest: str | Path, *, resume: bool = True, progress: Progress | None = None
    ) -> Path:
        """A backup's archive, checked against its sha256."""
        if self.core.base is None:
            self.handshake()
        url = self.core.v1(self.core.save_path(save.title_id, save.save_id))
        return self.download(url, dest, sha256=save.sha256, size=save.size, resume=resume, progress=progress)

    def delete_save(self, save: Save) -> None:
        if self.core.base is None:
            self.handshake()
        self._send(self.core.delete(self.core.v1(self.core.save_path(save.title_id, save.save_id)), "save"))

    # Cheats, written (SPEC.md § 10).

    def create_cheat(
        self,
        platform: str,
        title_id: str,
        text: str,
        *,
        build_id: str | None = None,
        source: str | None = None,
        note: str | None = None,
    ) -> CheatSet:
        """A new set (scope cheats.write): 201 and the set; Conflict when the same one exists (replace it)."""
        doc = self.core.cheat_write(platform, title_id, text, build_id=build_id, source=source, note=note)
        return self._send(self.core.cheat_create(doc))

    def replace_cheat(
        self,
        cheat_id: str,
        platform: str,
        title_id: str,
        text: str,
        *,
        build_id: str | None = None,
        source: str | None = None,
        note: str | None = None,
    ) -> None:
        doc = self.core.cheat_write(platform, title_id, text, build_id=build_id, source=source, note=note)
        self._send(self.core.cheat_replace(cheat_id, doc))

    def delete_cheat(self, cheat_id: str) -> None:
        if self.core.base is None:
            self.handshake()
        self._send(self.core.delete(self.core.cheat_url(cheat_id), "cheat set"))

    # Requests (SPEC.md § 11).

    def requests(self, *, platform: str | None = None) -> TitleRequests:
        return self._send(self.core.requests(platform))

    def request_title(self, title_id: str, *, platform: str | None = None) -> TitleRequest:
        """Asks for a title: the new request, or the open one for the same title."""
        return self._send(self.core.request_create(title_id, platform))

    def withdraw_request(self, request_id: str) -> None:
        if self.core.base is None:
            self.handshake()
        self._send(self.core.delete(self.core.v1("/requests/" + _segment(request_id)), "request"))

    # Administration (SPEC.md § 5.7, scope admin).

    def admin_users(self, *, page_size: int | None = None, cursor: str | None = None) -> AdminUsers:
        return self._send(self.core.admin_users(page_size, cursor))

    def iter_admin_users(self, *, page_size: int | None = None) -> Iterator[AdminUser]:
        return self._pages(self.core.admin_users(page_size, None), lambda p: p.items, lambda p: p.next)

    def create_user(self, name: str, scopes: Sequence[str], *, state: str | None = None) -> AdminUser:
        return self._send(self.core.admin_create_user(name, scopes, state))

    def update_user(self, name: str, *, state: str | None = None, scopes: Sequence[str] | None = None) -> AdminUser:
        return self._send(self.core.admin_update_user(name, state, scopes))

    def admin_devices(
        self, *, user: str | None = None, page_size: int | None = None, cursor: str | None = None
    ) -> AdminDevices:
        return self._send(self.core.admin_devices(user, page_size, cursor))

    def iter_admin_devices(self, *, user: str | None = None, page_size: int | None = None) -> Iterator[AdminDevice]:
        return self._pages(self.core.admin_devices(user, page_size, None), lambda p: p.items, lambda p: p.next)

    def revoke_device(self, device_id: str) -> None:
        if self.core.base is None:
            self.handshake()
        self._send(self.core.delete(self.core.v1("/admin/devices/" + _segment(device_id)), "device"))

    def admin_pairings(self, *, page_size: int | None = None, cursor: str | None = None) -> AdminPairings:
        """The pairings waiting: show each one's code next to the short fingerprint of the server's key as this
        app pinned it (SPEC.md § 5.7, L-5.7-5)."""
        return self._send(self.core.admin_pairings(page_size, cursor))

    def iter_admin_pairings(self, *, page_size: int | None = None) -> Iterator[AdminPairing]:
        return self._pages(self.core.admin_pairings(page_size, None), lambda p: p.items, lambda p: p.next)

    def approve_pairing(
        self,
        pairing_id: str,
        *,
        user: str | None = None,
        scopes: Sequence[str] | None = None,
        rating_cap: RatingCap | None = None,
    ) -> None:
        self._send(self.core.admin_decide(pairing_id, "approve", user, scopes, rating_cap))

    def delete_user(self, name: str, *, confirm: str) -> None:
        """Deletes an account, at once and whole (SPEC.md § 5.7): its devices, invitations, pairings waiting,
        backups, requests and sync data. `confirm` is the name as the admin typed it again: a slip of the
        finger deletes nothing (400); one's own account cannot be (409). It cannot be undone."""
        self._send(self.core.admin_delete_user(name, confirm))

    def refuse_pairing(self, pairing_id: str) -> None:
        self._send(self.core.admin_decide(pairing_id, "refuse", None, None, None))

    def admin_invitations(self, *, page_size: int | None = None, cursor: str | None = None) -> Invitations:
        return self._send(self.core.admin_invitations(page_size, cursor))

    def iter_admin_invitations(self, *, page_size: int | None = None) -> Iterator[Invitation]:
        return self._pages(self.core.admin_invitations(page_size, None), lambda p: p.items, lambda p: p.next)

    def create_invitation(
        self,
        user: str,
        scopes: Sequence[str],
        *,
        expires: str,
        devices: int = 1,
        rating_cap: RatingCap | None = None,
        note: str | None = None,
    ) -> Invitation:
        doc = InvitationCreate(
            schema=1,
            user=user,
            scopes=list(scopes),
            expires=expires,
            devices=devices,
            rating_cap=rating_cap,
            note=note,
        )
        return self._send(self.core.admin_create_invitation(doc))

    def revoke_invitation(self, invitation_id: str) -> None:
        if self.core.base is None:
            self.handshake()
        self._send(self.core.delete(self.core.v1("/admin/invitations/" + _segment(invitation_id)), "invitation"))

    # Files (SPEC.md § 6.6).

    def fetch(self, url: str, *, sha256: str, size: int) -> bytes:
        """A small file, whole in memory, checked against its SHA-256 and size."""
        verifier = Verifier(sha256, size, url)
        request = self.core.prepare("GET", self.core.url(url), headers={"Accept": "*/*"})
        with self.transport.send(request, timeout=self.timeout) as response:
            if response.status != 200:
                raise self.core.error(url, response.status, response.headers, _error_body(response))
            verifier.start(response.status, response.headers, 0)
            hasher = Sha256()
            out = bytearray()
            for chunk in response.iter_bytes():
                verifier.feed(hasher, chunk)
                out += chunk
        verifier.finish(hasher)
        return bytes(out)

    def download(
        self,
        url: str,
        dest: str | Path,
        *,
        sha256: str,
        size: int,
        resume: bool = True,
        progress: Progress | None = None,
    ) -> Path:
        """Download a file to `dest`, through `dest` + ".part": resumed with a
        Range from what that file already holds, hashed as it arrives, and
        renamed to `dest` only once its size and SHA-256 are right. A file
        that is not raises IntegrityError, and its part is deleted; a cut
        connection raises TransportError and keeps the part for the next try."""
        verifier = Verifier(sha256, size, url)
        target = Path(dest)
        part = target.with_name(target.name + ".part")
        for _ in range(3):
            offset = part.stat().st_size if resume and part.exists() else 0
            if offset > size:
                part.unlink()
                offset = 0
            hasher = sha256_file(part, offset) if offset else Sha256()
            if offset == size:
                try:
                    verifier.finish(hasher)
                except IntegrityError:
                    part.unlink()
                    continue
                part.replace(target)
                return target
            headers = {"Accept": "*/*"} | ({"Range": f"bytes={offset}-"} if offset else {})
            request = self.core.prepare("GET", self.core.url(url), headers=headers)
            with self.transport.send(request, timeout=self.timeout) as response:
                if response.status == 416 and offset:
                    part.unlink()
                    continue
                if response.status not in (200, 206):
                    raise self.core.error(url, response.status, response.headers, _error_body(response))
                start = verifier.start(response.status, response.headers, offset)
                if start == 0:
                    hasher = Sha256()
                try:
                    with part.open("ab" if start else "wb") as f:
                        for chunk in response.iter_bytes():
                            verifier.feed(hasher, chunk)
                            f.write(chunk)
                            if progress is not None:
                                progress(hasher.size, size)
                except IntegrityError:
                    part.unlink(missing_ok=True)
                    raise
            try:
                verifier.finish(hasher)
            except IntegrityError:
                part.unlink(missing_ok=True)
                raise
            part.replace(target)
            return target
        raise LanternError(f"{url}: the download could not be resumed")

    def download_app(
        self, app: App, dest: str | Path, *, resume: bool = True, progress: Progress | None = None
    ) -> Path:
        """An app's file, checked against its sha256 (SPEC.md § 6.1, § 6.6)."""
        return self.download(app.file, dest, sha256=app.sha256, size=app.size, resume=resume, progress=progress)

    def download_package(
        self, package: Package, dest: str | Path, *, resume: bool = True, progress: Progress | None = None
    ) -> Path:
        """A homebrew package, checked against its sha256 (SPEC.md § 8.2)."""
        return self.download(
            package.file, dest, sha256=package.sha256, size=package.size, resume=resume, progress=progress
        )


def _segment(value: str) -> str:
    if not value or len(value) > 128:
        raise ValueError("an id is 1 to 128 characters")
    return quote(value, safe="")


def _error_body(response: Response) -> bytes:
    try:
        return response.read(ERROR_BODY)
    except DocumentError:
        return b""
