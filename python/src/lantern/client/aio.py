"""The asynchronous client, over httpx (the `httpx` extra): the same calls as
LanternClient, awaited."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Iterable, Sequence
from contextlib import aclosing
from pathlib import Path
from typing import BinaryIO, TypeVar
from urllib.parse import quote

from lantern import e2e
from lantern import sync as syncing
from lantern._base import LanternError
from lantern._generated.models import (
    AdminDevice,
    AdminDevices,
    AdminPairing,
    AdminPairings,
    AdminRequests,
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
from lantern.canonical import canonical
from lantern.chunks import INDEX_LIMIT, Collector, Index, Piece, Refused, Seed, UnusableIndex, read_index
from lantern.client.auth import DeviceSigner, Pairing, check_pairing_code
from lantern.client.core import (
    ERROR_BODY,
    JSON_DOCUMENT,
    RESUME_CHUNK,
    USER_AGENT,
    Call,
    ClientCore,
    UploadState,
    chunked,
    events_of,
    item_of,
    merge_titles,
    next_cursor,
    retry_signature,
    token_record,
)
from lantern.client.delta import Assembly, DeltaReport, NothingShared, check_range, range_headers
from lantern.client.download import Verifier
from lantern.client.streams import AsyncEventStream
from lantern.client.transport import (
    AsyncResponse,
    AsyncTransport,
    BearerToken,
    Credentials,
    Request,
    RequestSigner,
)
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


class AsyncLanternClient:
    """LanternClient's calls, async. `transport` defaults to
    lantern.client.httpx_transport.AsyncHttpxTransport (the `httpx` extra).

        async with AsyncLanternClient("https://shelf.example.org/", platform="switch") as client:
            async for app in client.iter_apps():
                ...
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
        transport: AsyncTransport | None = None,
        mirror_transport: AsyncTransport | None = None,
        peer_transport: AsyncTransport | None = None,
        verify: bool = True,
        pin: str | None = None,
        accept_language: str | None = None,
        base: str | None = None,
        timeout: float = 30.0,
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
        if transport is None:
            from lantern.client.httpx_transport import AsyncHttpxTransport

            transport = AsyncHttpxTransport(verify=verify, pin=pin)
        self.transport: AsyncTransport = transport
        # For download_from(): made when first needed, and closed with the client when it made them
        self._mirror_transport = mirror_transport
        self._peer_transport = peer_transport
        self._own_side_transports: list[AsyncTransport] = []
        self.timeout = timeout
        self.last_upload: str | None = None
        #: What the last download_delta() did: a differential update, or why the whole file was read.
        self.last_delta: DeltaReport | None = None
        self.last_header: bytes | None = None
        #: What the user agreed to sync with this server (SPEC.md § 20.1): no call of /v1/sync without it.
        self.sync_consent: syncing.SyncConsent | None = None

    @classmethod
    def paired(cls, record: ServerRecord, **options: object) -> AsyncLanternClient:
        """A client of a server the device paired with (LanternClient.paired())."""
        key = DeviceKey.from_b64(record.key) if record.key is not None else None
        if record.spki is not None and "transport" not in options:
            options["pin"] = record.spki
        return cls(record.url, token=record.token, key=key, **options)  # type: ignore[arg-type]

    async def __aenter__(self) -> AsyncLanternClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.transport.close()
        for side in self._own_side_transports:
            await side.close()
        self._own_side_transports.clear()

    def _side_transport(self, peer: bool) -> AsyncTransport:
        """The transport of mirrors (certificates checked) or of peers (a console's own key: nothing but a
        grant goes there, SPEC.md § 19.4), the app's or one made on first use."""
        given = self._peer_transport if peer else self._mirror_transport
        if given is not None:
            return given
        from lantern.client.httpx_transport import AsyncHttpxTransport

        made = AsyncHttpxTransport(verify=not peer)
        self._own_side_transports.append(made)
        if peer:
            self._peer_transport = made
        else:
            self._mirror_transport = made
        return made

    def set_token(self, token: str | None, key: DeviceKey | None = None) -> None:
        self.core.pipeline.credentials = BearerToken(token) if token is not None else None
        self.core.pipeline.signer = DeviceSigner(key, self.core.now) if key is not None else None

    @property
    def rating_cap(self) -> RatingCap | None:
        return self.core.hello.account.rating_cap if self.core.hello is not None else None

    @property
    def hello(self) -> Handshake | None:
        return self.core.hello

    async def _send(self, call: Call[T]) -> T:
        if not call.well_known and call.url is None and self.core.base is None:
            await self.handshake()
        for attempt in range(2):
            request = self.core.request(call)
            async with await self.transport.send(request, timeout=call.timeout or self.timeout) as response:
                self.core.last_spki = response.spki
                ok = response.status in call.statuses
                body = await response.read(JSON_DOCUMENT) if ok else await _error_body(response)
                try:
                    return self.core.finish(call, response.status, response.headers, body)
                except LanternError as e:
                    if not retry_signature(self.core, e, request, attempt):
                        raise
        raise AssertionError("unreachable")

    async def _pages(
        self, call: Call[I], items: Callable[[I], list[T]], cursor: Callable[[I], str | None]
    ) -> AsyncIterator[T]:
        seen: set[str] = set()
        while True:
            page = await self._send(call)
            for item in items(page):
                yield item
            following = next_cursor(seen, cursor(page), call.what)
            if following is None:
                return
            call = call.with_cursor(following)

    async def handshake(self) -> Handshake:
        return await self._send(self.core.handshake())

    async def offers(self, family: str) -> bool:
        if self.core.hello is None:
            await self.handshake()
        return self.core.offers(family)

    async def apps(
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
        return await self._send(
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
    ) -> AsyncIterator[App]:
        call = self.core.apps(
            platform=platform, type=type, title_id=title_id, q=q, sort=sort, page_size=page_size, cursor=None
        )
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    async def missing(
        self,
        installed: Iterable[InstalledApp | tuple[str, int]],
        want: Iterable[str] = ("update", "dlc"),
        *,
        platform: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> AppsPage:
        return await self._send(
            self.core.missing(installed, want, platform=platform, page_size=page_size, cursor=cursor)
        )

    def iter_missing(
        self,
        installed: Iterable[InstalledApp | tuple[str, int]],
        want: Iterable[str] = ("update", "dlc"),
        *,
        platform: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[App]:
        call = self.core.missing(list(installed), want, platform=platform, page_size=page_size, cursor=None)
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    async def changes(self, since: str | None = None, *, platform: str | None = None) -> Changes:
        return await self._send(self.core.changes(since, platform))

    # Events (SPEC.md § 18).

    def events(
        self,
        since: str | None = None,
        *,
        platform: str | None = None,
        reconnect: bool = True,
        sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    ) -> AsyncEventStream:
        """LanternClient.events(), as an async iterator: `async for event in client.events(): …`."""
        return AsyncEventStream(self, since, platform=platform, reconnect=reconnect, sleep=sleep)

    async def wait_changes(self, since: str, wait: int = 60, *, platform: str | None = None) -> Changes:
        if self.core.base is None:
            await self.handshake()
        return await self._send(self.core.wait_changes(since, wait, platform, self.timeout))

    async def poll_events(
        self, since: str, wait: int = 60, *, platform: str | None = None
    ) -> tuple[list[ServerEvent], str]:
        changes = await self.wait_changes(since, wait, platform=platform)
        return events_of(changes), changes.since

    # Grants (SPEC.md § 19.3).

    async def grant(self, sha256: str, size: int, *, platform: str | None = None) -> Grant:
        if self.core.hello is None:
            await self.handshake()
        found = await self._send(self.core.grant(sha256, platform))
        self.core.check_grant(found, sha256, size)
        return found

    # Sync (SPEC.md § 20), with the user's consent alone.

    async def _consent(self, collection: str | None, *, write: bool) -> syncing.SyncConsent:
        hello = self.core.hello or await self.handshake()
        return syncing.consent_for(self.sync_consent, hello.uid, collection, write=write)

    def _generation(self, consent: syncing.SyncConsent, found: str) -> None:
        if not syncing.same_generation(consent, found):
            self.sync_consent = None
            raise syncing.SyncReset(consent.generation, found)

    async def sync(self) -> Sync:
        consent = await self._consent(None, write=False)
        found = await self._send(self.core.sync_overview())
        self._generation(consent, found.generation)
        return found

    async def sync_items(
        self, collection: str, since: int | None = None, *, page_size: int | None = None
    ) -> tuple[list[syncing.Item], int]:
        consent = await self._consent(collection, write=False)
        call = self.core.sync_read(collection, since, page_size, None)
        items: list[syncing.Item] = []
        rev: int | None = None
        seen: set[str] = set()
        while True:
            page = await self._send(call)
            self._generation(consent, page.generation)
            rev = page.rev if rev is None else rev
            items += [item_of(i) for i in page.items]
            following = next_cursor(seen, page.next, "sync")
            if following is None:
                consent.revs[collection] = rev
                return items, rev
            call = call.with_cursor(following)

    async def sync_write(
        self, collection: str, items: Sequence[syncing.Item], *, if_match: bool = False
    ) -> SyncCollection:
        consent = await self._consent(collection, write=True)
        if consent.generation is None:
            await self.sync()
        assert consent.generation is not None
        tag = None
        if if_match:
            if collection not in consent.revs:
                raise ValueError("if_match needs the collection read first (sync_items())")
            tag = f'"{consent.generation}-{consent.revs[collection]}"'
        try:
            found = await self._send(self.core.sync_write(collection, consent.generation, items, tag))
        except Conflict as e:
            self.sync_consent = None
            raise syncing.SyncReset(consent.generation, "?") from e
        self._generation(consent, found.generation)
        return found

    async def delete_sync(self, collection: str | None = None) -> None:
        await self._send(self.core.sync_delete(collection))
        if self.sync_consent is not None:
            self.sync_consent.generation = None
            self.sync_consent.revs.clear()

    async def sections(self, *, platform: str | None = None) -> Sections:
        return await self._send(self.core.sections(platform))

    async def title(self, title_id: str, *, platform: str | None = None) -> Title:
        return await self._send(self.core.title(title_id, platform))

    async def titles(self, ids: Iterable[str], *, platform: str | None = None) -> Titles:
        return merge_titles([await self._send(self.core.titles(part, platform)) for part in chunked(ids)])

    async def title_changes(self, since: str | None = None, *, platform: str | None = None) -> TitleChanges:
        return await self._send(self.core.title_changes(since, platform))

    async def homebrew(
        self,
        *,
        platform: str | None = None,
        q: str | None = None,
        kind: str | None = None,
        genre: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> HomebrewPage:
        return await self._send(
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
    ) -> AsyncIterator[HomebrewEntry]:
        call = self.core.homebrew(platform=platform, q=q, kind=kind, genre=genre, page_size=page_size, cursor=None)
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    async def homebrew_entry(self, homebrew_id: str, *, platform: str | None = None) -> HomebrewEntry:
        return await self._send(self.core.homebrew_entry(homebrew_id, platform))

    async def homebrew_updates(
        self,
        installed: Iterable[InstalledHomebrew | tuple[str, int]],
        *,
        platform: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> HomebrewPage:
        return await self._send(
            self.core.homebrew_updates(installed, platform=platform, page_size=page_size, cursor=cursor)
        )

    def iter_homebrew_updates(
        self,
        installed: Iterable[InstalledHomebrew | tuple[str, int]],
        *,
        platform: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[HomebrewEntry]:
        call = self.core.homebrew_updates(list(installed), platform=platform, page_size=page_size, cursor=None)
        return self._pages(call, lambda p: p.items, lambda p: p.next)

    async def cheats(
        self, *, title_id: str | None = None, build_id: str | None = None, platform: str | None = None
    ) -> CheatSets:
        return await self._send(self.core.cheats(title_id=title_id, build_id=build_id, platform=platform))

    async def cheat_text(self, cheat: CheatSet) -> str:
        if cheat.size > CHEAT_SET:
            raise DocumentError(f"cheat set {cheat.id}: {cheat.size} bytes, above {CHEAT_SET}")
        if self.core.base is None:
            await self.handshake()
        data = await self.fetch(self.core.cheat_url(cheat.id), sha256=cheat.sha256, size=cheat.size)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DocumentError(f"cheat set {cheat.id}: not UTF-8 text") from e

    # Pairing (SPEC.md § 5.2 to § 5.5).

    async def pair(
        self,
        device: str,
        scopes: Sequence[str],
        *,
        key: DeviceKey | None | bool = True,
        invitation: str | None = None,
    ) -> Pairing:
        """LanternClient.pair(), awaited."""
        if self.core.hello is None:
            await self.handshake()
        device_key = DeviceKey.generate() if key is True else key if isinstance(key, DeviceKey) else None
        doc = await self._send(self.core.pairing(device, scopes, device_key, invitation))
        check_pairing_code(doc, self.core.root)
        spki = self.core.last_spki
        transport = self.transport
        if spki is not None and getattr(transport, "verify", True) is False and getattr(transport, "pin", 0) is None:
            transport.pin = spki  # type: ignore[attr-defined]
        poll = self.core.on_origin(doc.poll, "pairing poll")
        return Pairing(doc, device_key, spki, poll, interval=float(doc.interval))

    async def poll_pairing(self, pairing: Pairing) -> PairingToken | None:
        signer = DeviceSigner(pairing.key, self.core.now) if pairing.key is not None else None
        token = await self._send(self.core.poll(pairing.poll_url, signer))
        if token is not None:
            self.set_token(token.token, pairing.key if token.bound is not False else None)
        return token

    async def wait_for_pairing(
        self,
        pairing: Pairing,
        *,
        store: ServerStore | None = None,
        sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    ) -> ServerRecord:
        """LanternClient.wait_for_pairing(), awaited."""
        interval = pairing.interval
        while True:
            if pairing.expired:
                raise Gone(410)
            try:
                token = await self.poll_pairing(pairing)
            except SlowDown as e:
                interval = max(interval + 5, float(e.retry_after or 0))
                token = None
            if token is not None:
                await self.handshake()
                record = token_record(self.core, pairing, token)
                if store is not None:
                    store.save(record)
                return record
            await sleep(interval)

    # Saves (SPEC.md § 9).

    async def saves(self, *, title_id: str | None = None, platform: str | None = None) -> Saves:
        return await self._send(self.core.saves(title_id, platform))

    async def save(
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
        return await self._send(
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

    async def upload_save(
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
        """LanternClient.upload_save(), awaited; the file is read from a worker thread."""
        source = Path(path)
        size = (await asyncio.to_thread(source.stat)).st_size
        digest = (await asyncio.to_thread(sha256_file, source)).hexdigest()
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
            upload = await self._send(self.core.upload_open(title_id, request, platform))
            address, chunk_size, offset = upload.upload, upload.chunk_size, upload.offset
        else:
            address = resume
            state = await self._send(self.core.upload_state(resume))  # Lantern-Chunk-Size (L-9.3-3)
            offset, chunk_size = state.offset, state.chunk_size or RESUME_CHUNK
        if chunk_size < 1:
            raise UnexpectedResponse("upload: a chunk_size under 1")
        self.last_upload = address
        while True:
            chunk = await asyncio.to_thread(_read_at, source, offset, chunk_size)
            result = await self._send(self.core.upload_chunk(address, offset, chunk))
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

    async def save_encrypted(
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
        """LanternClient.save_encrypted(), awaited."""
        data = await asyncio.to_thread(e2e.encrypt, key, archive)
        return await self._send(
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

    async def upload_encrypted_save(
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
        """LanternClient.upload_encrypted_save(), awaited; the encryption runs in a worker thread."""
        source = Path(archive)
        if resume is None:
            header = e2e.make_header(key)
        elif header is None:
            raise ValueError("resuming an encrypted upload needs the header it began with (self.last_header)")
        size = e2e.encrypted_size((await asyncio.to_thread(source.stat)).st_size)
        if resume is None:
            digest = await asyncio.to_thread(_encrypted_digest, key, source, header)
            request = UploadRequest(
                schema=1,
                size=size,
                sha256=digest,
                kind=kind,
                slot=slot,
                game_version_code=game_version_code,
                profile=profile,
                note=note,
                encryption=Encryption(scheme=e2e.SCHEME, key_id=key.key_id),
            )
            upload = await self._send(self.core.upload_open(title_id, request, platform))
            address, chunk_size, offset = upload.upload, upload.chunk_size, upload.offset
        else:
            address = resume
            state = await self._send(self.core.upload_state(resume))  # Lantern-Chunk-Size (L-9.3-3)
            offset, chunk_size = state.offset, state.chunk_size or RESUME_CHUNK
        if chunk_size < 1:
            raise UnexpectedResponse("upload: a chunk_size under 1")
        self.last_upload, self.last_header = address, header
        while True:
            chunk = await asyncio.to_thread(_encrypted_at, key, source, header, offset, chunk_size)
            result = await self._send(self.core.upload_chunk(address, offset, chunk))
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

    async def download_encrypted_save(self, save: Save, key: e2e.SaveKey, dest: str | Path) -> Path:
        """LanternClient.download_encrypted_save(), awaited."""
        if save.encryption is None or save.encryption.scheme != e2e.SCHEME:
            raise e2e.RefusedBackup("not a backup encrypted with lantern-save-e2e-1")
        if save.encryption.key_id != key.key_id:
            raise e2e.RefusedBackup(f"a backup of the key {save.encryption.key_id}, not of {key.key_id}")
        target = Path(dest)
        sealed = target.with_name(target.name + ".lne")
        try:
            await self.download_save(save, sealed, resume=False)
            return await asyncio.to_thread(e2e.decrypt_file, key, sealed, target)
        finally:
            sealed.unlink(missing_ok=True)

    async def upload_offset(self, upload: str) -> tuple[int, int | None]:
        state = await self._send(self.core.upload_state(upload))
        return state.offset, state.length

    async def upload_state(self, upload: str) -> UploadState:
        """LanternClient.upload_state(), awaited."""
        return await self._send(self.core.upload_state(upload))

    async def abandon_upload(self, upload: str) -> None:
        await self._send(self.core.delete(upload, "upload"))

    async def download_save(
        self, save: Save, dest: str | Path, *, resume: bool = True, progress: Progress | None = None
    ) -> Path:
        if self.core.base is None:
            await self.handshake()
        url = self.core.v1(self.core.save_path(save.title_id, save.save_id))
        return await self.download(url, dest, sha256=save.sha256, size=save.size, resume=resume, progress=progress)

    async def delete_save(self, save: Save) -> None:
        if self.core.base is None:
            await self.handshake()
        await self._send(self.core.delete(self.core.v1(self.core.save_path(save.title_id, save.save_id)), "save"))

    # Cheats, written (SPEC.md § 10).

    async def create_cheat(
        self,
        platform: str,
        title_id: str,
        text: str,
        *,
        build_id: str | None = None,
        source: str | None = None,
        note: str | None = None,
    ) -> CheatSet:
        doc = self.core.cheat_write(platform, title_id, text, build_id=build_id, source=source, note=note)
        return await self._send(self.core.cheat_create(doc))

    async def replace_cheat(
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
        await self._send(self.core.cheat_replace(cheat_id, doc))

    async def delete_cheat(self, cheat_id: str) -> None:
        if self.core.base is None:
            await self.handshake()
        await self._send(self.core.delete(self.core.cheat_url(cheat_id), "cheat set"))

    # Requests (SPEC.md § 11).

    async def requests(self, *, platform: str | None = None) -> TitleRequests:
        return await self._send(self.core.requests(platform))

    async def request_title(self, title_id: str, *, platform: str | None = None) -> TitleRequest:
        return await self._send(self.core.request_create(title_id, platform))

    async def withdraw_request(self, request_id: str) -> None:
        if self.core.base is None:
            await self.handshake()
        await self._send(self.core.delete(self.core.v1("/requests/" + _segment(request_id)), "request"))

    # Administration (SPEC.md § 5.7, scope admin).

    async def admin_users(self, *, page_size: int | None = None, cursor: str | None = None) -> AdminUsers:
        return await self._send(self.core.admin_users(page_size, cursor))

    def iter_admin_users(self, *, page_size: int | None = None) -> AsyncIterator[AdminUser]:
        return self._pages(self.core.admin_users(page_size, None), lambda p: p.items, lambda p: p.next)

    async def create_user(self, name: str, scopes: Sequence[str], *, state: str | None = None) -> AdminUser:
        return await self._send(self.core.admin_create_user(name, scopes, state))

    async def update_user(
        self, name: str, *, state: str | None = None, scopes: Sequence[str] | None = None
    ) -> AdminUser:
        return await self._send(self.core.admin_update_user(name, state, scopes))

    async def admin_devices(
        self, *, user: str | None = None, page_size: int | None = None, cursor: str | None = None
    ) -> AdminDevices:
        return await self._send(self.core.admin_devices(user, page_size, cursor))

    def iter_admin_devices(
        self, *, user: str | None = None, page_size: int | None = None
    ) -> AsyncIterator[AdminDevice]:
        return self._pages(self.core.admin_devices(user, page_size, None), lambda p: p.items, lambda p: p.next)

    async def revoke_device(self, device_id: str) -> None:
        if self.core.base is None:
            await self.handshake()
        await self._send(self.core.delete(self.core.v1("/admin/devices/" + _segment(device_id)), "device"))

    async def admin_pairings(self, *, page_size: int | None = None, cursor: str | None = None) -> AdminPairings:
        return await self._send(self.core.admin_pairings(page_size, cursor))

    def iter_admin_pairings(self, *, page_size: int | None = None) -> AsyncIterator[AdminPairing]:
        return self._pages(self.core.admin_pairings(page_size, None), lambda p: p.items, lambda p: p.next)

    async def admin_requests(
        self,
        *,
        status: str | None = None,
        user: str | None = None,
        platform: str | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
    ) -> AdminRequests:
        """Every account's requests, newest first (SPEC.md § 11), filtered by status, user and platform."""
        return await self._send(self.core.admin_requests(status, user, platform, page_size, cursor))

    async def decline_request(self, request_id: str, reason: str | None = None) -> TitleRequest:
        """Declines an open request, with the words its requester will read (SPEC.md § 11); 409 once decided."""
        return await self._send(self.core.admin_decide_request(request_id, "decline", reason))

    async def complete_request(self, request_id: str) -> TitleRequest:
        """Marks an open request done (SPEC.md § 11); 409 once decided."""
        return await self._send(self.core.admin_decide_request(request_id, "done", None))

    async def approve_pairing(
        self,
        pairing_id: str,
        *,
        user: str | None = None,
        scopes: Sequence[str] | None = None,
        rating_cap: RatingCap | None = None,
    ) -> None:
        await self._send(self.core.admin_decide(pairing_id, "approve", user, scopes, rating_cap))

    async def delete_user(self, name: str, *, confirm: str) -> None:
        """LanternClient.delete_user(), awaited."""
        await self._send(self.core.admin_delete_user(name, confirm))

    async def refuse_pairing(self, pairing_id: str) -> None:
        await self._send(self.core.admin_decide(pairing_id, "refuse", None, None, None))

    async def admin_invitations(self, *, page_size: int | None = None, cursor: str | None = None) -> Invitations:
        return await self._send(self.core.admin_invitations(page_size, cursor))

    def iter_admin_invitations(self, *, page_size: int | None = None) -> AsyncIterator[Invitation]:
        return self._pages(self.core.admin_invitations(page_size, None), lambda p: p.items, lambda p: p.next)

    async def create_invitation(
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
            schema=1, user=user, scopes=list(scopes), expires=expires, devices=devices, rating_cap=rating_cap, note=note
        )
        return await self._send(self.core.admin_create_invitation(doc))

    async def revoke_invitation(self, invitation_id: str) -> None:
        if self.core.base is None:
            await self.handshake()
        await self._send(self.core.delete(self.core.v1("/admin/invitations/" + _segment(invitation_id)), "invitation"))

    async def fetch(self, url: str, *, sha256: str, size: int) -> bytes:
        verifier = Verifier(sha256, size, url)
        request = self.core.prepare("GET", self.core.url(url), headers={"Accept": "*/*"})
        async with await self.transport.send(request, timeout=self.timeout) as response:
            if response.status != 200:
                raise self.core.error(url, response.status, response.headers, await _error_body(response))
            verifier.start(response.status, response.headers, 0)
            hasher = Sha256()
            out = bytearray()
            async for chunk in response.iter_bytes():
                verifier.feed(hasher, chunk)
                out += chunk
        verifier.finish(hasher)
        return bytes(out)

    async def download(
        self,
        url: str,
        dest: str | Path,
        *,
        sha256: str,
        size: int,
        resume: bool = True,
        progress: Progress | None = None,
    ) -> Path:
        """LanternClient.download(), awaited; the file is written from a worker thread."""
        verifier = Verifier(sha256, size, url)
        target = Path(dest)
        part = target.with_name(target.name + ".part")
        for _ in range(3):
            offset = await asyncio.to_thread(_part_size, part, resume)
            if offset > size:
                await asyncio.to_thread(part.unlink)
                offset = 0
            hasher = await asyncio.to_thread(sha256_file, part, offset) if offset else Sha256()
            if offset == size:
                try:
                    verifier.finish(hasher)
                except IntegrityError:
                    await asyncio.to_thread(part.unlink)
                    continue
                await asyncio.to_thread(part.replace, target)
                return target
            headers = {"Accept": "*/*"} | ({"Range": f"bytes={offset}-"} if offset else {})
            request = self.core.prepare("GET", self.core.url(url), headers=headers)
            async with await self.transport.send(request, timeout=self.timeout) as response:
                if response.status == 416 and offset:
                    await asyncio.to_thread(part.unlink)
                    continue
                if response.status not in (200, 206):
                    raise self.core.error(url, response.status, response.headers, await _error_body(response))
                start = verifier.start(response.status, response.headers, offset)
                if start == 0:
                    hasher = Sha256()
                f = await asyncio.to_thread(_open, part, "ab" if start else "wb")
                try:
                    async for chunk in response.iter_bytes():
                        verifier.feed(hasher, chunk)
                        await asyncio.to_thread(f.write, chunk)
                        if progress is not None:
                            progress(hasher.size, size)
                except IntegrityError:
                    await asyncio.to_thread(f.close)
                    await asyncio.to_thread(part.unlink, missing_ok=True)
                    raise
                finally:
                    if not f.closed:
                        await asyncio.to_thread(f.close)
            try:
                verifier.finish(hasher)
            except IntegrityError:
                await asyncio.to_thread(part.unlink, missing_ok=True)
                raise
            await asyncio.to_thread(part.replace, target)
            return target
        raise LanternError(f"{url}: the download could not be resumed")

    async def _sources(
        self, file: App | Package, mirrors: bool, peers: Sequence[FoundPeer], platform: str | None
    ) -> list[tuple[str, bool, dict[str, str]]]:
        """LanternClient._sources(), awaited: (url, from a peer, headers) of the mirrors, then the peers."""
        sources: list[tuple[str, bool, dict[str, str]]] = []
        if mirrors:
            for m in (file.mirrors or [])[:8]:
                if plain_http_to(m.url):
                    sources.append((m.url, False, {}))
        chosen = [p for p in peers if self.core.hello is None or self.core.hello.uid in p.servers][:2]
        if chosen:
            if self.core.hello is None:
                await self.handshake()
            try:
                grant = await self.grant(file.sha256, file.size, platform=platform)
            except (LanternError, ValueError):
                grant = None
            if grant is not None:
                for peer in chosen:
                    url = peer.blob_url(file.sha256)
                    if plain_http_to(url):
                        sources.append((url, True, {"Lantern-Grant": grant.grant}))
        return sources

    async def download_from(
        self,
        file: App | Package,
        dest: str | Path,
        *,
        mirrors: bool = True,
        peers: Sequence[FoundPeer] = (),
        platform: str | None = None,
        progress: Progress | None = None,
    ) -> Path:
        """LanternClient.download_from(), awaited: an app's or a package's file from its mirrors and from
        peers first, then from the server (SPEC.md § 19), checked by the size and SHA-256 of the server's
        document before it is kept (L-19.1-1); a source that gives more, or bytes that fail the check, is
        left for the next (L-19.1-3). No token, signature or cookie goes to a mirror or a peer; a peer gets
        a grant, asked for once (L-19.1-2). Plain HTTP only to a private network's address (L-19.2-1,
        L-19.4-6); at most 2 peers are tried (L-19.5-2)."""
        for url, from_peer, headers in await self._sources(file, mirrors, peers, platform):
            try:
                return await self._download_source(
                    url,
                    transport=self._side_transport(from_peer),
                    headers=headers,
                    sha256=file.sha256,
                    size=file.size,
                    dest=dest,
                    progress=progress,
                )
            except (IntegrityError, TransportError, UnexpectedResponse, DocumentError, ProblemError):
                continue
        return await self.download(file.file, dest, sha256=file.sha256, size=file.size, resume=False, progress=progress)

    # Differential updates (SPEC.md § 22).

    async def chunk_index(self, file: App | Package) -> Index:
        """LanternClient.chunk_index(), awaited."""
        ref = file.chunks
        if ref is None:
            raise UnusableIndex("the document gives no chunk index for this file")
        if not 0 < ref.size <= INDEX_LIMIT:
            raise UnusableIndex(f"a chunk index of {ref.size} bytes")
        try:
            raw = await self.fetch(ref.url, sha256=ref.sha256, size=ref.size)
        except IntegrityError as e:
            raise UnusableIndex(str(e)) from None
        return read_index(raw, sha256=file.sha256, size=file.size, ref=ref)

    async def chunk_index_of(self, sha256: str, size: int, *, platform: str | None = None) -> Index:
        """LanternClient.chunk_index_of(), awaited."""
        doc = await self._send(self.core.chunk_index(sha256, platform))
        return read_index(canonical(doc), sha256=sha256, size=size)

    async def download_delta(
        self,
        file: App | Package,
        dest: str | Path,
        *,
        seeds: Sequence[Seed],
        mirrors: bool = True,
        peers: Sequence[FoundPeer] = (),
        platform: str | None = None,
        progress: Progress | None = None,
    ) -> Path:
        """LanternClient.download_delta(), awaited: an app's or a package's file put together from `seeds`
        (bytes, or the paths of files) and the ranges of the file they lack (SPEC.md § 22.3), each chunk and
        then the whole file checked before `dest` exists; the whole file is read, as download_from() does,
        when anything fails (L-22.3-4). The seeds are cut, and written pieces are read, in a worker thread."""
        report = self.last_delta = DeltaReport()
        part = Path(dest).with_name(Path(dest).name + ".part")
        if file.chunks is None or not seeds:
            report.reason = "the file has no chunk index" if file.chunks is None else "no seed"
        else:
            try:
                return await self._delta(
                    file,
                    dest,
                    part=part,
                    seeds=seeds,
                    mirrors=mirrors,
                    peers=peers,
                    platform=platform,
                    progress=progress,
                    report=report,
                )
            except (LanternError, ValueError, OSError) as e:
                await asyncio.to_thread(part.unlink, missing_ok=True)
                self.last_delta = DeltaReport(reason=f"{type(e).__name__}: {str(e)[:160]}")
        return await self.download_from(file, dest, mirrors=mirrors, peers=peers, platform=platform, progress=progress)

    async def _delta(
        self,
        file: App | Package,
        dest: str | Path,
        *,
        part: Path,
        seeds: Sequence[Seed],
        mirrors: bool,
        peers: Sequence[FoundPeer],
        platform: str | None,
        progress: Progress | None,
        report: DeltaReport,
    ) -> Path:
        index = await self.chunk_index(file)
        assembly = await asyncio.to_thread(Assembly, file, index, seeds)
        assembly.report = report
        if not assembly.shares:
            raise NothingShared("no chunk of the seeds is in the file")
        sources: list[tuple[str, bool | None, dict[str, str]]] = [
            *await self._sources(file, mirrors, peers, platform),
            (file.file, None, {}),
        ]
        f = await asyncio.to_thread(_open, part, "wb")
        try:
            for read, group in assembly.groups:
                if read:
                    await self._read_group(
                        file=file, assembly=assembly, group=group, sources=sources, out=f, progress=progress
                    )
                    continue
                for piece in group:
                    body = await asyncio.to_thread(assembly.seed, piece)
                    await asyncio.to_thread(f.write, assembly.take(piece, body))
                    if progress is not None:
                        progress(assembly.hasher.size, file.size)
        finally:
            await asyncio.to_thread(f.close)
        assembly.finish()
        await asyncio.to_thread(part.replace, dest)
        report.used = True
        return Path(dest)

    async def _read_group(
        self,
        *,
        file: App | Package,
        assembly: Assembly,
        group: list[Piece],
        sources: list[tuple[str, bool | None, dict[str, str]]],
        out: BinaryIO,
        progress: Progress | None,
    ) -> None:
        """LanternClient._read_group(), awaited."""
        done = 0
        last: LanternError | None = None
        for url, from_peer, headers in sources:
            rest = group[done:]
            collector = Collector(rest)
            start, end = rest[0].offset, rest[-1].offset + rest[-1].length - 1
            try:
                chunks = self._range(file=file, url=url, from_peer=from_peer, headers=headers, start=start, end=end)
                async with aclosing(chunks):
                    async for data in chunks:
                        for piece, body in collector.feed(data):
                            await asyncio.to_thread(out.write, assembly.take(piece, body))
                            assembly.report.read += piece.length
                            done += 1
                            if progress is not None:
                                progress(assembly.hasher.size, file.size)
                collector.finish()
                assembly.report.ranges += 1
                return
            except (IntegrityError, TransportError, UnexpectedResponse, DocumentError, ProblemError) as e:
                last = e
        raise last or UnexpectedResponse("no source for a range")

    async def _range(
        self,
        *,
        file: App | Package,
        url: str,
        from_peer: bool | None,
        headers: dict[str, str],
        start: int,
        end: int,
    ) -> AsyncGenerator[bytes]:
        """LanternClient._range(): the bytes `start` to `end` of the file at `url` as they arrive, 206 of
        exactly that range, no more (L-22.3-3). `from_peer` None: the server, with the client's credentials."""
        if from_peer is None:
            request = self.core.prepare("GET", self.core.url(url), headers=range_headers(start, end))
            transport = self.transport
        else:
            if not plain_http_to(url):
                raise InsecureTransport(f"{url}: plain HTTP only to a private network's address (SPEC.md § 19.2)")
            h = Headers({"User-Agent": self.core.user_agent, **range_headers(start, end)})
            for k, v in headers.items():
                h[k] = v
            request = Request("GET", url, h)
            transport = self._side_transport(from_peer)
        async with await transport.send(request, timeout=self.timeout) as response:
            if response.status >= 400:
                raise self.core.error(url, response.status, response.headers, await _error_body(response))
            check_range(
                response.status,
                response.headers,
                start=start,
                end=end,
                size=file.size,
                sha256=file.sha256,
                what=url,
            )
            got = 0
            async for chunk in response.iter_bytes():
                got += len(chunk)
                if got > end - start + 1:
                    raise Refused(f"{url}: more than the {end - start + 1} bytes asked for")
                yield chunk
            if got != end - start + 1:
                raise Refused(f"{url}: {got} of the {end - start + 1} bytes asked for")

    async def _download_source(
        self,
        url: str,
        *,
        transport: AsyncTransport,
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
        async with await transport.send(Request("GET", url, h), timeout=self.timeout) as response:
            if response.status != 200:
                raise self.core.error(url, response.status, response.headers, await _error_body(response))
            verifier.start(response.status, response.headers, 0)
            f = await asyncio.to_thread(_open, part, "wb")
            try:
                async for chunk in response.iter_bytes():
                    verifier.feed(hasher, chunk)
                    await asyncio.to_thread(f.write, chunk)
                    if progress is not None:
                        progress(hasher.size, size)
                await asyncio.to_thread(f.close)
                verifier.finish(hasher)
            except BaseException:
                if not f.closed:
                    await asyncio.to_thread(f.close)
                await asyncio.to_thread(part.unlink, missing_ok=True)
                raise
        await asyncio.to_thread(part.replace, target)
        return target

    async def download_app(
        self, app: App, dest: str | Path, *, resume: bool = True, progress: Progress | None = None
    ) -> Path:
        return await self.download(app.file, dest, sha256=app.sha256, size=app.size, resume=resume, progress=progress)

    async def download_package(
        self, package: Package, dest: str | Path, *, resume: bool = True, progress: Progress | None = None
    ) -> Path:
        return await self.download(
            package.file, dest, sha256=package.sha256, size=package.size, resume=resume, progress=progress
        )


def _segment(value: str) -> str:
    if not value or len(value) > 128:
        raise ValueError("an id is 1 to 128 characters")
    return quote(value, safe="")


def _read_at(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as f:
        f.seek(offset)
        return f.read(size)


def _part_size(part: Path, resume: bool) -> int:
    return part.stat().st_size if resume and part.exists() else 0


def _open(path: Path, mode: str) -> BinaryIO:
    return path.open(mode)  # type: ignore[return-value]


async def _error_body(response: AsyncResponse) -> bytes:
    try:
        return await response.read(ERROR_BODY)
    except DocumentError:
        return b""


def _encrypted_digest(key: e2e.SaveKey, source: Path, header: bytes) -> str:
    hasher = Sha256()
    for piece in e2e.iter_encrypted(key, source, header):
        hasher.update(piece)
    return hasher.hexdigest()


def _encrypted_at(key: e2e.SaveKey, source: Path, header: bytes, offset: int, size: int) -> bytes:
    chunk = bytearray()
    for piece in e2e.iter_encrypted(key, source, header, offset):
        chunk += piece
        if len(chunk) >= size:
            break
    return bytes(chunk[:size])
