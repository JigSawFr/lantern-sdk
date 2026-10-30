"""The asynchronous client, over httpx (the `httpx` extra): the same calls as
LanternClient, awaited."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from pathlib import Path
from typing import BinaryIO, TypeVar
from urllib.parse import quote

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
    Title,
    TitleChanges,
    TitleRequest,
    TitleRequests,
    Titles,
    UploadRequest,
)
from lantern._generated.models import Homebrew as HomebrewEntry
from lantern.client.auth import DeviceSigner, Pairing, check_pairing_code
from lantern.client.core import (
    ERROR_BODY,
    JSON_DOCUMENT,
    USER_AGENT,
    Call,
    ClientCore,
    chunked,
    merge_titles,
    next_cursor,
    retry_signature,
    token_record,
)
from lantern.client.download import Verifier
from lantern.client.transport import AsyncResponse, AsyncTransport, BearerToken, Credentials, RequestSigner
from lantern.digest import Sha256, sha256_file
from lantern.errors import DocumentError, Gone, IntegrityError, SlowDown, UnexpectedResponse
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
        self.timeout = timeout
        self.last_upload: str | None = None

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
            async with await self.transport.send(request, timeout=self.timeout) as response:
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
            address, chunk_size = resume, 1 << 20
            offset, _ = await self._send(self.core.upload_state(resume))
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

    async def upload_offset(self, upload: str) -> tuple[int, int | None]:
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

    async def approve_pairing(
        self,
        pairing_id: str,
        *,
        user: str | None = None,
        scopes: Sequence[str] | None = None,
        rating_cap: RatingCap | None = None,
    ) -> None:
        await self._send(self.core.admin_decide(pairing_id, "approve", user, scopes, rating_cap))

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
