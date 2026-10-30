"""The asynchronous client, over httpx (the `httpx` extra): the same calls as
LanternClient, awaited."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Iterable
from pathlib import Path
from typing import BinaryIO, TypeVar

from lantern._base import LanternError
from lantern._generated.models import (
    App,
    AppsPage,
    Changes,
    CheatSet,
    CheatSets,
    Handshake,
    HomebrewPage,
    InstalledApp,
    InstalledHomebrew,
    Package,
    Sections,
    Title,
    TitleChanges,
    Titles,
)
from lantern._generated.models import Homebrew as HomebrewEntry
from lantern.client.core import (
    ERROR_BODY,
    JSON_DOCUMENT,
    USER_AGENT,
    Call,
    ClientCore,
    chunked,
    merge_titles,
    next_cursor,
)
from lantern.client.download import Verifier
from lantern.client.transport import AsyncResponse, AsyncTransport, BearerToken, Credentials, RequestSigner
from lantern.digest import Sha256, sha256_file
from lantern.errors import DocumentError, IntegrityError
from lantern.limits import CHEAT_SET

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
        credentials: Credentials | None = None,
        signer: RequestSigner | None = None,
        transport: AsyncTransport | None = None,
        accept_language: str | None = None,
        base: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if token is not None and credentials is not None:
            raise ValueError("token or credentials, not both")
        self.core = ClientCore(
            url,
            user_agent=user_agent,
            platform=platform,
            credentials=BearerToken(token) if token is not None else credentials,
            signer=signer,
            accept_language=accept_language,
            base=base,
        )
        if transport is None:
            from lantern.client.httpx_transport import AsyncHttpxTransport

            transport = AsyncHttpxTransport()
        self.transport: AsyncTransport = transport
        self.timeout = timeout

    async def __aenter__(self) -> AsyncLanternClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.transport.close()

    def set_token(self, token: str | None) -> None:
        self.core.pipeline.credentials = BearerToken(token) if token is not None else None

    @property
    def hello(self) -> Handshake | None:
        return self.core.hello

    async def _send(self, call: Call[T]) -> T:
        if not call.well_known and self.core.base is None:
            await self.handshake()
        request = self.core.request(call)
        async with await self.transport.send(request, timeout=self.timeout) as response:
            body = await response.read(JSON_DOCUMENT) if response.status == 200 else await _error_body(response)
            return self.core.finish(call, response.status, response.headers, body)

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


def _part_size(part: Path, resume: bool) -> int:
    return part.stat().st_size if resume and part.exists() else 0


def _open(path: Path, mode: str) -> BinaryIO:
    return path.open(mode)  # type: ignore[return-value]


async def _error_body(response: AsyncResponse) -> bytes:
    try:
        return await response.read(ERROR_BODY)
    except DocumentError:
        return b""
