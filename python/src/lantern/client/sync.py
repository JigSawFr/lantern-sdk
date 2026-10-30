"""The synchronous client: the read side of draft 0.3."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import TypeVar

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
from lantern.client.stdlib import StdlibTransport
from lantern.client.transport import BearerToken, Credentials, RequestSigner, Response, Transport
from lantern.digest import Sha256, sha256_file
from lantern.errors import DocumentError, IntegrityError
from lantern.limits import CHEAT_SET

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
    only; `credentials` and `signer` take any other step of the request
    pipeline (lantern.client.transport). `transport` defaults to the standard
    library's.

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
        credentials: Credentials | None = None,
        signer: RequestSigner | None = None,
        transport: Transport | None = None,
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
        self.transport: Transport = transport or StdlibTransport()
        self.timeout = timeout

    def __enter__(self) -> LanternClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.transport.close()

    def set_token(self, token: str | None) -> None:
        """Set or clear the bearer token of later calls."""
        self.core.pipeline.credentials = BearerToken(token) if token is not None else None

    @property
    def hello(self) -> Handshake | None:
        """The last handshake read."""
        return self.core.hello

    # Plumbing.

    def _send(self, call: Call[T]) -> T:
        if not call.well_known and self.core.base is None:
            self.handshake()
        request = self.core.request(call)
        with self.transport.send(request, timeout=self.timeout) as response:
            body = response.read(JSON_DOCUMENT) if response.status == 200 else _error_body(response)
            return self.core.finish(call, response.status, response.headers, body)

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


def _error_body(response: Response) -> bytes:
    try:
        return response.read(ERROR_BODY)
    except DocumentError:
        return b""
