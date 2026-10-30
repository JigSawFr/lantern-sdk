"""What a server's app implements for the toolkit's routes: a `Library`
(its apps, titles, homebrew, cheat sets and files), optionally a `Journal`
of its changes, and an `authenticate` hook. `MemoryLibrary` is a complete
one, held in memory: a reference to read, and the base of tests and demos.

The toolkit checks nothing it is given is served wrong: MemoryLibrary
refuses an app, title, homebrew or cheat set that breaks the schemas or
SPEC.md § 8 (paths, roots, manifests, signatures, ports, requirements).
"""

from __future__ import annotations

import io
import secrets
import threading
import zipfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from lantern import homebrew as hb
from lantern import schema
from lantern._generated.models import (
    App,
    CheatSet,
    Homebrew,
    ManifestEntry,
    Mirror,
    Package,
    RatingCap,
    RemovedTitle,
    Title,
)
from lantern.digest import sha256_hex
from lantern.grants import MIRRORS_LIMIT, mirror_ok
from lantern.limits import CHEAT_SET
from lantern.profiles import profile
from lantern.server.events import LibraryChange
from lantern.server.files import FileRef
from lantern.server.http import ServerRequest

#: The families a Library may offer, beyond `changes` (which needs a Journal).
LIBRARY_FAMILIES = ("library", "titles", "homebrew", "cheats")


@dataclass(frozen=True)
class Account:
    """The caller, as `authenticate` (or the server's Accounts) resolves it:
    its state (`active` or `frozen`), its scopes (SPEC.md § 4.2) and the name
    the handshake shows; `key`, the device key its token is bound to (32
    bytes: LanternApp then checks the request's signature, SPEC.md § 5.4);
    `rating_cap`, the cap its token carries (§ 5.6); `device`, its device's
    id (§ 5.7)."""

    scopes: frozenset[str] = frozenset()
    state: str = "active"
    name: str | None = None
    key: bytes | None = None
    rating_cap: RatingCap | None = None
    device: str | None = None

    @property
    def bound(self) -> bool:
        return self.key is not None


#: Resolves a request's credentials (its Authorization) to an account, or None
#: when they are not valid ones. LanternApp checks the signature of a request
#: whose account has a `key`.
Authenticate = Callable[[ServerRequest], Account | None]


class Journal(Protocol):
    """A library's change journal, for /v1/changes and /v1/titles/changes
    (SPEC.md § 6.4, § 7.3). Positions grow with each change; `epoch` changes
    when the journal starts over (a token of another epoch is too old)."""

    @property
    def epoch(self) -> str: ...

    def position(self) -> int: ...

    def oldest(self) -> int:
        """The oldest position the journal still answers from."""
        ...

    def app_changes(self, after: int, platform: str | None) -> tuple[list[App], list[str]]:
        """The apps added since `after` and still there, and the ids of those removed."""
        ...

    def title_changes(
        self, after: int, platform: str | None, languages: Sequence[str]
    ) -> tuple[list[Title], list[RemovedTitle]]: ...


class Library(Protocol):
    """What a server serves. Every method is called per request: return what
    is there now (a database query, a scan kept in memory…)."""

    #: The families offered, among library, titles, homebrew and cheats.
    families: frozenset[str]

    def apps(self) -> Iterable[App]: ...

    def titles(self, languages: Sequence[str]) -> Iterable[Title]:
        """Every title, its texts in the best of `languages` it has."""
        ...

    def homebrew(self, languages: Sequence[str]) -> Iterable[Homebrew]:
        """Every entry, with its manifests (the toolkit leaves them out of listings)."""
        ...

    def cheats(self) -> Iterable[CheatSet]: ...

    def file(self, file_id: str) -> FileRef | None:
        """The file of <base>/v1/files/{file_id}: an app's or a homebrew package's."""
        ...

    def cheat_file(self, cheat_id: str) -> FileRef | None:
        """A cheat set's text."""
        ...

    def journal(self) -> Journal | None:
        """The change journal, or None: then the family `changes` is not offered, and
        /v1/titles/changes answers 410 to any token."""
        ...


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def zip_manifest(data: bytes) -> list[ManifestEntry]:
    """An archive's manifest (SPEC.md § 8.2): each of its files at "/" + its name."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return [
            ManifestEntry(path="/" + i.filename, size=i.file_size, sha256=sha256_hex(z.read(i)))
            for i in z.infolist()
            if not i.is_dir()
        ]


def check_homebrew(entry: Homebrew) -> list[str]:
    """Every reason a server must not serve `entry`: its schema, its
    manifests (paths, digest, the profile's roots), its signatures, its port's
    data and its requirements' shapes."""
    problems = [f"schema: {p}" for p in schema.definition("homebrew", entry.to_json())]
    packages = [entry.package, *(entry.packages or [])]
    for p in packages:
        problems += hb.manifest_problems(hb.manifest_of(p))
        if hb.manifest_sha256(hb.manifest_of(p)) != p.manifest_sha256:
            problems.append("manifest_sha256 is not the digest of the manifest")
        if not hb.arch_ok(p, entry.platform):
            problems.append(f"arch {p.arch!r} on {entry.platform}")
        if profile(entry.platform) is not None and not problems:
            try:
                hb.install_plan(entry, p)
            except hb.Refused as e:
                problems.append(str(e))
        if entry.signature is not None and hb.verify_signature(entry, p) is not True:
            problems.append("a signature that does not verify")
    problems += hb.port_problems(entry)
    problems += hb.requires_problems(entry)
    return problems


class MemoryJournal:
    """A journal kept in memory, of the last `keep` changes."""

    def __init__(self, keep: int = 10000) -> None:
        self.epoch = secrets.token_hex(4)
        self.keep = keep
        self.events: list[tuple[int, str, str, str]] = []  # (position, kind, key, platform)
        self.seq = 0
        self.floor = 0

    def record(self, kind: str, key: str, platform: str) -> None:
        self.seq += 1
        self.events.append((self.seq, kind, key, platform))
        if len(self.events) > self.keep:
            dropped = self.events[: len(self.events) - self.keep]
            self.events = self.events[len(dropped) :]
            self.floor = dropped[-1][0]

    def since(self, after: int, kinds: tuple[str, ...], platform: str | None) -> list[tuple[str, str]]:
        return [
            (kind, key)
            for n, kind, key, p in self.events
            if n > after and kind in kinds and (platform is None or p == platform)
        ]


class MemoryLibrary:
    """A Library held in memory, with its journal. Files are served from
    their path, or from memory when given as bytes.

        lib = MemoryLibrary(base="/api/lantern")
        lib.add_app_file("games/frost.nsp", platform="switch", title_id="0100ABCD00010000", …)
    """

    def __init__(
        self, *, base: str = "/api/lantern", families: Iterable[str] = LIBRARY_FAMILIES, journal: bool = True
    ) -> None:
        self.base = base.rstrip("/")
        self.families = frozenset(families)
        self._apps: dict[str, App] = {}
        self._titles: dict[tuple[str, str], Title] = {}
        self._homebrew: dict[tuple[str, str], Homebrew] = {}
        self._cheats: dict[str, CheatSet] = {}
        self._files: dict[str, FileRef] = {}
        self._cheat_files: dict[str, FileRef] = {}
        self._journal = MemoryJournal() if journal else None
        self._lock = threading.RLock()
        self._listeners: list[Callable[[LibraryChange], object]] = []

    def subscribe(self, listener: Callable[[LibraryChange], object]) -> None:
        """Calls `listener` with each change of the library (LanternApp sends the event `library` of it,
        SPEC.md § 18.2)."""
        self._listeners.append(listener)

    def _changed(self, change: LibraryChange) -> None:
        for listener in list(self._listeners):
            listener(change)

    # Adding and removing.

    def file_url(self, file_id: str) -> str:
        return f"{self.base}/v1/files/{file_id}"

    def add_file(self, file: FileRef) -> str:
        """Serve a file under a new, unguessable id; its URL (SPEC.md § 6.6)."""
        file_id = "f_" + secrets.token_urlsafe(12)
        with self._lock:
            self._files[file_id] = file
        return self.file_url(file_id)

    def add_app(self, app: App, file: FileRef | None = None) -> App:
        """Serve an app (its `file` URL one of this library's when `file` is given)."""
        if file is not None:
            if (file.size, file.sha256) != (app.size, app.sha256):
                raise ValueError(f"app {app.id}: its size and sha256 are not its file's")
            app.file = self.add_file(file)
        problems = schema.definition("app", app.to_json())
        if problems:
            raise ValueError(f"app {app.id}: " + "; ".join(problems[:3]))
        with self._lock:
            self._apps[app.id] = app
            if self._journal is not None:
                self._journal.record("added", app.id, app.platform)
            self._changed(LibraryChange("apps", app.platform, app.title_id))
        return app

    def add_app_file(
        self,
        path: str | Path | None = None,
        *,
        data: bytes | None = None,
        platform: str,
        title_id: str,
        app_id: str,
        type: str,
        version_code: int,
        name: str,
        format: str,
        version_name: str | None = None,
        added: str | None = None,
        mirrors: Sequence[str] = (),
    ) -> App:
        """An app from a file (hashed now) or bytes, given its identity (SPEC.md § 6.1), and the other
        addresses of its exact bytes, `mirrors` (§ 19.2: HTTPS, or HTTP at a private network's address)."""
        if len(mirrors) > MIRRORS_LIMIT or not all(mirror_ok(m) for m in mirrors):
            raise ValueError(f"mirrors: {MIRRORS_LIMIT} at most, HTTPS or HTTP on a private network (SPEC.md § 19.2)")
        if (path is None) == (data is None):
            raise ValueError("a path or data")
        file = FileRef.of(path) if path is not None else FileRef.of_bytes(data or b"")
        app = App(
            id="a_" + secrets.token_urlsafe(9),
            platform=platform,
            title_id=title_id,
            app_id=app_id,
            type=type,
            version_code=version_code,
            version_name=version_name,
            name=name,
            size=file.size,
            format=format,
            sha256=file.sha256,
            added=added or now(),
            file="",
            mirrors=[Mirror(url=m) for m in mirrors] or None,
        )
        return self.add_app(app, file)

    def remove_app(self, app_id: str) -> None:
        with self._lock:
            app = self._apps.pop(app_id, None)
            if app is not None and self._journal is not None:
                self._journal.record("removed", app_id, app.platform)
            if app is not None:
                self._changed(LibraryChange("apps", app.platform, app.title_id))

    def add_title(self, title: Title) -> Title:
        title.schema = None
        problems = schema.definition("title", title.to_json())
        if problems:
            raise ValueError(f"title {title.platform}/{title.title_id}: " + "; ".join(problems[:3]))
        with self._lock:
            self._titles[(title.platform, title.title_id)] = title
            if self._journal is not None:
                self._journal.record("title", f"{title.platform}/{title.title_id}", title.platform)
            self._changed(LibraryChange("titles", title.platform, title.title_id))
        return title

    def remove_title(self, platform: str, title_id: str) -> None:
        with self._lock:
            if self._titles.pop((platform, title_id), None) is not None:
                if self._journal is not None:
                    self._journal.record("title", f"{platform}/{title_id}", platform)
                self._changed(LibraryChange("titles", platform, title_id))

    def add_homebrew(self, entry: Homebrew, files: dict[str, FileRef] | None = None) -> Homebrew:
        """Serve a homebrew entry. `files` maps each package's `file` to the
        file it serves, which is checked against the package and given a
        URL of this library. Refused (ValueError) when check_homebrew() finds
        a reason, or a file is not its package's."""
        for p in [entry.package, *(entry.packages or [])]:
            file = (files or {}).get(p.file)
            if file is not None:
                if (file.size, file.sha256) != (p.size, p.sha256):
                    raise ValueError(f"homebrew {entry.id}: {p.file} is not its package's file")
                p.file = self.add_file(file)
        entry.schema = None
        problems = check_homebrew(entry)
        if problems:
            raise ValueError(f"homebrew {entry.platform}/{entry.id}: " + "; ".join(problems[:3]))
        with self._lock:
            self._homebrew[(entry.platform, entry.id)] = entry
            self._changed(LibraryChange("homebrew", entry.platform, ratings=tuple(entry.ratings or ())))
        return entry

    def add_cheat(
        self,
        *,
        platform: str,
        title_id: str,
        text: str,
        source: str,
        build_id: str | None = None,
        note: str | None = None,
        updated: str | None = None,
    ) -> CheatSet:
        """A cheat set from its text (SPEC.md § 10)."""
        data = text.encode()
        if len(data) > CHEAT_SET:
            raise ValueError(f"a cheat set is {CHEAT_SET} bytes at most")
        file = FileRef.of_bytes(data, "text/plain; charset=utf-8")
        cheat = CheatSet(
            id="cs_" + secrets.token_urlsafe(9),
            platform=platform,
            title_id=title_id,
            build_id=build_id,
            source=source,
            note=note,
            updated=updated or now(),
            size=file.size,
            sha256=file.sha256,
        )
        problems = schema.definition("cheat_set", cheat.to_json())
        if problems:
            raise ValueError("cheat set: " + "; ".join(problems[:3]))
        with self._lock:
            self._cheats[cheat.id] = cheat
            self._cheat_files[cheat.id] = file
            self._changed(LibraryChange("cheats", cheat.platform, cheat.title_id))
        return cheat

    # Library.

    def apps(self) -> list[App]:
        with self._lock:
            return list(self._apps.values())

    def titles(self, languages: Sequence[str]) -> list[Title]:
        with self._lock:
            return list(self._titles.values())

    def homebrew(self, languages: Sequence[str]) -> list[Homebrew]:
        with self._lock:
            return list(self._homebrew.values())

    def cheats(self) -> list[CheatSet]:
        with self._lock:
            return list(self._cheats.values())

    def file(self, file_id: str) -> FileRef | None:
        with self._lock:
            return self._files.get(file_id)

    def cheat_file(self, cheat_id: str) -> FileRef | None:
        with self._lock:
            return self._cheat_files.get(cheat_id)

    def journal(self) -> Journal | None:
        return self if self._journal is not None else None

    # Journal.

    @property
    def epoch(self) -> str:
        return self._journal.epoch if self._journal is not None else ""

    def position(self) -> int:
        return self._journal.seq if self._journal is not None else 0

    def oldest(self) -> int:
        return self._journal.floor if self._journal is not None else 0

    def app_changes(self, after: int, platform: str | None) -> tuple[list[App], list[str]]:
        with self._lock:
            events = self._journal.since(after, ("added", "removed"), platform) if self._journal else []
            added = list(dict.fromkeys(k for kind, k in events if kind == "added" and k in self._apps))
            removed = sorted({k for kind, k in events if kind == "removed" and k not in self._apps})
            return [self._apps[a] for a in added], removed

    def title_changes(
        self, after: int, platform: str | None, languages: Sequence[str]
    ) -> tuple[list[Title], list[RemovedTitle]]:
        with self._lock:
            keys = sorted({k for _, k in (self._journal.since(after, ("title",), platform) if self._journal else [])})
            changed, removed = [], []
            for key in keys:
                p, _, tid = key.partition("/")
                if (p, tid) in self._titles:
                    changed.append(self._titles[(p, tid)])
                else:
                    removed.append(RemovedTitle(platform=p, title_id=tid))
            return changed, removed


def make_package(
    data: bytes, fmt: str, *, platform: str, homebrew_id: str, file_name: str = "", arch: list[str] | None = None
) -> tuple[Package, FileRef]:
    """A homebrew's package from its file's bytes, and the file to serve:
    an archive's manifest read from it, a single file's path given by the
    profile (Annex A), none for a format the platform's installer installs
    (whose manifest is empty). Only an archive carries `manifest`.
    Its `file` is a placeholder that MemoryLibrary.add_homebrew() replaces:
    pass {package.file: file} as its `files`."""
    ref = FileRef.of_bytes(data)
    placeholder = f"sha256:{ref.sha256}"
    if fmt == "zip":
        manifest = zip_manifest(data)
        return Package(
            format="zip",
            file=placeholder,
            size=ref.size,
            sha256=ref.sha256,
            manifest_sha256=hb.manifest_sha256(manifest),
            manifest=manifest,
            arch=arch,
        ), ref
    prof = profile(platform)
    path = prof.single_file_path(fmt, homebrew_id, file_name) if prof is not None else None
    entries = [ManifestEntry(path=path, size=ref.size, sha256=ref.sha256)] if path is not None else []
    return Package(
        format=fmt,
        file=placeholder,
        size=ref.size,
        sha256=ref.sha256,
        manifest_sha256=hb.manifest_sha256(entries),
        path=path,
        arch=arch,
    ), ref
