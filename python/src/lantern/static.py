"""Static libraries (SPEC.md § 21): a library's read routes as plain files,
on a web host (GitHub Pages, a NAS), a USB key or an SD card.

Reading one (§ 21.3):

    lib = StaticLibrary("https://lea.example.org/library/")   # or file:///media/usb/library, or a Path
    hello = lib.handshake()                                     # lantern.json, with its `static`
    for app in lib.iter_apps("switch"):
        ...
    todo = lib.missing([("0100ABCD00010000", 0)], ["update", "dlc"], platform="switch")  # § 6.3, computed here
    lib.download(todo[0], "frostline.nsz")                      # checked by its size and SHA-256

Files are read as JSON whatever their Content-Type (L-21.3-1), each file a
document points at only by a path relative to the root (L-21.1-2), checked
by its size and SHA-256 as from a server; what is missing and the homebrew
to update are computed from the pages, by the rules a server follows
(L-21.3-2). A document of a newer `schema` is absent (NewerSchema). Over
HTTP, HTTPS but on loopback (§ 2).

Writing one, the generator of the static profile:

    python -m lantern.static DIR --out OUT [--metadata FILE] [--page-size 100] [--language en]
    lantern-static DIR --out OUT                    # the same, as the package's console script

builds OUT/lantern.json and OUT/v1/ from the files of DIR and a metadata
file (DIR/lantern-static.json by default, `schema` 1):

    {"schema": 1, "name": "Lea's library", "uid": "…", "language": "en",
     "apps": [{"path": "games/frostline.nsz", "platform": "switch", "title_id": "0100ABCD00010000",
               "app_id": "0100ABCD00010000", "type": "base", "version_code": 0,
               "name": "Frostline Tales", "format": "nsz", "mirrors": ["https://…"]}],
     "titles": [{…a title, as SPEC.md § 7.1 gives it…}],
     "homebrew": [{"path": "homebrew/paperlamp.zip", "format": "zip", "arch": ["aarch64"],
                   "entry": {…a homebrew entry, § 8.1, without its package…}}],
     "cheats": [{"platform": "switch", "title_id": "0100ABCD00010000", "build_id": "…",
                 "source": "Lea", "path": "cheats/frostline.txt"}]}

or, in a program, export() writes any toolkit Library (a LanternApp's):

    export(library, "out/", uid=SERVER_UID, name="Living room shelf")

An export replaces the lantern.json and v1/ of an earlier one, and nothing
else of OUT; the same library gives the same pages. It never writes over a
lantern.json of a newer schema, and keeps the keys it does not know of the
one it replaces. `conformance/run.py --static OUT` checks what it wrote.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import uuid
from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar
from urllib.parse import quote, unquote, urljoin, urlsplit

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue, LanternError
from lantern._generated.models import (
    App,
    AppsPage,
    CheatSet,
    CheatSets,
    Handshake,
    Homebrew,
    HomebrewPage,
    Package,
    Title,
    Titles,
)
from lantern._version import __version__
from lantern.client.download import Verifier
from lantern.client.stdlib import StdlibTransport
from lantern.client.transport import Request, Transport
from lantern.digest import Sha256
from lantern.documents import schema_of
from lantern.errors import InsecureTransport, IntegrityError, NewerSchema, NotFound, UnexpectedResponse
from lantern.http import Headers, plain_http_allowed
from lantern.limits import CHEAT_SET, JSON_DOCUMENT, load_json
from lantern.missing import homebrew_updates, missing
from lantern.store import NewerOnDisk
from lantern.vocabulary import FAMILIES, HOMEBREW_ID, PLATFORM

T = TypeVar("T")
HANDSHAKE = "lantern.json"
#: The families a static library cannot offer (SPEC.md § 21.2): 0 in its handshake.
NOT_STATIC = (
    "changes",
    "sections",
    "saves",
    "encrypted_saves",
    "requests",
    "pairing",
    "signatures",
    "admin",
    "events",
    "peers",
    "sync",
)
#: A path relative to the root (SPEC.md § 21.1): no scheme, no leading /, no .. part, no backslash, no query.
RELATIVE = re.compile(r"^(?![a-zA-Z][a-zA-Z0-9+.-]*:)(?!/)(?!.*(?:^|/)\.\.(?:/|$))[^\\?#]+$")
PAGE_SIZE = 100
METADATA = "lantern-static.json"
USER_AGENT = f"LanternPython/{__version__}"
_PAGES_LIMIT = 100_000


def layout_path(kind: str, platform: str | None = None, ident: str | None = None, page: int | None = None) -> str:
    """The file of a read route, relative to the root (SPEC.md § 21.1): `kind` is handshake, apps, titles or
    homebrew (a page), title, entry (a homebrew entry), cheats (a title's sets), cheat (a set's text) or blob
    (a file by its SHA-256)."""
    if kind == "handshake":
        return HANDSHAKE
    if kind in ("apps", "titles", "homebrew"):
        if platform is None or page is None or page < 1:
            raise ValueError("a page has a platform and a number, from 1")
        return f"v1/{kind}/{platform}/pages/{page}.json"
    if kind in ("title", "entry", "cheats") and (platform is None or not ident):
        raise ValueError(f"{kind} has a platform and an id")
    if kind == "title":
        return f"v1/titles/{platform}/{ident}.json"
    if kind == "entry":
        return f"v1/homebrew/{platform}/{ident}.json"
    if kind == "cheats":
        return f"v1/cheats/{platform}/{ident}.json"
    if kind == "cheat" and ident:
        return f"v1/cheats/{ident}.txt"
    if kind == "blob" and ident:
        return f"v1/blobs/sha256/{ident}"
    raise ValueError(f"no route {kind!r}")


def relative_ok(path: object) -> bool:
    """Whether a document's `file`, or an image's `url`, is a path relative to the root (L-21.1-2)."""
    return isinstance(path, str) and 0 < len(path) <= 4096 and bool(RELATIVE.match(path))


def _segment(value: str, what: str) -> str:
    if not value or "/" in value or "\\" in value or value in (".", "..") or len(value) > 128:
        raise ValueError(f"{value[:80]!r} is not a {what}")
    return value


# Reading (SPEC.md § 21.3).


class StaticLibrary:
    """A static library at `root`: an https:// address (http:// on loopback), a file:// URL, or a folder.
    Nothing is sent but GET requests without credentials: a static library has no token (§ 21.3)."""

    def __init__(
        self,
        root: str | Path,
        *,
        transport: Transport | None = None,
        user_agent: str = USER_AGENT,
        timeout: float = 30.0,
    ) -> None:
        self.folder: Path | None = None
        self.url: str | None = None
        text = str(root)
        if isinstance(root, Path) or "://" not in text:
            self.folder = Path(root)
        elif text.startswith("file://"):
            self.folder = Path(unquote(urlsplit(text).path))
        else:
            if not plain_http_allowed(text):
                raise InsecureTransport(f"{text}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)")
            self.url = text if text.endswith("/") else text + "/"
        self._own = transport is None and self.url is not None
        self.transport: Transport | None = transport or (StdlibTransport() if self.url is not None else None)
        self.user_agent, self.timeout = user_agent, timeout
        self.hello: Handshake | None = None

    def __enter__(self) -> StaticLibrary:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._own and self.transport is not None:
            self.transport.close()

    def where(self, rel: str) -> str:
        """The address or path of a file of the library."""
        if not relative_ok(rel):
            raise DocumentError(f"{rel[:100]!r} is not a path relative to the library's root (SPEC.md § 21.1)")
        if self.folder is not None:
            return str(self.folder / rel)
        assert self.url is not None
        return urljoin(self.url, quote(rel, safe="/"))

    def _open(self, rel: str) -> tuple[Iterator[bytes], Callable[[], None]] | None:
        """A file's bytes as they come, and how to close it; None when it is not there."""
        where = self.where(rel)
        if self.folder is not None:
            path = Path(where)
            if not path.is_file():
                return None
            f = path.open("rb")

            def chunks() -> Iterator[bytes]:
                while piece := f.read(1 << 16):
                    yield piece

            return chunks(), f.close
        assert self.transport is not None
        headers = Headers({"User-Agent": self.user_agent, "Accept": "*/*"})
        response = self.transport.send(Request("GET", where, headers), timeout=self.timeout)
        if response.status == 404:
            response.close()
            return None
        if response.status != 200:
            response.close()
            raise UnexpectedResponse(f"{where}: status {response.status}", response.status)
        return response.iter_bytes(), response.close

    def read_bytes(self, rel: str, limit: int) -> bytes | None:
        opened = self._open(rel)
        if opened is None:
            return None
        chunks, close = opened
        out = bytearray()
        try:
            for piece in chunks:
                out += piece
                if len(out) > limit:
                    raise DocumentError(f"{rel}: above {limit} bytes")
        finally:
            close()
        return bytes(out)

    def document(self, rel: str, read: Callable[[JSONValue], T], what: str) -> T | None:
        """A document of the library, read as JSON whatever its Content-Type (L-21.3-1); None when it is not
        there; NewerSchema for a newer schema (absent, § 3.2)."""
        raw = self.read_bytes(rel, JSON_DOCUMENT)
        if raw is None:
            return None
        doc = load_json(raw, where=rel)
        schema = schema_of(doc, what)
        if schema > SCHEMA:
            raise NewerSchema(what, schema)
        return read(doc)

    def _required(self, rel: str, read: Callable[[JSONValue], T], what: str) -> T:
        found = self.document(rel, read, what)
        if found is None:
            raise NotFound(404)
        return found

    def handshake(self) -> Handshake:
        """lantern.json: a handshake with `static` (§ 21.2); UnexpectedResponse for a document without."""
        hello = self._required(HANDSHAKE, Handshake.from_json, "lantern.json")
        if hello.static is None:
            raise UnexpectedResponse("lantern.json has no static: not a static library's handshake")
        if 1 not in hello.versions:
            raise LanternError("the library does not serve version 1 of the protocol")
        self.hello = hello
        return hello

    def _hello(self) -> Handshake:
        return self.hello or self.handshake()

    def _pages(self, family: str, platform: str, read: Callable[[JSONValue], T]) -> Iterator[T]:
        if not PLATFORM.match(platform):
            raise ValueError(f"{platform!r} is not a platform's name")
        if platform not in self._hello().platforms:
            return
        n = 1
        while n <= _PAGES_LIMIT:
            page = self._required(layout_path(family, platform, page=n), read, f"{family} of {platform}")
            yield page
            following = getattr(page, "next", None)
            if following is None:
                return
            if following != str(n + 1):
                raise UnexpectedResponse(f"{family} of {platform}, page {n}: next {following!r}, not {n + 1!r}")
            n += 1
        raise UnexpectedResponse(f"{family} of {platform}: pages without end")

    def iter_apps(self, platform: str) -> Iterator[App]:
        for page in self._pages("apps", platform, AppsPage.from_json):
            yield from page.items

    def iter_titles(self, platform: str) -> Iterator[Title]:
        for page in self._pages("titles", platform, Titles.from_json):
            yield from page.titles

    def title(self, platform: str, title_id: str) -> Title:
        """A title (NotFound when the library has none)."""
        return self._required(
            layout_path("title", _segment(platform, "platform"), _segment(title_id, "title id")),
            Title.from_json,
            "title",
        )

    def iter_homebrew(self, platform: str) -> Iterator[Homebrew]:
        """The entries of a platform, without their manifests (read an entry for them)."""
        for page in self._pages("homebrew", platform, HomebrewPage.from_json):
            yield from page.items

    def homebrew_entry(self, platform: str, homebrew_id: str) -> Homebrew:
        if not HOMEBREW_ID.match(homebrew_id):
            raise ValueError(f"{homebrew_id!r} is not a homebrew id")
        return self._required(
            layout_path("entry", _segment(platform, "platform"), homebrew_id), Homebrew.from_json, "homebrew"
        )

    def cheats(self, platform: str, title_id: str) -> list[CheatSet]:
        """A title's cheat sets; none when the library has no file of them (§ 21.1)."""
        rel = layout_path("cheats", _segment(platform, "platform"), _segment(title_id, "title id"))
        found = self.document(rel, CheatSets.from_json, "cheats")
        return list(found.cheats) if found is not None else []

    def cheat_text(self, cheat: CheatSet) -> str:
        """A set's text, checked by its size and SHA-256."""
        if cheat.size > CHEAT_SET:
            raise DocumentError(f"cheat set {cheat.id}: {cheat.size} bytes, above {CHEAT_SET}")
        data = self.read_bytes(layout_path("cheat", ident=_segment(cheat.id, "cheat id")), cheat.size)
        if data is None:
            raise NotFound(404)
        verifier, hasher = Verifier(cheat.sha256, cheat.size, cheat.id), Sha256()
        verifier.feed(hasher, data)
        verifier.finish(hasher)
        return data.decode("utf-8")

    def missing(
        self, installed: Iterable[tuple[str, int]], want: Iterable[str] = ("update", "dlc"), *, platform: str
    ) -> list[App]:
        """What a device is missing (SPEC.md § 6.3), computed from the platform's whole listing by the rules a
        server follows (L-21.3-2)."""
        wants = set(want)
        if not wants or not wants <= {"base", "update", "dlc"}:
            raise ValueError("want lists base, update or dlc")
        return missing(list(self.iter_apps(platform)), platform, list(installed), wants)

    def homebrew_updates(self, installed: Iterable[tuple[str, int]], *, platform: str) -> list[Homebrew]:
        """The entries newer than what is installed, (id, build), by comparing `build` (§ 8.5, § 21.3)."""
        return homebrew_updates(self.iter_homebrew(platform), platform, installed)

    def download(self, file: App | Package, dest: str | Path) -> Path:
        """An app's or a package's file, through `dest` + ".part", renamed only once its size and SHA-256
        are the document's (§ 6.6); IntegrityError otherwise, and nothing is kept."""
        verifier = Verifier(file.sha256, file.size, file.file)
        target = Path(dest)
        part = target.with_name(target.name + ".part")
        opened = self._open(file.file)
        if opened is None:
            raise NotFound(404)
        chunks, close = opened
        hasher = Sha256()
        try:
            with part.open("wb") as f:
                for piece in chunks:
                    verifier.feed(hasher, piece)
                    f.write(piece)
            verifier.finish(hasher)
        except BaseException:
            part.unlink(missing_ok=True)
            raise
        finally:
            close()
        part.replace(target)
        return target


# Writing: the generator of the static profile.


def _dump(doc: JSONObject) -> bytes:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode()


def _pages(
    items: list[JSONObject], size: int, wrap: Callable[[list[JSONObject], str | None, int], JSONObject]
) -> list[JSONObject]:
    """A listing cut into pages of `size`, their cursors fixed: "<n+1>", null on the last (SPEC.md § 21.1)."""
    chunks = [items[i : i + size] for i in range(0, len(items), size)] or [[]]
    return [wrap(chunk, str(n + 1) if n < len(chunks) else None, len(items)) for n, chunk in enumerate(chunks, 1)]


def _images(doc: JSONObject) -> None:
    """Images a static library can point at (L-21.1-2): a path relative to the root as it is; an absolute
    address of elsewhere marked external; one on the server's own origin (a path from /) left out, which
    the library does not hold."""
    for key in ("icon", "banner"):
        img = doc.get(key)
        if isinstance(img, dict):
            fixed = _image(img)
            if fixed is None:
                del doc[key]
            else:
                doc[key] = fixed
    shots = doc.get("screenshots")
    if isinstance(shots, list):
        kept: list[JSONValue] = [
            y for y in (_image(x) if isinstance(x, dict) else None for x in shots) if y is not None
        ]
        if kept:
            doc["screenshots"] = kept
        else:
            del doc["screenshots"]


def _image(img: JSONObject) -> JSONObject | None:
    url = img.get("url")
    if img.get("external") is True or relative_ok(url):
        return img
    if isinstance(url, str) and urlsplit(url).scheme in ("http", "https"):
        return {**img, "external": True}
    return None


def export(
    library: object,
    out: str | Path,
    *,
    uid: str,
    name: str,
    page_size: int = PAGE_SIZE,
    language: str = "en",
    software: tuple[str, str] | None = None,
    platforms: Sequence[str] | None = None,
    generated: datetime | None = None,
) -> dict[str, JSONValue]:
    """Writes a toolkit Library (lantern.server.Library: apps, titles, homebrew, cheats and their files) as a
    static library into `out` (SPEC.md § 21); a summary of what it wrote. Files are taken by the id their
    `file` ends with (library.file(), library.cheat_file()). NewerOnDisk, and nothing written, when `out`
    holds a lantern.json of a newer schema; ValueError when it holds a v1/ that is not an earlier export's."""
    from lantern.server.files import FileRef

    if not 1 <= page_size <= 1000:
        raise ValueError("page_size is 1 to 1000 (SPEC.md § 21.2)")
    root = Path(out)
    previous: JSONObject | None = None
    old = root / HANDSHAKE
    if old.exists():
        try:
            raw = load_json(old.read_bytes(), where=str(old))
        except DocumentError:
            raw = None
        schema = raw.get("schema") if isinstance(raw, dict) else None
        if isinstance(schema, int) and not isinstance(schema, bool) and schema > SCHEMA:
            raise NewerOnDisk(f"{old}: schema {schema}, newer than {SCHEMA}: left as it is")
        previous = raw if isinstance(raw, dict) and isinstance(raw.get("static"), dict) else None
    if (root / "v1").exists() and previous is None:
        raise ValueError(f"{root / 'v1'} is not an earlier export's (no static lantern.json beside it): left as it is")
    families: frozenset[str] = getattr(library, "families", frozenset({"library", "titles", "homebrew", "cheats"}))
    file_of: Callable[[str], FileRef | None] = library.file  # type: ignore[attr-defined]
    cheat_file: Callable[[str], FileRef | None] = library.cheat_file  # type: ignore[attr-defined]
    langs = [language]
    apps: list[App] = list(library.apps()) if "library" in families else []  # type: ignore[attr-defined]
    titles: list[Title] = list(library.titles(langs)) if "titles" in families else []  # type: ignore[attr-defined]
    entries: list[Homebrew] = list(library.homebrew(langs)) if "homebrew" in families else []  # type: ignore[attr-defined]
    cheats: list[CheatSet] = list(library.cheats()) if "cheats" in families else []  # type: ignore[attr-defined]
    found = sorted(
        {a.platform for a in apps}
        | {t.platform for t in titles}
        | {e.platform for e in entries}
        | {c.platform for c in cheats}
    )
    chosen = sorted(set(platforms)) if platforms is not None else found
    docs: dict[str, bytes] = {}
    blobs: dict[str, FileRef] = {}

    def blob(file: str, sha256: str, size: int) -> str:
        ref = file_of(file.rstrip("/").rsplit("/", 1)[-1])
        if ref is None or ref.sha256 != sha256 or ref.size != size:
            raise ValueError(f"{file}: no file of this size and SHA-256 in the library")
        blobs[sha256] = ref
        return layout_path("blob", ident=sha256)

    for p in chosen:
        mine = []
        for a in sorted((a for a in apps if a.platform == p), key=lambda a: ((a.name or "").casefold(), a.id)):
            doc = a.to_json()
            doc["file"] = blob(a.file, a.sha256, a.size)
            mine.append(doc)
        for n, page in enumerate(
            _pages(mine, page_size, lambda c, nxt, t: {"schema": SCHEMA, "items": list(c), "total": t, "next": nxt}),
            1,
        ):
            docs[layout_path("apps", p, page=n)] = _dump(page)
        tdocs = []
        for t in sorted((t for t in titles if t.platform == p), key=lambda t: (t.name.casefold(), t.title_id)):
            doc = t.to_json()
            doc.pop("schema", None)
            _images(doc)
            tdocs.append(doc)
            docs[layout_path("title", p, t.title_id)] = _dump({"schema": SCHEMA, **doc})
        for n, page in enumerate(
            _pages(
                tdocs, page_size, lambda c, nxt, t: {"schema": SCHEMA, "titles": list(c), "unknown": [], "next": nxt}
            ),
            1,
        ):
            docs[layout_path("titles", p, page=n)] = _dump(page)
        listed = []
        for e in sorted((e for e in entries if e.platform == p), key=lambda e: (e.name.casefold(), e.id)):
            full = e.to_json()
            full.pop("schema", None)
            _images(full)
            extra = full.get("packages")
            packages = [full["package"], *(extra if isinstance(extra, list) else [])]
            for pdoc, model in zip(packages, [e.package, *(e.packages or [])], strict=True):
                assert isinstance(pdoc, dict)
                pdoc["file"] = blob(model.file, model.sha256, model.size)
            docs[layout_path("entry", p, e.id)] = _dump({"schema": SCHEMA, **full})
            short = json.loads(json.dumps(full))
            short["package"].pop("manifest", None)
            for x in short.get("packages") or []:
                x.pop("manifest", None)
            listed.append(short)
        for n, page in enumerate(
            _pages(listed, page_size, lambda c, nxt, t: {"schema": SCHEMA, "items": list(c), "total": t, "next": nxt}),
            1,
        ):
            docs[layout_path("homebrew", p, page=n)] = _dump(page)
    by_title: dict[tuple[str, str], list[JSONValue]] = {}
    texts: dict[str, FileRef] = {}
    for c in sorted(
        (c for c in cheats if c.platform in chosen),
        key=lambda c: (c.platform, c.title_id, c.build_id or "", (c.source or "").casefold(), c.id),
    ):
        ref = cheat_file(c.id)
        if ref is None:
            raise ValueError(f"cheat set {c.id}: no text in the library")
        by_title.setdefault((c.platform, c.title_id), []).append(c.to_json())
        texts[c.id] = ref
    for (p, tid), sets in by_title.items():
        docs[layout_path("cheats", p, tid)] = _dump({"schema": SCHEMA, "cheats": sets})
    features: JSONObject = dict.fromkeys(FAMILIES, 0)
    features.update(
        library=SCHEMA if "library" in families else 0,
        titles=SCHEMA if "titles" in families else 0,
        homebrew=SCHEMA if "homebrew" in families else 0,
        cheats=SCHEMA if by_title else 0,
    )
    for f in NOT_STATIC:
        features[f] = 0
    when = (generated or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    scopes: list[JSONValue] = ["library", "cheats"] if by_title else ["library"]
    hello: JSONObject = {
        "schema": SCHEMA,
        "uid": uid,
        "name": name,
        "software": {"name": software[0], "version": software[1]}
        if software
        else {"name": "lantern-protocol", "version": __version__},
        "base": ".",
        "versions": [1],
        "platforms": list(chosen),
        "language": language,
        "account": {"state": "anonymous", "scopes": scopes},
        "features": features,
        "limits": {"page_size": page_size},
        "static": {"generated": when, "page_size": page_size},
    }
    known = set(Handshake.KEYS)
    if previous is not None:  # a rewritten file keeps the keys it does not know
        hello = {**{k: v for k, v in previous.items() if k not in known}, **hello}
    # Written: v1/ whole, then lantern.json last, so that a reader never sees a handshake without its pages.
    tree = root / "v1"
    if tree.exists():
        shutil.rmtree(tree)
    for rel, data in docs.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for sha, ref in blobs.items():
        _copy(ref, root / layout_path("blob", ident=sha))
    for cid, ref in texts.items():
        _copy(ref, root / layout_path("cheat", ident=cid))
    root.mkdir(parents=True, exist_ok=True)
    tmp = root / (HANDSHAKE + ".tmp")
    tmp.write_bytes(_dump(hello))
    tmp.replace(root / HANDSHAKE)
    return {"documents": len(docs) + 1, "files": len(blobs) + len(texts), "platforms": list(chosen)}


def _copy(ref: object, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    data = getattr(ref, "data", None)
    if data is not None:
        target.write_bytes(data)
    else:
        shutil.copyfile(str(getattr(ref, "path", "")), target)
    # A file copied wrong is never served: checked again, as a reader will.
    from lantern.digest import sha256_file

    h = sha256_file(target)
    if h.hexdigest() != getattr(ref, "sha256", None) or h.size != getattr(ref, "size", None):
        target.unlink()
        raise IntegrityError(f"{target}: not the file of its SHA-256 once copied")


# The command line, over a folder and a metadata file.


class MetadataError(LanternError):
    """A metadata file the generator cannot build from: it writes nothing."""


def read_metadata(path: Path) -> JSONObject:
    """The generator's metadata (`schema` 1): its fields, the ones it does not know skipped. MetadataError
    when it is absent, not JSON, without an integer schema, or of a newer one (read as absent: nothing is
    written then, so that an earlier export stays as it was)."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise MetadataError(f"{path}: no metadata file") from None
    try:
        doc = load_json(raw, where=str(path))
    except DocumentError as e:
        raise MetadataError(f"{path}: {e}") from None
    schema = doc.get("schema") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
        raise MetadataError(f"{path}: a metadata file is an object with an integer schema")
    if schema > SCHEMA:
        raise MetadataError(f"{path}: schema {schema}, newer than this generator reads: nothing written")
    return doc


def build_library(folder: Path, meta: JSONObject) -> object:
    """A MemoryLibrary of the files of `folder` the metadata describes."""
    from lantern.server.library import MemoryLibrary, make_package

    lib = MemoryLibrary(base="/")

    def path_of(value: JSONValue, what: str) -> Path:
        if not relative_ok(value):
            raise MetadataError(f"{what}: {str(value)[:80]!r} is not a path relative to {folder}")
        assert isinstance(value, str)
        found = folder / value
        if not found.is_file():
            raise MetadataError(f"{what}: {found} is not a file")
        return found

    def items(key: str) -> list[JSONObject]:
        value = meta.get(key, [])
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise MetadataError(f"{key} is a list of objects")
        return [x for x in value if isinstance(x, dict)]

    try:
        for i, a in enumerate(items("apps")):
            mirrors = a.get("mirrors", [])
            lib.add_app_file(
                path_of(a.get("path"), f"apps[{i}]"),
                platform=str(a.get("platform")),
                title_id=str(a.get("title_id")),
                app_id=str(a.get("app_id")),
                type=str(a.get("type")),
                version_code=int(a.get("version_code")),  # type: ignore[arg-type]
                name=str(a.get("name")),
                format=str(a.get("format")),
                version_name=a["version_name"] if isinstance(a.get("version_name"), str) else None,  # type: ignore[arg-type]
                added=a["added"] if isinstance(a.get("added"), str) else None,  # type: ignore[arg-type]
                mirrors=[str(m) for m in mirrors] if isinstance(mirrors, list) else [],
            )
        for t in items("titles"):
            lib.add_title(Title.from_json(t, "titles[]"))
        for i, h in enumerate(items("homebrew")):
            entry = h.get("entry")
            if not isinstance(entry, dict):
                raise MetadataError(f"homebrew[{i}]: entry is a homebrew entry, without its package")
            platform, hid = str(entry.get("platform")), str(entry.get("id"))
            data = path_of(h.get("path"), f"homebrew[{i}]").read_bytes()
            arch = h.get("arch")
            package, ref = make_package(
                data,
                str(h.get("format")),
                platform=platform,
                homebrew_id=hid,
                file_name=Path(str(h.get("path"))).name,
                arch=[str(x) for x in arch] if isinstance(arch, list) else None,
            )
            doc = {**entry, "package": package.to_json()}
            lib.add_homebrew(Homebrew.from_json(doc, f"homebrew[{i}]"), {package.file: ref})
        for i, c in enumerate(items("cheats")):
            text = path_of(c.get("path"), f"cheats[{i}]").read_text(encoding="utf-8")
            lib.add_cheat(
                platform=str(c.get("platform")),
                title_id=str(c.get("title_id")),
                text=text,
                source=str(c.get("source") or "unknown"),
                build_id=c["build_id"] if isinstance(c.get("build_id"), str) else None,  # type: ignore[arg-type]
                note=c["note"] if isinstance(c.get("note"), str) else None,  # type: ignore[arg-type]
                updated=c["updated"] if isinstance(c.get("updated"), str) else None,  # type: ignore[arg-type]
            )
    except (ValueError, TypeError, DocumentError) as e:
        raise MetadataError(str(e)) from None
    return lib


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="lantern-static", description="Builds a static Lantern library (SPEC.md § 21) from a folder of files."
    )
    p.add_argument("folder", type=Path, help="the folder of the files, and of lantern-static.json")
    p.add_argument("--out", type=Path, required=True, help="where the library is written")
    p.add_argument("--metadata", type=Path, help=f"the metadata file (default: <folder>/{METADATA})")
    p.add_argument("--page-size", type=int, default=PAGE_SIZE, help="items per page, 1 to 1000")
    p.add_argument("--language", help="the language of its texts (default: the metadata's, else en)")
    p.add_argument("--name", help="the library's name (default: the metadata's)")
    p.add_argument(
        "--uid", help="its uid, which never changes (default: the metadata's, the earlier export's, or a new one)"
    )
    args = p.parse_args(argv)
    try:
        meta = read_metadata(args.metadata or args.folder / METADATA)
        lib = build_library(args.folder, meta)
        uid = args.uid or meta.get("uid") or _earlier_uid(args.out) or str(uuid.uuid4())
        name = args.name or meta.get("name") or "Lantern library"
        language = args.language or meta.get("language") or "en"
        done = export(lib, args.out, uid=str(uid), name=str(name), page_size=args.page_size, language=str(language))
    except (MetadataError, NewerOnDisk, ValueError, OSError) as e:
        print(f"lantern-static: {e}", file=sys.stderr)
        return 2
    print(
        f"lantern-static: {done['documents']} document(s) and {done['files']} file(s) written to {args.out} "
        f"({', '.join(str(x) for x in done['platforms']) or 'no platform'})",  # type: ignore[union-attr]
        file=sys.stderr,
    )
    return 0


def _earlier_uid(out: Path) -> str | None:
    try:
        doc = json.loads((out / HANDSHAKE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    uid = doc.get("uid") if isinstance(doc, dict) else None
    return uid if isinstance(uid, str) and uid else None


__all__ = [
    "HANDSHAKE",
    "METADATA",
    "NOT_STATIC",
    "MetadataError",
    "StaticLibrary",
    "build_library",
    "export",
    "layout_path",
    "main",
    "read_metadata",
    "relative_ok",
]


if __name__ == "__main__":
    sys.exit(main())
