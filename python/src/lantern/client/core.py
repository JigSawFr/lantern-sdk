"""The client without its I/O: what each call sends, and how its answer is
read. LanternClient (sync) and AsyncLanternClient share it."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Generic, TypeVar
from urllib.parse import quote, urlencode, urljoin, urlsplit

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern._generated.models import (
    AppsPage,
    Changes,
    CheatSets,
    Handshake,
    HomebrewPage,
    HomebrewUpdatesRequest,
    InstalledApp,
    InstalledHomebrew,
    MissingRequest,
    Sections,
    Title,
    TitleChanges,
    Titles,
)
from lantern._generated.models import (
    Homebrew as HomebrewEntry,
)
from lantern._version import __version__
from lantern.client.transport import Credentials, Pipeline, Request, RequestSigner
from lantern.documents import schema_of
from lantern.errors import InsecureTransport, LanternError, NewerSchema, UnexpectedResponse, problem_error
from lantern.http import JSON, PLATFORM_HEADER, Headers, media_type, origin, plain_http_allowed
from lantern.limits import JSON_DOCUMENT, TITLES_AT_ONCE, load_json
from lantern.vocabulary import CORE_ID, FAMILIES, HOMEBREW_ID, is_platform

T = TypeVar("T")
ERROR_BODY = 1 << 16
USER_AGENT = f"LanternPython/{__version__}"
#: The `schema` this library reads, per family (sent as Accept-Schema, SPEC.md § 3.2).
KNOWN: Mapping[str, int] = dict.fromkeys(FAMILIES, SCHEMA)
MISSING_WANTS = ("base", "update", "dlc")


@dataclass
class Call(Generic[T]):
    """One request below <base>/v1 (or the handshake), and how its answer reads."""

    method: str
    path: str
    read: Callable[[JSONValue], T]
    what: str
    query: list[tuple[str, str]] = field(default_factory=list)
    body: JSONObject | None = None
    well_known: bool = False

    def with_cursor(self, cursor: str) -> Call[T]:
        query = [(k, v) for k, v in self.query if k != "cursor"] + [("cursor", cursor)]
        return replace(self, query=query)


def _model(cls: type[T]) -> Callable[[JSONValue], T]:
    def read(data: JSONValue) -> T:
        return cls.from_json(data)  # type: ignore[attr-defined, no-any-return]

    return read


def _platform(platform: str | None) -> list[tuple[str, str]]:
    if platform is None:
        return []
    if not is_platform(platform):
        raise ValueError(f"{platform!r} is not a platform's name")
    return [("platform", platform)]


def _listing(page_size: int | None, cursor: str | None, **filters: str | None) -> list[tuple[str, str]]:
    out = [(k, v) for k, v in filters.items() if v is not None]
    if page_size is not None:
        if page_size < 1:
            raise ValueError("page_size is 1 or more")
        out.append(("page_size", str(page_size)))
    if cursor is not None:
        out.append(("cursor", cursor))
    return out


class ClientCore:
    """The client's state (the server's origin and base, its handshake) and
    its calls, as requests and readers."""

    def __init__(
        self,
        url: str,
        *,
        user_agent: str = USER_AGENT,
        platform: str | None = None,
        credentials: Credentials | None = None,
        signer: RequestSigner | None = None,
        accept_language: str | None = None,
        base: str | None = None,
    ) -> None:
        if "://" not in url:
            url = "https://" + url
        if not plain_http_allowed(url):
            raise InsecureTransport(f"{url}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)")
        parts = urlsplit(url)
        self.root = f"{parts.scheme}://{parts.netloc}"
        self.pipeline = Pipeline(origin(url), credentials, signer)
        if platform is not None and not is_platform(platform):
            raise ValueError(f"{platform!r} is not a platform's name")
        if "/" in user_agent and " " not in user_agent.split("/", maxsplit=1)[0]:
            self.user_agent = user_agent
        else:
            raise ValueError("User-Agent is <Name>/<version> (SPEC.md § 2)")
        self.platform = platform
        self.accept_language = accept_language
        self.base = self._check_base(base) if base is not None else None
        self.hello: Handshake | None = None

    @staticmethod
    def _check_base(base: str) -> str:
        if not base.startswith("/") or base.startswith("//") or "?" in base or "#" in base:
            raise DocumentError(f"base {base[:80]!r} is not a path on the server's origin")
        return base.rstrip("/")

    # Requests.

    def url(self, path: str) -> str:
        """An absolute URL for a path or URL a document gave (`file`, `poll`…), on the server's origin
        unless it names another."""
        return urljoin(self.root + "/", path)

    def request(self, call: Call[T]) -> Request:
        if call.well_known:
            url = self.root + "/.well-known/lantern"
        else:
            if self.base is None:
                raise LanternError("no base yet: read the handshake first")
            url = self.root + self.base + "/v1" + call.path
        if call.query:
            url += "?" + urlencode(call.query, quote_via=quote, safe=",")
        return self.prepare(call.method, url, call.body)

    def prepare(
        self, method: str, url: str, body: JSONObject | None = None, headers: Mapping[str, str] | None = None
    ) -> Request:
        if not plain_http_allowed(url):
            raise InsecureTransport(f"{url}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)")
        h = Headers(
            {
                "User-Agent": self.user_agent,
                "Accept": JSON,
                "Accept-Encoding": "identity",
                "Accept-Schema": ", ".join(f"{k}={v}" for k, v in KNOWN.items()),
            }
        )
        if self.accept_language:
            h["Accept-Language"] = self.accept_language
        if self.platform:
            h[PLATFORM_HEADER] = self.platform
        raw = None
        if body is not None:
            raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
            h["Content-Type"] = JSON
        for k, v in (headers or {}).items():
            h[k] = v
        return self.pipeline.prepare(Request(method, url, h, raw))

    def finish(self, call: Call[T], status: int, headers: Headers, body: bytes) -> T:
        """The answer's document, read; the error of its status otherwise."""
        if status == 200:
            if media_type(headers.get("Content-Type")) != JSON:
                raise UnexpectedResponse(f"{call.what}: Content-Type {headers.get('Content-Type')!r}, not JSON", status)
            doc = load_json(body, where=call.what)
            schema = schema_of(doc, call.what)
            if schema > SCHEMA:
                raise NewerSchema(call.what, schema)
            result = call.read(doc)
            if call.well_known:
                self.hello = self.accept_handshake(result)  # type: ignore[arg-type]
            return result
        raise self.error(call.what, status, headers, body)

    @staticmethod
    def error(what: str, status: int, headers: Headers, body: bytes) -> LanternError:
        if 300 <= status < 400:
            return UnexpectedResponse(f"{what}: a redirect ({status}), which Lantern never sends", status)
        if status >= 400:
            return problem_error(status, body, headers)
        return UnexpectedResponse(f"{what}: status {status}", status)

    def accept_handshake(self, hello: Handshake) -> Handshake:
        if 1 not in hello.versions:
            raise LanternError("the server does not serve version 1 of the protocol")
        if self.base is None:
            self.base = self._check_base(hello.base)
        return hello

    # The calls.

    def handshake(self) -> Call[Handshake]:
        return Call("GET", "", _model(Handshake), "handshake", well_known=True)

    def apps(
        self,
        *,
        platform: str | None,
        type: str | None,
        title_id: str | None,
        q: str | None,
        sort: str | None,
        page_size: int | None,
        cursor: str | None,
    ) -> Call[AppsPage]:
        if sort is not None and sort not in ("name", "added", "release"):
            raise ValueError("sort is name, added or release")
        query = _platform(platform) + _listing(page_size, cursor, type=type, title_id=title_id, q=q, sort=sort)
        return Call("GET", "/apps", _model(AppsPage), "apps", query)

    def missing(
        self,
        installed: Iterable[InstalledApp | tuple[str, int]],
        want: Iterable[str],
        *,
        platform: str | None,
        page_size: int | None,
        cursor: str | None,
    ) -> Call[AppsPage]:
        if platform is None and self.platform is None:
            raise ValueError("what is missing needs a platform (SPEC.md § 6.3)")
        wants = list(dict.fromkeys(want))
        if not wants or any(w not in MISSING_WANTS for w in wants):
            raise ValueError("want lists base, update or dlc")
        items = [i if isinstance(i, InstalledApp) else InstalledApp(app_id=i[0], version_code=i[1]) for i in installed]
        doc = MissingRequest(schema=SCHEMA, installed=items, want=wants).to_json()
        return Call(
            "POST", "/apps/missing", _model(AppsPage), "missing", _platform(platform) + _listing(page_size, cursor), doc
        )

    def changes(self, since: str | None, platform: str | None) -> Call[Changes]:
        query = _platform(platform) + ([("since", since)] if since is not None else [])
        return Call("GET", "/changes", _model(Changes), "changes", query)

    def sections(self, platform: str | None) -> Call[Sections]:
        return Call("GET", "/sections", _model(Sections), "sections", _platform(platform))

    def title(self, title_id: str, platform: str | None) -> Call[Title]:
        if not CORE_ID.match(title_id) or title_id == "changes":
            raise ValueError(f"{title_id!r} is not a title id")
        return Call("GET", "/titles/" + quote(title_id, safe=""), _model(Title), "title", _platform(platform))

    def titles(self, ids: list[str], platform: str | None) -> Call[Titles]:
        if not ids or len(ids) > TITLES_AT_ONCE:
            raise ValueError(f"1 to {TITLES_AT_ONCE} title ids at once")
        bad = [i for i in ids if not CORE_ID.match(i)]
        if bad:
            raise ValueError(f"{bad[0]!r} is not a title id")
        query = [("ids", ",".join(ids)), *_platform(platform)]
        return Call("GET", "/titles", _model(Titles), "titles", query)

    def title_changes(self, since: str | None, platform: str | None) -> Call[TitleChanges]:
        query = _platform(platform) + ([("since", since)] if since is not None else [])
        return Call("GET", "/titles/changes", _model(TitleChanges), "title changes", query)

    def homebrew(
        self,
        *,
        platform: str | None,
        q: str | None,
        kind: str | None,
        genre: str | None,
        page_size: int | None,
        cursor: str | None,
    ) -> Call[HomebrewPage]:
        query = _platform(platform) + _listing(page_size, cursor, q=q, kind=kind, genre=genre)
        return Call("GET", "/homebrew", _model(HomebrewPage), "homebrew", query)

    def homebrew_entry(self, homebrew_id: str, platform: str | None) -> Call[HomebrewEntry]:
        if not HOMEBREW_ID.match(homebrew_id):
            raise ValueError(f"{homebrew_id!r} is not a homebrew id")
        return Call(
            "GET",
            "/homebrew/" + quote(homebrew_id, safe=""),
            _model(HomebrewEntry),
            "homebrew entry",
            _platform(platform),
        )

    def homebrew_updates(
        self,
        installed: Iterable[InstalledHomebrew | tuple[str, int]],
        *,
        platform: str | None,
        page_size: int | None,
        cursor: str | None,
    ) -> Call[HomebrewPage]:
        if platform is None and self.platform is None:
            raise ValueError("homebrew updates need a platform (SPEC.md § 8.5)")
        items = [i if isinstance(i, InstalledHomebrew) else InstalledHomebrew(id=i[0], build=i[1]) for i in installed]
        doc = HomebrewUpdatesRequest(schema=SCHEMA, installed=items).to_json()
        return Call(
            "POST",
            "/homebrew/updates",
            _model(HomebrewPage),
            "homebrew updates",
            _platform(platform) + _listing(page_size, cursor),
            doc,
        )

    def cheats(self, *, title_id: str | None, build_id: str | None, platform: str | None) -> Call[CheatSets]:
        query = _platform(platform) + _listing(None, None, title_id=title_id, build_id=build_id)
        return Call("GET", "/cheats", _model(CheatSets), "cheats", query)

    def cheat_url(self, cheat_id: str) -> str:
        if self.base is None:
            raise LanternError("no base yet: read the handshake first")
        return self.root + self.base + "/v1/cheats/" + quote(cheat_id, safe="")

    def offers(self, family: str) -> bool:
        """Whether the handshake says the server offers `family` to this caller, in a schema this library reads."""
        if self.hello is None:
            raise LanternError("no handshake yet")
        level = self.hello.features.get(family, 0)
        return 0 < level <= KNOWN.get(family, SCHEMA)


def next_cursor(seen: set[str], page_next: str | None, what: str) -> str | None:
    """The cursor of the next page, None after the last; refuses a server that gives one twice."""
    if page_next is None:
        return None
    if page_next in seen:
        raise UnexpectedResponse(f"{what}: the server gave the same cursor twice")
    seen.add(page_next)
    return page_next


def chunked(ids: Iterable[str]) -> list[list[str]]:
    """Title ids by requests of TITLES_AT_ONCE at most, each id once."""
    unique = list(dict.fromkeys(ids))
    return [unique[i : i + TITLES_AT_ONCE] for i in range(0, len(unique), TITLES_AT_ONCE)]


def merge_titles(parts: list[Titles]) -> Titles:
    if not parts:
        return Titles(schema=SCHEMA, titles=[], unknown=[])
    out = Titles(schema=SCHEMA, titles=[], unknown=[], extra=dict(parts[0].extra))
    for p in parts:
        out.titles += p.titles
        out.unknown += p.unknown
    return out


__all__ = ["JSON_DOCUMENT", "Call", "ClientCore", "chunked", "merge_titles", "next_cursor"]
