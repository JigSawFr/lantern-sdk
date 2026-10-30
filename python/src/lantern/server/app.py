"""The reference routes of the library family, over a Library: what a server
author mounts in an existing app (lantern.server.flask, lantern.server.fastapi)
to serve Lantern.

    app = LanternApp(library, uid="6f1c2a8e-…", name="Living room shelf")
    response = app.handle(ServerRequest("GET", "/api/lantern/v1/apps", …))

It answers the handshake (at /.well-known/lantern and <base>/v1/), the
families library (apps, what is missing, files), changes (with a journal),
titles, homebrew and cheats (reading), and refuses the others with 404
(their features are 0). Pairing, tokens and saves are not here: a server
plugs its own `authenticate` hook in, which resolves a request's credentials
to an Account.
"""

from __future__ import annotations

import secrets
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import TypeVar

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern._generated.models import (
    App,
    CheatSet,
    Homebrew,
    HomebrewUpdatesRequest,
    MissingRequest,
    Title,
)
from lantern.limits import TITLES_AT_ONCE
from lantern.profiles import profile, switch_ids
from lantern.server.files import file_response
from lantern.server.http import (
    ProblemError,
    ServerRequest,
    ServerResponse,
    bad_request,
    json_response,
    method_not_allowed,
    not_found,
    platform_of,
    problem_response,
    read_document,
    unauthorized,
)
from lantern.server.library import Account, Authenticate, Library
from lantern.server.paging import Cursors, Sealer, SinceTokens, SortKey, page_size
from lantern.vocabulary import BUILD_ID, CORE_ID, FAMILIES, HOMEBREW_ID, WORD

#: The scope each family needs (SPEC.md § 4.2).
SCOPE_OF = {"library": "library", "titles": "library", "changes": "library", "homebrew": "library", "cheats": "cheats"}
APP_SORTS = ("name", "added", "release")
T = TypeVar("T")
Handler = Callable[[ServerRequest, Account, Sequence[str]], ServerResponse]


@dataclass(frozen=True)
class Route:
    pattern: tuple[str, ...]
    methods: tuple[str, ...]
    family: str
    handler: str


ROUTES = (
    Route(("apps",), ("GET", "HEAD"), "library", "apps"),
    Route(("apps", "missing"), ("POST",), "library", "missing"),
    Route(("files", "{}"), ("GET", "HEAD"), "library", "file"),
    Route(("changes",), ("GET", "HEAD"), "changes", "changes"),
    Route(("titles",), ("GET", "HEAD"), "titles", "titles"),
    Route(("titles", "changes"), ("GET", "HEAD"), "titles", "title_changes"),
    Route(("titles", "{}"), ("GET", "HEAD"), "titles", "title"),
    Route(("homebrew",), ("GET", "HEAD"), "homebrew", "homebrew_list"),
    Route(("homebrew", "updates"), ("POST",), "homebrew", "homebrew_updates"),
    Route(("homebrew", "{}"), ("GET", "HEAD"), "homebrew", "homebrew_entry"),
    Route(("cheats",), ("GET", "HEAD"), "cheats", "cheats"),
    Route(("cheats", "{}"), ("GET", "HEAD"), "cheats", "cheat_text"),
)


def _epoch(text: str | None) -> int | None:
    if not text:
        return None
    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _ordinal(text: str | None) -> int | None:
    if not text:
        return None
    try:
        return date.fromisoformat(text).toordinal()
    except ValueError:
        return None


class LanternApp:
    """Lantern's read routes over a `library`.

    - `uid`: the server's UUID, which never changes; `name`: what clients show.
    - `authenticate`: resolves a request's `Authorization` (a bearer token
      today) to an Account, or None when it is not a valid one (401). A
      request without credentials is anonymous: it gets `anonymous_scopes`
      on a `public` server, nothing on a private one.
    - `secret`: seals cursors and since tokens; give the same one to every
      process of the server, and keep it across restarts, or the tokens they
      gave are refused.
    """

    def __init__(
        self,
        library: Library,
        *,
        uid: str,
        name: str,
        base: str = "/api/lantern",
        software: tuple[str, str] | None = None,
        motd: str | None = None,
        authenticate: Authenticate | None = None,
        public: bool = True,
        anonymous_scopes: Sequence[str] = ("library", "cheats"),
        page_limit: int = 500,
        default_page_size: int = 100,
        secret: bytes | None = None,
        cursor_lifetime: float = 3600.0,
        platforms: Sequence[str] | None = None,
    ) -> None:
        if not base.startswith("/"):
            raise ValueError("base is a path, such as /api/lantern")
        if not 1 <= page_limit <= 1000:
            raise ValueError("page_limit is 1 to 1000 (SPEC.md § 13)")
        self.library, self.uid, self.name, self.base = library, uid, name, base.rstrip("/")
        self.software, self.motd = software, motd
        self.authenticate, self.public = authenticate, public
        self.anonymous_scopes = frozenset(anonymous_scopes)
        self.page_limit, self.default_page_size = page_limit, default_page_size
        sealer = Sealer(secret or secrets.token_bytes(32))
        self.cursors = Cursors(sealer, cursor_lifetime)
        self.since = SinceTokens(sealer)
        self.fixed_platforms = list(platforms) if platforms is not None else None
        self.on_error: Callable[[BaseException], object] = traceback.print_exception

    # Dispatch.

    def handle(self, request: ServerRequest) -> ServerResponse:
        """The answer to `request`: never raises (a failure of the server answers 500 `internal`)."""
        try:
            return self.route(request)
        except ProblemError as e:
            return problem_response(request, e)
        except Exception as e:  # noqa: BLE001 - any failure of the server answers 500 (SPEC.md § 12)
            self.on_error(e)
            return problem_response(request, ProblemError(500, "internal", "The server failed; try again later."))

    def owns(self, path: str) -> bool:
        """Whether `path` is one of Lantern's: the handshake or below <base>/v1/."""
        return path == "/.well-known/lantern" or path == self.base + "/v1" or path.startswith(self.base + "/v1/")

    def route(self, request: ServerRequest) -> ServerResponse:
        path = request.path
        if path in ("/.well-known/lantern", self.base + "/v1", self.base + "/v1/"):
            account = self.account(request)
            if request.method not in ("GET", "HEAD"):
                raise method_not_allowed(["GET", "HEAD"])
            return json_response(request, self.handshake(account))
        prefix = self.base + "/v1/"
        if not path.startswith(prefix):
            raise not_found("No such route on this server.")
        segments = path[len(prefix) :].split("/")
        matched = [
            (route, [s for p, s in zip(route.pattern, segments, strict=True) if p == "{}"])
            for route in ROUTES
            if len(route.pattern) == len(segments)
            and all(p == s or (p == "{}" and s) for p, s in zip(route.pattern, segments, strict=True))
        ]
        if not matched:
            raise not_found("No such route on this server.")
        account = self.account(request)
        chosen = next(((r, a) for r, a in matched if request.method in r.methods), None)
        if chosen is None:
            raise method_not_allowed(list(dict.fromkeys(m for r, _ in matched for m in r.methods)))
        route, args = chosen
        self.allow(account, route.family)
        handler: Handler = getattr(self, "h_" + route.handler)
        return handler(request, account, args)

    # Who calls, and what they may do (SPEC.md § 4.2, § 5.1).

    def account(self, request: ServerRequest) -> Account:
        header = request.header("Authorization")
        if not header:
            return Account(scopes=self.anonymous_scopes if self.public else frozenset(), state="anonymous")
        scheme, _, value = header.strip().partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            raise unauthorized("Send a token: Authorization: Bearer <token>.")
        account = self.authenticate(request) if self.authenticate is not None else None
        if account is None:
            raise unauthorized("Unknown, revoked or expired token.", invalid_token=True)
        return account

    def offered(self, family: str) -> bool:
        if family == "changes":
            return "library" in self.library.families and self.library.journal() is not None
        return family in self.library.families

    def allow(self, account: Account, family: str) -> None:
        if not self.offered(family):
            raise not_found("This server does not offer it.")
        if account.state == "anonymous" and not self.public:
            raise unauthorized("This server asks for a token.")
        if account.state == "frozen":
            raise ProblemError(403, "account_frozen", "This account may do nothing for now.", title="Account frozen")
        if SCOPE_OF[family] not in account.scopes:
            raise ProblemError(403, "forbidden", f"This account lacks the scope {SCOPE_OF[family]}.")

    def features(self, account: Account) -> dict[str, int]:
        out = {}
        for family in FAMILIES:
            try:
                if family not in SCOPE_OF:
                    raise not_found()
                self.allow(account, family)
                out[family] = SCHEMA
            except ProblemError:
                out[family] = 0
        return out

    def platforms(self) -> list[str]:
        """The platforms the server has something for (SPEC.md § 4.2)."""
        if self.fixed_platforms is not None:
            return sorted(set(self.fixed_platforms))
        found: set[str] = set()
        lib = self.library
        if "library" in lib.families:
            found |= {a.platform for a in lib.apps()}
        if "titles" in lib.families:
            found |= {t.platform for t in lib.titles(())}
        if "homebrew" in lib.families:
            found |= {h.platform for h in lib.homebrew(())}
        if "cheats" in lib.families:
            found |= {c.platform for c in lib.cheats()}
        return sorted(found)

    def handshake(self, account: Account) -> JSONObject:
        """The handshake document (SPEC.md § 4.2) for `account`."""
        scopes: list[JSONValue] = [*sorted(account.scopes)]
        acc: JSONObject = {"state": account.state, "scopes": scopes}
        if account.name:
            acc["name"] = account.name
        doc: JSONObject = {"schema": SCHEMA, "uid": self.uid, "name": self.name}
        if self.software:
            doc["software"] = {"name": self.software[0], "version": self.software[1]}
        platforms: list[JSONValue] = list(self.platforms())
        doc.update({"base": self.base, "versions": [1], "platforms": platforms})
        if self.motd:
            doc["motd"] = self.motd
        features: JSONObject = dict(self.features(account))
        doc.update({"account": acc, "features": features, "limits": {"page_size": self.page_limit}})
        return doc

    # Library (SPEC.md § 6).

    def _size(self, request: ServerRequest) -> int:
        return page_size(request.query.get("page_size"), self.default_page_size, self.page_limit)

    def app_key(self, sort: str, releases: dict[tuple[str, str], int]) -> Callable[[App], SortKey]:
        if sort == "added":
            return lambda a: (-(_epoch(a.added) or 0), a.id)
        if sort == "release":

            def release(a: App) -> SortKey:
                day = releases.get((a.platform, a.title_id))
                return (0, -day, a.id) if day is not None else (1, 0, a.id)

            return release
        return lambda a: ((a.name or "").casefold(), a.id)

    def releases(self) -> dict[tuple[str, str], int]:
        if "titles" not in self.library.families:
            return {}
        out = {}
        for t in self.library.titles(()):
            day = _ordinal(t.release)
            if day is not None:
                out[(t.platform, t.title_id)] = day
        return out

    def _sort(self, request: ServerRequest) -> str:
        sort = request.query.get("sort") or "name"
        if sort not in APP_SORTS:
            raise bad_request("sort is " + ", ".join(APP_SORTS) + ".")
        return sort

    def _apps_page(self, request: ServerRequest, apps: list[App], scope: str, sort: str) -> ServerResponse:
        key = self.app_key(sort, self.releases() if sort == "release" else {})
        page = self.cursors.page(apps, key, size=self._size(request), cursor=request.query.get("cursor"), scope=scope)
        return json_response(
            request,
            {"schema": SCHEMA, "items": [a.to_json() for a in page.items], "total": page.total, "next": page.next},
        )

    def h_apps(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        q = request.query
        kind, title_id, text = q.get("type"), q.get("title_id"), q.get("q")
        if kind is not None and not WORD.match(kind):
            raise bad_request("type is a lower-case word, such as base, update or dlc.")
        if title_id is not None and not CORE_ID.match(title_id):
            raise bad_request("title_id is 1 to 128 letters, digits, '.', '_' and '-'.")
        sort = self._sort(request)
        apps = [
            a
            for a in self.library.apps()
            if (platform is None or a.platform == platform)
            and (kind is None or a.type == kind)
            and (title_id is None or a.title_id == title_id)
            and (not text or text.casefold() in (a.name or "").casefold())
        ]
        scope = self.cursors.scope("apps", platform, kind, title_id, text, sort)
        return self._apps_page(request, apps, scope, sort)

    def h_missing(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        try:
            doc = MissingRequest.from_json(read_document(request), "the body")
        except DocumentError as e:
            raise bad_request(f"installed is a list of {{app_id, version_code}}, want a list: {e}") from None
        platform = platform_of(request, required=True)
        assert platform is not None
        if any(not CORE_ID.match(i.app_id) or i.version_code < 0 for i in doc.installed):
            raise bad_request("installed is a list of {app_id, version_code}.")
        if not doc.want or any(w not in ("base", "update", "dlc") for w in doc.want):
            raise bad_request("want lists base, update or dlc.")
        sort = self._sort(request)
        found = missing(
            [a for a in self.library.apps() if a.platform == platform],
            platform,
            [(i.app_id, i.version_code) for i in doc.installed],
            set(doc.want),
        )
        scope = self.cursors.scope(
            "missing", platform, sorted((i.app_id, i.version_code) for i in doc.installed), sorted(set(doc.want)), sort
        )
        return self._apps_page(request, found, scope, sort)

    def h_file(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        file = self.library.file(args[0])
        if file is None:
            raise not_found("No such file; read the app again.")
        return file_response(request, file)

    def h_changes(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        journal = self.library.journal()
        if journal is None:
            raise not_found("This server does not offer it.")
        platform = platform_of(request)
        current = journal.position()
        token = self.since.give("s", journal.epoch, current)
        since = request.query.get("since")
        if since is None:
            return json_response(request, {"schema": SCHEMA, "added": [], "removed": [], "since": token})
        after = self.since.position("s", since, journal.epoch, journal.oldest(), current)
        added, removed = journal.app_changes(after, platform)
        gone_ids: list[JSONValue] = list(removed)
        return json_response(
            request, {"schema": SCHEMA, "added": [a.to_json() for a in added], "removed": gone_ids, "since": token}
        )

    # Titles (SPEC.md § 7).

    def _title(self, title: Title) -> JSONObject:
        return title.to_json()

    def h_titles(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        ids = [i for i in (request.query.get("ids") or "").split(",") if i]
        if not ids:
            raise bad_request("ids lists the title ids, comma-separated.")
        if len(ids) > TITLES_AT_ONCE:
            raise bad_request(f"At most {TITLES_AT_ONCE} ids at once.")
        if not all(CORE_ID.match(i) for i in ids):
            raise bad_request("A title id is 1 to 128 letters, digits, '.', '_' and '-'.")
        wanted = set(ids)
        titles = sorted(
            (
                t
                for t in self.library.titles(request.languages)
                if t.title_id in wanted and (platform is None or t.platform == platform)
            ),
            key=lambda t: (t.platform, t.title_id),
        )
        known = {t.title_id for t in titles}
        return json_response(
            request,
            {
                "schema": SCHEMA,
                "titles": [self._title(t) for t in titles],
                "unknown": [i for i in dict.fromkeys(ids) if i not in known],
            },
        )

    def h_title(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        found = [
            t
            for t in self.library.titles(request.languages)
            if t.title_id == args[0] and (platform is None or t.platform == platform)
        ]
        title = _one(found, "title")
        return json_response(request, {"schema": SCHEMA, **self._title(title)})

    def h_title_changes(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        journal = self.library.journal()
        since = request.query.get("since")
        if journal is None:
            if since is not None:
                raise ProblemError(410, "gone", "This server keeps no journal: read the titles again.")
            return json_response(
                request,
                {"schema": SCHEMA, "titles": [], "removed": [], "since": self.since.give("t", "", 0), "more": False},
            )
        current = journal.position()
        token = self.since.give("t", journal.epoch, current)
        doc: JSONObject = {"schema": SCHEMA, "titles": [], "removed": [], "since": token, "more": False}
        if since is not None:
            after = self.since.position("t", since, journal.epoch, journal.oldest(), current)
            titles, removed = journal.title_changes(after, platform, request.languages)
            doc["titles"] = [self._title(t) for t in titles]
            doc["removed"] = [r.to_json() for r in removed]
        return json_response(request, doc)

    # Homebrew (SPEC.md § 8).

    @staticmethod
    def listed(entry: Homebrew) -> JSONObject:
        """An entry as a listing shows it: without its manifests (SPEC.md § 8.2)."""
        doc = entry.to_json()
        for key in ("package", "packages"):
            value = doc.get(key)
            if isinstance(value, dict):
                value.pop("manifest", None)
            elif isinstance(value, list):
                for p in value:
                    if isinstance(p, dict):
                        p.pop("manifest", None)
        return doc

    @staticmethod
    def homebrew_key(e: Homebrew) -> SortKey:
        return (e.name.casefold(), e.platform, e.id)

    def h_homebrew_list(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        q = request.query
        text, kind, genre = q.get("q"), q.get("kind"), q.get("genre")
        if kind is not None and not WORD.match(kind):
            raise bad_request("kind is a lower-case word, such as app, game, port or tool.")
        if genre is not None and not WORD.match(genre):
            raise bad_request("genre is a lower-case word, such as adventure or puzzle.")
        if (q.get("sort") or "name") != "name":
            raise bad_request("homebrew is sorted by name.")
        entries = [
            e
            for e in self.library.homebrew(request.languages)
            if (platform is None or e.platform == platform)
            and (kind is None or e.effective_kind == kind)
            and (genre is None or genre in (e.genres or ()))
            and (not text or text.casefold() in e.name.casefold())
        ]
        scope = self.cursors.scope("homebrew", platform, text, kind, genre)
        page = self.cursors.page(
            entries, self.homebrew_key, size=self._size(request), cursor=q.get("cursor"), scope=scope
        )
        return json_response(
            request,
            {"schema": SCHEMA, "items": [self.listed(e) for e in page.items], "total": page.total, "next": page.next},
        )

    def h_homebrew_entry(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        if not HOMEBREW_ID.match(args[0]):
            raise not_found("No such homebrew.")
        found = [
            e
            for e in self.library.homebrew(request.languages)
            if e.id == args[0] and (platform is None or e.platform == platform)
        ]
        entry = _one(found, "homebrew")
        return json_response(request, {"schema": SCHEMA, **entry.to_json()})

    def h_homebrew_updates(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        try:
            doc = HomebrewUpdatesRequest.from_json(read_document(request), "the body")
        except DocumentError as e:
            raise bad_request(f"installed is a list of {{id, build}}: {e}") from None
        platform = platform_of(request, required=True)
        if any(not HOMEBREW_ID.match(i.id) or i.build < 0 for i in doc.installed):
            raise bad_request("installed is a list of {id, build}.")
        builds: dict[str, int] = {}
        for i in doc.installed:
            builds[i.id] = max(builds.get(i.id, -1), i.build)
        newer = [
            e
            for e in self.library.homebrew(request.languages)
            if e.platform == platform and e.id in builds and e.build > builds[e.id]
        ]
        scope = self.cursors.scope("updates", platform, sorted(builds.items()))
        page = self.cursors.page(
            newer, self.homebrew_key, size=self._size(request), cursor=request.query.get("cursor"), scope=scope
        )
        return json_response(
            request,
            {"schema": SCHEMA, "items": [self.listed(e) for e in page.items], "total": page.total, "next": page.next},
        )

    # Cheats (SPEC.md § 10).

    def h_cheats(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        title_id, build_id = request.query.get("title_id"), request.query.get("build_id")
        if title_id is not None and not CORE_ID.match(title_id):
            raise bad_request("title_id is 1 to 128 letters, digits, '.', '_' and '-'.")
        if build_id is not None and not BUILD_ID.match(build_id):
            raise bad_request("build_id is 1 to 64 letters, digits, '.', '_' and '-'.")
        sets: list[CheatSet] = [
            c
            for c in self.library.cheats()
            if (platform is None or c.platform == platform)
            and (title_id is None or c.title_id == title_id)
            and (build_id is None or c.build_id == build_id)
        ]
        sets.sort(key=lambda c: (c.platform, c.title_id, c.build_id or "", (c.source or "").casefold(), c.id))
        return json_response(request, {"schema": SCHEMA, "cheats": [c.to_json() for c in sets]})

    def h_cheat_text(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        found = [c for c in self.library.cheats() if c.id == args[0] and (platform is None or c.platform == platform)]
        file = self.library.cheat_file(args[0]) if found else None
        if file is None:
            raise not_found("No such cheat set.")
        return file_response(request, file)


def _one(found: list[T], what: str) -> T:
    """The one item found by id; 400 when several platforms have it (SPEC.md § 4.3)."""
    if not found:
        raise not_found(f"No such {what} on this server.")
    if len(found) > 1:
        raise bad_request("Several platforms have it: name one (Lantern-Platform).")
    return found[0]


def missing(apps: list[App], platform: str, installed: list[tuple[str, int]], want: set[str]) -> list[App]:
    """What a device of `platform` is missing (SPEC.md § 6.3), among `apps` (of that platform)."""
    prof = profile(platform)
    replaces = prof.newer_base_replaces if prof is not None else False
    by_app = {a.app_id: a for a in apps}
    have: dict[str, int] = {}
    for app_id, version in installed:
        known = by_app.get(app_id)
        if known is not None:
            title, kind = known.title_id, known.type
        elif platform == "switch" and len(app_id) == 16:
            try:
                title, kind = switch_ids(app_id)
            except ValueError:
                continue
        else:
            continue  # a game this server does not know
        if kind in ("base", "update"):
            have[title] = max(have.get(title, -1), version)
    ids = {app_id for app_id, _ in installed}
    out: dict[str, App] = {}
    for title, version in have.items():
        mine = [a for a in apps if a.title_id == title]
        if replaces:
            updates = [a for a in mine if a.type == "base" and a.app_id in ids]
        else:
            updates = [a for a in mine if a.type == "update"]
        newest = max((a.version_code for a in updates), default=-1)
        if "update" in want and newest > version:
            out.update({a.id: a for a in updates if a.version_code == newest})
        if "dlc" in want:
            out.update({a.id: a for a in mine if a.type == "dlc" and a.app_id not in ids})
    if "base" in want:
        out.update({a.id: a for a in apps if a.type == "base" and a.title_id not in have})
    return list(out.values())
