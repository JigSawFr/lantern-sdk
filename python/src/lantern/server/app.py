"""The reference routes of Lantern, over a Library: what a server author
mounts in an existing app (lantern.server.flask, lantern.server.fastapi) to
serve Lantern.

    app = LanternApp(library, uid="6f1c2a8e-…", name="Living room shelf", accounts=MemoryAccounts(…))
    response = app.handle(ServerRequest("GET", "/api/lantern/v1/apps", …))

It answers the handshake (at /.well-known/lantern and <base>/v1/), the
families library (apps, what is missing, files), changes (with a journal),
titles, homebrew and cheats (reading); events (a stream and long polling,
§ 18), grants for peers (with a grant key, § 19.3) and sync (with a sync
store, § 20); and refuses the others with 404 (their features are 0).

Who calls is decided one of two ways:

- with `accounts` (an Accounts store, such as MemoryAccounts), LanternApp
  issues the tokens itself: pairing (§ 5.2) with or without a device key,
  signed requests checked with a replay cache and a skew (§ 5.4),
  invitations (§ 5.5), rating caps (§ 5.6) and the administration API
  (§ 5.7). The server's approval page is its own (`approval_page()` is a
  start): it calls `desk.by_code()` and `desk.approve()`;
- with an `authenticate` hook, the server resolves its own tokens to an
  Account; one with a `key` is still checked for its signature.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import TypeVar

from lantern import ed25519, ratings, schema
from lantern import signatures as sig
from lantern import sync as syncing
from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern._generated.models import (
    AdminPairingDecision,
    AdminUserCreate,
    AdminUserUpdate,
    App,
    CheatSet,
    Homebrew,
    HomebrewUpdatesRequest,
    InvitationCreate,
    MissingRequest,
    PairingRequest,
    Rating,
    RatingCap,
    SyncWrite,
    Title,
)
from lantern.digest import digest_sha256, sha256_hex
from lantern.grants import LIFETIME_LIMIT, make_grant
from lantern.http import Headers
from lantern.limits import NAME, NOTE, TITLES_AT_ONCE, printable
from lantern.missing import missing
from lantern.server.accounts import (
    ACCOUNT_NAME,
    SCOPES,
    AccountError,
    Accounts,
    Device,
    Invitation,
    ordered_scopes,
    parse_time,
    utc,
)
from lantern.server.events import EVENT_SCOPES, EventHub, EventStreamBody, LibraryChange, Recorded
from lantern.server.files import file_response
from lantern.server.http import (
    ProblemError,
    ServerRequest,
    ServerResponse,
    bad_request,
    caching_headers,
    html_response,
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
from lantern.server.pairing import Limiter, PairingDesk, Pending, approval_page, slow_down
from lantern.server.sync import SyncStore
from lantern.spki import short as spki_short
from lantern.vocabulary import BUILD_ID, CORE_ID, FAMILIES, HOMEBREW_ID, PLATFORM, SHA256, WORD

#: The scope each family needs (SPEC.md § 4.2); pairing needs none.
SCOPE_OF = {
    "library": "library",
    "titles": "library",
    "changes": "library",
    "homebrew": "library",
    "cheats": "cheats",
    "admin": "admin",
    "peers": "library",
    "sync": "sync.read",
    "sync.write": "sync.write",
}
#: How long an invitation may live (SPEC.md § 5.5), and how many may wait at once.
INVITATION_DAYS = 30
INVITATIONS_LIMIT = 1000
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
    Route(("changes",), ("GET", "HEAD"), "changes", "changes"),  # with wait, a long poll: family events
    Route(("events",), ("GET",), "events", "events"),
    Route(("grants", "sha256", "{}"), ("GET", "HEAD"), "peers", "grant"),
    Route(("sync",), ("GET", "HEAD"), "sync", "sync_overview"),
    Route(("sync",), ("DELETE",), "sync.write", "sync_erase"),
    Route(("sync", "{}"), ("GET", "HEAD"), "sync", "sync_read"),
    Route(("sync", "{}"), ("PATCH", "DELETE"), "sync.write", "sync_write"),
    Route(("titles",), ("GET", "HEAD"), "titles", "titles"),
    Route(("titles", "changes"), ("GET", "HEAD"), "titles", "title_changes"),
    Route(("titles", "{}"), ("GET", "HEAD"), "titles", "title"),
    Route(("homebrew",), ("GET", "HEAD"), "homebrew", "homebrew_list"),
    Route(("homebrew", "updates"), ("POST",), "homebrew", "homebrew_updates"),
    Route(("homebrew", "{}"), ("GET", "HEAD"), "homebrew", "homebrew_entry"),
    Route(("cheats",), ("GET", "HEAD"), "cheats", "cheats"),
    Route(("cheats", "{}"), ("GET", "HEAD"), "cheats", "cheat_text"),
    Route(("pairing",), ("POST",), "pairing", "pair_start"),
    Route(("pairing", "{}"), ("GET",), "pairing", "pair_poll"),
    Route(("admin", "users"), ("GET", "HEAD", "POST"), "admin", "admin_users"),
    Route(("admin", "users", "{}"), ("PATCH", "DELETE"), "admin", "admin_user"),
    Route(("admin", "devices"), ("GET", "HEAD"), "admin", "admin_devices"),
    Route(("admin", "devices", "{}"), ("DELETE",), "admin", "admin_device"),
    Route(("admin", "pairings"), ("GET", "HEAD"), "admin", "admin_pairings"),
    Route(("admin", "pairings", "{}"), ("POST",), "admin", "admin_pairing"),
    Route(("admin", "invitations"), ("GET", "HEAD", "POST"), "admin", "admin_invitations"),
    Route(("admin", "invitations", "{}"), ("DELETE",), "admin", "admin_invitation"),
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
    - `accounts`: the server's accounts, devices and invitations; with it,
      LanternApp pairs devices and issues, checks and revokes their tokens
      (features pairing, signatures and admin). `bound_only`: issue and take
      only tokens bound to a device key (SPEC.md § 5.4). `skew`: auth.skew,
      60 to 900 seconds. `verify`: the server's approval page (a path on its
      origin, or an absolute URL), `/pair` by default. `spki`: the SHA-256 of
      the server's TLS key, which invitation links carry when no CA vouches
      for it (§ 5.5). `token_lifetime`: seconds a new token lives (none: until
      revoked). `scheme`: the scheme clients reach the server by, when a proxy
      in front of it changes it (a signature covers it). `pair_page`: the
      server's approval page at `verify` (signing the user in, then
      `desk.approve()`); without it, LanternApp serves a page that shows the
      code and the key's fingerprint and approves nothing (approval then goes
      through the administration API).
    - `authenticate`: without `accounts`, resolves a request's
      `Authorization` to an Account, or None when it is not a valid one (401).
      A request without credentials is anonymous: it gets `anonymous_scopes`
      on a `public` server, nothing on a private one.
    - `secret`: seals cursors and since tokens; give the same one to every
      process of the server, and keep it across restarts, or the tokens they
      gave are refused.
    - `events`: offer the family events (SPEC.md § 18): a stream at
      <base>/v1/events, and long polls with changes?wait=; `heartbeat`,
      `event_streams` and `wait_limit` are the handshake's limits.heartbeat,
      .event_streams and .wait. Streams are held in this process: run one
      process, or give each its own hub. `stream_probe`: how often an idle
      stream writes a blank line, to learn that its client left.
      `library_changed()` and `emit()` send events of the server's own.
    - `grant_seed`: the 32-byte seed of the server's grant key (SPEC.md
      § 19.3), which offers the family peers: grants for the files of the
      library, valid `grant_lifetime` seconds. Keep it, and keep it for
      grants alone: peers know its public key from the handshake.
    - `sync`: a SyncStore (MemorySync is one), which offers the family sync
      (SPEC.md § 20) to the accounts with sync.read and sync.write.
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
        accounts: Accounts | None = None,
        bound_only: bool = False,
        skew: int = sig.SKEW,
        verify: str = "/pair",
        spki: str | None = None,
        token_lifetime: float | None = None,
        scheme: str | None = None,
        pair_page: Callable[[ServerRequest], ServerResponse] | None = None,
        events: bool = True,
        heartbeat: int = 15,
        event_streams: int = 2,
        wait_limit: int = 60,
        stream_probe: float = 1.0,
        stream_lifetime: float = 3600.0,
        grant_seed: bytes | None = None,
        grant_lifetime: int = 600,
        sync: SyncStore | None = None,
    ) -> None:
        if not sig.SKEW_RANGE[0] <= skew <= sig.SKEW_RANGE[1]:
            raise ValueError("skew is 60 to 900 seconds (SPEC.md § 5.4)")
        if accounts is not None and authenticate is not None:
            raise ValueError("accounts or authenticate, not both")
        if not base.startswith("/"):
            raise ValueError("base is a path, such as /api/lantern")
        if not 1 <= page_limit <= 1000:
            raise ValueError("page_limit is 1 to 1000 (SPEC.md § 13)")
        if not (5 <= heartbeat <= 60 and event_streams >= 1 and 30 <= wait_limit <= 300):
            raise ValueError("heartbeat is 5 to 60 s, event_streams 1 or more, wait_limit 30 to 300 s (SPEC.md § 18.4)")
        if grant_seed is not None and len(grant_seed) != 32:
            raise ValueError("grant_seed is an Ed25519 seed of 32 bytes")
        if not 1 <= grant_lifetime <= LIFETIME_LIMIT:
            raise ValueError("grant_lifetime is 1 to 900 seconds (SPEC.md § 19.3)")
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
        self.accounts, self.bound_only, self.skew = accounts, bound_only, skew
        self.verify, self.spki, self.scheme = verify, spki, scheme
        self.pair_page = pair_page
        self.nonces = sig.NonceCache(2 * skew)
        self.desk = (
            PairingDesk(accounts, lifetime=token_lifetime, announce=self._announce_pairing)
            if accounts is not None
            else None
        )
        self.hub = EventHub() if events else None
        self.heartbeat, self.event_streams, self.wait_limit = heartbeat, event_streams, wait_limit
        self.stream_probe, self.stream_lifetime = stream_probe, stream_lifetime
        self.grant_seed, self.grant_lifetime = grant_seed, grant_lifetime
        self.grant_public = ed25519.public_key(grant_seed) if grant_seed is not None else None
        self.sync = sync
        subscribe = getattr(library, "subscribe", None)
        if self.hub is not None and callable(subscribe):
            subscribe(lambda change: self.library_changed([change]))
        self.pair_limiter = Limiter(30, 60.0)  # pairing requests per address, as the reference server
        self.attempts = Limiter(10, 600.0)  # wrong invitation codes per address

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
        """Whether `path` is one of Lantern's: the handshake, below <base>/v1/, or the approval page."""
        return (
            path == "/.well-known/lantern"
            or path == self.base + "/v1"
            or path.startswith(self.base + "/v1/")
            or (path == self.verify_path and self.verify_path is not None)
        )

    @property
    def verify_path(self) -> str | None:
        """The approval page's path, when it is on this server and LanternApp pairs."""
        return self.verify if self.accounts is not None and self.verify.startswith("/") else None

    def approval(self, request: ServerRequest) -> ServerResponse:
        """The approval page (SPEC.md § 5.2, § 5.3): the server's own, or one that shows the code asked
        and the short fingerprint of the server's key, and approves nothing."""
        if self.pair_page is not None:
            return self.pair_page(request)
        if request.method not in ("GET", "HEAD"):
            raise method_not_allowed(["GET", "HEAD"])
        code = (request.query.get("code") or request.query.get("invitation") or "")[:64]
        page = approval_page(
            fingerprint=spki_short(self.spki) if self.spki else None,
            code=code,
            message="Sign in on this server to approve a device: an administrator approves it from an admin app.",
            action=self.verify,
        )
        return html_response(request, page)

    def route(self, request: ServerRequest) -> ServerResponse:
        path = request.path
        if self.verify_path is not None and path == self.verify_path:
            return self.approval(request)
        if path in ("/.well-known/lantern", self.base + "/v1", self.base + "/v1/"):
            account = self.account(request)
            self.check_signature(request, account)
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
        if not any(self.offered(self._family(r, request)) for r, _ in matched):
            raise not_found("This server does not offer it.")
        account = self.account(request)
        self.check_signature(request, account)
        chosen = next(((r, a) for r, a in matched if request.method in r.methods), None)
        if chosen is None:
            raise method_not_allowed(list(dict.fromkeys(m for r, _ in matched for m in r.methods)))
        route, args = chosen
        self.allow(account, self._family(route, request))
        handler: Handler = getattr(self, "h_" + route.handler)
        return handler(request, account, args)

    @staticmethod
    def _family(route: Route, request: ServerRequest) -> str:
        """The family a request is of: changes with `wait` is a long poll of events (SPEC.md § 18.3)."""
        if route.handler == "changes" and "wait" in request.query:
            return "events"
        return route.family

    # Who calls, and what they may do (SPEC.md § 4.2, § 5.1).

    def account(self, request: ServerRequest) -> Account:
        header = request.header("Authorization")
        if not header:
            return Account(scopes=self.anonymous_scopes if self.public else frozenset(), state="anonymous")
        scheme, _, value = header.strip().partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            raise unauthorized("Send a token: Authorization: Bearer <token>.")
        if self.accounts is not None:
            account = self.account_of(value.strip())
        else:
            account = self.authenticate(request) if self.authenticate is not None else None
        if account is None:
            raise unauthorized("Unknown, revoked or expired token.", invalid_token=True)
        return account

    def account_of(self, token: str) -> Account | None:
        """The caller of a token the server issued: its device's scopes, cut back to its account's."""
        assert self.accounts is not None
        device = self.accounts.device_of(token)
        user = self.accounts.user(device.user) if device is not None else None
        if device is None or user is None:
            return None
        return Account(
            scopes=frozenset(s for s in device.scopes if s in user.scopes),
            state="frozen" if user.state == "frozen" else "active",
            name=user.name,
            key=device.key,
            rating_cap=device.rating_cap,
            device=device.id,
        )

    # Signed requests (SPEC.md § 5.4).

    def signature_problem(
        self, request: ServerRequest, code: str, detail: str, with_token: bool, key_id: str | None
    ) -> ProblemError:
        titles = {
            "signature_required": "Signature required",
            "signature_invalid": "Signature invalid",
            "signature_expired": "Signature expired",
            "signature_replayed": "Signature replayed",
        }
        challenge = 'Bearer realm="lantern"' + (', error="invalid_token"' if with_token else "")
        headers = {
            "WWW-Authenticate": challenge,
            "Accept-Signature": sig.accept_signature(with_token, bool(request.body), key_id),
        }
        return ProblemError(401, code, detail, title=titles[code], headers=headers)

    def verify_signature(self, request: ServerRequest, public: bytes, *, with_token: bool) -> None:
        """Checks the request's signature by `public`, or raises its 401; then its body against its
        Content-Digest (422 `digest_mismatch`)."""
        try:
            uri = request.target_uri(self.scheme)
        except ValueError:
            raise bad_request("No Host this server can read.") from None
        try:
            sig.verify_request(
                request.method,
                uri,
                request.headers,
                public,
                with_token=with_token,
                with_body=bool(request.body),
                nonces=self.nonces,
                skew=self.skew,
            )
        except sig.Refused as e:
            raise self.signature_problem(request, e.code, e.detail, with_token, sig.keyid(public)) from None
        if request.body:
            check_content_digest(request)

    def check_signature(self, request: ServerRequest, account: Account) -> None:
        if account.key is not None:
            self.verify_signature(request, account.key, with_token=True)
        elif self.bound_only and account.state != "anonymous":
            raise self.signature_problem(
                request,
                "signature_required",
                "This server takes only tokens bound to a device key: pair this device again, with a key.",
                True,
                None,
            )

    def offered(self, family: str) -> bool:
        if family in ("pairing", "signatures"):
            return self.accounts is not None
        if family == "admin":
            return self.accounts is not None
        if family == "changes":
            return "library" in self.library.families and self.library.journal() is not None
        if family == "events":
            return self.hub is not None
        if family == "peers":
            return self.grant_seed is not None and "library" in self.library.families
        if family in ("sync", "sync.write"):
            return self.sync is not None
        if family == "encrypted_saves":
            return False
        return family in self.library.families

    def allow(self, account: Account, family: str) -> None:
        if not self.offered(family):
            raise not_found("This server does not offer it.")
        if family == "pairing":  # whoever reaches the server may ask to pair (SPEC.md § 4.2, § 5.2)
            return
        if account.state == "anonymous" and (not self.public or family in ("admin", "sync", "sync.write")):
            raise unauthorized("This server asks for a token.")
        if account.state == "frozen":
            raise ProblemError(403, "account_frozen", "This account may do nothing for now.", title="Account frozen")
        if family == "events":  # SPEC.md § 18: offered to whoever may read one kind of event
            if not set(EVENT_SCOPES.values()) & account.scopes:
                raise ProblemError(403, "forbidden", "This account may read no event.")
            return
        if SCOPE_OF[family] not in account.scopes:
            raise ProblemError(403, "forbidden", f"This account lacks the scope {SCOPE_OF[family]}.")

    def features(self, account: Account) -> dict[str, int]:
        out = {}
        for family in FAMILIES:
            try:
                if family not in SCOPE_OF and family != "events":
                    raise not_found()
                self.allow(account, family)
                out[family] = SCHEMA
            except ProblemError:
                out[family] = 0
        # The same for every caller (SPEC.md § 4.2): whoever reaches the server may pair, with a key.
        out["pairing"] = out["signatures"] = SCHEMA if self.accounts is not None else 0
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
        if account.state != "anonymous":
            acc["bound"] = account.bound
        if account.rating_cap is not None:
            acc["rating_cap"] = account.rating_cap.to_json()
        doc: JSONObject = {"schema": SCHEMA, "uid": self.uid, "name": self.name}
        if self.software:
            doc["software"] = {"name": self.software[0], "version": self.software[1]}
        platforms: list[JSONValue] = list(self.platforms())
        doc.update({"base": self.base, "versions": [1], "platforms": platforms})
        if self.motd:
            doc["motd"] = self.motd
        if self.motd:
            doc["language"] = "en"
        features: JSONObject = dict(self.features(account))
        doc.update({"account": acc, "features": features})
        if features["signatures"]:
            doc["auth"] = {"bearer_only": not self.bound_only, "skew": self.skew}
        if self.grant_public is not None and self.offered("peers"):  # the same for every caller (L-19.3-3)
            doc["peers"] = {"key": base64.b64encode(self.grant_public).decode(), "grant_lifetime": self.grant_lifetime}
        limits: JSONObject = {"page_size": self.page_limit}
        if self.hub is not None:
            limits.update(heartbeat=self.heartbeat, event_streams=self.event_streams, wait=self.wait_limit)
        if self.sync is not None:
            limits["sync_items"] = self.sync.limit
        doc["limits"] = limits
        return doc

    # Rating caps (SPEC.md § 5.6).

    def hides(self, account: Account) -> Callable[[str, str], bool]:
        """Whether the caller's rating cap hides the title (platform, title_id), its apps and cheat sets."""
        cap = account.rating_cap
        if cap is None:
            return lambda platform, title_id: False
        rated: dict[tuple[str, str], list[Rating]] = {}
        if "titles" in self.library.families:
            rated = {(t.platform, t.title_id): list(t.ratings or ()) for t in self.library.titles(())}
        return lambda platform, title_id: ratings.hidden(rated.get((platform, title_id), []), cap)

    def file_hidden(self, account: Account, file_id: str) -> bool:
        """Whether the file is a hidden app's or a hidden homebrew's (SPEC.md § 5.6)."""
        if account.rating_cap is None:
            return False
        hide = self.hides(account)
        tail = "/files/" + file_id
        for a in self.library.apps():
            if a.file.endswith(tail) and hide(a.platform, a.title_id):
                return True
        if "homebrew" in self.library.families:
            for e in self.library.homebrew(()):
                files = [p.file for p in [e.package, *(e.packages or [])]]
                if any(f.endswith(tail) for f in files) and ratings.hidden(e.ratings, account.rating_cap):
                    return True
        return False

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
        hide = self.hides(account)
        apps = [
            a
            for a in self.library.apps()
            if not hide(a.platform, a.title_id)
            and (platform is None or a.platform == platform)
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
        hide = self.hides(account)
        found = missing(
            [a for a in self.library.apps() if a.platform == platform and not hide(a.platform, a.title_id)],
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
        if file is None or self.file_hidden(account, args[0]):
            raise not_found("No such file; read the app again.")
        return file_response(request, file)

    def changes_token(self) -> str:
        """The token of now (SPEC.md § 6.4): the journal's position, and the events' when there are."""
        journal = self.library.journal()
        epoch, position = (journal.epoch, journal.position()) if journal is not None else ("", 0)
        return self.since.give("s", epoch, position, (self.hub.epoch, self.hub.seq) if self.hub else None)

    def _token_at(self, seq: int) -> str:
        """An event's id: a token of /v1/changes at the journal's position now (L-18.1-1)."""
        journal = self.library.journal()
        epoch, position = (journal.epoch, journal.position()) if journal is not None else ("", 0)
        assert self.hub is not None
        return self.since.give("s", epoch, position, (self.hub.epoch, seq))

    def _app_changes(
        self, account: Account, since: str, platform: str | None
    ) -> tuple[list[JSONValue], list[JSONValue]]:
        journal = self.library.journal()
        if journal is None or not self._may(account, "changes"):
            return [], []
        after = self.since.position("s", since, journal.epoch, journal.oldest(), journal.position())
        added, removed = journal.app_changes(after, platform)
        hide = self.hides(account)
        return [a.to_json() for a in added if not hide(a.platform, a.title_id)], list(removed)

    def h_changes(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        if "wait" in request.query:
            return self.long_poll(request, account)
        journal = self.library.journal()
        if journal is None:
            raise not_found("This server does not offer it.")
        platform = platform_of(request)
        token = self.changes_token()
        since = request.query.get("since")
        if since is None:
            return json_response(request, {"schema": SCHEMA, "added": [], "removed": [], "since": token})
        shown, gone_ids = self._app_changes(account, since, platform)
        return json_response(request, {"schema": SCHEMA, "added": shown, "removed": gone_ids, "since": token})

    # Events (SPEC.md § 18).

    def _may(self, account: Account, family: str) -> bool:
        try:
            self.allow(account, family)
        except ProblemError:
            return False
        return True

    def emit(
        self,
        event: str,
        data: JSONObject,
        *,
        user: str | None = None,
        platform: str | None = None,
        title_id: str | None = None,
    ) -> Recorded | None:
        """Sends an event of the server's own (a request done, a backup kept: SPEC.md § 18.2) to the streams
        that may see it: of its scope, of `user`'s account, of `platform`, within their rating cap for
        `title_id`. None when the server offers no events."""
        if self.hub is None:
            return None
        return self.hub.emit(
            event, data, self._token_at, scope=EVENT_SCOPES.get(event), user=user, platform=platform, title_id=title_id
        )

    def library_changed(self, changes: Sequence[LibraryChange]) -> None:
        """The library changed (MemoryLibrary says so by itself): the event `library`, each caller told only
        of the families and platforms of which it sees a change (L-18.2-1)."""
        if self.hub is None or not changes:
            return
        self.hub.emit("library", {"schema": SCHEMA}, self._token_at, scope="library", changes=changes)

    def _announce_pairing(self, entry: Pending) -> None:
        doc: JSONObject = {
            "schema": SCHEMA,
            "id": entry.id,
            "code": entry.code,
            "device": entry.device,
            "expires": entry.expires,
        }
        if entry.key is not None:
            doc["key"] = sig.short_fingerprint(entry.key)
        self.emit("pairing", doc)

    def shutdown(self) -> None:
        """The server stops on purpose: every stream gets `shutdown` and ends (L-18.2-2)."""
        if self.hub is not None:
            self.hub.stop()

    def visible(self, account: Account, platform: str | None, rec: Recorded) -> JSONObject | None:
        """The data of an event for this caller, or None when it may not see it (SPEC.md § 18.2): of its
        scopes and account, of its platform when it named one, within its rating cap."""
        if rec.event in ("ready", "shutdown"):
            return rec.data
        if rec.scope is None or rec.scope not in account.scopes:
            return None
        if rec.event == "library":
            hide = self.hides(account) if account.rating_cap is not None else None
            families, platforms = set(), set()
            for c in rec.changes:
                if platform is not None and c.platform != platform:
                    continue
                if account.rating_cap is not None and c.ratings is not None:
                    hidden = ratings.hidden(list(c.ratings), account.rating_cap)
                else:
                    hidden = hide is not None and c.title_id is not None and hide(c.platform, c.title_id)
                if not hidden:
                    families.add(c.family)
                    platforms.add(c.platform)
            if not families:
                return None
            fams: list[JSONValue] = [*sorted(families)]
            plats: list[JSONValue] = [*sorted(platforms)]
            return {"schema": SCHEMA, "families": fams, "platforms": plats}
        if rec.user is not None and rec.user != account.name:
            return None
        if platform is not None and rec.platform not in (None, platform):
            return None
        capped = rec.title_id is not None and rec.platform is not None and account.rating_cap is not None
        if capped and self.hides(account)(str(rec.platform), str(rec.title_id)):
            return None
        return rec.data

    def _event_start(self, since: str | None) -> int:
        """The event a stream or a long poll starts after: `since`'s, or now's; 400 for a token never given,
        410 for one too old (L-18.1-4)."""
        assert self.hub is not None
        if since is None:
            return self.hub.seq
        found = self.since.events("s", since)
        if found is None or found[0] != self.hub.epoch or found[1] < self.hub.floor:
            raise ProblemError(
                410, "gone", "This event id is too old for this server: read again, then connect without one."
            )
        if found[1] > self.hub.seq:
            raise bad_request("Unknown event id: one this server never gave.")
        return found[1]

    def long_poll(self, request: ServerRequest, account: Account) -> ServerResponse:
        assert self.hub is not None
        wait, since = request.query.get("wait") or "", request.query.get("since")
        if not wait.isdigit() or since is None:
            raise bad_request("wait is a number of seconds, from 0, with since (SPEC.md § 18.3).")
        platform = platform_of(request)
        start = self._event_start(since)
        deadline = time.monotonic() + min(int(wait), self.wait_limit)
        while True:
            examined = self.hub.seq
            found: list[JSONValue] = []
            for e in self.hub.after(start):
                if e.seq > examined:
                    break
                data = self.visible(account, platform, e)
                if data is not None and e.event not in ("ready", "shutdown"):
                    found.append({"id": e.id, "event": e.event, "data": data})
            left = deadline - time.monotonic()
            if found or left <= 0 or self.hub.stopping.is_set():
                break
            self.hub.wait(examined, min(left, 1.0))
        added, removed = self._app_changes(account, since, platform)
        doc: JSONObject = {
            "schema": SCHEMA,
            "added": added,
            "removed": removed,
            "since": self._token_at(examined),
            "events": found,
        }
        response = json_response(request, doc)
        response.headers["Cache-Control"] = "no-store"
        return response

    def h_events(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.hub is not None
        hub = self.hub
        platform = platform_of(request)
        since = request.query.get("since") or (request.header("Last-Event-ID") or "").strip() or None
        start = self._event_start(since)
        ready = since if since is not None else self._token_at(start)
        header = request.header("Authorization")
        key = "t:" + hashlib.sha256(header.encode()).hexdigest() if header else "a:" + request.remote
        if not hub.take_stream(key, self.event_streams):
            raise slow_down(self.heartbeat, f"At most {self.event_streams} event streams at once (SPEC.md § 18.4).")

        def alive() -> bool:
            try:
                now = self.account(request)
            except ProblemError:
                return False
            return now.state != "frozen"

        body = EventStreamBody(
            hub,
            start=start,
            ready_id=ready,
            visible=lambda rec: self.visible(account, platform, rec),
            alive=alive,
            release=lambda: hub.release_stream(key),
            shutdown_id=lambda: self._token_at(hub.seq),
            heartbeat=self.heartbeat,
            probe=self.stream_probe,
            lifetime=self.stream_lifetime,
        )
        headers = Headers(
            {
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
                "Vary": "Authorization, Lantern-Platform",
            }
        )
        return ServerResponse(200, headers, body)

    # Grants (SPEC.md § 19.3).

    def h_grant(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.grant_seed is not None
        sha = args[0]
        if not SHA256.match(sha):
            raise not_found("A file is named by its SHA-256, lower-case hex.")
        platform = platform_of(request)
        hide = self.hides(account)
        size = next(
            (
                a.size
                for a in self.library.apps()
                if a.sha256 == sha and (platform is None or a.platform == platform) and not hide(a.platform, a.title_id)
            ),
            None,
        )
        if size is None and "homebrew" in self.library.families:
            for e in self.library.homebrew(()):
                if (platform is None or e.platform == platform) and not ratings.hidden(e.ratings, account.rating_cap):
                    size = next((p.size for p in [e.package, *(e.packages or [])] if p.sha256 == sha), size)
        if size is None:
            raise not_found("No such file for this caller.")
        exp = int(time.time()) + self.grant_lifetime
        doc: JSONObject = {
            "schema": SCHEMA,
            "sha256": sha,
            "size": size,
            "grant": make_grant(self.grant_seed, self.uid, sha, size, exp),
            "expires": utc(datetime.fromtimestamp(exp, UTC)),
        }
        response = json_response(request, doc)
        response.headers["Cache-Control"] = "no-store"
        return response

    # Sync (SPEC.md § 20).

    @staticmethod
    def _collection(name: str) -> str:
        if name not in syncing.COLLECTIONS:
            raise not_found("No such collection: " + ", ".join(syncing.COLLECTIONS) + ".")
        return name

    def _sync_event(self, account: Account, collection: str, rev: int) -> None:
        self.emit("sync", {"schema": SCHEMA, "collection": collection, "rev": rev}, user=account.name)

    def h_sync_overview(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.sync is not None
        assert account.name is not None
        generation, collections = self.sync.overview(account.name)
        doc: JSONObject = {
            "schema": SCHEMA,
            "generation": generation,
            "collections": {k: {"rev": rev, "items": n} for k, (rev, n) in collections.items()},
        }
        if account.device is not None and syncing.DEVICE_ID.match(account.device):
            doc["device"] = account.device
        return json_response(request, doc)

    def h_sync_erase(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.sync is not None
        assert account.name is not None
        self.sync.erase(account.name)
        for name in syncing.COLLECTIONS:
            self._sync_event(account, name, 0)
        return _no_content(request)

    def h_sync_read(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.sync is not None
        assert account.name is not None
        name = self._collection(args[0])
        text = request.query.get("since")
        if text is not None and not text.isdigit():
            raise bad_request("since is a revision, an integer.")
        since = int(text) if text is not None else None
        generation, rev, items = self.sync.read(account.name, name, since)

        def key(i: syncing.Item) -> SortKey:
            return (i.rev or 0, i.key) if since is not None else (i.key,)

        scope = self.cursors.scope("sync", account.name, name, since, generation)
        page = self.cursors.page(items, key, size=self._size(request), cursor=request.query.get("cursor"), scope=scope)
        doc: JSONObject = {
            "schema": SCHEMA,
            "collection": name,
            "generation": generation,
            "rev": rev,
            "items": [i.to_json() for i in page.items],
            "next": page.next,
        }
        return json_response(request, doc)

    def _sync_item(self, account: Account, name: str, raw: JSONValue) -> syncing.Item:
        """An item sent, of its collection's form (SPEC.md § 20.2, § 20.4, L-20.4-6); 403 for another device's
        item of installed (L-20.4-5)."""
        if not isinstance(raw, dict) or not isinstance(raw.get("key"), str) or "rev" in raw:
            raise bad_request("An item is {key, value, updated} or {key, deleted: true, updated} (SPEC.md § 20.2).")
        key, updated = raw["key"], raw.get("updated")
        if syncing.parse_updated(updated) is None:
            raise bad_request("updated is a UTC time to the millisecond, such as 2026-10-30T09:12:03.250Z.")
        assert isinstance(key, str)
        assert isinstance(updated, str)
        deleted = raw.get("deleted")
        if ("value" in raw) == (deleted is not None) or deleted not in (None, True):
            raise bad_request("An item has a value, or deleted: true, not both.")
        value = raw.get("value")
        if name == "wishes":
            platform, _, title_id = key.partition("/")
            if not PLATFORM.match(platform) or not CORE_ID.match(title_id):
                raise bad_request(f"{key[:80]!r}: a wish's key is <platform>/<title_id> (SPEC.md § 20.2).")
            if value is not None and (
                not isinstance(value, dict)
                or value.get("platform") != platform
                or value.get("title_id") != title_id
                or schema.definition("wish", value)
            ):
                raise bad_request("A wish is {platform, title_id, name?, note?}, those of its key.")
        elif name == "installed":
            if not syncing.DEVICE_ID.match(key):
                raise bad_request("An item of installed is keyed by its device's id, d_….")
            if value is not None and (not isinstance(value, dict) or schema.definition("installed", value)):
                raise bad_request(
                    "installed is {device, platform, apps: [{app_id, version_code}], homebrew: [{id, "
                    "build}]} (SPEC.md § 20.2)."
                )
            if key != account.device:
                raise ProblemError(403, "forbidden", "A device writes its own item of installed only (SPEC.md § 20.4).")
        return syncing.Item(key, updated, value, deleted is True)

    def h_sync_write(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.sync is not None
        assert account.name is not None
        name = self._collection(args[0])
        if request.method == "DELETE":
            self.sync.erase(account.name, name)
            self._sync_event(account, name, 0)
            return _no_content(request)
        raw = read_document(request)
        try:
            doc = SyncWrite.from_json(raw, "the body")
        except DocumentError:
            doc = None
        items = raw.get("items")
        if doc is None or not isinstance(items, list) or not 1 <= len(items) <= syncing.WRITE_LIMIT:
            raise bad_request(f"A write is {{schema, generation, items}}, 1 to {syncing.WRITE_LIMIT} items.")
        checked = [self._sync_item(account, name, i) for i in items]
        if len({i.key for i in checked}) != len(checked):
            raise bad_request("An item's key twice in one write.")
        before = self.sync.overview(account.name)[1][name][0]
        generation, rev, out = self.sync.merge(
            account.name,
            name,
            doc.generation,
            checked,
            if_match=request.header("If-Match"),
            now=datetime.now(UTC),
            skew=self.skew,
        )
        if rev != before:
            self._sync_event(account, name, rev)
        body: JSONObject = {
            "schema": SCHEMA,
            "collection": name,
            "generation": generation,
            "rev": rev,
            "items": [i.to_json() for i in out],
        }
        return json_response(request, body)

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
        hide = self.hides(account)
        titles = sorted(
            (
                t
                for t in self.library.titles(request.languages)
                if t.title_id in wanted
                and (platform is None or t.platform == platform)
                and not hide(t.platform, t.title_id)
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
        hide = self.hides(account)
        found = [
            t
            for t in self.library.titles(request.languages)
            if t.title_id == args[0]
            and (platform is None or t.platform == platform)
            and not hide(t.platform, t.title_id)
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
            hide = self.hides(account)
            doc["titles"] = [self._title(t) for t in titles if not hide(t.platform, t.title_id)]
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
            if not ratings.hidden(e.ratings, account.rating_cap)
            and (platform is None or e.platform == platform)
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
            if e.id == args[0]
            and (platform is None or e.platform == platform)
            and not ratings.hidden(e.ratings, account.rating_cap)
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
            if e.platform == platform
            and e.id in builds
            and e.build > builds[e.id]
            and not ratings.hidden(e.ratings, account.rating_cap)
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
        hide = self.hides(account)
        sets: list[CheatSet] = [
            c
            for c in self.library.cheats()
            if not hide(c.platform, c.title_id)
            and (platform is None or c.platform == platform)
            and (title_id is None or c.title_id == title_id)
            and (build_id is None or c.build_id == build_id)
        ]
        sets.sort(key=lambda c: (c.platform, c.title_id, c.build_id or "", (c.source or "").casefold(), c.id))
        return json_response(request, {"schema": SCHEMA, "cheats": [c.to_json() for c in sets]})

    def h_cheat_text(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        hide = self.hides(account)
        found = [
            c
            for c in self.library.cheats()
            if c.id == args[0] and (platform is None or c.platform == platform) and not hide(c.platform, c.title_id)
        ]
        file = self.library.cheat_file(args[0]) if found else None
        if file is None:
            raise not_found("No such cheat set.")
        return file_response(request, file)

    # Pairing (SPEC.md § 5.2, § 5.4, § 5.5).

    def verify_url(self, request: ServerRequest) -> str:
        if "://" in self.verify:
            return self.verify
        try:
            return request.origin(self.scheme) + self.verify
        except ValueError:
            raise bad_request("No Host this server can read.") from None

    def h_pair_start(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.desk is not None
        assert self.accounts is not None
        raw = read_document(request)
        try:
            doc = PairingRequest.from_json(raw, "the body")
        except DocumentError as e:
            raise bad_request(f"A pairing request is {{schema, device, scopes, key?, invitation?}}: {e}") from None
        device = doc.device.strip()
        if not device or printable(device, NAME) != device:
            raise bad_request("device is the device's name, 512 bytes at most, without control characters.")
        known = ordered_scopes(doc.scopes)
        if not known:
            raise bad_request("scopes names none of " + ", ".join(SCOPES) + ".")
        key = None
        if doc.key is not None:
            key = _device_key(doc.key.alg, doc.key.public_key)
        elif self.bound_only:
            raise ProblemError(
                400,
                "key_required",
                "This server binds every token to a device key: send one (key: {alg: ed25519, public_key}).",
                title="Device key required",
            )
        wait = self.pair_limiter.hit(request.remote)
        if wait:
            raise slow_down(wait, "Too many pairing requests from this address.")
        invitation: Invitation | None = None
        if doc.invitation is not None:
            wait = self.attempts.wait(request.remote)
            if wait:
                raise slow_down(wait, "Too many attempts at invitations from this address.")
            invitation = self.accounts.redeem(doc.invitation)
            if invitation is None:
                self.attempts.record(request.remote)
                raise ProblemError(
                    410, "gone", "This invitation is unknown, expired, revoked or used up.", title="Invitation gone"
                )
        entry = self.desk.start(device, known, key, waiting=invitation is None)
        if invitation is not None:  # approved at once, as the invitation says (SPEC.md § 5.5)
            self.desk.approve(entry, invitation.user, invitation.scopes, invitation.rating_cap, invitation.id)
        verify = self.verify_url(request)
        complete = verify + ("&" if "?" in verify else "?") + "code=" + entry.code
        response = json_response(
            request,
            {
                "schema": SCHEMA,
                "code": entry.code,
                "verify": verify,
                "verify_complete": complete,
                "poll": f"{self.base}/v1/pairing/{entry.poll}",
                "interval": entry.interval,
                "expires": self.desk.expires,
            },
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    def h_pair_poll(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.desk is not None
        entry = self.desk.peek(args[0])
        if entry is not None and entry.key is not None:  # a pairing with a key polls signed by it (SPEC.md § 5.4)
            self.verify_signature(request, entry.key, with_token=False)
        doc = self.desk.poll(args[0])
        if doc is None:
            waiting = ServerResponse(202, caching_headers(request))
            waiting.headers["Cache-Control"] = "no-store"
            waiting.headers["Content-Length"] = "0"
            return waiting
        response = json_response(request, doc)
        response.headers["Cache-Control"] = "no-store"
        return response

    # Administration (SPEC.md § 5.7).

    def _admin_page(
        self, request: ServerRequest, docs: list[JSONObject], scope: str, key: Callable[[JSONObject], SortKey]
    ) -> ServerResponse:
        page = self.cursors.page(docs, key, size=self._size(request), cursor=request.query.get("cursor"), scope=scope)
        items: list[JSONValue] = list(page.items)
        return json_response(request, {"schema": SCHEMA, "items": items, "total": page.total, "next": page.next})

    def _user_doc(self, name: str) -> JSONObject:
        assert self.accounts is not None
        user = self.accounts.user(name)
        if user is None:
            raise not_found("No such account.")
        doc: JSONObject = {
            "name": user.name,
            "state": "frozen" if user.state == "frozen" else "active",
            "scopes": list(user.scopes),
            "devices": len(self.accounts.devices(user.name)),
            "created": user.created,
        }
        return doc

    @staticmethod
    def _scopes(values: Sequence[str] | None, what: str = "scopes") -> tuple[str, ...]:
        if values is None or any(v not in SCOPES for v in values) or len(set(values)) != len(values):
            raise bad_request(f"{what} is a list of scopes: " + ", ".join(SCOPES) + ".")
        return ordered_scopes(values)

    def h_admin_users(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.accounts is not None
        if request.method != "POST":
            docs = [self._user_doc(u.name) for u in self.accounts.users()]
            return self._admin_page(request, docs, self.cursors.scope("admin-users"), lambda d: (str(d["name"]),))
        raw = read_document(request)
        if "password" in raw:
            raise bad_request("An account made here has no password (SPEC.md § 5.7).")
        try:
            doc = AdminUserCreate.from_json(raw, "the body")
        except DocumentError as e:
            raise bad_request(f"An account is {{schema, name, scopes, state?}}: {e}") from None
        state = doc.state or "active"
        if not ACCOUNT_NAME.match(doc.name) or state not in ("active", "frozen"):
            raise bad_request("name is 1 to 64 letters, digits, '.', '_' and '-'; state is active or frozen.")
        try:
            self.accounts.create_user(doc.name, self._scopes(doc.scopes), state)
        except AccountError as e:
            raise ProblemError(e.status, e.code, e.detail) from None
        return json_response(request, {"schema": SCHEMA, **self._user_doc(doc.name)}, 201)

    def h_admin_user(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.accounts is not None
        if request.method == "DELETE":
            return self.delete_user(request, account, args[0])
        try:
            doc = AdminUserUpdate.from_json(read_document(request), "the body")
        except DocumentError as e:
            raise bad_request(f"A change is {{schema, state?, scopes?}}: {e}") from None
        if doc.state is None and doc.scopes is None:
            raise bad_request("Give state (active or frozen), scopes, or both.")
        if doc.state is not None and doc.state not in ("active", "frozen"):
            raise bad_request("state is active or frozen.")
        scopes = None if doc.scopes is None else self._scopes(doc.scopes)
        try:
            self.accounts.update_user(args[0], state=doc.state, scopes=scopes)
        except AccountError as e:
            raise ProblemError(e.status, e.code, e.detail) from None
        return json_response(request, {"schema": SCHEMA, **self._user_doc(args[0])})

    def delete_user(self, request: ServerRequest, account: Account, name: str) -> ServerResponse:
        """DELETE an account (SPEC.md § 5.7): confirmed by its name (400 otherwise), never the caller's own
        (409); its devices, invitations, pairings not yet collected and sync data go at once, and its
        streams end at their next wake (L-5.7-6, L-5.7-7, L-18.1-8)."""
        assert self.accounts is not None
        if self.accounts.user(name) is None:
            raise not_found("No such account.")
        if request.query.get("confirm") != name:
            raise bad_request("confirm repeats the account's name: ?confirm=<name> (SPEC.md § 5.7).")
        if name == account.name:
            raise ProblemError(409, "conflict", "An admin does not delete the account they use.")
        try:
            self.accounts.delete_user(name)
        except AccountError as e:
            raise ProblemError(e.status, e.code, e.detail) from None
        if self.desk is not None:
            self.desk.forget_user(name)
        if self.sync is not None:
            self.sync.forget(name)
        if self.hub is not None:
            self.hub.wake()
        return _no_content(request)

    @staticmethod
    def device_doc(device: Device) -> JSONObject:
        """A device as the administration API shows it: never its token, nor the token's hash."""
        doc: JSONObject = {
            "id": device.id,
            "user": device.user,
            "device": device.device,
            "scopes": list(device.scopes),
            "created": device.created,
            "bound": device.bound,
        }
        if device.key is not None:
            doc["key"] = sig.short_fingerprint(device.key)
        if device.rating_cap is not None:
            doc["rating_cap"] = device.rating_cap.to_json()
        for k, v in (("invitation", device.invitation), ("expires", device.expires), ("last_used", device.last_used)):
            if v is not None:
                doc[k] = v
        return doc

    def h_admin_devices(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.accounts is not None
        user = request.query.get("user")
        docs = [self.device_doc(d) for d in self.accounts.devices(user)]
        return self._admin_page(
            request,
            docs,
            self.cursors.scope("admin-devices", user),
            lambda d: (str(d["user"]), str(d["created"]), str(d["id"])),
        )

    def h_admin_device(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.accounts is not None
        if not self.accounts.revoke(args[0]):
            raise not_found("No such device.")
        return _no_content(request)

    def h_admin_pairings(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.desk is not None
        docs: list[JSONObject] = []
        for e in self.desk.waiting():
            doc: JSONObject = {
                "id": e.id,
                "code": e.code,
                "device": e.device,
                "scopes": list(e.scopes),
                "created": e.created,
                "expires": e.expires,
            }
            if e.key is not None:
                doc["key"] = sig.short_fingerprint(e.key)
            docs.append(doc)
        return self._admin_page(
            request, docs, self.cursors.scope("admin-pairings"), lambda d: (str(d["created"]), str(d["id"]))
        )

    def h_admin_pairing(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.desk is not None
        assert self.accounts is not None
        try:
            doc = AdminPairingDecision.from_json(read_document(request), "the body")
        except DocumentError as e:
            raise bad_request(f"A decision is {{schema, decision, user?, scopes?, rating_cap?}}: {e}") from None
        entry = self.desk.by_id(args[0])
        if entry is None:
            raise not_found("No such pairing waiting: approved, refused or expired.")
        if doc.decision == "refuse":
            self.desk.refuse(entry)
            return _no_content(request)
        if doc.decision != "approve":
            raise bad_request("decision is approve or refuse.")
        name = doc.user or account.name
        if name is None or self.accounts.user(name) is None:
            raise bad_request(f"No account named {str(name)[:64]}.")
        scopes = None if doc.scopes is None else self._scopes(doc.scopes)
        self.desk.approve(entry, name, scopes, _cap(doc.rating_cap))
        return _no_content(request)

    def invitation_doc(self, request: ServerRequest, inv: Invitation) -> JSONObject:
        verify = self.verify_url(request)
        query = f"invitation={inv.code}" + (f"&spki={self.spki.lower()}" if self.spki else "")
        doc: JSONObject = {
            "id": inv.id,
            "code": inv.code,
            "link": verify + ("&" if "?" in verify else "?") + query,
            "user": inv.user,
            "scopes": list(inv.scopes),
            "expires": inv.expires,
            "devices": inv.devices,
            "used": inv.used,
            "created": inv.created,
        }
        if inv.rating_cap is not None:
            doc["rating_cap"] = inv.rating_cap.to_json()
        if inv.note is not None:
            doc["note"] = inv.note
        return doc

    def h_admin_invitations(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.accounts is not None
        if request.method != "POST":
            docs = [self.invitation_doc(request, i) for i in self.accounts.invitations()]
            return self._admin_page(
                request, docs, self.cursors.scope("admin-invitations"), lambda d: (str(d["created"]), str(d["id"]))
            )
        try:
            doc = InvitationCreate.from_json(read_document(request), "the body")
        except DocumentError as e:
            raise bad_request(f"An invitation is {{schema, user, scopes, expires, devices, …}}: {e}") from None
        user = self.accounts.user(doc.user)
        if user is None:
            raise bad_request("user is the account the devices join, which exists.")
        scopes = self._scopes(doc.scopes)
        if not scopes or any(x not in user.scopes for x in scopes):
            raise bad_request("scopes are some of the account's own (SPEC.md § 5.5).")
        expires = parse_time(doc.expires)
        now = datetime.now(UTC)
        if expires is None or not now < expires <= now + timedelta(days=INVITATION_DAYS):
            raise bad_request(f"expires is an RFC 3339 time in the next {INVITATION_DAYS} days (SPEC.md § 5.5).")
        if not 1 <= doc.devices <= 100:
            raise bad_request("devices is how many devices may redeem it, 1 to 100.")
        if doc.note is not None and (printable(doc.note, NOTE) != doc.note or "\n" in doc.note):
            raise bad_request("note: 120 bytes at most, without control characters.")
        if len(self.accounts.invitations()) >= INVITATIONS_LIMIT:
            raise slow_down(3600, f"At most {INVITATIONS_LIMIT} invitations at once.")
        inv = self.accounts.create_invitation(
            user.name, scopes, utc(expires), doc.devices, rating_cap=_cap(doc.rating_cap), note=doc.note
        )
        return json_response(request, {"schema": SCHEMA, **self.invitation_doc(request, inv)}, 201)

    def h_admin_invitation(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        assert self.accounts is not None
        if not self.accounts.revoke_invitation(args[0]):
            raise not_found("No such invitation.")
        return _no_content(request)


def _no_content(request: ServerRequest) -> ServerResponse:
    headers = caching_headers(request)
    return ServerResponse(204, headers)


def _cap(cap: RatingCap | None) -> RatingCap | None:
    if cap is None:
        return None
    problem = ratings.cap_problem(cap)
    if problem:
        raise bad_request(problem + " (SPEC.md § 5.6).")
    return cap


def _device_key(alg: str, public_key: str) -> bytes:
    """A device's public key from a pairing request (SPEC.md § 5.4): 400 unless it is an Ed25519 key that
    decodes canonically and is not of small order (L-5.4-12)."""
    try:
        public = base64.b64decode(public_key, validate=True)
    except (binascii.Error, ValueError):
        public = b""
    if alg != "ed25519" or not ed25519.is_public_key(public):
        raise bad_request("key is {alg: ed25519, public_key: the 32 bytes of an Ed25519 key, base64}.")
    return public


def check_content_digest(request: ServerRequest) -> None:
    """A body against its Content-Digest (RFC 9530): 400 when it is not one this server reads, 422
    `digest_mismatch` when the body does not match it."""
    header = request.header("Content-Digest")
    if header is None:
        return
    announced = digest_sha256(header)
    if announced is None:
        raise bad_request("Content-Digest gives no sha-256 this server reads.")
    if announced != sha256_hex(request.body):
        raise ProblemError(
            422, "digest_mismatch", "The body does not match its Content-Digest.", title="Digest mismatch"
        )


def _one(found: list[T], what: str) -> T:
    """The one item found by id; 400 when several platforms have it (SPEC.md § 4.3)."""
    if not found:
        raise not_found(f"No such {what} on this server.")
    if len(found) > 1:
        raise bad_request("Several platforms have it: name one (Lantern-Platform).")
    return found[0]
