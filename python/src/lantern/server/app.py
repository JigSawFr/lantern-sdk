"""The reference routes of Lantern, over a Library: what a server author
mounts in an existing app (lantern.server.flask, lantern.server.fastapi) to
serve Lantern.

    app = LanternApp(library, uid="6f1c2a8e-…", name="Living room shelf", accounts=MemoryAccounts(…))
    response = app.handle(ServerRequest("GET", "/api/lantern/v1/apps", …))

It answers the handshake (at /.well-known/lantern and <base>/v1/), the
families library (apps, what is missing, files), changes (with a journal),
sections (with a library that curates them), titles, homebrew and cheats
(reading them, and writing them with the scope cheats.write); save backups
(with a save store, § 9: in one request and by resumable upload), and
encrypted ones kept as sent (§ 9.4); requests (with a request store, § 11);
events (a stream and long polling, § 18), grants for peers (with a grant
key, § 19.3) and sync (with a sync store, § 20); and refuses the others with
404 (their features are 0).

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
import dataclasses
import hashlib
import json
import re
import secrets
import threading
import time
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import TypeVar, cast
from urllib.parse import unquote

from lantern import e2e, ed25519, ratings, schema
from lantern import signatures as sig
from lantern import sync as syncing
from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern._generated.models import (
    AdminPairingDecision,
    AdminUserCreate,
    AdminUserUpdate,
    App,
    CheatSet,
    CheatWrite,
    Encryption,
    Homebrew,
    HomebrewUpdatesRequest,
    InvitationCreate,
    MissingRequest,
    PairingRequest,
    Rating,
    RatingCap,
    RequestCreate,
    Save,
    SyncWrite,
    Title,
    UploadRequest,
)
from lantern.digest import digest_sha256, sha256_hex
from lantern.grants import LIFETIME_LIMIT, make_grant
from lantern.http import Headers, media_type
from lantern.limits import CHEAT_SET, NAME, NOTE, PROFILE, STRING_CAPS, TITLES_AT_ONCE, printable
from lantern.missing import missing
from lantern.profiles import profile, title_id_ok
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
    BODY_LIMIT,
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
from lantern.server.library import Account, Authenticate, CheatWriter, Library, SectionSource
from lantern.server.paging import Cursors, Sealer, SinceTokens, SortKey, page_size
from lantern.server.pairing import Limiter, PairingDesk, Pending, approval_page, slow_down
from lantern.server.saves import (
    SAVE_KINDS,
    SLOT,
    ZIP_STARTS,
    SaveLimits,
    SaveStore,
    UploadSession,
    new_save_id,
    new_upload_id,
)
from lantern.server.sync import SyncStore
from lantern.server.title_requests import OPEN_LIMIT, STATUSES, RequestStore, StoredRequest, new_request_id
from lantern.spki import short as spki_short
from lantern.vocabulary import BUILD_ID, CORE_ID, FAMILIES, HOMEBREW_ID, PLATFORM, SHA256, WORD

#: The scope each family needs (SPEC.md § 4.2); pairing needs none.
SCOPE_OF = {
    "library": "library",
    "titles": "library",
    "changes": "library",
    "homebrew": "library",
    "sections": "library",
    "cheats": "cheats",
    "cheats.write": "cheats.write",
    "saves": "saves",
    "encrypted_saves": "saves",
    "requests": "requests",
    "admin": "admin",
    "peers": "library",
    "sync": "sync.read",
    "sync.write": "sync.write",
}
#: How long an invitation may live (SPEC.md § 5.5), and how many may wait at once.
INVITATION_DAYS = 30
INVITATIONS_LIMIT = 1000
APP_SORTS = ("name", "added", "release")
#: A cheat set's document: its text (1 MiB at most), escaped in JSON.
CHEAT_BODY = 3 << 20
#: A cheat set's source (SPEC.md § 10): a name of 1 to 64 letters, digits, spaces and . ' ( ) -.
CHEAT_SOURCE = re.compile(r"^[^\W_](?:[^\W_]|[ .'()-]){0,63}(?<! )$")
#: A line of a cheat set in Atmosphère's or Luma3DS's format: a [name], a {master}, or hex words (Annex A).
CHEAT_LINE = re.compile(r"^\s*(?:\[[^\]]{0,255}\]|\{[^}]{0,255}\}|[0-9A-Fa-f]{8}(?:\s+[0-9A-Fa-f]{8})*)?\s*$")
CHEAT_HEX_FORMATS = ("atmosphere", "gateshark")
#: A key id of lantern-save-e2e-1 (SPEC.md § 9.4).
KEY_ID = re.compile(r"^[0-9a-f]{16}$")
T = TypeVar("T")
#: The families that keep an account's own data: never offered without a token.
ACCOUNT_FAMILIES = ("admin", "sync", "sync.write", "saves", "encrypted_saves", "requests")
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
    Route(("sections",), ("GET", "HEAD"), "sections", "sections"),
    Route(("cheats",), ("GET", "HEAD"), "cheats", "cheats"),
    Route(("cheats",), ("POST",), "cheats.write", "cheat_post"),
    Route(("cheats", "{}"), ("GET", "HEAD"), "cheats", "cheat_text"),
    Route(("cheats", "{}"), ("PUT", "DELETE"), "cheats.write", "cheat_write"),
    Route(("saves",), ("GET", "HEAD"), "saves", "saves"),
    Route(("saves", "{}"), ("POST",), "saves", "save_post"),
    Route(("saves", "{}", "uploads"), ("POST",), "saves", "upload_open"),
    Route(("saves", "{}", "{}"), ("GET", "HEAD", "DELETE"), "saves", "save_one"),
    Route(("uploads", "{}"), ("HEAD", "PATCH", "DELETE"), "saves", "upload"),
    Route(("requests",), ("GET", "HEAD", "POST"), "requests", "requests"),
    Route(("requests", "{}"), ("DELETE",), "requests", "request_delete"),
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
    - `saves`: a SaveStore (MemorySaveStore, FileSaveStore), which offers
      save backups (SPEC.md § 9) to the accounts with the scope saves, within
      `save_limits`; `encrypted_saves`: keep backups encrypted on the device
      as they come (§ 9.4), which the server never decrypts.
    - `requests`: a RequestStore (MemoryRequests), which offers requests
      (SPEC.md § 11) to the accounts with the scope requests;
      `answer_request()` marks one done or declined.
    - `cheat_writes`: with a library that writes cheat sets (a CheatWriter,
      as MemoryLibrary is), take them from the accounts with cheats.write
      (SPEC.md § 10); without, writing answers 405.
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
        saves: SaveStore | None = None,
        save_limits: SaveLimits | None = None,
        encrypted_saves: bool = True,
        requests: RequestStore | None = None,
        cheat_writes: bool = True,
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
        self.saves, self.save_limits = saves, save_limits or SaveLimits()
        self.encrypted_saves = encrypted_saves
        self.requests, self.cheat_writes = requests, cheat_writes
        self._saves_lock = threading.RLock()
        self._requests_lock = threading.RLock()
        self._cheats_lock = threading.RLock()
        subscribe = getattr(library, "subscribe", None)
        if callable(subscribe) and (self.hub is not None or requests is not None):
            subscribe(self._library_change)
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
        # A method of a family the server does not offer (writing cheat sets) is one the route does not take.
        offered = [(r, a) for r, a in matched if self.offered(self._family(r, request))]
        chosen = next(((r, a) for r, a in offered if request.method in r.methods), None)
        if chosen is None:
            raise method_not_allowed(list(dict.fromkeys(m for r, _ in offered for m in r.methods)))
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
            device_name=device.device,
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
        if family == "saves":
            return self.saves is not None
        if family == "encrypted_saves":
            return self.saves is not None and self.encrypted_saves
        if family == "requests":
            return self.requests is not None
        if family == "sections":
            return "sections" in self.library.families and isinstance(self.library, SectionSource)
        if family == "cheats.write":
            return "cheats" in self.library.families and self.cheat_writes and isinstance(self.library, CheatWriter)
        return family in self.library.families

    def allow(self, account: Account, family: str) -> None:
        if not self.offered(family):
            raise not_found("This server does not offer it.")
        if family == "pairing":  # whoever reaches the server may ask to pair (SPEC.md § 4.2, § 5.2)
            return
        if account.state == "anonymous" and (not self.public or family in ACCOUNT_FAMILIES):
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
        if self.saves is not None:
            limits.update(
                save_body=self.save_limits.body,
                save_size=self.save_limits.size,
                saves_kept_per_title=self.save_limits.kept,
            )
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
        if rec.user is not None and rec.user != self.owner(account):
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
        self.emit("sync", {"schema": SCHEMA, "collection": collection, "rev": rev}, user=self.owner(account))

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

    # Sections (SPEC.md § 6.5).

    def h_sections(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        source = cast("SectionSource", self.library)
        hide = self.hides(account)
        apps = {a.id: a for a in self.library.apps()}
        shelves: list[JSONValue] = []
        for section in source.sections(request.languages):
            ids: list[JSONValue] = [
                i
                for i in dict.fromkeys(section.apps)
                if i in apps
                and (platform is None or apps[i].platform == platform)
                and not hide(apps[i].platform, apps[i].title_id)
            ]
            if ids:  # a shelf of nothing this caller sees is left out
                shelves.append({"id": section.id, "title": section.title, "apps": ids})
        return json_response(request, {"schema": SCHEMA, "sections": shelves})

    # Cheats, written (SPEC.md § 10).

    def _cheat_fields(self, request: ServerRequest) -> CheatWrite:
        """A cheat set to write, checked (SPEC.md § 10, § 13, Annex A): its platform, title and build in the
        profile's forms, its source and note, its text within 1 MiB and in the platform's format."""
        try:
            # A set's text is bounded by § 13's cheat set, 1 MiB, not a string field's 4 KiB: checked below (413).
            raw = read_document(request, limit=CHEAT_BODY, caps={**STRING_CAPS, "text": CHEAT_BODY})
            doc = CheatWrite.from_json(raw, "the body")
        except DocumentError as e:
            raise bad_request(f"A cheat set is {{schema, platform, title_id, build_id, text, …}}: {e}") from None
        platform = doc.platform
        if not PLATFORM.match(platform):
            raise bad_request("platform is a platform's name (SPEC.md § 4.3).")
        prof = profile(platform)
        if prof is not None and prof.cheats is None:
            raise bad_request(f"{platform} has no cheats (Annex A).")
        if not title_id_ok(platform, doc.title_id):
            raise bad_request(f"title_id is not a title id of {platform}.")
        pattern = prof.cheats.build_id if prof is not None and prof.cheats is not None else None
        if pattern is not None and (doc.build_id is None or not pattern.match(doc.build_id)):
            raise bad_request(f"build_id is the game's build, in {platform}'s form (Annex A).")
        if doc.build_id is not None and not BUILD_ID.match(doc.build_id):
            raise bad_request("build_id is 1 to 64 letters, digits, '.', '_' and '-'.")
        doc.source = doc.source if doc.source is not None else "Lantern"
        if not CHEAT_SOURCE.match(doc.source):
            raise bad_request("source is 1 to 64 letters, digits, spaces and . ' ( ) -, a letter or a digit first.")
        if doc.note is not None and (printable(doc.note, NOTE) != doc.note or "\n" in doc.note):
            raise bad_request("note: 120 bytes at most, without control characters.")
        if len(doc.text.encode()) > CHEAT_SET:
            raise ProblemError(413, "too_large", f"A cheat set is {CHEAT_SET} bytes at most (SPEC.md § 13).")
        if any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in doc.text):
            raise bad_request("text has a control character.")
        fmt = prof.cheats.format if prof is not None and prof.cheats is not None else None
        if fmt in CHEAT_HEX_FORMATS:
            bad = next((n for n, line in enumerate(doc.text.splitlines(), 1) if not CHEAT_LINE.match(line)), None)
            if bad is not None:
                raise bad_request(f"line {bad} is neither a [name] nor words of 8 hex digits ({fmt}, Annex A).")
        elif fmt == "json":
            try:
                json.loads(doc.text)
            except ValueError:
                raise bad_request("text is a set in JSON (Annex A).") from None
        return doc

    def _writer(self) -> CheatWriter:
        return cast("CheatWriter", self.library)

    def h_cheat_post(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        doc = self._cheat_fields(request)
        if self.hides(account)(doc.platform, doc.title_id):
            raise not_found("No such title on this server.")
        assert doc.source is not None
        key = (doc.platform, doc.title_id, doc.build_id, doc.source)
        with self._cheats_lock:
            same = next((c for c in self.library.cheats() if _cheat_key(c) == key), None)
            if same is not None:
                raise ProblemError(409, "conflict", f"This set exists, {same.id}: PUT replaces it (SPEC.md § 10).")
            made = self._writer().write_cheat(
                platform=doc.platform,
                title_id=doc.title_id,
                build_id=doc.build_id,
                source=doc.source,
                note=doc.note,
                text=doc.text,
            )
        return json_response(request, {"schema": SCHEMA, **made.to_json()}, 201)

    def h_cheat_write(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        hide = self.hides(account)
        with self._cheats_lock:
            found = next(
                (
                    c
                    for c in self.library.cheats()
                    if c.id == args[0]
                    and (platform is None or c.platform == platform)
                    and not hide(c.platform, c.title_id)
                ),
                None,
            )
            if found is None:
                raise not_found("No such cheat set.")
            if request.method == "DELETE":
                self._writer().delete_cheat(found.id)
                return _no_content(request)
            doc = self._cheat_fields(request)
            if (doc.platform, doc.title_id, doc.build_id, doc.source) != (
                found.platform,
                found.title_id,
                found.build_id,
                found.source,
            ):
                raise bad_request("PUT replaces a set's text and note; its platform, title, build and source stay.")
            assert doc.source is not None
            self._writer().write_cheat(
                platform=doc.platform,
                title_id=doc.title_id,
                build_id=doc.build_id,
                source=doc.source,
                note=doc.note,
                text=doc.text,
                replacing=found.id,
            )
        return _no_content(request)

    # Save backups (SPEC.md § 9, § 9.4).

    @staticmethod
    def owner(account: Account) -> str:
        """Whose data a caller reads and writes: its account's name, else its device's id."""
        return account.name if account.name is not None else "device:" + (account.device or "")

    def _store(self) -> SaveStore:
        assert self.saves is not None
        return self.saves

    @staticmethod
    def _save_doc(save: Save) -> JSONObject:
        return {"schema": SCHEMA, **save.to_json()}

    def h_saves(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        platform = platform_of(request)
        title_id = request.query.get("title_id")
        if title_id is not None and not CORE_ID.match(title_id):
            raise bad_request("title_id is 1 to 128 letters, digits, '.', '_' and '-'.")
        with self._saves_lock:
            kept = self._store().saves(self.owner(account))
        found = [
            (i, s)
            for i, s in enumerate(kept)
            if (platform is None or s.platform == platform) and (title_id is None or s.title_id == title_id)
        ]
        found.sort(key=lambda p: (p[1].created, p[0]), reverse=True)  # newest first,
        found.sort(key=lambda p: (p[1].platform, p[1].title_id))  # per title (L-9.1-1)
        saves: list[JSONValue] = [s.to_json() for _, s in found]
        return json_response(request, {"schema": SCHEMA, "saves": saves})

    def _save_target(self, request: ServerRequest, title_id: str) -> str:
        """The platform a save is written for (400 without one, L-4.3-4), and its title id in its form."""
        platform = platform_of(request, required=True)
        assert platform is not None
        if not title_id_ok(platform, title_id):
            raise bad_request(f"Not a title id of {platform}.")
        return platform

    def _encryption(self, account: Account, value: Encryption | None) -> Encryption | None:
        """A backup's encryption (SPEC.md § 9.4): of lantern-save-e2e-1, with a key id; 400 for another, and
        for any when the server does not take encrypted backups from this caller (L-9.4-5)."""
        if value is None:
            return None
        if not self._may(account, "encrypted_saves"):
            raise bad_request("This server keeps no encrypted backup (SPEC.md § 9.4).")
        if value.scheme != e2e.SCHEME or not KEY_ID.match(value.key_id):
            raise bad_request(f"encryption is {{scheme: {e2e.SCHEME}, key_id: 16 hex digits}} (SPEC.md § 9.4).")
        return Encryption(scheme=e2e.SCHEME, key_id=value.key_id)

    @staticmethod
    def _text_header(request: ServerRequest, name: str, limit: int) -> str | None:
        raw = request.header(name)
        if raw is None:
            return None
        try:
            value = unquote(raw, errors="strict")
        except UnicodeDecodeError:
            raise bad_request(f"{name} is UTF-8, percent-encoded.") from None
        if len(value.encode()) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise bad_request(f"{name}: {limit} bytes at most, without control characters.")
        return value or None

    def _backup(
        self,
        account: Account,
        platform: str,
        title_id: str,
        *,
        size: int,
        sha256: str,
        kind: str | None,
        slot: str | None,
        game_version_code: int | None,
        profile_name: str | None,
        note: str | None,
        encryption: Encryption | None,
    ) -> Save:
        """A backup's document, its fields checked (SPEC.md § 9.1, § 13); its save_id and created given."""
        if kind is not None and kind not in SAVE_KINDS:
            raise bad_request("kind is " + ", ".join(SAVE_KINDS) + ".")
        if slot is not None and not SLOT.match(slot):
            raise bad_request("slot is 1 to 64 letters, digits, '.', '_' and '-'.")
        if game_version_code is not None and game_version_code < 0:
            raise bad_request("game_version_code is an integer, 0 or more.")
        for value, limit, what in ((profile_name, PROFILE, "profile"), (note, NOTE, "note")):
            if value is not None and (len(value.encode()) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise bad_request(f"{what}: {limit} bytes at most, without control characters.")
        return Save(
            platform=platform,
            title_id=title_id,
            save_id=new_save_id(),
            created=utc(),
            size=size,
            sha256=sha256,
            slot=slot,
            kind=kind,
            game_version_code=game_version_code,
            profile=profile_name or None,
            note=note or None,
            device=account.device_name,
            encryption=encryption,
        )

    @staticmethod
    def _check_archive(head: bytes, encryption: Encryption | None) -> None:
        """A backup's first bytes (SPEC.md § 9.1, § 9.4): a zip in clear; encrypted, the header of
        lantern-save-e2e-1 with its key id, nothing more being read of it. 400 otherwise."""
        if encryption is not None:
            if head[:8] != e2e.MAGIC or head[8:16].hex() != encryption.key_id:
                raise bad_request("An encrypted backup begins with LTNE2E01 and its key id (SPEC.md § 9.4).")
        elif not head.startswith(ZIP_STARTS):
            raise bad_request("A save is a zip archive (SPEC.md § 9.1).")

    def _kept(self, account: Account, save: Save) -> None:
        """A backup was kept: the oldest beyond saves_kept_per_title dropped (SPEC.md § 9.1), then its event
        (§ 18.2). Called under the lock of saves."""
        owner = self.owner(account)
        store = self._store()
        same = [s for s in store.saves(owner) if (s.platform, s.title_id) == (save.platform, save.title_id)]
        for old in same[: max(0, len(same) - self.save_limits.kept)]:
            store.drop(owner, old.save_id)
        data: JSONObject = {
            "schema": SCHEMA,
            "platform": save.platform,
            "title_id": save.title_id,
            "save_id": save.save_id,
            "created": save.created,
        }
        if save.device is not None:
            data["device"] = save.device
        self.emit("save", data, user=owner, platform=save.platform, title_id=save.title_id)

    def h_save_post(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        title_id = args[0]
        platform = self._save_target(request, title_id)
        header = request.header("Content-Digest")
        if header is None:
            raise bad_request("Content-Digest: sha-256=:<base64>: is required (SPEC.md § 9.2).")
        announced = digest_sha256(header)
        if announced is None:
            raise bad_request("Content-Digest gives no sha-256 this server reads.")
        version = request.header("Lantern-Game-Version")
        if version is not None and not version.strip().isdigit():
            raise bad_request("Lantern-Game-Version is an integer.")
        text = request.header("Lantern-Save-Encryption")
        encryption = None
        if text is not None:
            scheme, _, params = text.partition(";")
            fields = dict(p.strip().partition("=")[::2] for p in params.split(";") if p.strip())
            encryption = self._encryption(
                account, Encryption(scheme=scheme.strip(), key_id=fields.get("key_id", "").strip())
            )
        save = self._backup(
            account,
            platform,
            title_id,
            size=len(request.body),
            sha256=announced,
            kind=request.header("Lantern-Save-Kind"),
            slot=request.header("Lantern-Save-Slot"),
            game_version_code=int(version) if version is not None else None,
            profile_name=self._text_header(request, "Lantern-Profile", PROFILE),
            note=self._text_header(request, "Lantern-Note", NOTE),
            encryption=encryption,
        )
        if len(request.body) > self.save_limits.body:
            raise ProblemError(
                413, "too_large", f"At most {self.save_limits.body} bytes in one request: upload it (SPEC.md § 9.3)."
            )
        if sha256_hex(request.body) != announced:
            raise ProblemError(
                422, "digest_mismatch", "The body does not match its Content-Digest.", title="Digest mismatch"
            )
        self._check_archive(request.body[:16], encryption)
        with self._saves_lock:
            self._store().keep(self.owner(account), save, request.body)
            self._kept(account, save)
        return json_response(request, self._save_doc(save), 201)

    def _purge_uploads(self) -> None:
        """Drops the uploads not finished in time (SPEC.md § 9.3). Called under the lock of saves."""
        now = datetime.now(UTC)
        for s in self._store().uploads():
            expires = parse_time(s.expires)
            if expires is None or expires <= now:
                self._store().abandon(s.id)

    def h_upload_open(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        raw = read_document(request)
        title_id = args[0]
        platform = self._save_target(request, title_id)
        try:
            doc = UploadRequest.from_json(raw, "the body")
        except DocumentError as e:
            raise bad_request(f"An upload is {{schema, size, sha256, kind?, slot?, …}}: {e}") from None
        if doc.size < 0 or not SHA256.match(doc.sha256):
            raise bad_request("size is an integer, 0 or more, and sha256 a lower-case hex SHA-256.")
        if doc.size > self.save_limits.size:
            raise ProblemError(413, "too_large", f"A save is {self.save_limits.size} bytes at most here.")
        save = self._backup(
            account,
            platform,
            title_id,
            size=doc.size,
            sha256=doc.sha256,
            kind=doc.kind,
            slot=doc.slot,
            game_version_code=doc.game_version_code,
            profile_name=doc.profile,
            note=doc.note,
            encryption=self._encryption(account, doc.encryption),
        )
        expires = utc(datetime.now(UTC) + timedelta(hours=self.save_limits.upload_hours))
        session = UploadSession(new_upload_id(), self.owner(account), save, expires)
        with self._saves_lock:
            self._purge_uploads()
            self._store().open_upload(session)
        address = f"{self.base}/v1/uploads/{session.id}"
        body: JSONObject = {
            "schema": SCHEMA,
            "upload": address,
            "chunk_size": self.save_limits.chunk,
            "offset": 0,
            "expires": expires,
        }
        response = json_response(request, body, 201)
        response.headers["Location"] = address
        response.headers["Cache-Control"] = "no-store"
        return response

    def h_upload(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        """An upload under way (SPEC.md § 9.3): HEAD where it stands, PATCH a chunk, DELETE it."""
        store = self._store()
        with self._saves_lock:
            session = store.upload(args[0])
            expires = parse_time(session.expires) if session is not None else None
            if session is not None and (expires is None or expires <= datetime.now(UTC)):
                store.abandon(session.id)
                session = None
            if session is None or session.user != self.owner(account):
                raise not_found("No such upload: it finished, expired or was abandoned.")
            if request.method == "DELETE":
                store.abandon(session.id)
                return _no_content(request)
            if request.method == "HEAD":
                state = _no_content(request)
                state.headers.update(
                    {
                        "Upload-Offset": str(session.offset),
                        "Upload-Length": str(session.save.size),
                        "Cache-Control": "no-store",
                    }
                )
                return state
            return self._chunk(request, account, session)

    def _chunk(self, request: ServerRequest, account: Account, session: UploadSession) -> ServerResponse:
        store = self._store()
        if media_type(request.header("Content-Type")) != "application/offset+octet-stream":
            raise bad_request("A chunk is application/offset+octet-stream (SPEC.md § 9.3).")
        offset = (request.header("Upload-Offset") or "").strip()
        if not offset.isdigit():
            raise bad_request("Upload-Offset is the chunk's offset, an integer.")
        if len(request.body) > self.save_limits.chunk:
            raise ProblemError(413, "too_large", f"A chunk is {self.save_limits.chunk} bytes at most here.")
        check_content_digest(request)
        if int(offset) != session.offset:
            raise ProblemError(
                409,
                "conflict",
                f"This upload is at {session.offset}: resume from there.",
                headers={"Upload-Offset": str(session.offset)},
            )
        if session.offset + len(request.body) > session.save.size:
            raise bad_request(f"This chunk goes past the upload's size, {session.save.size} bytes.")
        at = store.append(session.id, request.body)
        if at < session.save.size:
            response = _no_content(request)
            response.headers.update({"Upload-Offset": str(at), "Cache-Control": "no-store"})
            return response
        digest, head = store.upload_digest(session.id)
        try:
            if digest != session.save.sha256:
                raise ProblemError(
                    422,
                    "digest_mismatch",
                    "The archive's SHA-256 is not the one announced; the upload was discarded.",
                    title="Digest mismatch",
                )
            self._check_archive(head, session.save.encryption)
        except ProblemError:
            store.abandon(session.id)
            raise
        save = dataclasses.replace(session.save, save_id=new_save_id(), created=utc())
        store.keep_upload(session.id, save)
        self._kept(account, save)
        response = json_response(request, self._save_doc(save), 201)
        response.headers["Upload-Offset"] = str(at)
        return response

    def h_save_one(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        title_id, save_id = args
        platform = platform_of(request)
        owner = self.owner(account)
        store = self._store()
        with self._saves_lock:
            found = next(
                (
                    s
                    for s in store.saves(owner)
                    if s.save_id == save_id and s.title_id == title_id and (platform is None or s.platform == platform)
                ),
                None,
            )
            if found is None:
                raise not_found("No such save backup.")
            if request.method == "DELETE":
                store.drop(owner, save_id)
                return _no_content(request)
            file = store.archive(owner, save_id)
        if file is None:
            raise not_found("No such save backup.")
        return file_response(request, file)

    # Requests (SPEC.md § 11).

    def _request_store(self) -> RequestStore:
        assert self.requests is not None
        return self.requests

    def _request_event(self, r: StoredRequest, *, deleted: bool = False) -> None:
        """The event `request` (SPEC.md § 18.2): the account's devices of its platform learn of it."""
        data: JSONObject = {"schema": SCHEMA, "id": r.id, "platform": r.platform, "title_id": r.title_id}
        if deleted:
            data["deleted"] = True
        else:
            data["status"] = r.status
        self.emit("request", data, user=r.user, platform=r.platform, title_id=r.title_id)

    def _title_name(self, platform: str, title_id: str) -> str | None:
        """A title's name, from the library's titles, else its apps."""
        if "titles" in self.library.families:
            for t in self.library.titles(()):
                if (t.platform, t.title_id) == (platform, title_id):
                    return t.name
        if "library" in self.library.families:
            for a in self.library.apps():
                if (a.platform, a.title_id) == (platform, title_id) and a.name:
                    return a.name
        return None

    def h_requests(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        owner = self.owner(account)
        if request.method != "POST":
            platform = platform_of(request)
            with self._requests_lock:
                mine = [r for r in self._request_store().requests(owner) if platform is None or r.platform == platform]
            mine.sort(key=lambda r: (r.created, r.id), reverse=True)
            listed: list[JSONValue] = [r.to_json() for r in mine]
            return json_response(request, {"schema": SCHEMA, "requests": listed})
        try:
            doc = RequestCreate.from_json(read_document(request), "the body")
        except DocumentError as e:
            raise bad_request(f"A request is {{schema, platform?, title_id}}: {e}") from None
        platform = doc.platform if doc.platform is not None else platform_of(request, required=True)
        assert platform is not None
        if not PLATFORM.match(platform):
            raise bad_request("platform is a platform's name (SPEC.md § 4.3).")
        if not title_id_ok(platform, doc.title_id):
            raise bad_request(f"title_id is not a title id of {platform}.")
        store = self._request_store()
        with self._requests_lock:
            mine = store.requests(owner)
            same = next(
                (r for r in mine if r.status == "open" and (r.platform, r.title_id) == (platform, doc.title_id)), None
            )
            if same is not None:
                return json_response(request, {"schema": SCHEMA, **same.to_json()}, 200)
            if sum(r.status == "open" for r in mine) >= OPEN_LIMIT:
                raise slow_down(3600, f"At most {OPEN_LIMIT} open requests per account.")
            made = StoredRequest(
                id=new_request_id(),
                user=owner,
                platform=platform,
                title_id=doc.title_id,
                status="open",
                created=utc(),
                name=self._title_name(platform, doc.title_id),
            )
            store.add(made)
        self._request_event(made)
        return json_response(request, {"schema": SCHEMA, **made.to_json()}, 201)

    def h_request_delete(self, request: ServerRequest, account: Account, args: Sequence[str]) -> ServerResponse:
        with self._requests_lock:
            gone = self._request_store().remove(self.owner(account), args[0])
        if gone is None:
            raise not_found("No such request of this account.")
        self._request_event(gone, deleted=True)
        return _no_content(request)

    def answer_request(self, request_id: str, status: str) -> StoredRequest | None:
        """Marks a request `done` or `declined` (or `open` again), as the server's own administration
        decides (SPEC.md § 11): the account's devices get its event (§ 18.2). None when there is none."""
        if status not in STATUSES:
            raise ValueError("status is " + ", ".join(STATUSES))
        store = self._request_store()
        with self._requests_lock:
            before = next((r for r in store.requests() if r.id == request_id), None)
            if before is None:
                return None
            if before.status == status:
                return before
            after = store.set_status(request_id, status)
        if after is not None:
            self._request_event(after)
        return after

    def all_requests(self) -> list[StoredRequest]:
        """Every account's requests, newest first: what a server's own administration pages show."""
        with self._requests_lock:
            found = self._request_store().requests()
        return sorted(found, key=lambda r: (r.created, r.id), reverse=True)

    def _library_change(self, change: LibraryChange) -> None:
        """The library changed: the event `library` (SPEC.md § 18.2), and the open requests of a title whose
        app just arrived are done (§ 11)."""
        self.library_changed([change])
        if self.requests is None or change.family != "apps" or change.title_id is None:
            return
        with self._requests_lock:
            waiting = [
                r
                for r in self.requests.requests()
                if r.status == "open" and (r.platform, r.title_id) == (change.platform, change.title_id)
            ]
        if waiting and any((a.platform, a.title_id) == (change.platform, change.title_id) for a in self.library.apps()):
            for r in waiting:
                self.answer_request(r.id, "done")

    @property
    def body_limit(self) -> int:
        """The largest body an adapter reads for this app: a request document's, a cheat set's, a save sent in
        one request or an upload's chunk."""
        limit = BODY_LIMIT
        if self.saves is not None:
            limit = max(limit, self.save_limits.body, self.save_limits.chunk)
        if self.offered("cheats.write"):
            limit = max(limit, CHEAT_BODY)
        return limit

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
        (409); its devices, invitations, pairings not yet collected, save backups, requests and sync data
        go at once, and its streams end at their next wake (L-5.7-6, L-5.7-7, L-18.1-8)."""
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
        if self.saves is not None:
            with self._saves_lock:
                self.saves.forget(name)
        if self.requests is not None:
            with self._requests_lock:
                self.requests.forget(name)
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


def _cheat_key(c: CheatSet) -> tuple[str, str, str | None, str | None]:
    """What makes a cheat set the same as another (SPEC.md § 10): its platform, title, build and source."""
    return (c.platform, c.title_id, c.build_id, c.source)


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
