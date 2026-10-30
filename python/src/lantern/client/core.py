"""The client without its I/O: what each call sends, and how its answer is
read. LanternClient (sync) and AsyncLanternClient share it."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from email.utils import parsedate_to_datetime
from typing import Generic, TypeVar
from urllib.parse import quote, urlencode, urljoin, urlsplit

from lantern import e2e
from lantern import sync as syncing
from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern._generated.models import (
    AdminDevices,
    AdminPairingDecision,
    AdminPairings,
    AdminUser,
    AdminUserCreate,
    AdminUsers,
    AdminUserUpdate,
    App,
    AppsPage,
    Changes,
    CheatSet,
    CheatSets,
    CheatWrite,
    Grant,
    Handshake,
    HomebrewPage,
    HomebrewUpdatesRequest,
    InstalledApp,
    InstalledHomebrew,
    Invitation,
    InvitationCreate,
    Invitations,
    MissingRequest,
    PairingCode,
    PairingRequest,
    PairingToken,
    RatingCap,
    RequestCreate,
    Save,
    Saves,
    Sections,
    Sync,
    SyncCollection,
    SyncItem,
    SyncWrite,
    Title,
    TitleChanges,
    TitleRequest,
    TitleRequests,
    Titles,
    Upload,
    UploadRequest,
)
from lantern._generated.models import DeviceKey as DeviceKeyDocument
from lantern._generated.models import (
    Homebrew as HomebrewEntry,
)
from lantern._version import __version__
from lantern.client.auth import Pairing
from lantern.client.transport import Credentials, Pipeline, Request, RequestSigner
from lantern.digest import format_digest, sha256_hex
from lantern.documents import schema_of
from lantern.errors import (
    InsecureTransport,
    LanternError,
    NewerSchema,
    SignatureExpired,
    SignatureReplayed,
    UnexpectedResponse,
    problem_error,
)
from lantern.events import ServerEvent, event_of
from lantern.grants import grant_key, read_grant
from lantern.http import JSON, PLATFORM_HEADER, Headers, media_type, origin, plain_http_allowed
from lantern.limits import CHEAT_SET, JSON_DOCUMENT, NOTE, PROFILE, TITLES_AT_ONCE, load_json, printable
from lantern.pinning import ServerRecord
from lantern.signatures import SKEW, DeviceKey
from lantern.vocabulary import BUILD_ID, CORE_ID, FAMILIES, HOMEBREW_ID, is_platform

T = TypeVar("T")
ERROR_BODY = 1 << 16
USER_AGENT = f"LanternPython/{__version__}"
#: The `schema` this library reads, per family (sent as Accept-Schema, SPEC.md § 3.2).
KNOWN: Mapping[str, int] = dict.fromkeys(FAMILIES, SCHEMA)
MISSING_WANTS = ("base", "update", "dlc")


log = logging.getLogger("lantern")


@dataclass(frozen=True)
class Deprecation:
    """A route or schema a server said is going away (SPEC.md § 3.4): `since`
    (Deprecation, a Structured Fields date such as `@1793318400`), `sunset`
    (the HTTP date after which it may stop answering), and the `link` that
    says what replaces it."""

    what: str
    since: str
    sunset: str | None
    link: str | None


@dataclass
class Call(Generic[T]):
    """One request below <base>/v1 (or the handshake, or an address a document
    gave: `url`), and how its answer reads: a JSON document for a status of
    `statuses`, through `read`; none for a status of `empty_statuses`, through
    `empty`. `raw` is a body that is not JSON (a save's archive, a chunk);
    `anonymous` sends no credentials (pairing); `signer` signs it in place of
    the client's own (a keyed pairing's poll)."""

    method: str
    path: str
    read: Callable[[JSONValue], T]
    what: str
    query: list[tuple[str, str]] = field(default_factory=list)
    body: JSONObject | None = None
    well_known: bool = False
    statuses: tuple[int, ...] = (200,)
    empty_statuses: tuple[int, ...] = ()
    empty: Callable[[int, Headers], T] | None = None
    raw: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    anonymous: bool = False
    signer: RequestSigner | None = None
    #: The seconds to wait for its answer, when not the client's own (a long poll's).
    timeout: float | None = None

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


def _none(status: int, headers: Headers) -> None:
    return None


def _reject(data: JSONValue) -> None:
    raise UnexpectedResponse("a document where the protocol gives none")


def _upload_offset(status: int, headers: Headers) -> int:
    value = (headers.get("Upload-Offset") or "").strip()
    if not value.isdigit():
        raise UnexpectedResponse(f"status {status} without an Upload-Offset", status)
    return int(value)


def _upload_state(status: int, headers: Headers) -> tuple[int, int | None]:
    length = (headers.get("Upload-Length") or "").strip()
    return _upload_offset(status, headers), int(length) if length.isdigit() else None


def _header_text(value: str, limit: int, what: str) -> str:
    """A text for a save's header (SPEC.md § 9.2): UTF-8, percent-encoded, within § 13's limit."""
    if len(value.encode()) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{what}: at most {limit} bytes, without control characters")
    return quote(value, safe="")


def _ascii_word(value: str, what: str) -> str:
    if not CORE_ID.match(value):
        raise ValueError(f"{what}: 1 to 64 letters, digits, '.', '_' and '-'")
    return value


def _collection(name: str) -> str:
    if not name or len(name) > 32 or not name.replace("_", "").isalnum() or not name[0].isalpha():
        raise ValueError(f"{name!r} is not a sync collection's name")
    return name


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
        #: Seconds to add to this device's clock to read the server's (SPEC.md § 5.4, Annex B.9).
        self.clock_offset = 0.0
        #: The fingerprint of the key of the last TLS connection, when the transport said.
        self.last_spki: str | None = None
        #: What the server said is deprecated (SPEC.md § 3.4), once each.
        self.deprecations: list[Deprecation] = []

    def note(self, what: str, headers: Headers) -> None:
        """Records a Deprecation (and its Sunset) where developers see it: `deprecations`, and the log
        `lantern` (L-3.4-5)."""
        since = headers.get("Deprecation")
        if not since:
            return
        links = [p for p in (headers.get("Link") or "").split(",") if 'rel="deprecation"' in p]
        link = links[0].split(";")[0].strip().strip("<>") if links else None
        found = Deprecation(what, printable(since, 64), printable(headers.get("Sunset") or "", 64) or None, link)
        if found not in self.deprecations:
            self.deprecations.append(found)
            log.warning("%s is deprecated since %s, sunset %s: %s", what, found.since, found.sunset, link or "")

    def now(self) -> float:
        """The time to sign with: this device's clock, corrected by its offset to the server's."""
        return time.time() + self.clock_offset

    def server_offset(self, headers: Headers) -> float | None:
        """The offset of the server's Date to this device's clock, in seconds; None without a Date."""
        value = headers.get("Date")
        if not value:
            return None
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when.tzinfo is None:
            return None
        return when.timestamp() - time.time()

    def adjust_clock(self, headers: Headers) -> bool:
        """Takes the offset of the server's Date (after a 401 signature_expired, SPEC.md § 5.4);
        False when the answer has no Date to take it from, or it would change nothing."""
        offset = self.server_offset(headers)
        if offset is None or abs(offset - self.clock_offset) < 1:
            return False
        self.clock_offset = offset
        return True

    def skew(self) -> int:
        auth = self.hello.auth if self.hello is not None else None
        return auth.skew if auth is not None else SKEW

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

    def on_origin(self, address: str, what: str) -> str:
        """An address a document gave (a poll, an upload), made absolute: it must be on the server's origin,
        where alone the client's token and signatures go."""
        url = self.url(address)
        try:
            same = origin(url) == self.pipeline.server_origin
        except ValueError:
            same = False
        if not same:
            raise UnexpectedResponse(f"{what}: {address[:100]!r} is not on the server's origin")
        return url

    def v1(self, path: str) -> str:
        if self.base is None:
            raise LanternError("no base yet: read the handshake first")
        return self.root + self.base + "/v1" + path

    def request(self, call: Call[T]) -> Request:
        if call.url is not None:
            url = call.url
        elif call.well_known:
            url = self.root + "/.well-known/lantern"
        else:
            url = self.v1(call.path)
        if call.query:
            url += "?" + urlencode(call.query, quote_via=quote, safe=",")
        return self.prepare(
            call.method,
            url,
            call.body,
            call.headers,
            raw=call.raw,
            anonymous=call.anonymous,
            signer=call.signer,
        )

    def prepare(
        self,
        method: str,
        url: str,
        body: JSONObject | None = None,
        headers: Mapping[str, str] | None = None,
        *,
        raw: bytes | None = None,
        anonymous: bool = False,
        signer: RequestSigner | None = None,
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
        if body is not None:
            raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
            h["Content-Type"] = JSON
        for k, v in (headers or {}).items():
            h[k] = v
        request = Request(method, url, h, raw)
        if anonymous or signer is not None:
            pipeline = Pipeline(self.pipeline.server_origin, None if anonymous else self.pipeline.credentials, signer)
            return pipeline.prepare(request)
        return self.pipeline.prepare(request)

    def finish(self, call: Call[T], status: int, headers: Headers, body: bytes) -> T:
        """The answer's document, read; the error of its status otherwise."""
        self.note(call.what, headers)
        if status in call.statuses:
            if media_type(headers.get("Content-Type")) != JSON:
                raise UnexpectedResponse(f"{call.what}: Content-Type {headers.get('Content-Type')!r}, not JSON", status)
            doc = load_json(body, where=call.what)
            schema = schema_of(doc, call.what)
            if schema > SCHEMA:
                raise NewerSchema(call.what, schema)
            result = call.read(doc)
            if call.well_known:
                self.hello = self.accept_handshake(result)  # type: ignore[arg-type]
                self.observe_clock(headers)
            return result
        if status in call.empty_statuses and call.empty is not None:
            return call.empty(status, headers)
        raise self.error(call.what, status, headers, body)

    def observe_clock(self, headers: Headers) -> None:
        """After the handshake (Annex B.9): a server that checks signatures, and a clock off by half its
        window or more, and the client signs with the server's time from then on."""
        offset = self.server_offset(headers)
        if offset is not None and abs(offset - self.clock_offset) >= self.skew() / 2:
            self.clock_offset = offset

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

    # Pairing (SPEC.md § 5.2, § 5.4, § 5.5).

    def pairing(
        self, device: str, scopes: Sequence[str], key: DeviceKey | None, invitation: str | None
    ) -> Call[PairingCode]:
        if not device.strip() or len(device.encode()) > 512:
            raise ValueError("device is the device's name, 512 bytes at most")
        if not scopes:
            raise ValueError("ask for one scope at least")
        doc = PairingRequest(
            schema=SCHEMA,
            device=device,
            scopes=list(dict.fromkeys(scopes)),
            key=DeviceKeyDocument(alg="ed25519", public_key=key.public_b64) if key is not None else None,
            invitation=invitation,
        ).to_json()
        return Call("POST", "/pairing", _model(PairingCode), "pairing", body=doc, anonymous=True)

    def poll(self, url: str, signer: RequestSigner | None) -> Call[PairingToken | None]:
        """One poll: the token's document once approved, None while waiting (202)."""
        read: Callable[[JSONValue], PairingToken | None] = _model(PairingToken)
        return Call(
            "GET",
            "",
            read,
            "pairing poll",
            url=self.on_origin(url, "pairing poll"),
            empty_statuses=(202,),
            empty=_none,
            anonymous=True,
            signer=signer,
        )

    # Saves (SPEC.md § 9).

    def saves(self, title_id: str | None, platform: str | None) -> Call[Saves]:
        query = _platform(platform) + _listing(None, None, title_id=title_id)
        return Call("GET", "/saves", _model(Saves), "saves", query)

    def save_path(self, title_id: str, save_id: str | None = None) -> str:
        if not CORE_ID.match(title_id) or (save_id is not None and not CORE_ID.match(save_id)):
            raise ValueError("a title id and a save id are 1 to 128 letters, digits, '.', '_' and '-'")
        return "/saves/" + quote(title_id, safe="") + ("/" + quote(save_id, safe="") if save_id is not None else "")

    def save_post(
        self,
        title_id: str,
        data: bytes,
        *,
        kind: str | None,
        slot: str | None,
        game_version_code: int | None,
        profile: str | None,
        note: str | None,
        platform: str | None,
        key_id: str | None = None,
    ) -> Call[Save]:
        """A save in one request (SPEC.md § 9.2): the zip, its Content-Digest, and its fields as headers;
        with `key_id`, a backup encrypted on the device (§ 9.4), its bytes the encrypted ones."""
        self._needs_platform(platform, "writing a save")
        headers = {"Content-Type": "application/zip", "Content-Digest": format_digest(sha256_hex(data))}
        if key_id is not None:
            if len(key_id) != 16 or any(c not in "0123456789abcdef" for c in key_id):
                raise ValueError("a key id is 16 lower-case hex digits")
            headers["Content-Type"] = "application/octet-stream"
            headers["Lantern-Save-Encryption"] = e2e.encryption_header(key_id)
        if kind is not None:
            headers["Lantern-Save-Kind"] = _ascii_word(kind, "kind")
        if slot is not None:
            headers["Lantern-Save-Slot"] = _ascii_word(slot, "slot")
        if game_version_code is not None:
            if game_version_code < 0:
                raise ValueError("game_version_code is 0 or more")
            headers["Lantern-Game-Version"] = str(game_version_code)
        if profile is not None:
            headers["Lantern-Profile"] = _header_text(profile, PROFILE, "profile")
        if note is not None:
            headers["Lantern-Note"] = _header_text(note, NOTE, "note")
        return Call(
            "POST",
            self.save_path(title_id),
            _model(Save),
            "save",
            _platform(platform),
            raw=data,
            headers=headers,
            statuses=(201,),
        )

    def upload_open(self, title_id: str, request: UploadRequest, platform: str | None) -> Call[Upload]:
        self._needs_platform(platform, "writing a save")
        return Call(
            "POST",
            self.save_path(title_id) + "/uploads",
            _model(Upload),
            "upload",
            _platform(platform),
            body=request.to_json(),
            statuses=(201,),
        )

    def upload_chunk(self, upload: str, offset: int, chunk: bytes) -> Call[int | Save]:
        """One chunk (SPEC.md § 9.3): the server's new offset (204), or the save once the last arrived (201)."""
        read: Callable[[JSONValue], int | Save] = _model(Save)
        return Call(
            "PATCH",
            "",
            read,
            "upload chunk",
            url=self.on_origin(upload, "upload"),
            raw=chunk,
            headers={
                "Content-Type": "application/offset+octet-stream",
                "Upload-Offset": str(offset),
                "Content-Digest": format_digest(sha256_hex(chunk)),
            },
            statuses=(201,),
            empty_statuses=(204,),
            empty=_upload_offset,
        )

    def upload_state(self, upload: str) -> Call[tuple[int, int | None]]:
        """HEAD of an upload: where to resume (Upload-Offset), and its length."""
        read: Callable[[JSONValue], tuple[int, int | None]] = _reject  # type: ignore[assignment]
        return Call(
            "HEAD",
            "",
            read,
            "upload state",
            url=self.on_origin(upload, "upload"),
            statuses=(),
            empty_statuses=(200, 204),
            empty=_upload_state,
        )

    def delete(self, url: str, what: str) -> Call[None]:
        return Call(
            "DELETE", "", _reject, what, url=self.on_origin(url, what), statuses=(), empty_statuses=(204,), empty=_none
        )

    # Cheats, written (SPEC.md § 10).

    @staticmethod
    def cheat_write(
        platform: str, title_id: str, text: str, *, build_id: str | None, source: str | None, note: str | None
    ) -> JSONObject:
        if not is_platform(platform) or not CORE_ID.match(title_id):
            raise ValueError("a platform's name and a title id")
        if build_id is not None and not BUILD_ID.match(build_id):
            raise ValueError("build_id is 1 to 64 letters, digits, '.', '_' and '-'")
        if len(text.encode()) > CHEAT_SET:
            raise ValueError(f"a cheat set is {CHEAT_SET} bytes at most")
        doc = CheatWrite(
            schema=SCHEMA, platform=platform, title_id=title_id, build_id=build_id, source=source, note=note, text=text
        )
        return doc.to_json()

    def cheat_create(self, doc: JSONObject) -> Call[CheatSet]:
        return Call("POST", "/cheats", _model(CheatSet), "cheat set", body=doc, statuses=(201,))

    def cheat_replace(self, cheat_id: str, doc: JSONObject) -> Call[None]:
        return Call(
            "PUT",
            "/cheats/" + quote(cheat_id, safe=""),
            _reject,
            "cheat set",
            body=doc,
            statuses=(),
            empty_statuses=(204,),
            empty=_none,
        )

    # Requests (SPEC.md § 11).

    def requests(self, platform: str | None) -> Call[TitleRequests]:
        return Call("GET", "/requests", _model(TitleRequests), "requests", _platform(platform))

    def request_create(self, title_id: str, platform: str | None) -> Call[TitleRequest]:
        if not CORE_ID.match(title_id):
            raise ValueError(f"{title_id!r} is not a title id")
        if platform is not None and not is_platform(platform):
            raise ValueError(f"{platform!r} is not a platform's name")
        doc = RequestCreate(schema=SCHEMA, platform=platform, title_id=title_id).to_json()
        return Call("POST", "/requests", _model(TitleRequest), "request", body=doc, statuses=(200, 201))

    # Administration (SPEC.md § 5.7).

    def admin_users(self, page_size: int | None, cursor: str | None) -> Call[AdminUsers]:
        return Call("GET", "/admin/users", _model(AdminUsers), "accounts", _listing(page_size, cursor))

    def admin_create_user(self, name: str, scopes: Sequence[str], state: str | None) -> Call[AdminUser]:
        doc = AdminUserCreate(schema=SCHEMA, name=name, scopes=list(scopes), state=state).to_json()
        return Call("POST", "/admin/users", _model(AdminUser), "account", body=doc, statuses=(201,))

    def admin_update_user(self, name: str, state: str | None, scopes: Sequence[str] | None) -> Call[AdminUser]:
        if state is None and scopes is None:
            raise ValueError("change the state, the scopes, or both")
        doc = AdminUserUpdate(schema=SCHEMA, state=state, scopes=list(scopes) if scopes is not None else None)
        return Call("PATCH", "/admin/users/" + quote(name, safe=""), _model(AdminUser), "account", body=doc.to_json())

    def admin_devices(self, user: str | None, page_size: int | None, cursor: str | None) -> Call[AdminDevices]:
        query = _listing(page_size, cursor, user=user)
        return Call("GET", "/admin/devices", _model(AdminDevices), "devices", query)

    def admin_pairings(self, page_size: int | None, cursor: str | None) -> Call[AdminPairings]:
        return Call("GET", "/admin/pairings", _model(AdminPairings), "pairings", _listing(page_size, cursor))

    def admin_decide(
        self,
        pairing_id: str,
        decision: str,
        user: str | None,
        scopes: Sequence[str] | None,
        rating_cap: RatingCap | None,
    ) -> Call[None]:
        if decision not in ("approve", "refuse"):
            raise ValueError("decision is approve or refuse")
        doc = AdminPairingDecision(
            schema=SCHEMA,
            decision=decision,
            user=user,
            scopes=list(scopes) if scopes is not None else None,
            rating_cap=rating_cap,
        )
        return Call(
            "POST",
            "/admin/pairings/" + quote(pairing_id, safe=""),
            _reject,
            "pairing decision",
            body=doc.to_json(),
            statuses=(),
            empty_statuses=(204,),
            empty=_none,
        )

    def admin_invitations(self, page_size: int | None, cursor: str | None) -> Call[Invitations]:
        return Call("GET", "/admin/invitations", _model(Invitations), "invitations", _listing(page_size, cursor))

    def admin_create_invitation(self, doc: InvitationCreate) -> Call[Invitation]:
        return Call("POST", "/admin/invitations", _model(Invitation), "invitation", body=doc.to_json(), statuses=(201,))

    def admin_delete_user(self, name: str, confirm: str) -> Call[None]:
        """DELETE an account (SPEC.md § 5.7): `confirm` repeats its name, as its user typed it."""
        if not name or len(name) > 64:
            raise ValueError("an account's name is 1 to 64 characters")
        return Call(
            "DELETE",
            "/admin/users/" + quote(name, safe=""),
            _reject,
            "account deletion",
            [("confirm", confirm)],
            statuses=(),
            empty_statuses=(204,),
            empty=_none,
        )

    # Events (SPEC.md § 18).

    def events_request(self, since: str | None, platform: str | None) -> Request:
        """The request that opens a stream (SPEC.md § 18.1): resumed after `since` with Last-Event-ID."""
        url = self.v1("/events")
        query = _platform(platform)
        if query:
            url += "?" + urlencode(query, quote_via=quote)
        headers = {"Accept": "text/event-stream", "Cache-Control": "no-store"}
        if since is not None:
            if not since or len(since) > 1024 or any(ord(c) < 32 for c in since):
                raise ValueError("an event id is a token of /v1/changes")
            headers["Last-Event-ID"] = since
        return self.prepare("GET", url, headers=headers)

    def wait_changes(self, since: str, wait: int, platform: str | None, timeout: float) -> Call[Changes]:
        """A long poll (SPEC.md § 18.3): the changes and events after `since`, answered as soon as one comes
        or after `wait` seconds (lowered to the server's `limits.wait`)."""
        if wait < 0:
            raise ValueError("wait is a number of seconds, from 0")
        limits = self.hello.limits if self.hello is not None else None
        if limits is not None and limits.wait is not None:
            wait = min(wait, limits.wait)
        query = [*_platform(platform), ("since", since), ("wait", str(wait))]
        return Call("GET", "/changes", _model(Changes), "long poll", query, timeout=timeout + wait)

    # Grants (SPEC.md § 19.3).

    def grant(self, sha256: str, platform: str | None) -> Call[Grant]:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("a file is named by its SHA-256, lower-case hex")
        return Call("GET", "/grants/sha256/" + sha256, _model(Grant), "grant", _platform(platform))

    def check_grant(self, grant: Grant, sha256: str, size: int) -> None:
        """A grant the server gave, checked before it goes to a peer: of the file asked for, verifying by the
        handshake's `peers.key` for its uid, not expired by the server's clock. A grant that does not is
        refused (IntegrityError): a peer would refuse it too, and nothing else of the server goes to one."""
        from lantern.errors import IntegrityError

        hello = self.hello
        key = grant_key(hello.peers.key) if hello is not None and hello.peers is not None else None
        if hello is None or key is None:
            raise IntegrityError("the server gives no grant key (peers.key): it offers no grants")
        if grant.sha256 != sha256 or grant.size != size:
            raise IntegrityError(f"a grant for {grant.sha256[:16]}…, {grant.size} bytes: not the file asked for")
        found = read_grant(grant.grant, {hello.uid: key}, now=self.now())
        if found is None or found.sha256 != sha256 or found.size != size:
            raise IntegrityError("a grant that does not verify by peers.key, names another file, or expired")

    # Sync (SPEC.md § 20).

    def sync_overview(self) -> Call[Sync]:
        return Call("GET", "/sync", _model(Sync), "sync")

    def sync_read(
        self, collection: str, since: int | None, page_size: int | None, cursor: str | None
    ) -> Call[SyncCollection]:
        query = [("since", str(since))] if since is not None else []
        query += _listing(page_size, cursor)
        return Call("GET", "/sync/" + _collection(collection), _model(SyncCollection), "sync collection", query)

    def sync_write(
        self, collection: str, generation: str, items: Sequence[syncing.Item], if_match: str | None
    ) -> Call[SyncCollection]:
        if not 1 <= len(items) <= syncing.WRITE_LIMIT:
            raise ValueError(f"a write sends 1 to {syncing.WRITE_LIMIT} items")
        if len({i.key for i in items}) != len(items):
            raise ValueError("an item's key twice in one write")
        for i in items:
            if syncing.parse_updated(i.updated) is None:
                raise ValueError(f"{i.updated!r}: updated is a UTC time to the millisecond")
        doc = SyncWrite(schema=SCHEMA, generation=generation, items=[]).to_json()
        doc["items"] = [{k: v for k, v in i.to_json().items() if k != "rev"} for i in items]
        headers = {"If-Match": if_match} if if_match is not None else {}
        return Call(
            "PATCH", "/sync/" + _collection(collection), _model(SyncCollection), "sync write", body=doc, headers=headers
        )

    def sync_delete(self, collection: str | None) -> Call[None]:
        path = "/sync" + ("/" + _collection(collection) if collection is not None else "")
        return Call("DELETE", path, _reject, "sync deletion", statuses=(), empty_statuses=(204,), empty=_none)

    def _needs_platform(self, platform: str | None, what: str) -> None:
        if platform is None and self.platform is None:
            raise ValueError(f"{what} needs a platform (SPEC.md § 4.3)")

    def offers(self, family: str) -> bool:
        """Whether the handshake says the server offers `family` to this caller, in a schema this library reads."""
        if self.hello is None:
            raise LanternError("no handshake yet")
        level = self.hello.features.get(family, 0)
        return 0 < level <= KNOWN.get(family, SCHEMA)


def retry_signature(core: ClientCore, error: LanternError, request: Request, attempt: int) -> bool:
    """Whether a request refused for its signature is signed again (SPEC.md § 5.4, Annex B.2): once, after
    `signature_expired` with the server's Date taken, or after `signature_replayed` with a new nonce. Any other
    refusal asks the user to pair again."""
    if attempt > 0 or "Signature" not in request.headers:
        return False
    if isinstance(error, SignatureExpired):
        return core.adjust_clock(Headers(error.headers))
    return isinstance(error, SignatureReplayed)


def token_record(core: ClientCore, pairing: Pairing, token: PairingToken) -> ServerRecord:
    """What a client keeps of a server once paired (SPEC.md § 5.3): its uid, the key it pinned when no CA
    vouched for it, the token and the device key."""
    hello = core.hello
    if hello is None:
        raise LanternError("no handshake yet")
    return ServerRecord(
        uid=hello.uid,
        url=core.root + "/",
        token=token.token,
        name=hello.name,
        spki=pairing.spki,
        key=pairing.key.seed_b64() if pairing.key is not None and token.bound is not False else None,
        scopes=list(token.scopes),
        bound=bool(token.bound) and pairing.key is not None,
        rating_cap=token.rating_cap.to_json() if token.rating_cap is not None else None,
        paired=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


def item_of(doc: SyncItem) -> syncing.Item:
    """A sync item as read (SPEC.md § 20.2)."""
    return syncing.Item(doc.key, doc.updated, doc.value, bool(doc.deleted), doc.rev)


def events_of(changes: Changes) -> list[ServerEvent]:
    """The events of a long poll, read by the rules of SPEC.md § 18.1: one of a type this library does not
    know, or of a newer schema, skipped; ready and shutdown are a stream's alone."""
    out = []
    for e in changes.events or []:
        found = event_of(e.id, e.event, e.data.to_json())
        if found is not None and found.event not in ("ready", "shutdown"):
            out.append(found)
    return out


def what_fits(apps: Iterable[App], free: int) -> tuple[list[App], list[App]]:
    """The apps that fit in `free` bytes, and those that do not (SPEC.md § 6.3: the client decides): each
    compared by its `installed_size`, or its `size` without one."""
    fit: list[App] = []
    too_big: list[App] = []
    for app in apps:
        (fit if (app.installed_size or app.size) <= free else too_big).append(app)
    return fit, too_big


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


__all__ = [
    "JSON_DOCUMENT",
    "Call",
    "ClientCore",
    "Deprecation",
    "chunked",
    "events_of",
    "item_of",
    "merge_titles",
    "next_cursor",
    "retry_signature",
    "token_record",
    "what_fits",
]
