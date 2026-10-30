"""Pairing (SPEC.md § 5.2), on the server's side: the codes waiting for the
user, their poll addresses, their approval on the server's own page or
through the administration API (§ 5.7), and the token given once. Held in
memory: a code lives 10 minutes at most.

    entry = desk.by_code(typed)                # on the server's approval page
    desk.approve(entry, "lea", scopes=None)    # the scopes asked for that the account has
"""

from __future__ import annotations

import html
import secrets
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from lantern._base import JSONObject
from lantern._generated.models import RatingCap
from lantern.server.accounts import Accounts, new_code, ordered_scopes, typed_code, utc
from lantern.server.http import ProblemError

CODE_SYMBOLS = 8  # 40 bits (SPEC.md § 5.2)
PENDING_LIMIT = 1000


def slow_down(wait: float, detail: str) -> ProblemError:
    return ProblemError(
        429, "slow_down", detail, title="Slow down", headers={"Retry-After": str(max(1, int(wait + 0.999)))}
    )


class Limiter:
    """At most `count` events per `window` seconds per key (an address)."""

    def __init__(self, count: int, window: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.count, self.window, self.clock = count, window, clock
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def wait(self, key: str) -> float:
        """Seconds to wait before the next event of `key`; 0 when it may happen now."""
        now = self.clock()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > now - self.window]
            self._hits[key] = hits
            if len(self._hits) > 10000:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > now - self.window}
            return 0.0 if len(hits) < self.count else hits[0] + self.window - now

    def record(self, key: str) -> None:
        with self._lock:
            self._hits.setdefault(key, []).append(self.clock())

    def hit(self, key: str) -> float:
        """wait(), and the event recorded when it may happen."""
        wait = self.wait(key)
        if not wait:
            self.record(key)
        return wait


@dataclass
class Pending:
    """A pairing waiting for the user. `poll` is its secret address's last
    part; `id` names it in the administration API, and is not a secret."""

    poll: str
    id: str
    code: str
    device: str
    scopes: tuple[str, ...]
    key: bytes | None
    until: float
    created: str
    expires: str
    interval: int
    state: str = "pending"  # approved, refused
    polled: float | None = None
    token: str | None = None
    granted: tuple[str, ...] = ()
    rating_cap: RatingCap | None = None
    lifetime: float | None = None


class PairingDesk:
    """The pairings waiting, and their approval. `accounts` issues the tokens."""

    def __init__(
        self,
        accounts: Accounts,
        *,
        interval: int = 5,
        expires: int = 600,
        lifetime: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= expires <= 600:
            raise ValueError("a code expires within 10 minutes (SPEC.md § 5.2)")
        self.accounts, self.interval, self.expires, self.lifetime = accounts, interval, expires, lifetime
        self.clock = clock
        self._pending: dict[str, Pending] = {}
        self._lock = threading.Lock()

    def _purge(self) -> None:
        now = self.clock()
        for poll in [p for p, e in self._pending.items() if e.until <= now]:
            del self._pending[poll]

    def start(self, device: str, scopes: Sequence[str], key: bytes | None) -> Pending:
        with self._lock:
            self._purge()
            if len(self._pending) >= PENDING_LIMIT:
                raise slow_down(self.interval, "Too many pairings are waiting; try again later.")
            codes = {typed_code(e.code) for e in self._pending.values()}
            while typed_code(code := _code()) in codes:
                pass
            entry = Pending(
                poll="p_" + secrets.token_urlsafe(24),  # 192 bits: whoever has it collects the token
                id="pr_" + secrets.token_urlsafe(9),
                code=code,
                device=device,
                scopes=ordered_scopes(scopes),
                key=key,
                until=self.clock() + self.expires,
                created=utc(),
                expires=utc_in(self.expires),
                interval=self.interval,
            )
            self._pending[entry.poll] = entry
            return entry

    def by_code(self, typed: str) -> Pending | None:
        """The pairing waiting with this code, as the user typed it."""
        code = typed_code(typed)
        with self._lock:
            self._purge()
            return next(
                (
                    e
                    for e in self._pending.values()
                    if e.state == "pending" and secrets.compare_digest(typed_code(e.code), code)
                ),
                None,
            )

    def by_id(self, pairing_id: str) -> Pending | None:
        with self._lock:
            self._purge()
            return next((e for e in self._pending.values() if e.state == "pending" and e.id == pairing_id), None)

    def peek(self, poll: str) -> Pending | None:
        with self._lock:
            self._purge()
            return self._pending.get(poll)

    def waiting(self) -> list[Pending]:
        with self._lock:
            self._purge()
            return sorted((e for e in self._pending.values() if e.state == "pending"), key=lambda e: e.created)

    def approve(
        self,
        entry: Pending,
        user: str,
        scopes: Sequence[str] | None = None,
        rating_cap: RatingCap | None = None,
        invitation: str | None = None,
    ) -> tuple[str, ...]:
        """Approves `entry` for the account `user`: the scopes it asked for (or
        those of `scopes` among them) that the account holds (SPEC.md § 5.2,
        § 5.7). Gives the scopes granted; the token waits for the next poll."""
        account = self.accounts.user(user)
        if account is None:
            raise ValueError(f"no account named {user}")
        wanted = entry.scopes if scopes is None else tuple(s for s in entry.scopes if s in scopes)
        granted = tuple(s for s in wanted if s in account.scopes)
        token, _ = self.accounts.issue(
            user,
            entry.device,
            granted,
            key=entry.key,
            rating_cap=rating_cap,
            invitation=invitation,
            lifetime=self.lifetime,
        )
        with self._lock:
            entry.state, entry.token, entry.granted, entry.rating_cap = "approved", token, granted, rating_cap
            entry.lifetime = self.lifetime
        return granted

    def refuse(self, entry: Pending) -> None:
        with self._lock:
            entry.state = "refused"

    def poll(self, poll: str) -> JSONObject | None:
        """The token's document once approved (given once), None while waiting;
        a ProblemError 410 when refused, expired, collected or unknown, 429 when
        polled faster than `interval`."""
        with self._lock:
            self._purge()
            entry = self._pending.get(poll)
            if entry is None:
                raise ProblemError(410, "gone", "Refused, expired, already collected or unknown.", title="Gone")
            now = self.clock()
            if entry.polled is not None and now - entry.polled < entry.interval * 0.8:
                entry.polled = now
                raise slow_down(entry.interval, f"Poll every {entry.interval} seconds.")
            entry.polled = now
            if entry.state == "refused":
                del self._pending[poll]
                raise ProblemError(410, "gone", "The user refused this device.", title="Gone")
            if entry.state != "approved" or entry.token is None:
                return None
            del self._pending[poll]
        doc: JSONObject = {
            "schema": 1,
            "token": entry.token,
            "scopes": list(entry.granted),
            "bound": entry.key is not None,
        }
        if entry.lifetime:
            doc["expires"] = int(entry.lifetime)
        if entry.rating_cap is not None:
            doc["rating_cap"] = entry.rating_cap.to_json()
        return doc


def _code() -> str:
    return new_code(CODE_SYMBOLS)


def utc_in(seconds: float) -> str:
    return utc(datetime.now(UTC) + timedelta(seconds=seconds))


def approval_page(*, fingerprint: str | None, code: str = "", message: str | None = None, action: str = "") -> str:
    """A minimal page for a server's own approval step (SPEC.md § 5.2, § 5.3):
    it shows the short fingerprint of the server's key, next to a form for
    the code. Signing the user in, and approving, are the server's: this page
    approves nothing by itself (L-5.2-11)."""
    shown = html.escape(fingerprint) if fingerprint else "(no TLS key: plain HTTP on loopback)"
    note = f"<p>{html.escape(message)}</p>" if message else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer"><title>Pair a device</title></head><body>'
        "<h1>Pair a device</h1>"
        f"<p>This server's key: <code>{shown}</code>. Compare it with the one the device shows.</p>{note}"
        f'<form method="post" action="{html.escape(action)}"><label>Code '
        f'<input name="code" value="{html.escape(code)}" autocomplete="off"></label>'
        "<button>Continue</button></form></body></html>"
    )
