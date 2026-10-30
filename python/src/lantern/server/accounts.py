"""Accounts, devices and invitations (SPEC.md § 5.1, § 5.5, § 5.7): what a
server keeps so that LanternApp can issue tokens by pairing, check them and
their signatures, and answer the administration API.

`Accounts` is the interface a server implements over its own store (a
database, a file…); `MemoryAccounts` is a complete one, held in memory, for
tests, demos and as a reference to read. A server that keeps its own tokens
can skip all this and give LanternApp an `authenticate` hook instead.

What is kept follows SPEC.md § 5: a token's hash only (never the token), the
device's public key when it paired with one, the scopes approved (never more
than its account's), its rating cap, and the invitation it came by.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol

from lantern._generated.models import RatingCap

#: The pairing alphabet (SPEC.md § 5.2): no 0, O, 1 or I.
CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
#: An account's name (SPEC.md § 5.7).
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
#: The scopes, in the order the handshake lists them (SPEC.md § 4.2).
SCOPES = ("library", "saves", "cheats", "cheats.write", "requests", "admin")
INVITATION_SYMBOLS = 16  # 80 bits (SPEC.md § 5.5)


def utc(when: datetime | None = None) -> str:
    """An RFC 3339 time, in UTC, to the second."""
    return (when or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo is not None else None


def token_hash(token: str) -> str:
    """What a server keeps of a token (SPEC.md § 5.1): its SHA-256, hex."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    """A new token: `et_` and 256 random bits."""
    return "et_" + secrets.token_urlsafe(32)


def new_code(symbols: int) -> str:
    """A code of the pairing alphabet, `symbols` long, in groups of 4 joined by `-` (SPEC.md § 5.2)."""
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(symbols))
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def typed_code(text: str) -> str:
    """A code as a user typed it, compared without case, spaces or dashes."""
    return re.sub(r"[\s-]", "", text).upper()


def ordered_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    """The scopes this text knows among `scopes`, in their order, each once."""
    wanted = set(scopes)
    return tuple(s for s in SCOPES if s in wanted)


@dataclass(frozen=True)
class User:
    """An account (SPEC.md § 5.7): its name, state and scopes. No password: a
    server's own means may give it one, outside this."""

    name: str
    scopes: tuple[str, ...]
    state: str = "active"
    created: str = field(default_factory=utc)


@dataclass(frozen=True)
class Device:
    """A paired device and its token (SPEC.md § 5.1, § 5.7), as kept: the token's hash, never the token."""

    id: str
    token_hash: str
    user: str
    device: str
    scopes: tuple[str, ...]
    created: str
    key: bytes | None = None
    rating_cap: RatingCap | None = None
    invitation: str | None = None
    expires: str | None = None
    last_used: str | None = None

    @property
    def bound(self) -> bool:
        return self.key is not None

    def live(self, now: datetime | None = None) -> bool:
        if self.expires is None:
            return True
        until = parse_time(self.expires)
        return until is not None and until > (now or datetime.now(UTC))


@dataclass(frozen=True)
class Invitation:
    """An invitation (SPEC.md § 5.5)."""

    id: str
    code: str
    user: str
    scopes: tuple[str, ...]
    expires: str
    devices: int
    used: int = 0
    rating_cap: RatingCap | None = None
    note: str | None = None
    created: str = field(default_factory=utc)

    def redeemable(self, now: datetime | None = None) -> bool:
        until = parse_time(self.expires)
        return until is not None and until > (now or datetime.now(UTC)) and self.used < self.devices


class AccountError(Exception):
    """A change the store refuses: `status` (404, 409…) and why."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


class Accounts(Protocol):
    """Where a server keeps its accounts, devices and invitations. Every
    method is called per request; each must be safe from several threads."""

    def user(self, name: str) -> User | None: ...

    def users(self) -> Sequence[User]: ...

    def create_user(self, name: str, scopes: Sequence[str], state: str = "active") -> User:
        """A new account; AccountError 409 `conflict` when the name is taken."""
        ...

    def update_user(self, name: str, *, state: str | None = None, scopes: Sequence[str] | None = None) -> User:
        """An account changed; AccountError 404 when there is none. Its devices' scopes are cut back with its own."""
        ...

    def device_of(self, token: str) -> Device | None:
        """The live device whose token is `token`, or None (unknown, revoked or expired)."""
        ...

    def issue(
        self,
        user: str,
        device: str,
        scopes: Sequence[str],
        *,
        key: bytes | None = None,
        rating_cap: RatingCap | None = None,
        invitation: str | None = None,
        lifetime: float | None = None,
    ) -> tuple[str, Device]:
        """A new token for a device, and the device as kept (its hash only)."""
        ...

    def devices(self, user: str | None = None) -> Sequence[Device]: ...

    def revoke(self, device_id: str) -> bool:
        """Revokes a device's token, at once; False when there is none."""
        ...

    def create_invitation(
        self,
        user: str,
        scopes: Sequence[str],
        expires: str,
        devices: int,
        *,
        rating_cap: RatingCap | None = None,
        note: str | None = None,
    ) -> Invitation: ...

    def invitations(self) -> Sequence[Invitation]:
        """The invitations that can still be redeemed."""
        ...

    def revoke_invitation(self, invitation_id: str) -> bool: ...

    def redeem(self, code: str) -> Invitation | None:
        """The invitation of `code` (as typed), its use counted at once, so that
        devices redeeming it together never pass `devices`; None when it is
        unknown, expired, revoked or used up."""
        ...


class MemoryAccounts:
    """Accounts, devices and invitations held in memory."""

    def __init__(self, users: Iterable[User] = ()) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {u.name: u for u in users}
        self._devices: dict[str, Device] = {}  # by token hash
        self._invitations: dict[str, Invitation] = {}

    # Accounts.

    def user(self, name: str) -> User | None:
        with self._lock:
            return self._users.get(name)

    def users(self) -> list[User]:
        with self._lock:
            return sorted(self._users.values(), key=lambda u: u.name)

    def create_user(self, name: str, scopes: Sequence[str], state: str = "active") -> User:
        if not ACCOUNT_NAME.match(name):
            raise AccountError(400, "bad_request", "name is 1 to 64 letters, digits, '.', '_' and '-'.")
        with self._lock:
            if name in self._users:
                raise AccountError(409, "conflict", f"An account named {name} exists.")
            user = User(name, ordered_scopes(scopes), state)
            self._users[name] = user
            return user

    def update_user(self, name: str, *, state: str | None = None, scopes: Sequence[str] | None = None) -> User:
        with self._lock:
            user = self._users.get(name)
            if user is None:
                raise AccountError(404, "not_found", "No such account.")
            if state is not None:
                user = replace(user, state=state)
            if scopes is not None:
                user = replace(user, scopes=ordered_scopes(scopes))
                for h, d in list(self._devices.items()):
                    if d.user == name:
                        self._devices[h] = replace(d, scopes=tuple(s for s in d.scopes if s in user.scopes))
            self._users[name] = user
            return user

    # Devices.

    def device_of(self, token: str) -> Device | None:
        with self._lock:
            found = self._devices.get(token_hash(token))
        return found if found is not None and found.live() else None

    def issue(
        self,
        user: str,
        device: str,
        scopes: Sequence[str],
        *,
        key: bytes | None = None,
        rating_cap: RatingCap | None = None,
        invitation: str | None = None,
        lifetime: float | None = None,
    ) -> tuple[str, Device]:
        token = new_token()
        digest = token_hash(token)
        expires = utc(datetime.now(UTC) + timedelta(seconds=lifetime)) if lifetime else None
        record = Device(
            id="d_" + secrets.token_urlsafe(12),
            token_hash=digest,
            user=user,
            device=device,
            scopes=ordered_scopes(scopes),
            created=utc(),
            key=key,
            rating_cap=rating_cap,
            invitation=invitation,
            expires=expires,
        )
        with self._lock:
            self._devices[digest] = record
        return token, record

    def add_token(
        self,
        token: str,
        user: str,
        device: str,
        scopes: Sequence[str],
        *,
        key: bytes | None = None,
        rating_cap: RatingCap | None = None,
    ) -> Device:
        """Keeps a token the server did not issue here (a demo's, or one moved from another store): its hash."""
        record = Device(
            id="d_" + secrets.token_urlsafe(12),
            token_hash=token_hash(token),
            user=user,
            device=device,
            scopes=ordered_scopes(scopes),
            created=utc(),
            key=key,
            rating_cap=rating_cap,
        )
        with self._lock:
            self._devices[record.token_hash] = record
        return record

    def devices(self, user: str | None = None) -> list[Device]:
        with self._lock:
            found = [d for d in self._devices.values() if d.live() and (user is None or d.user == user)]
        return sorted(found, key=lambda d: (d.user, d.created, d.id))

    def revoke(self, device_id: str) -> bool:
        with self._lock:
            found = [h for h, d in self._devices.items() if d.id == device_id]
            for h in found:
                del self._devices[h]
            return bool(found)

    # Invitations.

    def create_invitation(
        self,
        user: str,
        scopes: Sequence[str],
        expires: str,
        devices: int,
        *,
        rating_cap: RatingCap | None = None,
        note: str | None = None,
    ) -> Invitation:
        with self._lock:
            codes = {typed_code(i.code) for i in self._invitations.values()}
            while typed_code(code := new_code(INVITATION_SYMBOLS)) in codes:
                pass
            inv = Invitation(
                id="i_" + secrets.token_urlsafe(9),
                code=code,
                user=user,
                scopes=ordered_scopes(scopes),
                expires=expires,
                devices=devices,
                rating_cap=rating_cap,
                note=note,
            )
            self._invitations[inv.id] = inv
            return inv

    def invitations(self) -> list[Invitation]:
        with self._lock:
            return sorted((i for i in self._invitations.values() if i.redeemable()), key=lambda i: (i.created, i.id))

    def revoke_invitation(self, invitation_id: str) -> bool:
        with self._lock:
            return self._invitations.pop(invitation_id, None) is not None

    def redeem(self, code: str) -> Invitation | None:
        typed = typed_code(code)
        with self._lock:
            for inv in self._invitations.values():
                if hmac.compare_digest(typed_code(inv.code), typed):
                    if not inv.redeemable():
                        return None
                    used = replace(inv, used=inv.used + 1)
                    self._invitations[inv.id] = used
                    return used
        return None
