"""Cursors and `since` tokens a server can give without keeping them.

A cursor (SPEC.md § 6.2) holds the sort key of a page's last item, the
listing it belongs to, and when it was given, sealed with the server's
secret (HMAC-SHA-256). The next page starts after that key, so reading while
the library changes neither skips nor repeats an item. A cursor the server
never gave (or gave for another listing) answers 400; an expired one, 410.

A `since` token (SPEC.md § 6.4, § 7.3) holds a position in the server's
change journal, sealed the same way: 400 when the server never gave it, 410
when the journal no longer reaches back to it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar

from lantern._base import JSONValue
from lantern.server.http import ProblemError, bad_request, gone

T = TypeVar("T")
SortKey = tuple[str | int, ...]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Sealer:
    """Seals small JSON payloads with an HMAC, so that they come back unchanged or not at all."""

    def __init__(self, secret: bytes | None = None) -> None:
        self.secret = secret or secrets.token_bytes(32)

    def seal(self, prefix: str, payload: JSONValue) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        mac = hmac.new(self.secret, prefix.encode() + b"." + raw, hashlib.sha256).digest()[:16]
        return f"{prefix}_{_b64(raw)}.{_b64(mac)}"

    def open(self, prefix: str, token: str) -> JSONValue:
        """The payload of a token this sealer gave with `prefix`; ValueError otherwise."""
        head, _, rest = token.partition("_")
        body, _, mac = rest.partition(".")
        if head != prefix or not body or not mac or len(token) > 1024:
            raise ValueError("not a token of this server")
        try:
            raw, given = _unb64(body), _unb64(mac)
        except (binascii.Error, ValueError):
            raise ValueError("not a token of this server") from None
        expected = hmac.new(self.secret, prefix.encode() + b"." + raw, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(given, expected):
            raise ValueError("not a token of this server")
        result: JSONValue = json.loads(raw)
        return result


@dataclass
class Page(Generic[T]):
    items: list[T]
    next: str | None
    total: int


class Cursors:
    """Pages of a listing, by keyset: each item has a unique sort key (a
    tuple of strings and integers; break ties with the item's id)."""

    def __init__(self, sealer: Sealer, lifetime: float = 3600.0, clock: Callable[[], float] = time.time) -> None:
        self.sealer, self.lifetime, self.clock = sealer, lifetime, clock

    def scope(self, *parts: object) -> str:
        """A listing's identity, from its route and filters: a cursor of another listing is refused."""
        return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:16]

    def after(self, cursor: str, scope: str) -> SortKey:
        try:
            payload = self.sealer.open("c", cursor)
        except ValueError:
            raise bad_request("Unknown cursor: one this server never gave.") from None
        keys = payload.get("k") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or payload.get("s") != scope or not isinstance(keys, list):
            raise bad_request("This cursor belongs to another listing.")
        issued = payload.get("t")
        if not isinstance(issued, (int, float)) or self.clock() - issued > self.lifetime:
            raise gone("Cursor expired: read the list again from its start.")
        return tuple(k for k in keys if isinstance(k, (str, int)))

    def page(
        self, items: Sequence[T], key: Callable[[T], SortKey], *, size: int, cursor: str | None, scope: str
    ) -> Page[T]:
        """The page of `items` (any order) after `cursor`, of `size` items at most."""
        ordered = sorted(items, key=key)
        if cursor is not None:
            last = self.after(cursor, scope)
            ordered = [i for i in ordered if key(i) > last]
        chosen = ordered[:size]
        following = None
        if len(ordered) > size:
            payload: JSONValue = {"s": scope, "k": list(key(chosen[-1])), "t": int(self.clock())}
            following = self.sealer.seal("c", payload)
        return Page(chosen, following, len(items))


class SinceTokens:
    """`since` tokens over a change journal's positions."""

    def __init__(self, sealer: Sealer) -> None:
        self.sealer = sealer

    def give(self, kind: str, epoch: str, position: int) -> str:
        return self.sealer.seal(kind, {"e": epoch, "n": position})

    def position(self, kind: str, token: str, epoch: str, oldest: int, current: int) -> int:
        """The position a token names: 400 when the server never gave it, 410 when too old."""
        try:
            payload = self.sealer.open(kind, token)
        except ValueError:
            raise bad_request("Unknown since token: one this server never gave.") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("n"), int):
            raise bad_request("Unknown since token.")
        n = payload["n"]
        assert isinstance(n, int)
        if payload.get("e") != epoch or n < oldest or n > current:
            raise gone("Token too old for this server: read them all again.")
        return n


def page_size(value: str | None, default: int, limit: int) -> int:
    """A listing's page_size (SPEC.md § 6.2): a positive integer, lowered to `limit`; 400 otherwise."""
    if value is None or value == "":
        return min(default, limit)
    if not value.isdigit() or int(value) < 1:
        raise bad_request("page_size is a positive integer.")
    return min(int(value), limit)


__all__ = ["Cursors", "Page", "ProblemError", "Sealer", "SinceTokens", "SortKey", "page_size"]
