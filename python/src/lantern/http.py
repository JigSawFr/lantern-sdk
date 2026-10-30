"""HTTP pieces both sides share: case-insensitive headers, origins, and the
loopback rule of SPEC.md § 2."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from urllib.parse import urlsplit

PLATFORM_HEADER = "Lantern-Platform"
JSON = "application/json"
PROBLEM_JSON = "application/problem+json"


class Headers(MutableMapping[str, str]):
    """HTTP headers, their names compared without case; a name given twice
    keeps its values joined by ", " (as RFC 9110 allows for list fields)."""

    def __init__(self, items: Mapping[str, str] | Iterable[tuple[str, str]] = ()) -> None:
        self._items: dict[str, tuple[str, str]] = {}
        pairs = items.items() if isinstance(items, Mapping) else items
        for name, value in pairs:
            self.add(name, value)

    def add(self, name: str, value: str) -> None:
        key = name.lower()
        if key in self._items:
            self._items[key] = (self._items[key][0], f"{self._items[key][1]}, {value}")
        else:
            self._items[key] = (name, value)

    def __getitem__(self, name: str) -> str:
        return self._items[name.lower()][1]

    def __setitem__(self, name: str, value: str) -> None:
        self._items[name.lower()] = (name, value)

    def __delitem__(self, name: str) -> None:
        del self._items[name.lower()]

    def __iter__(self) -> Iterator[str]:
        return (name for name, _ in self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.lower() in self._items

    def __repr__(self) -> str:
        return f"Headers({dict(self.items())!r})"


def origin(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) of an absolute URL, the port made explicit."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"{url[:100]!r} is not an absolute http(s) URL")
    return scheme, parts.hostname.lower(), parts.port or (443 if scheme == "https" else 80)


def is_loopback(host: str) -> bool:
    """127.0.0.0/8, ::1 or localhost: where plain HTTP is allowed, for testing (SPEC.md § 2)."""
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def plain_http_allowed(url: str) -> bool:
    """Whether `url` may be spoken to: HTTPS, or plain HTTP to a loopback address."""
    scheme, host, _ = origin(url)
    return scheme == "https" or is_loopback(host)


def media_type(content_type: str | None) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def accept_languages(header: str | None) -> list[str]:
    """The languages of an Accept-Language header, best first (q=0 left out)."""
    out: list[tuple[float, int, str]] = []
    for i, part in enumerate((header or "").split(",")):
        tag, _, params = part.strip().partition(";")
        tag = tag.strip()
        if not tag or tag == "*":
            continue
        q = 1.0
        for param in params.split(";"):
            name, _, value = param.strip().partition("=")
            if name.strip().lower() == "q":
                try:
                    q = float(value)
                except ValueError:
                    q = 0.0
        if q > 0:
            out.append((-q, i, tag))
    return [tag for _, _, tag in sorted(out)]
