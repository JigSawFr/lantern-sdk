"""What a client pins: the servers it paired with (SPEC.md § 5.3, § 5.4:
their key's fingerprint, its token and device key, `ServerStore`), and the
keys of each homebrew (SPEC.md § 8.4): on the first
install of an id, its signing key (or that it had none); later, a version
signed by another key, or unsigned after a signed one, is refused unless the
user explicitly accepts the change, after seeing both keys' fingerprints.

`KeyPins` and `ServerStore` are the interfaces; a client keeps its pins where
it keeps its state. `MemoryKeyPins`, `FileKeyPins`, `MemoryServerStore` and
`FileServerStore` (JSON files, by the `schema` rule) are implementations.

    decision = check_key(pins, entry)
    if decision.change == "changed" and not ask_user(decision):
        refuse()
    ... install ...
    pins.pin(entry.platform, entry.id, decision.offered)
"""

from __future__ import annotations

import contextlib
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from lantern._base import SCHEMA, JSONObject, JSONValue
from lantern._generated.models import Homebrew
from lantern.homebrew import key_change, key_fingerprint
from lantern.store import load_document, save_document


class KeyPins(Protocol):
    """Where a client keeps the key it pinned per homebrew id and platform."""

    def pinned(self, platform: str, homebrew_id: str) -> str | None:
        """The pinned key (base64), "" when the id was first installed unsigned, None when never installed."""
        ...

    def pin(self, platform: str, homebrew_id: str, public_key: str) -> None:
        """Pin `public_key` ("" for none) for the id, after an install the user accepted."""
        ...

    def forget(self, platform: str, homebrew_id: str) -> None:
        """Forget the id's key, once it is uninstalled."""
        ...


@dataclass(frozen=True)
class KeyDecision:
    """check_key()'s answer: `change` is "pin", "same" or "changed", with both
    keys (base64, "" for none) and their short fingerprints, for the user."""

    change: Literal["pin", "same", "changed"]
    pinned: str | None
    offered: str

    @property
    def needs_consent(self) -> bool:
        return self.change == "changed"

    @property
    def pinned_fingerprint(self) -> str | None:
        return key_fingerprint(self.pinned) if self.pinned else None

    @property
    def offered_fingerprint(self) -> str | None:
        return key_fingerprint(self.offered) if self.offered else None


def check_key(pins: KeyPins, entry: Homebrew) -> KeyDecision:
    """Whether `entry`'s key is the one pinned for its id (SPEC.md § 8.4)."""
    pinned = pins.pinned(entry.platform, entry.id)
    offered = entry.signature.public_key if entry.signature is not None else ""
    return KeyDecision(key_change(pinned, entry), pinned, offered)


class MemoryKeyPins:
    """Pins kept in memory."""

    def __init__(self) -> None:
        self._pins: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def pinned(self, platform: str, homebrew_id: str) -> str | None:
        with self._lock:
            return self._pins.get((platform, homebrew_id))

    def pin(self, platform: str, homebrew_id: str, public_key: str) -> None:
        with self._lock:
            self._pins[(platform, homebrew_id)] = public_key

    def forget(self, platform: str, homebrew_id: str) -> None:
        with self._lock:
            self._pins.pop((platform, homebrew_id), None)


class FileKeyPins:
    """Pins kept in a JSON file: {"schema": 1, "pins": {"<platform>/<id>": "<key>"}}.
    A file of a newer schema is read as absent and never written over (the
    pins are then refused: pin() raises store.NewerOnDisk); keys this library
    does not know are kept when it writes the file again."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> JSONObject:
        doc = load_document(self.path, known=SCHEMA)
        return doc if doc is not None else {"schema": SCHEMA, "pins": {}}

    def pinned(self, platform: str, homebrew_id: str) -> str | None:
        with self._lock:
            pins = self._read().get("pins")
            value = pins.get(f"{platform}/{homebrew_id}") if isinstance(pins, dict) else None
            return value if isinstance(value, str) else None

    def _update(self, key: str, value: str | None) -> None:
        with self._lock:
            doc = self._read()
            pins = doc.get("pins")
            pins = dict(pins) if isinstance(pins, dict) else {}
            if value is None:
                pins.pop(key, None)
            else:
                pins[key] = value
            doc["pins"] = pins
            save_document(self.path, doc, known=SCHEMA)

    def pin(self, platform: str, homebrew_id: str, public_key: str) -> None:
        self._update(f"{platform}/{homebrew_id}", public_key)

    def forget(self, platform: str, homebrew_id: str) -> None:
        self._update(f"{platform}/{homebrew_id}", None)


# The servers a client paired with (SPEC.md § 5.2 to § 5.4).


@dataclass
class ServerRecord:
    """What a client keeps of a server it paired with, by its `uid`: where it
    is, the fingerprint of the key it pinned (`spki`, SHA-256 hex, None when a
    CA vouches for its certificate), its token, the device key the token is
    bound to (`key`: its secret seed, base64; None for a bearer-only token),
    the scopes and rating cap the token carries, and when it paired. Fields
    this library does not know are kept in `extra`, and written back."""

    uid: str
    url: str
    token: str
    name: str = ""
    spki: str | None = None
    key: str | None = None
    scopes: list[str] = field(default_factory=list)
    bound: bool = False
    rating_cap: JSONObject | None = None
    paired: str = ""
    extra: JSONObject = field(default_factory=dict)

    KEYS = frozenset({"uid", "url", "token", "name", "spki", "key", "scopes", "bound", "rating_cap", "paired"})

    def to_json(self) -> JSONObject:
        out: JSONObject = {"uid": self.uid, "url": self.url, "token": self.token, "name": self.name}
        if self.spki is not None:
            out["spki"] = self.spki
        if self.key is not None:
            out["key"] = self.key
        scopes: list[JSONValue] = list(self.scopes)
        out.update({"scopes": scopes, "bound": self.bound, "paired": self.paired})
        if self.rating_cap is not None:
            out["rating_cap"] = self.rating_cap
        return {**self.extra, **out}

    @classmethod
    def from_json(cls, data: JSONValue) -> ServerRecord | None:
        """A record, or None when it is not one this library can use."""
        if not isinstance(data, dict):
            return None
        uid, url, token = data.get("uid"), data.get("url"), data.get("token")
        if not (isinstance(uid, str) and isinstance(url, str) and isinstance(token, str)):
            return None
        spki, key, cap = data.get("spki"), data.get("key"), data.get("rating_cap")
        scopes = data.get("scopes")
        return cls(
            uid=uid,
            url=url,
            token=token,
            name=str(data.get("name") or ""),
            spki=spki if isinstance(spki, str) else None,
            key=key if isinstance(key, str) else None,
            scopes=[s for s in scopes if isinstance(s, str)] if isinstance(scopes, list) else [],
            bound=data.get("bound") is True,
            rating_cap=cap if isinstance(cap, dict) else None,
            paired=str(data.get("paired") or ""),
            extra={k: v for k, v in data.items() if k not in cls.KEYS},
        )

    def __repr__(self) -> str:
        return f"ServerRecord(uid={self.uid!r}, url={self.url!r}, spki={self.spki!r}, bound={self.bound})"


class ServerStore(Protocol):
    """Where a client keeps the servers it paired with: their tokens and
    device keys are secrets, kept where the system protects them when it has
    such a place (SPEC.md § 5.4)."""

    def server(self, uid: str) -> ServerRecord | None: ...

    def servers(self) -> list[ServerRecord]: ...

    def save(self, record: ServerRecord) -> None:
        """Keep `record` (a new pairing replaces the server's former one)."""
        ...

    def forget(self, uid: str) -> None: ...


class MemoryServerStore:
    """Servers kept in memory."""

    def __init__(self) -> None:
        self._servers: dict[str, ServerRecord] = {}
        self._lock = threading.Lock()

    def server(self, uid: str) -> ServerRecord | None:
        with self._lock:
            return self._servers.get(uid)

    def servers(self) -> list[ServerRecord]:
        with self._lock:
            return list(self._servers.values())

    def save(self, record: ServerRecord) -> None:
        with self._lock:
            self._servers[record.uid] = record

    def forget(self, uid: str) -> None:
        with self._lock:
            self._servers.pop(uid, None)


class FileServerStore:
    """Servers kept in a JSON file, readable by its owner alone:
    {"schema": 1, "servers": {"<uid>": {…}}}. A file of a newer schema is
    read as absent and never written over (save() raises store.NewerOnDisk);
    keys this library does not know, the file's and each record's, are kept."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> JSONObject:
        doc = load_document(self.path, known=SCHEMA)
        return doc if doc is not None else {"schema": SCHEMA, "servers": {}}

    def _records(self) -> dict[str, JSONValue]:
        servers = self._read().get("servers")
        return dict(servers) if isinstance(servers, dict) else {}

    def server(self, uid: str) -> ServerRecord | None:
        with self._lock:
            return ServerRecord.from_json(self._records().get(uid))

    def servers(self) -> list[ServerRecord]:
        with self._lock:
            found = [ServerRecord.from_json(v) for v in self._records().values()]
        return [r for r in found if r is not None]

    def _update(self, uid: str, value: JSONObject | None) -> None:
        with self._lock:
            doc = self._read()
            servers = doc.get("servers")
            servers = dict(servers) if isinstance(servers, dict) else {}
            if value is None:
                servers.pop(uid, None)
            else:
                servers[uid] = value
            doc["servers"] = servers
            save_document(self.path, doc, known=SCHEMA)
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)

    def save(self, record: ServerRecord) -> None:
        self._update(record.uid, record.to_json())

    def forget(self, uid: str) -> None:
        self._update(uid, None)
