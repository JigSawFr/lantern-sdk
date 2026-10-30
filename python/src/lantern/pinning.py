"""The keys a client pinned for each homebrew (SPEC.md § 8.4): on the first
install of an id, its signing key (or that it had none); later, a version
signed by another key, or unsigned after a signed one, is refused unless the
user explicitly accepts the change, after seeing both keys' fingerprints.

`KeyPins` is the interface; a client keeps its pins where it keeps its
state. `MemoryKeyPins` and `FileKeyPins` (a JSON file, by the `schema` rule)
are two implementations.

    decision = check_key(pins, entry)
    if decision.change == "changed" and not ask_user(decision):
        refuse()
    ... install ...
    pins.pin(entry.platform, entry.id, decision.offered)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from lantern._base import SCHEMA, JSONObject
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
