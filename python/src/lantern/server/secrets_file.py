"""The secrets a server must keep across restarts, in one file readable by its owner alone.

`LanternApp`'s `secret` seals cursors and since tokens (the same for every instance and after a restart, or
clients' tokens stop working) and `grant_seed` is the Ed25519 seed of the grant key (SPEC.md § 21): neither can be
drawn again at each start. `SecretsFile` draws each once, by name, and returns the same bytes ever after.

    vault = SecretsFile("/config/lantern-secrets.json")
    LanternApp(library, secret=vault.get("cursor"), grant_seed=vault.get("grant", 32), ...)

The file carries its `schema`. A file of a newer schema is not used (`SecretsSchemaError`) and is never
rewritten; a key this version does not know is kept when it rewrites the file.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import threading
from pathlib import Path

__all__ = ["SCHEMA", "SecretsFile", "SecretsSchemaError"]

#: The schema this version writes.
SCHEMA = 1


class SecretsSchemaError(Exception):
    """The file was written by a newer version: it is left as it is."""


class SecretsFile:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, object]:
        try:
            doc = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return {"schema": SCHEMA, "secrets": {}}
        if not isinstance(doc, dict) or not isinstance(doc.get("secrets", {}), dict):
            raise SecretsSchemaError(f"{self.path} is not a secrets file: it is left as it is.")
        schema = doc.get("schema")
        if isinstance(schema, int) and schema > SCHEMA:
            raise SecretsSchemaError(
                f"This secrets file is of schema {schema}, newer than the {SCHEMA} this version knows: "
                "it is left as it is."
            )
        doc.setdefault("secrets", {})
        return doc

    def get(self, name: str, size: int = 32) -> bytes:
        """The secret called `name`, `size` bytes, drawn at random the first time and kept."""
        if not name or size < 1:
            raise ValueError("a secret has a name and a size of 1 byte or more")
        with self._lock:
            doc = self._read()
            kept = doc["secrets"]
            assert isinstance(kept, dict)
            have = kept.get(name)
            if isinstance(have, str):
                with contextlib.suppress(ValueError):
                    value = bytes.fromhex(have)
                    if len(value) == size:
                        return value
                raise ValueError(f"The secret {name!r} kept is not {size} bytes: delete it to draw it again.")
            value = secrets.token_bytes(size)
            kept[name] = value.hex()
            doc.setdefault("schema", SCHEMA)
            self._write(doc)
            return value

    def _write(self, doc: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as out:
            json.dump(doc, out)
            out.flush()
            os.fsync(out.fileno())
        tmp.replace(self.path)
