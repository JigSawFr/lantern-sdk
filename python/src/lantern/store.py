"""Files a client or a server keeps, by the `schema` rule (SPEC.md § 3.2):

- a file of a newer `schema` than the program knows is read as absent, and
  never written over (save_document() raises NewerOnDisk);
- a file written again keeps the keys the program does not know;
- a file is written whole or not at all (a temporary file, then a rename).

    doc = load_document(path)               # None: absent, unreadable or newer
    doc = doc or {"schema": 1, "pins": {}}
    doc["pins"]["switch/org.example.frostline"] = key
    save_document(path, doc)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from lantern._base import SCHEMA, JSONObject, LanternError
from lantern.documents import M, Model, read
from lantern.limits import load_json


class NewerOnDisk(LanternError):
    """The file holds a newer `schema` than this program writes: it is left as it is."""


def _read_raw(path: Path) -> JSONObject | None:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        doc = load_json(raw, where=str(path))
    except LanternError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("schema"), int) or isinstance(doc.get("schema"), bool):
        return None
    return doc


def load_document(path: str | Path, *, known: int = SCHEMA) -> JSONObject | None:
    """The file's document; None when it is absent, unreadable, without a
    `schema`, or of a newer one than `known`."""
    doc = _read_raw(Path(path))
    if doc is None:
        return None
    schema = doc["schema"]
    return doc if isinstance(schema, int) and 1 <= schema <= known else None


def save_document(path: str | Path, document: JSONObject, *, known: int = SCHEMA) -> None:
    """Write `document` to `path`, atomically, keeping the keys of the file
    already there that `document` lacks. NewerOnDisk when that file is of a
    newer schema than `known`: it is never written over."""
    target = Path(path)
    current = _read_raw(target)
    if current is not None:
        schema = current["schema"]
        if isinstance(schema, int) and schema > known:
            raise NewerOnDisk(f"{target}: schema {schema}, newer than {known}: left as it is")
        document = {**{k: v for k, v in current.items() if k not in document}, **document}
    document.setdefault("schema", known)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(document, f, ensure_ascii=False, indent=1)
            f.write("\n")
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_model(model: type[M], path: str | Path, *, known: int = SCHEMA) -> M | None:
    """A model read from a file by the same rule: None when absent, unreadable or newer."""
    doc = _read_raw(Path(path))
    if doc is None:
        return None
    try:
        return read(model, doc, known=known, where=str(path))
    except LanternError:
        return None


def save_model(path: str | Path, model: Model, *, known: int = SCHEMA) -> None:
    """Write a model (its unknown fields included, from `extra`) by save_document()'s rule."""
    save_document(path, model.to_json(), known=known)
