"""The limits of SPEC.md § 13, which a client bounds what it reads with and a
server stays within, and a JSON reader that keeps to them."""

from __future__ import annotations

import json
from collections.abc import Mapping

from lantern._base import DocumentError, JSONValue

JSON_DOCUMENT = 32 << 20  #: a JSON document, in bytes
DEPTH = 16  #: a JSON document's nesting
STRING = 4096  #: a string field, in UTF-8 bytes
NAME = 512  #: `name`
NOTE = 120  #: `note`
PROFILE = 64  #: `profile`
PAGE_ITEMS = 1000  #: the items of a page
TITLES_AT_ONCE = 100  #: the titles read at once (SPEC.md § 7.2)
MANIFEST_FILES = 4096  #: the files of a manifest
PATH = 1024  #: a manifest's path, in bytes
PATH_PART = 255  #: a part of a path, in bytes
PACKAGES = 16  #: a homebrew's `packages`
TAGS = 32  #: the tags of a title or a homebrew
TAG = 64  #: a tag, in bytes
REQUIRED_DATA = 256  #: the files of a port's requires_data, alternatives included
ACCEPT = 32  #: the accepted versions of a port's data file
CHEAT_SET = 1 << 20  #: a cheat set's text, in bytes
DATAGRAM = 1200  #: a discovery datagram, in bytes

#: The string fields whose bound is not STRING, by name.
STRING_CAPS: Mapping[str, int] = {"name": NAME, "note": NOTE, "profile": PROFILE}


def problems(document: JSONValue, caps: Mapping[str, int] = STRING_CAPS) -> list[str]:
    """Every way `document` goes beyond SPEC.md § 13 ([] when it does not):
    its depth, its strings (by their key's bound), and the lists the section
    bounds (a page's items, a manifest, packages, tags, a port's data)."""
    out: list[str] = []

    def walk(value: JSONValue, depth: int, key: str | None, path: str) -> None:
        if isinstance(value, (dict, list)) and depth > DEPTH:
            out.append(f"{path}: nested deeper than {DEPTH}")
            return
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, depth + 1, k, f"{path}.{k}")
            data = value.get("requires_data")
            if key == "port" and isinstance(data, list):
                count = 0
                for d in data:
                    groups = d.get("one_of") if isinstance(d, dict) else None
                    count += sum(len(g) for g in groups if isinstance(g, list)) if isinstance(groups, list) else 1
                if count > REQUIRED_DATA:
                    out.append(f"{path}.requires_data: {count} files, above {REQUIRED_DATA}")
        elif isinstance(value, list):
            bound = {
                "items": PAGE_ITEMS,
                "manifest": MANIFEST_FILES,
                "packages": PACKAGES,
                "tags": TAGS,
                "accept": ACCEPT,
            }.get(key or "")
            if bound is not None and len(value) > bound:
                out.append(f"{path}: {len(value)} items, above {bound}")
            for i, v in enumerate(value):
                walk(v, depth + 1, "tag" if key == "tags" else key, f"{path}[{i}]")
        elif isinstance(value, str):
            cap = TAG if key == "tag" else caps.get(key or "", STRING)
            size = len(value.encode("utf-8", "surrogatepass"))
            if size > cap:
                out.append(f"{path}: {size} bytes, above {cap}")

    walk(document, 1, None, "$")
    return out


def _constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def load_json(
    raw: bytes, *, limit: int = JSON_DOCUMENT, caps: Mapping[str, int] = STRING_CAPS, where: str = "document"
) -> JSONValue:
    """A JSON document read within SPEC.md § 13: at most `limit` bytes, UTF-8,
    nested 16 deep at most, its strings within their bounds; DocumentError
    otherwise."""
    if len(raw) > limit:
        raise DocumentError(f"{len(raw)} bytes, above {limit}", where)
    try:
        text = raw.decode("utf-8")
        document: JSONValue = json.loads(text, parse_constant=_constant)
    except RecursionError:
        raise DocumentError(f"nested deeper than {DEPTH}", where) from None
    except (UnicodeDecodeError, ValueError) as e:
        raise DocumentError(f"not JSON ({e})", where) from None
    found = problems(document, caps)
    if found:
        raise DocumentError("beyond SPEC.md § 13: " + "; ".join(found[:3]), where)
    return document


def clip(text: str, limit: int) -> str:
    """`text` cut to `limit` UTF-8 bytes, on a character's boundary."""
    return text.encode()[:limit].decode(errors="ignore")


def printable(text: str, limit: int = STRING) -> str:
    """`text` without control characters, within `limit` bytes: what a client
    shows of a server's `detail` or `motd` (SPEC.md § 12)."""
    kept = "".join(c for c in text if c == "\n" or (ord(c) >= 32 and not 127 <= ord(c) < 160))
    return clip(kept, limit)
