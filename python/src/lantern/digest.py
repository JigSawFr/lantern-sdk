"""SHA-256, streamed, and the digest fields of RFC 9530 that Lantern uses:
`Repr-Digest` on every file response (SPEC.md § 6.6) and `Content-Digest` on
a save sent in one request (SPEC.md § 9.2), both `sha-256=:<base64>:`."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

CHUNK = 1 << 20
_KEY = re.compile(r"^[a-z*][a-z0-9_\-.*]*$")


class Sha256:
    """A SHA-256 fed as bytes arrive, which counts them too."""

    def __init__(self, data: bytes = b"") -> None:
        self._hash = hashlib.sha256()
        self.size = 0
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        self._hash.update(data)
        self.size += len(data)

    def digest(self) -> bytes:
        return self._hash.digest()

    def hexdigest(self) -> str:
        return self._hash.hexdigest()

    def copy(self) -> Sha256:
        other = Sha256()
        other._hash, other.size = self._hash.copy(), self.size
        return other


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_chunks(chunks: Iterable[bytes]) -> Sha256:
    h = Sha256()
    for chunk in chunks:
        h.update(chunk)
    return h


def sha256_file(path: str | Path, limit: int | None = None) -> Sha256:
    """The SHA-256 of a file, read in chunks; of its first `limit` bytes only when given."""
    h = Sha256()
    left = limit
    with Path(path).open("rb") as f:
        while left is None or left > 0:
            chunk = f.read(CHUNK if left is None else min(CHUNK, left))
            if not chunk:
                break
            h.update(chunk)
            if left is not None:
                left -= len(chunk)
    return h


def _raw(sha256: str | bytes) -> bytes:
    if isinstance(sha256, bytes):
        if len(sha256) != 32:
            raise ValueError("a SHA-256 is 32 bytes")
        return sha256
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError(f"{sha256[:70]!r} is not a SHA-256 in hex")
    return bytes.fromhex(sha256)


def format_digest(sha256: str | bytes) -> str:
    """The field's value for a SHA-256 (hex or 32 bytes): `sha-256=:<base64>:`."""
    return "sha-256=:" + base64.b64encode(_raw(sha256)).decode() + ":"


def parse_digest(value: str) -> dict[str, bytes]:
    """A `Repr-Digest` or `Content-Digest` value (an RFC 8941 dictionary of
    byte sequences): each algorithm and its digest. Members that are not a
    byte sequence, or not base64, are left out; parameters are ignored."""
    out: dict[str, bytes] = {}
    for member in value.split(","):
        key, eq, rest = member.strip().partition("=")
        key = key.strip()
        item = rest.split(";", 1)[0].strip()
        if not eq or not _KEY.match(key) or len(item) < 2 or item[0] != ":" or item[-1] != ":":
            continue
        try:
            out[key] = base64.b64decode(item[1:-1], validate=True)
        except (binascii.Error, ValueError):
            continue
    return out


def digest_sha256(value: str | None) -> str | None:
    """The SHA-256 a digest field gives, lower-case hex; None without one (or a malformed one)."""
    if value is None:
        return None
    raw = parse_digest(value).get("sha-256")
    return raw.hex() if raw is not None and len(raw) == 32 else None
