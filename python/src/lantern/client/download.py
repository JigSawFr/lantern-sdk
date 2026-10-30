"""What a download checks, without its I/O (SPEC.md § 6.6): the answer's
`Repr-Digest` against the document's SHA-256, its range when resuming, its
size as it arrives, and the whole file's SHA-256 at the end. Nothing is done
until that last check passes."""

from __future__ import annotations

import re

from lantern.digest import Sha256, digest_sha256
from lantern.errors import IntegrityError, UnexpectedResponse
from lantern.http import Headers
from lantern.vocabulary import SHA256

_CONTENT_RANGE = re.compile(r"^\s*bytes\s+(\d+)-(\d+)/(\d+)\s*$")


class Verifier:
    """Checks one file's download against its `sha256` and `size`."""

    def __init__(self, sha256: str, size: int, what: str) -> None:
        if not SHA256.match(sha256):
            raise ValueError(f"{what}: {sha256[:70]!r} is not a lower-case hex SHA-256")
        if size < 0:
            raise ValueError(f"{what}: a negative size")
        self.sha256, self.size, self.what = sha256, size, what

    def start(self, status: int, headers: Headers, offset: int) -> int:
        """Checks an answer's headers; gives the offset its body starts at (0
        when the server sent the whole file, `offset` when it sent the rest)."""
        announced = headers.get("Repr-Digest")
        digest = digest_sha256(announced)
        if announced is not None and digest is not None and digest != self.sha256:
            raise IntegrityError(f"{self.what}: the server's Repr-Digest is {digest}, the document says {self.sha256}")
        if status == 206:
            m = _CONTENT_RANGE.match(headers.get("Content-Range") or "")
            if not m or int(m.group(1)) != offset or int(m.group(2)) != self.size - 1 or int(m.group(3)) != self.size:
                raise UnexpectedResponse(
                    f"{self.what}: Content-Range {headers.get('Content-Range')!r}, asked "
                    f"bytes {offset}-{self.size - 1}/{self.size}",
                    status,
                )
            return offset
        if status == 200:
            length = headers.get("Content-Length")
            if length is not None and length.strip().isdigit() and int(length) != self.size:
                raise IntegrityError(f"{self.what}: {length} bytes, the document says {self.size}")
            return 0
        raise UnexpectedResponse(f"{self.what}: status {status}", status)

    def feed(self, hasher: Sha256, chunk: bytes) -> None:
        if hasher.size + len(chunk) > self.size:
            raise IntegrityError(f"{self.what}: more bytes than its size, {self.size}")
        hasher.update(chunk)

    def finish(self, hasher: Sha256) -> None:
        """Raises IntegrityError unless what arrived is the whole file, of its SHA-256."""
        if hasher.size != self.size:
            raise IntegrityError(f"{self.what}: {hasher.size} bytes, the document says {self.size}")
        if hasher.hexdigest() != self.sha256:
            raise IntegrityError(f"{self.what}: SHA-256 {hasher.hexdigest()}, the document says {self.sha256}")
