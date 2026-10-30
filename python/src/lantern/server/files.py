"""Files as SPEC.md § 6.6 wants them served: a strong ETag, Repr-Digest (the
whole file's SHA-256) on every answer, ranged or not and on HEAD,
Accept-Ranges, single byte ranges (206), 416 with Content-Range outside the
file, and If-Range."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from lantern.digest import format_digest, sha256_file, sha256_hex
from lantern.server.http import FileBody, ProblemError, ServerRequest, ServerResponse, caching_headers
from lantern.vocabulary import SHA256

_RANGE = re.compile(r"\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*")


@dataclass(frozen=True)
class FileRef:
    """A file the server serves: where it is (`path`, or its bytes in `data`
    for a small one), its size and SHA-256, known beforehand (a server hashes
    a file before it lists it, SPEC.md § 6.1)."""

    path: str
    size: int
    sha256: str
    content_type: str = "application/octet-stream"
    data: bytes | None = None

    def __post_init__(self) -> None:
        if not SHA256.match(self.sha256):
            raise ValueError("sha256 is lower-case hex")

    @classmethod
    def of(cls, path: str | Path, content_type: str = "application/octet-stream") -> FileRef:
        """A file, hashed now."""
        h = sha256_file(path)
        return cls(str(path), h.size, h.hexdigest(), content_type)

    @classmethod
    def of_bytes(cls, data: bytes, content_type: str = "application/octet-stream") -> FileRef:
        """A file held in memory."""
        return cls("", len(data), sha256_hex(data), content_type, data)

    @property
    def etag(self) -> str:
        """A strong ETag, from the content: the same file gives the same one."""
        return f'"{self.sha256[:32]}"'


def parse_range(header: str, size: int) -> tuple[int, int] | str | None:
    """(first, last) byte of a single range (RFC 9110 § 14), "unsatisfiable",
    or None to ignore it (another unit, several ranges, nonsense)."""
    m = _RANGE.fullmatch(header)
    if not m or (m.group(1) == "" and m.group(2) == ""):
        return None
    if m.group(1) == "":
        n = int(m.group(2))
        return (max(0, size - n), size - 1) if n and size else "unsatisfiable"
    first = int(m.group(1))
    last = int(m.group(2)) if m.group(2) else size - 1
    if m.group(2) and last < first:
        return None
    if first >= size:
        return "unsatisfiable"
    return first, min(last, size - 1)


def file_response(request: ServerRequest, file: FileRef) -> ServerResponse:
    """A file's answer to GET or HEAD, with a Range honoured when given."""
    status, first, last = 200, 0, file.size - 1
    headers = caching_headers(request)
    headers.update(
        {
            "Content-Type": file.content_type,
            "Accept-Ranges": "bytes",
            "ETag": file.etag,
            "Repr-Digest": format_digest(file.sha256),
        }
    )
    asked = request.header("Range")
    if_range = request.header("If-Range")
    if asked and (if_range is None or if_range.strip() == file.etag):
        parsed = parse_range(asked, file.size)
        if parsed == "unsatisfiable":
            raise ProblemError(
                416,
                "bad_request",
                f"The file is {file.size} bytes.",
                title="Range not satisfiable",
                headers={"Content-Range": f"bytes */{file.size}"},
            )
        if isinstance(parsed, tuple):
            first, last = parsed
            status = 206
            headers["Content-Range"] = f"bytes {first}-{last}/{file.size}"
    length = last - first + 1 if file.size else 0
    headers["Content-Length"] = str(length)
    if request.method == "HEAD" or not length:
        return ServerResponse(status, headers)
    if file.data is not None:
        return ServerResponse(status, headers, file.data[first : last + 1])
    return ServerResponse(status, headers, FileBody(file.path, first, length))
