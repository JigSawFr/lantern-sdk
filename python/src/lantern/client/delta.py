"""What a differential download checks and keeps, without its I/O (SPEC.md
§ 22.3): the pieces of the file in order, which a seed gives and which are
read as ranges, each checked by its SHA-256 as it comes (L-22.3-2), no more
written than the file's size nor read of a source than the range asked
(L-22.3-3), and the whole file checked at the end. LanternClient and
AsyncLanternClient drive it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass

from lantern._base import LanternError
from lantern._generated.models import App, Package
from lantern.chunks import Index, Piece, Refused, Seed, plan, read_seed, segments
from lantern.client.download import Verifier
from lantern.digest import Sha256, digest_sha256
from lantern.errors import UnexpectedResponse
from lantern.http import Headers

#: Chunks to read this close together (bytes) are asked for in one range: a request costs about as much.
RANGE_GAP = 16 << 10
#: The most ranges a download asks for: more, and the gap between two is widened.
MAX_RANGES = 512
_CONTENT_RANGE = re.compile(r"^\s*bytes\s+(\d+)-(\d+)/(\d+)\s*$")


class NothingShared(LanternError):
    """No chunk of the seeds is in the file: a differential download would read all of it, in pieces."""


@dataclass
class DeltaReport:
    """What the last differential download did (`client.last_delta`): `used` false when the whole file was
    read, and `reason` why; otherwise `reused` bytes taken from the seeds, `read` bytes read as `ranges`
    ranges of the file."""

    used: bool = False
    reason: str | None = None
    reused: int = 0
    read: int = 0
    ranges: int = 0


class Assembly:
    """A file being put together from an index and seeds: `groups` are its pieces in order, (True, the pieces
    one range holds) or (False, pieces a seed gives). Every piece goes through take(), in order; finish()
    checks the whole."""

    def __init__(self, file: App | Package, index: Index, seeds: Sequence[Seed]) -> None:
        self.verifier = Verifier(file.sha256, file.size, file.file)
        self.hasher = Sha256()
        self.seeds = list(seeds)
        self.pieces = plan(index, self.seeds)
        gap = RANGE_GAP
        self.groups = segments(self.pieces, gap)
        while sum(1 for read, _ in self.groups if read) > MAX_RANGES and gap < file.size:
            gap *= 4
            self.groups = segments(self.pieces, gap)
        self.report = DeltaReport(used=True)

    @property
    def shares(self) -> bool:
        """Whether any chunk is in the seeds: without one, a differential download gains nothing."""
        return any(p.source is not None for p in self.pieces)

    def seed(self, piece: Piece) -> bytes:
        """The bytes of a piece a seed gives, checked: a seed that changed since it was cut is refused."""
        assert piece.source is not None
        body = read_seed(self.seeds[piece.source[0]], piece.source[1], piece.length)
        if hashlib.sha256(body).hexdigest() != piece.sha256:
            raise Refused(f"the seed's chunk for {piece.offset} does not match its SHA-256")
        self.report.reused += piece.length
        return body

    def take(self, piece: Piece, body: bytes) -> bytes:
        """A piece (whose SHA-256 was checked: by seed(), or by the Collector that read it) to be written at its
        offset, the end of what is written: IntegrityError past the file's size (L-22.3-3)."""
        if piece.offset != self.hasher.size or len(body) != piece.length:
            raise Refused(f"the chunk at {piece.offset}: out of order or of another length")
        self.verifier.feed(self.hasher, body)
        return body

    def finish(self) -> None:
        """IntegrityError unless the file put together is whole and its document's (L-22.3-2)."""
        self.verifier.finish(self.hasher)


def range_headers(start: int, end: int) -> dict[str, str]:
    """The headers of a request for the bytes `start` to `end`, inclusive, as they are (no coding)."""
    return {"Accept": "*/*", "Accept-Encoding": "identity", "Range": f"bytes={start}-{end}"}


def check_range(status: int, headers: Headers, *, start: int, end: int, size: int, sha256: str, what: str) -> None:
    """An answer to a request for `start`-`end`: 206 of exactly that range of a file of `size` bytes, whose
    `Repr-Digest`, if sent, is the document's. UnexpectedResponse otherwise (a server that sends the whole
    file for a range is not read further: L-22.3-3)."""
    if status != 206:
        raise UnexpectedResponse(f"{what}: status {status} for bytes={start}-{end}", status)
    m = _CONTENT_RANGE.match(headers.get("Content-Range") or "")
    if not m or (int(m.group(1)), int(m.group(2)), int(m.group(3))) != (start, end, size):
        raise UnexpectedResponse(
            f"{what}: Content-Range {headers.get('Content-Range')!r}, asked bytes {start}-{end}/{size}", status
        )
    announced = digest_sha256(headers.get("Repr-Digest"))
    if announced is not None and announced != sha256:
        raise Refused(f"{what}: the server's Repr-Digest is {announced}, the document says {sha256}")
