"""The client's side of SPEC.md § 5: signing requests with a device key,
pairing, and invitations.

- `DeviceSigner`: a RequestSigner that signs every request to the server's
  origin by RFC 9421, as § 5.4 says, with the clock's offset to the server's
  (a console's clock is often wrong);
- `Pairing`: a pairing under way: what the device shows (the code, the
  address, the QR code's text, the short fingerprint of the server's key)
  and how it polls;
- `invitation_link()`: what an invitation's link carries (§ 5.5): the
  server's approval page, the code, and the fingerprint to pin.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from lantern._base import DocumentError
from lantern._generated.models import PairingCode
from lantern.client.transport import Request
from lantern.http import origin, plain_http_allowed
from lantern.signatures import DeviceKey, new_nonce, sign_request
from lantern.spki import SHA256_HEX, short


class DeviceSigner:
    """Signs each request to the server's origin with the device key (SPEC.md
    § 5.4): `@method`, `@target-uri`, then `authorization` when it carries a
    token and `content-digest` when it has a body (Content-Digest is added).
    `clock` gives the time to sign with: the client's, corrected by its
    offset to the server's Date."""

    def __init__(self, key: DeviceKey, clock: Callable[[], float] = time.time) -> None:
        self.key, self.clock = key, clock

    def sign(self, request: Request) -> None:
        sign_request(
            self.key,
            request.method,
            request.url,
            request.headers,
            request.body,
            created=int(self.clock()),
            nonce=new_nonce(),
        )

    def __repr__(self) -> str:
        return f"DeviceSigner({self.key!r})"


@dataclass
class Pairing:
    """A pairing under way (SPEC.md § 5.2). Show `code`, `verify` and
    `fingerprint` (the short fingerprint of the key of the server the client
    talks to: the user compares it with the one the server's page shows),
    and `verify_complete` as a QR code the client draws, the code and the
    fingerprint kept next to it. Then poll."""

    document: PairingCode
    key: DeviceKey | None
    spki: str | None
    poll_url: str
    started: float = field(default_factory=time.monotonic)
    interval: float = 5.0

    @property
    def code(self) -> str:
        return self.document.code

    @property
    def verify(self) -> str:
        return self.document.verify

    @property
    def verify_complete(self) -> str:
        """The QR code's text: `verify` with the code in its query."""
        return self.document.verify_complete or self.document.verify

    @property
    def fingerprint(self) -> str | None:
        """The short fingerprint of the server's key, as this client sees it; None over plain HTTP."""
        return short(self.spki) if self.spki else None

    @property
    def deadline(self) -> float:
        return self.started + self.document.expires

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


def check_pairing_code(doc: PairingCode, root: str) -> None:
    """The checks a client makes on a pairing code before it shows anything
    (SPEC.md § 5.2): `verify` an address it may open (HTTPS, or HTTP on
    loopback); `verify_complete` on verify's origin with the code in its
    query; the poll address on the server's origin."""
    where = "pairing code"
    try:
        verify_ok = plain_http_allowed(doc.verify)
    except ValueError:
        verify_ok = False
    if not verify_ok:
        raise DocumentError(f"verify {doc.verify[:100]!r} is not an HTTPS address", where)
    if doc.verify_complete is not None:
        try:
            same = origin(doc.verify_complete) == origin(doc.verify)
        except ValueError:
            same = False
        typed = "".join(c for c in doc.code.upper() if c.isalnum())
        query = "".join(c for c in urlsplit(doc.verify_complete).query.upper() if c.isalnum())
        if not same or typed not in query:
            raise DocumentError("verify_complete is not verify's address with the code in it", where)
    poll = urlsplit(doc.poll)
    if poll.scheme or poll.netloc:
        try:
            on_origin = origin(doc.poll) == origin(root)
        except ValueError:
            on_origin = False
        if not on_origin:
            raise DocumentError("the poll address is not on the server's origin", where)
    if not 1 <= doc.expires <= 600 or doc.interval < 1:
        raise DocumentError("expires is 1 to 600 seconds, interval 1 or more", where)


@dataclass(frozen=True)
class InvitationLink:
    """What an invitation's link carries (SPEC.md § 5.5): the server's origin,
    the invitation's code, and the fingerprint of its key (SHA-256 hex) when
    no CA vouches for its certificate: a client pins that one, without asking
    the user to compare."""

    url: str
    code: str
    spki: str | None


def invitation_link(link: str) -> InvitationLink:
    """Reads an invitation's link; ValueError when it is not one."""
    parts = urlsplit(link)
    if not plain_http_allowed(link):
        raise ValueError("an invitation's link is an HTTPS address")
    query = parse_qs(parts.query)
    codes, spkis = query.get("invitation", []), query.get("spki", [])
    if len(codes) != 1 or len(spkis) > 1:
        raise ValueError("an invitation's link carries one invitation code")
    code = codes[0].strip().upper()
    if not 16 <= len(code.replace("-", "")) <= 32:
        raise ValueError("an invitation's code is 16 to 32 symbols")
    spki = spkis[0].lower() if spkis else None
    if spki is not None and not SHA256_HEX.match(spki):
        raise ValueError("spki is the server key's SHA-256, hex")
    return InvitationLink(f"{parts.scheme}://{parts.netloc}/", code, spki)
