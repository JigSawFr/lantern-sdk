"""Grants, mirrors and the addresses plain HTTP may reach (SPEC.md § 19).

A file is its SHA-256: a client may read it from a **mirror** an app or a
package names, or from a **peer**, a paired console on its network that
holds it, and checks it the same way whatever the source (§ 19.1). A peer
serves a file only to the holder of a **grant**: a statement signed by the
server's grant key (`peers.key` in its handshake), naming one file of one
server, valid a few minutes (§ 19.3).

    grant = make_grant(seed, uid, sha256, size, exp)           # a server
    found = read_grant(grant, {uid: public_key}, now=time.time())  # a peer: None unless it serves

A grant is `<payload>.<signature>`, each base64url without padding; the
payload is `{"exp":…,"purpose":"lantern-grant-1","sha256":"…","size":…,
"uid":"…"}`, these keys in this order and no space. Test vectors:
vectors/grants.json.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from lantern import ed25519
from lantern.vocabulary import SHA256

PURPOSE = "lantern-grant-1"
#: A grant's largest size (SPEC.md § 13), and the longest `peers.grant_lifetime` (§ 19.3).
GRANT_LIMIT = 1024
LIFETIME_LIMIT = 900
#: The private networks of SPEC.md § 19.2, where plain HTTP may fetch a file by its hash.
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10")
)
#: The mirrors an app or a package names at most (SPEC.md § 13).
MIRRORS_LIMIT = 8
_GRANT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def grant_payload(uid: str, sha256: str, size: int, exp: int) -> bytes:
    """A grant's payload: these keys in this order, no space (SPEC.md § 19.3)."""
    doc = {"exp": exp, "purpose": PURPOSE, "sha256": sha256, "size": size, "uid": uid}
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()


def make_grant(seed: bytes, uid: str, sha256: str, size: int, exp: int) -> str:
    """A grant signed by the server's grant key (its 32-byte Ed25519 seed)."""
    if not SHA256.match(sha256) or size < 0:
        raise ValueError("a grant names a file by its lower-case hex SHA-256 and its size")
    payload = grant_payload(uid, sha256, size, exp)
    return _b64url(payload) + "." + _b64url(ed25519.sign(seed, payload))


@dataclass(frozen=True)
class GrantPayload:
    """What a grant states: until when (`exp`, Unix seconds), which file, of which server."""

    exp: int
    sha256: str
    size: int
    uid: str


def parse_grant(grant: str) -> tuple[GrantPayload, bytes, bytes] | None:
    """(what it states, its payload's bytes, its signature) of a grant of the right form, unverified; None
    otherwise."""
    if not isinstance(grant, str) or len(grant) > GRANT_LIMIT or not _GRANT.match(grant):
        return None
    head, sig = grant.split(".")
    try:
        payload, signature = _unb64url(head), _unb64url(sig)
        doc = json.loads(payload.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict) or doc.get("purpose") != PURPOSE:
        return None
    exp, sha, size, uid = doc.get("exp"), doc.get("sha256"), doc.get("size"), doc.get("uid")
    if not (
        isinstance(exp, int) and not isinstance(exp, bool) and isinstance(size, int) and not isinstance(size, bool)
    ):
        return None
    if not (isinstance(sha, str) and SHA256.match(sha) and isinstance(uid, str) and 0 < len(uid) <= 64):
        return None
    if payload != grant_payload(uid, sha, size, exp):  # the canonical bytes alone
        return None
    return GrantPayload(exp, sha, size, uid), payload, signature


def read_grant(grant: str, keys: Mapping[str, bytes], now: float | None = None) -> GrantPayload | None:
    """What a grant states, when it verifies by the key of the server it names among `keys` ({uid: the grant
    key's 32 public bytes}: the servers a peer paired with) and has not expired by `now`; None otherwise
    (SPEC.md § 19.4, L-19.4-1). The caller still checks that it names the file asked for."""
    parsed = parse_grant(grant)
    if parsed is None:
        return None
    found, payload, signature = parsed
    key = keys.get(found.uid)
    if key is None or found.exp < (time.time() if now is None else now):
        return None
    if not ed25519.verify(key, payload, signature):
        return None
    return found


def grant_key(value: str | None) -> bytes | None:
    """The 32 bytes of a handshake's `peers.key` (base64); None when it is not one."""
    if not value:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def is_private(host: str) -> bool:
    """An address of a private network of SPEC.md § 19.2 (or loopback, which § 2 opens to plain HTTP for
    testing); never a name, which a resolver could point anywhere."""
    try:
        ip = ipaddress.ip_address(host.strip("[]").split("%")[0])
    except ValueError:
        return False
    return ip.is_loopback or any(ip in net for net in PRIVATE_NETWORKS)


def plain_http_to(url: str) -> bool:
    """Whether a file may be read from `url` (a mirror, a peer): HTTPS, or plain HTTP to an address of a
    private network (SPEC.md § 2, § 19.2, L-19.2-1, L-19.4-6)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and parts.hostname is not None and is_private(parts.hostname)


def mirror_ok(url: object) -> bool:
    """A mirror's `url` of SPEC.md § 19.2's form: absolute, HTTPS, or HTTP at a private network's address;
    without credentials in it."""
    if not isinstance(url, str) or len(url) > 4096 or any(c.isspace() for c in url):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None:
        return False
    return plain_http_to(url)


__all__ = [
    "GRANT_LIMIT",
    "LIFETIME_LIMIT",
    "MIRRORS_LIMIT",
    "PRIVATE_NETWORKS",
    "PURPOSE",
    "GrantPayload",
    "grant_key",
    "grant_payload",
    "is_private",
    "make_grant",
    "mirror_ok",
    "parse_grant",
    "plain_http_to",
    "read_grant",
]
