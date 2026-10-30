"""Device keys and signed requests (SPEC.md § 5.4, RFC 9421 HTTP Message
Signatures), for both sides.

A token bound to a device key travels with a signature of the request, by
that key, under the label `lantern`:

- its components, in this order: "@method", "@target-uri", then
  "authorization" when the request carries a token, then "content-digest"
  when it has a body (a poll of a keyed pairing carries no token);
- its parameters, in this order: created (Unix seconds), nonce (22 to 64
  characters of base64url, 128 random bits at least), keyid (the base64url
  of the SHA-256 of the key's 32 bytes, unpadded) and alg="ed25519";
- the signature base: one line per component, then "@signature-params",
  joined by a line feed, without one at the end.

A client signs with `sign_request()` (a `DeviceKey`); a server checks with
`verify_request()`, which raises `Refused` with the code § 5.4 gives, in its
order. `vectors/signatures.json` of the specification spells out the bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from lantern import ed25519
from lantern.digest import format_digest

LABEL = "lantern"
ALG = "ed25519"
#: auth.skew when a server announces none (SPEC.md § 5.4), and its bounds.
SKEW = 300
SKEW_RANGE = (60, 900)
#: Signature-Input and Signature, each (SPEC.md § 13).
HEADER_LIMIT = 1024
CODES = ("signature_required", "signature_invalid", "signature_expired", "signature_replayed")

_INPUT = re.compile(
    r'lantern=\(((?:"[a-z@-]+")(?: "[a-z@-]+")*)\);created=([0-9]{1,12});'
    r'nonce="([A-Za-z0-9_-]{22,64})";keyid="([A-Za-z0-9_-]{43})";alg="ed25519"'
)
_VALUE = re.compile(r"lantern=:([A-Za-z0-9+/]{86}==):")
_NONCE = re.compile(r"[A-Za-z0-9_-]{22,64}")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def keyid(public: bytes) -> str:
    """A key's thumbprint, its `keyid`: the base64url of the SHA-256 of its 32 bytes, without padding."""
    return _b64url(hashlib.sha256(public).digest())


def short_fingerprint(public: bytes) -> str:
    """A key's short fingerprint, for people (SPEC.md § 5.3's form): `21FE 31DF A154 A261`."""
    digest = hashlib.sha256(public).hexdigest()
    return " ".join(digest[i : i + 4].upper() for i in range(0, 16, 4))


def new_nonce() -> str:
    """A nonce: 128 random bits, base64url, 22 characters."""
    return _b64url(secrets.token_bytes(16))


class DeviceKey:
    """A device's Ed25519 key for one server (SPEC.md § 5.4): made at pairing,
    kept with the token, never sent anywhere. Its secret `seed` is not in its
    repr()."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("a device key's seed is 32 bytes")
        self._seed = bytes(seed)
        self.public = ed25519.public_key(self._seed)

    @classmethod
    def generate(cls) -> DeviceKey:
        """A new key: a device that pairs again makes a new one."""
        return cls(ed25519.generate_seed())

    @classmethod
    def from_b64(cls, seed: str) -> DeviceKey:
        try:
            return cls(base64.b64decode(seed, validate=True))
        except (binascii.Error, ValueError) as e:
            raise ValueError("a device key is its 32-byte seed, in base64") from e

    @property
    def seed(self) -> bytes:
        """The secret: for the place the device keeps its keys, and nowhere else."""
        return self._seed

    def seed_b64(self) -> str:
        return base64.b64encode(self._seed).decode()

    @property
    def public_b64(self) -> str:
        return base64.b64encode(self.public).decode()

    @property
    def keyid(self) -> str:
        return keyid(self.public)

    @property
    def fingerprint(self) -> str:
        return short_fingerprint(self.public)

    def document(self) -> dict[str, str]:
        """`key` of a pairing request: {"alg": "ed25519", "public_key": <base64>}."""
        return {"alg": ALG, "public_key": self.public_b64}

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self._seed, message)

    def __repr__(self) -> str:
        return f"DeviceKey(keyid={self.keyid!r})"


def target_uri(url: str) -> str:
    """`@target-uri` (RFC 9421 § 2.2.2, SPEC.md § 5.4): the scheme, the host in
    lower case, its port only when not the scheme's default, then the path and
    query exactly as sent (their percent-encoding unchanged)."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname or "@" in parts.netloc:
        raise ValueError(f"{url[:100]!r} is not an absolute http(s) URL")
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port is not None and port != (443 if scheme == "https" else 80):
        host += f":{port}"
    return f"{scheme}://{host}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


def received_uri(scheme: str, host: str, target: str) -> str:
    """`@target-uri` of a request a server received: its scheme, its `Host`
    header and its request target (path and query) as sent."""
    host = host.strip()
    if not host or any(c in host for c in "/?#@ \t"):
        raise ValueError("no Host this server can read")
    return target_uri(f"{scheme}://{host}{target if target.startswith('/') else '/' + target}")


def components(with_token: bool, with_body: bool) -> list[str]:
    """The components a request covers, in their order."""
    return (
        ["@method", "@target-uri"]
        + (["authorization"] if with_token else [])
        + (["content-digest"] if with_body else [])
    )


def signature_params(covered: list[str], created: int, nonce: str, key_id: str) -> str:
    """`@signature-params`: the `lantern` member's value of Signature-Input."""
    inner = " ".join(f'"{c}"' for c in covered)
    return f'({inner});created={created};nonce="{nonce}";keyid="{key_id}";alg="{ALG}"'


def signature_base(method: str, uri: str, authorization: str | None, digest: str | None, params: str) -> str:
    """The signature base (RFC 9421 § 2.5) of SPEC.md § 5.4's components."""
    lines = [f'"@method": {method}', f'"@target-uri": {uri}']
    if authorization is not None:
        lines.append(f'"authorization": {authorization}')
    if digest is not None:
        lines.append(f'"content-digest": {digest}')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def _get(headers: Mapping[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return value
    lower = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lower), None)


def sign_request(
    key: DeviceKey,
    method: str,
    url: str,
    headers: MutableMapping[str, str],
    body: bytes | None,
    *,
    created: int | None = None,
    nonce: str | None = None,
) -> None:
    """Signs a request in place (SPEC.md § 5.4): adds Content-Digest when it
    has a body and none, then Signature-Input and Signature. It covers
    `authorization` when `headers` has an Authorization."""
    method = method.upper()
    authorization = _get(headers, "Authorization")
    digest = None
    if body:
        digest = _get(headers, "Content-Digest")
        if digest is None:
            digest = format_digest(hashlib.sha256(body).digest())
            headers["Content-Digest"] = digest
    nonce = nonce if nonce is not None else new_nonce()
    if not _NONCE.fullmatch(nonce):
        raise ValueError("a nonce is 22 to 64 characters of base64url")
    when = int(time.time()) if created is None else int(created)
    params = signature_params(components(authorization is not None, bool(body)), when, nonce, key.keyid)
    base = signature_base(method, target_uri(url), authorization, digest, params)
    headers["Signature-Input"] = f"{LABEL}={params}"
    headers["Signature"] = f"{LABEL}=:" + base64.b64encode(key.sign(base.encode())).decode() + ":"


class Refused(Exception):
    """A signature refused (SPEC.md § 5.4): `code` is signature_required,
    signature_invalid, signature_expired or signature_replayed; the server
    answers 401 with it."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class NonceCache:
    """The nonces taken, per key, kept `keep` seconds (twice auth.skew at
    least, SPEC.md § 5.4): a nonce is never taken twice within them. Bounded:
    past `limit` entries the expired go first, then the oldest."""

    def __init__(self, keep: float = 2 * SKEW, limit: int = 200_000, clock: Callable[[], float] = time.monotonic):
        self.keep, self.limit, self.clock = keep, limit, clock
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def take(self, key_id: str, nonce: str) -> bool:
        """True the first time; False when it was taken within the window."""
        now = self.clock()
        with self._lock:
            if len(self._seen) >= self.limit:
                self._seen = {k: t for k, t in self._seen.items() if t > now}
                if len(self._seen) >= self.limit:
                    for k in sorted(self._seen, key=self._seen.__getitem__)[: max(1, self.limit // 10)]:
                        del self._seen[k]
            entry = (key_id, nonce)
            if self._seen.get(entry, 0.0) > now:
                return False
            self._seen[entry] = now + self.keep
            return True

    def __len__(self) -> int:
        return len(self._seen)


@dataclass(frozen=True)
class Verified:
    """A signature that verified: its key's id, created and nonce."""

    keyid: str
    created: int
    nonce: str


def verify_request(
    method: str,
    uri: str,
    headers: Mapping[str, str],
    public: bytes,
    *,
    with_token: bool,
    with_body: bool,
    nonces: NonceCache,
    skew: int = SKEW,
    now: float | None = None,
) -> Verified:
    """Checks a request's signature by the key `public` (32 bytes), in the
    order of SPEC.md § 5.4; raises Refused. `uri` is the request's
    @target-uri (received_uri()). The body's match with its Content-Digest
    is the caller's to check after (422 `digest_mismatch`)."""
    sig_input, value = _get(headers, "Signature-Input"), _get(headers, "Signature")
    if not sig_input or not value:
        raise Refused(
            "signature_required", "This token is bound to a device key: sign the request (Signature-Input, Signature)."
        )
    if len(sig_input) > HEADER_LIMIT or len(value) > HEADER_LIMIT:
        raise Refused("signature_invalid", "Signature-Input and Signature are 1 KiB at most.")
    m, v = _INPUT.fullmatch(sig_input.strip()), _VALUE.fullmatch(value.strip())
    if not m or not v:
        raise Refused(
            "signature_invalid",
            "Signature-Input or Signature is not of the form SPEC.md § 5.4 gives "
            "(the label lantern alone, its parameters in their order).",
        )
    covered = [c.strip('"') for c in m.group(1).split(" ")]
    wanted = components(with_token, with_body)
    if covered != wanted:
        raise Refused("signature_invalid", "The signature covers " + " ".join(covered) + ", not " + " ".join(wanted))
    digest = _get(headers, "Content-Digest")
    if with_body and not digest:
        raise Refused("signature_invalid", "A signed request with a body carries its Content-Digest.")
    if m.group(4) != keyid(public):
        raise Refused("signature_invalid", "keyid is not this token's key.")
    params = sig_input.strip()[len(LABEL) + 1 :]
    base = signature_base(
        method.upper(),
        uri,
        _get(headers, "Authorization") if with_token else None,
        digest if with_body else None,
        params,
    )
    if not ed25519.verify(public, base.encode(), base64.b64decode(v.group(1))):
        raise Refused("signature_invalid", "The signature does not verify over the signature base of SPEC.md § 5.4.")
    created = int(m.group(2))
    clock = time.time() if now is None else now
    if abs(created - clock) > skew:
        raise Refused(
            "signature_expired",
            f"created is {int(created - clock)} s from this server's clock: take its Date, and sign within {skew} s.",
        )
    if not nonces.take(m.group(4), m.group(3)):
        raise Refused("signature_replayed", "This nonce was taken already: a new one for each request.")
    return Verified(m.group(4), created, m.group(3))


def accept_signature(with_token: bool, with_body: bool, key_id: str | None = None) -> str:
    """Accept-Signature (RFC 9421 § 5.1) for a 401 of a signature: the
    components and parameters the server wants."""
    wanted = " ".join(f'"{c}"' for c in components(with_token, with_body))
    return f"{LABEL}=({wanted})" + (f';keyid="{key_id}"' if key_id else "") + f';alg="{ALG}"'


@dataclass(frozen=True)
class AcceptSignature:
    """A server's Accept-Signature, read: the components it wants, and the keyid and alg it names."""

    components: tuple[str, ...]
    keyid: str | None
    alg: str | None


_ACCEPT = re.compile(r'^\s*lantern=\(((?:"[a-z@-]+"(?: "[a-z@-]+")*)?)\)((?:;[a-z]+=(?:"[^"]*"|[0-9]+))*)\s*$')


def parse_accept_signature(value: str | None) -> AcceptSignature | None:
    """The `lantern` member of an Accept-Signature, or None when there is none this library can read."""
    if not value or len(value) > HEADER_LIMIT:
        return None
    for member in re.split(r",(?=\s*[a-z][a-z0-9_-]*=)", value):
        m = _ACCEPT.match(member)
        if not m:
            continue
        covered = tuple(c.strip('"') for c in m.group(1).split(" ")) if m.group(1) else ()
        params = dict(re.findall(r';([a-z]+)=(?:"([^"]*)"|[0-9]+)', m.group(2)))
        return AcceptSignature(covered, params.get("keyid") or None, params.get("alg") or None)
    return None
