"""Ed25519 (RFC 8032): the verification of a homebrew's signature (SPEC.md
§ 8.4) and of a signed request (§ 5.4), and the device key a client makes at
pairing and signs its requests with (§ 5.4). A library never signs for a
homebrew's author.

Every verification first refuses what § 8.4 (L-8.4-4) refuses: a key or an R
that does not decode, is not encoded canonically, or is one of the 8 points
of small order, and an S of L or more. Only then is the equation checked.

With the `crypto` extra (the `cryptography` package), the equation and the
signing are that package's. Without it, pure Python is used: slow next to C
(milliseconds per signature), and not constant-time. That is harmless for a
verification, which handles only public data; a device key signing in pure
Python is exposed to timing measurements on the device itself, so a client
that can install the extra should.

The pure-Python code follows the reference server's server/ed25519.py, in the
Lantern specification's repository (JigSawFr/lantern, MIT), after RFC 8032's
own reference code (§ 5.1.7).
"""

from __future__ import annotations

import hashlib
import secrets

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def _add(a: Point, b: Point) -> Point:
    """The sum of two points, in extended coordinates."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa, pb = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    pc, pd = 2 * t1 * t2 * D % P, 2 * z1 * z2 % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return e * f % P, g * h % P, f * g % P, e * h % P


def _multiply(s: int, point: Point) -> Point:
    q: Point = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, point)
        point, s = _add(point, point), s >> 1
    return q


def _decode(raw: bytes) -> Point | None:
    """The point of a 32-byte encoding, or None."""
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _encode(point: Point) -> bytes:
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
assert _GX is not None
G: Point = (_GX, _GY, 1, _GX * _GY % P)


def _same(a: Point, b: Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


_IDENTITY: Point = (0, 1, 1, 0)


def _small_order(point: Point) -> bool:
    """Whether `point` is one of the eight points of small order, which a
    forged signature can use: for them [8]P is the identity."""
    return _same(_multiply(8, point), _IDENTITY)


def _strict(public: bytes, signature: bytes) -> bool:
    """The checks every verification makes first, whatever the backend: both
    points decode, neither has a small order, and S is reduced. Without them
    a key of small order with a crafted signature verifies on some messages
    (and some libraries accept it outright)."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decode(public), _decode(signature[:32])
    if a is None or r is None or _small_order(a) or _small_order(r):
        return False
    return int.from_bytes(signature[32:], "little") < L


def verify_pure(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 § 5.1.7, in pure Python, with the checks of `_strict`."""
    if not _strict(public, signature):
        return False
    a, r = _decode(public), _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return _same(_multiply(s, G), _add(r, _multiply(h, a)))


def backend() -> str:
    """ "cryptography" when the `crypto` extra is installed, "python" otherwise."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    except ImportError:
        return "python"
    return "cryptography"


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` (64 bytes) is `public`'s (32 bytes) over `message`."""
    if not _strict(public, signature):
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return verify_pure(public, message, signature)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def is_public_key(public: bytes) -> bool:
    """Whether `public` is a key a server takes at pairing (SPEC.md § 5.4, L-5.4-12): 32 bytes that decode
    canonically to a point that is not of small order."""
    point = _decode(public)
    return point is not None and not _small_order(point)


def generate_seed() -> bytes:
    """A new secret seed of 32 random bytes: a device key (SPEC.md § 5.4)."""
    return secrets.token_bytes(32)


def public_key(seed: bytes) -> bytes:
    """The public key of a 32-byte secret seed (RFC 8032 § 5.1.5)."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        a = _clamp(hashlib.sha512(seed).digest()[:32])
        return _encode(_multiply(a, G))
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _clamp(raw: bytes) -> int:
    a = int.from_bytes(raw, "little")
    a &= (1 << 254) - 8
    return a | (1 << 254)


def sign(seed: bytes, message: bytes) -> bytes:
    """An Ed25519 signature by a 32-byte secret seed (RFC 8032 § 5.1.6): a
    device's request (SPEC.md § 5.4), an author's tools, tests. Deterministic:
    the same bytes with either backend."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return sign_pure(seed, message)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def sign_pure(seed: bytes, message: bytes) -> bytes:
    """sign(), in pure Python."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h[:32])
    public = _encode(_multiply(a, G))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % L
    big_r = _encode(_multiply(r, G))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % L
    return big_r + ((r + k * a) % L).to_bytes(32, "little")
