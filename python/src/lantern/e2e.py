"""End-to-end encrypted save backups (SPEC.md § 9.4), scheme
`lantern-save-e2e-1`: a backup encrypted on the device with a key its
user's devices alone hold, so that the server keeps bytes it cannot read.

    from lantern.e2e import SaveKey, encrypt_file, decrypt_file

    key = SaveKey.generate()            # once per user; keep it where the system keeps keys
    show(key.phrase())                  # only when the user asks (L-9.4-8): 14 groups of 4 symbols
    header = encrypt_file(key, "save.zip", "save.lne")
    decrypt_file(key, "save.lne", "back.zip")   # refuses a backup changed in any way (L-9.4-1)

- The save key's **id** and **wrapping key** come from it by HKDF-SHA-256
  (RFC 5869); only the id leaves the device (L-9.4-2).
- A backup is an 88-byte header (`LTNE2E01`, the key id, the wrap's nonce,
  a random file key sealed by the wrapping key), then the archive in chunks
  of 64 KiB, each sealed by the file key with XChaCha20-Poly1305: its index
  and whether it is the last in its nonce, the header as additional data
  (age's STREAM). A chunk cut, moved, dropped or added never opens.
- The key travels as a **recovery phrase** in the pairing alphabet (56
  symbols with a 24-bit check, `7KQ2-MZ4P-…`) or a **QR code**'s text
  (`LANTERN-SAVE-KEY-1:` and the 56 symbols).

The AEAD is RFC 8439's ChaCha20-Poly1305 of the `cryptography` package (the
`crypto` extra), after HChaCha20 (draft-irtf-cfrg-xchacha-03 § 2.2), which is
written here: 20 rounds of additions, rotations and exclusive ors of 32-bit
words, with neither table nor branch on the key, run twice per backup (the
wrap, and the chunks' subkey, whose 16 first nonce bytes are always zero).
HKDF, the key id, the phrases and the QR text need nothing but the standard
library; sealing and opening need the extra, and say so when it is missing.

Every function is checked byte for byte against the specification's
vectors (vectors/encrypted-saves.json).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

from lantern._base import LanternError

SCHEME = "lantern-save-e2e-1"
MAGIC = b"LTNE2E01"
#: The header: magic 8, key id 8, wrap nonce 24, the wrapped file key 32 + its tag 16.
HEADER = 88
CHUNK = 65536
TAG = 16
KEY = 32
NONCE = 24
#: The pairing alphabet (SPEC.md § 5.2): 5 bits a symbol, no 0, O, 1 or I.
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
QR_PREFIX = "LANTERN-SAVE-KEY-1:"
SYMBOLS = 56
_INFO_ID = b"lantern-save-e2e-1 key id"
_INFO_WRAP = b"lantern-save-e2e-1 wrap"
_CHECK = b"lantern-save-key"


class RefusedBackup(LanternError):
    """An encrypted backup a reader must refuse (L-9.4-1): of another key, a header or a chunk that does not
    open, a last chunk not marked last, or bytes after it. Restore nothing of it."""


class BadPhrase(ValueError):
    """A recovery phrase or a QR code that is not a save key's: symbols outside the alphabet, too few or too
    many, or a check that does not match (L-9.4-7). Say so before anything else."""


# HKDF-SHA-256 (RFC 5869).


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """HKDF-SHA-256: an empty salt is HashLen zero bytes (RFC 5869 § 2.2)."""
    if not 0 < length <= 255 * 32:
        raise ValueError("HKDF-SHA-256 gives 1 to 8160 bytes")
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, block = b"", b""
    for i in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
    return out[:length]


# HChaCha20 (draft-irtf-cfrg-xchacha-03 § 2.2).

_MASK = 0xFFFFFFFF
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _quarter(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & _MASK
    x[d] ^= x[a]
    x[d] = ((x[d] << 16) | (x[d] >> 16)) & _MASK
    x[c] = (x[c] + x[d]) & _MASK
    x[b] ^= x[c]
    x[b] = ((x[b] << 12) | (x[b] >> 20)) & _MASK
    x[a] = (x[a] + x[b]) & _MASK
    x[d] ^= x[a]
    x[d] = ((x[d] << 8) | (x[d] >> 24)) & _MASK
    x[c] = (x[c] + x[d]) & _MASK
    x[b] ^= x[c]
    x[b] = ((x[b] << 7) | (x[b] >> 25)) & _MASK


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20: a 32-byte subkey from a 32-byte key and 16 bytes of nonce."""
    if len(key) != KEY or len(nonce16) != 16:
        raise ValueError("HChaCha20 takes a 32-byte key and a 16-byte nonce")
    x = [*_SIGMA, *struct.unpack("<8I", key), *struct.unpack("<4I", nonce16)]
    for _ in range(10):
        _quarter(x, 0, 4, 8, 12)
        _quarter(x, 1, 5, 9, 13)
        _quarter(x, 2, 6, 10, 14)
        _quarter(x, 3, 7, 11, 15)
        _quarter(x, 0, 5, 10, 15)
        _quarter(x, 1, 6, 11, 12)
        _quarter(x, 2, 7, 8, 13)
        _quarter(x, 3, 4, 9, 14)
    return struct.pack("<8I", *x[0:4], *x[12:16])


# XChaCha20-Poly1305, over the `cryptography` package's ChaCha20-Poly1305.

Seal = Callable[[bytes, bytes, bytes], bytes]


class _Aead:
    """XChaCha20-Poly1305 under one key: HChaCha20 once per distinct first half of the nonce."""

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY:
            raise ValueError("XChaCha20-Poly1305 takes a 32-byte key")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError as e:  # pragma: no cover - the extra is missing
            raise ImportError("encrypted saves need the crypto extra: pip install 'lantern-protocol[crypto]'") from e
        self._cls = ChaCha20Poly1305
        self._key = key
        self._subkeys: dict[bytes, object] = {}

    def _cipher(self, nonce: bytes) -> object:
        head = nonce[:16]
        found = self._subkeys.get(head)
        if found is None:
            found = self._subkeys[head] = self._cls(hchacha20(self._key, head))
        return found

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != NONCE:
            raise ValueError("XChaCha20-Poly1305 takes a 24-byte nonce")
        cipher = self._cipher(nonce)
        sealed: bytes = cipher.encrypt(bytes(4) + nonce[16:], plaintext, aad)  # type: ignore[attr-defined]
        return sealed

    def open(self, nonce: bytes, sealed: bytes, aad: bytes) -> bytes | None:
        from cryptography.exceptions import InvalidTag

        if len(nonce) != NONCE or len(sealed) < TAG:
            return None
        cipher = self._cipher(nonce)
        try:
            opened: bytes = cipher.decrypt(bytes(4) + nonce[16:], sealed, aad)  # type: ignore[attr-defined]
        except InvalidTag:
            return None
        return opened


def xchacha20poly1305_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """The ciphertext, then its 16-byte tag (the `crypto` extra)."""
    return _Aead(key).seal(nonce, plaintext, aad)


def xchacha20poly1305_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes | None:
    """The plaintext; None when the tag does not match (the `crypto` extra)."""
    return _Aead(key).open(nonce, sealed, aad)


def available() -> bool:
    """Whether this Python can seal and open backups (the `crypto` extra is installed)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401
    except ImportError:  # pragma: no cover - the extra is missing
        return False
    return True


# The save key and how it travels.


def _check(raw: bytes) -> bytes:
    return hashlib.sha256(_CHECK + raw).digest()[:3]


class SaveKey:
    """A user's save key: 32 random bytes, made once by their first device that encrypts, carried to the
    others by its phrase or QR code, never sent to a server or a peer (L-9.4-2)."""

    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        if len(raw) != KEY:
            raise ValueError("a save key is 32 bytes")
        self._raw = bytes(raw)

    @classmethod
    def generate(cls) -> SaveKey:
        """A new key, from the system's secure random source."""
        return cls(secrets.token_bytes(KEY))

    @property
    def raw(self) -> bytes:
        """The key's 32 bytes: for the system's key store, never for a server."""
        return self._raw

    @property
    def key_id(self) -> str:
        """Which key a backup needs, in clear: the first 8 bytes of HKDF(info `lantern-save-e2e-1 key id`),
        16 lower-case hex digits."""
        return hkdf_sha256(self._raw, _INFO_ID, 8).hex()

    @property
    def wrapping_key(self) -> bytes:
        return hkdf_sha256(self._raw, _INFO_WRAP)

    def phrase(self) -> str:
        """The recovery phrase: the key and 3 bytes of check, 56 symbols in 14 groups of 4. Show it only
        when the user asks, on the device's own screen (L-9.4-8)."""
        n = int.from_bytes(self._raw + _check(self._raw), "big")
        symbols = "".join(ALPHABET[(n >> (5 * (SYMBOLS - 1 - i))) & 31] for i in range(SYMBOLS))
        return "-".join(symbols[i : i + 4] for i in range(0, SYMBOLS, 4))

    def qr(self) -> str:
        """The QR code's text, which its alphanumeric mode holds as it is."""
        return QR_PREFIX + self.phrase().replace("-", "")

    @classmethod
    def from_phrase(cls, text: str) -> SaveKey:
        """The key a phrase gives, case, spaces and dashes ignored; BadPhrase when it is not 56 symbols of the
        alphabet or its check does not match (L-9.4-7)."""
        symbols = "".join(c for c in text.upper() if c not in " -\t\r\n")
        if len(symbols) != SYMBOLS or any(c not in ALPHABET for c in symbols):
            raise BadPhrase(f"a recovery phrase is {SYMBOLS} symbols of {ALPHABET}")
        n = 0
        for c in symbols:
            n = n << 5 | ALPHABET.index(c)
        raw = n.to_bytes(35, "big")
        if not hmac.compare_digest(raw[32:], _check(raw[:32])):
            raise BadPhrase("the phrase's check does not match: a symbol is mistyped")
        return cls(raw[:32])

    @classmethod
    def from_qr(cls, text: str) -> SaveKey:
        if not text.startswith(QR_PREFIX):
            raise BadPhrase(f"a save key's QR code begins with {QR_PREFIX}")
        return cls.from_phrase(text[len(QR_PREFIX) :])

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SaveKey) and hmac.compare_digest(self._raw, other._raw)

    def __hash__(self) -> int:
        return hash(self.key_id)

    def __repr__(self) -> str:
        return f"SaveKey(id={self.key_id})"


# A backup.


def encrypted_size(size: int) -> int:
    """The bytes of the encrypted backup of an archive of `size` bytes: 88 + size + 16 per chunk."""
    if size < 0:
        raise ValueError("a negative size")
    return HEADER + size + TAG * max(1, -(-size // CHUNK))


def chunk_nonce(index: int, last: bool) -> bytes:
    """Chunk `index`'s nonce: 16 zero bytes, the index on 7 bytes big-endian, then 01 for the last chunk."""
    return bytes(16) + index.to_bytes(7, "big") + (b"\x01" if last else b"\x00")


def make_header(key: SaveKey, file_key: bytes | None = None, wrap_nonce: bytes | None = None) -> bytes:
    """A new backup's header: a new file key and wrap nonce from the secure random source for each backup
    (L-9.4-3); given here only by the vectors' tests."""
    file_key = file_key if file_key is not None else secrets.token_bytes(KEY)
    wrap_nonce = wrap_nonce if wrap_nonce is not None else secrets.token_bytes(NONCE)
    if len(file_key) != KEY or len(wrap_nonce) != NONCE:
        raise ValueError("a file key is 32 bytes, a wrap nonce 24")
    start = MAGIC + bytes.fromhex(key.key_id)
    return start + wrap_nonce + _Aead(key.wrapping_key).seal(wrap_nonce, file_key, start)


def key_id_of(header: bytes) -> str:
    """The key id a backup names; RefusedBackup when its bytes do not begin as one's."""
    if len(header) < 16 or header[:8] != MAGIC:
        raise RefusedBackup("not a lantern-save-e2e-1 backup: no LTNE2E01 header")
    return header[8:16].hex()


def open_header(key: SaveKey, header: bytes) -> bytes:
    """The file key a header wraps; RefusedBackup for another key's backup or a header changed."""
    if len(header) < HEADER:
        raise RefusedBackup("the header is cut")
    found = key_id_of(header)
    if found != key.key_id:
        raise RefusedBackup(f"a backup of the key {found}, not of {key.key_id}")
    file_key = _Aead(key.wrapping_key).open(header[16:40], header[40:HEADER], header[:16])
    if file_key is None:
        raise RefusedBackup("the file key does not open: another key, or a header changed")
    return file_key


def _read_full(source: BinaryIO, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        piece = source.read(size - len(out))
        if not piece:
            break
        out += piece
    return bytes(out)


def encrypt_stream(
    key: SaveKey,
    source: BinaryIO,
    write: Callable[[bytes], object],
    *,
    header: bytes | None = None,
) -> bytes:
    """Encrypts what `source` holds, chunk by chunk, into `write`; the header it made (or `header`, a header
    made before, to encrypt again to the same bytes: a resumed upload, SPEC.md § 9.4)."""
    head = header if header is not None else make_header(key)
    aead = _Aead(open_header(key, head))
    write(head)
    index = 0
    piece = _read_full(source, CHUNK)
    while True:
        following = _read_full(source, CHUNK) if len(piece) == CHUNK else b""
        last = not following
        write(aead.seal(chunk_nonce(index, last), piece, head))
        if last:
            return head
        piece, index = following, index + 1


def encrypt(key: SaveKey, archive: bytes, *, header: bytes | None = None) -> bytes:
    """The encrypted backup of `archive`, in memory."""
    import io

    out = bytearray()
    encrypt_stream(key, io.BytesIO(archive), out.extend, header=header)
    return bytes(out)


def encrypt_file(key: SaveKey, archive: str | Path, dest: str | Path, *, header: bytes | None = None) -> bytes:
    """Encrypts the file `archive` into `dest`; the header (keep it to resume an upload)."""
    with Path(archive).open("rb") as src, Path(dest).open("wb") as out:
        return encrypt_stream(key, src, out.write, header=header)


def iter_encrypted(key: SaveKey, archive: str | Path, header: bytes, start: int = 0) -> Iterator[bytes]:
    """The encrypted backup of the file `archive` from byte `start`, made again from the archive and its
    header without keeping the encrypted file: where an upload resumes (SPEC.md § 9.4, L-9.4-3)."""
    path = Path(archive)
    size = path.stat().st_size
    total = encrypted_size(size)
    if not 0 <= start <= total:
        raise ValueError(f"offset {start} outside the {total} bytes of the backup")
    aead = _Aead(open_header(key, header))
    if start < HEADER:
        yield header[start:HEADER]
        start = HEADER
    chunks = max(1, -(-size // CHUNK))
    index, skip = divmod(start - HEADER, CHUNK + TAG)
    with path.open("rb") as f:
        f.seek(index * CHUNK)
        while index < chunks:
            piece = _read_full(f, CHUNK)
            sealed = aead.seal(chunk_nonce(index, index == chunks - 1), piece, header)
            yield sealed[skip:]
            skip, index = 0, index + 1


def decrypt_stream(key: SaveKey, source: BinaryIO, write: Callable[[bytes], object]) -> int:
    """Decrypts an encrypted backup from `source` into `write`, chunk by chunk; the archive's size.
    RefusedBackup for anything § 9.4 refuses: what was written is then not the archive, and the caller
    restores nothing of it (decrypt_file() writes through a part file for that)."""
    head = _read_full(source, HEADER)
    if len(head) < HEADER:
        key_id_of(head)
        raise RefusedBackup("the header is cut")
    aead = _Aead(open_header(key, head))
    index, total = 0, 0
    sealed = _read_full(source, CHUNK + TAG)
    while True:
        if len(sealed) < TAG:
            raise RefusedBackup(f"chunk {index} is cut, or missing: no last chunk")
        following = _read_full(source, CHUNK + TAG) if len(sealed) == CHUNK + TAG else b""
        last = not following
        piece = aead.open(chunk_nonce(index, last), sealed, head)
        if piece is None:
            if aead.open(chunk_nonce(index, not last), sealed, head) is not None:
                if last:
                    raise RefusedBackup(f"chunk {index} ends the backup but is not marked last: chunks were dropped")
                raise RefusedBackup(f"chunk {index} is marked last, but more follows")
            raise RefusedBackup(f"chunk {index} does not open: changed, moved, or of another backup")
        write(piece)
        total += len(piece)
        if last:
            return total
        sealed, index = following, index + 1


def decrypt(key: SaveKey, data: bytes) -> bytes:
    """The archive of an encrypted backup held in memory; RefusedBackup as decrypt_stream() says."""
    import io

    out = bytearray()
    decrypt_stream(key, io.BytesIO(data), out.extend)
    return bytes(out)


def decrypt_file(key: SaveKey, backup: str | Path, dest: str | Path) -> Path:
    """Decrypts the file `backup` into `dest`, through `dest` + ".part", renamed only once every chunk
    opened: a backup refused leaves nothing (L-9.4-1)."""
    target = Path(dest)
    part = target.with_name(target.name + ".part")
    try:
        with Path(backup).open("rb") as src, part.open("wb") as out:
            decrypt_stream(key, src, out.write)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    part.replace(target)
    return target


def encryption_header(key_id: str) -> str:
    """`Lantern-Save-Encryption` of a backup sent in one request (SPEC.md § 9.4)."""
    return f"{SCHEME}; key_id={key_id}"


__all__ = [
    "ALPHABET",
    "CHUNK",
    "HEADER",
    "MAGIC",
    "QR_PREFIX",
    "SCHEME",
    "TAG",
    "BadPhrase",
    "RefusedBackup",
    "SaveKey",
    "available",
    "chunk_nonce",
    "decrypt",
    "decrypt_file",
    "decrypt_stream",
    "encrypt",
    "encrypt_file",
    "encrypt_stream",
    "encrypted_size",
    "encryption_header",
    "hchacha20",
    "hkdf_sha256",
    "iter_encrypted",
    "key_id_of",
    "make_header",
    "open_header",
    "xchacha20poly1305_open",
    "xchacha20poly1305_seal",
]
