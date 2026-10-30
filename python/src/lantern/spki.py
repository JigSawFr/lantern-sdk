"""A server's key fingerprint (SPEC.md § 5.3): the SHA-256 of its
certificate's DER SubjectPublicKeyInfo, and its short form for people
(`3F9A 1C07 B2E4 55D0`). Test vectors: `vectors/spki.json`.

The certificate is read with a small DER reader of the standard library
alone: only the structure that leads to the SubjectPublicKeyInfo."""

from __future__ import annotations

import hashlib
import re
import ssl

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class CertificateError(ValueError):
    """A certificate this reader cannot find the key of."""


def _element(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, start of the content, end of the element) of the DER element at `pos`."""
    if pos + 2 > len(data):
        raise CertificateError("a truncated certificate")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise CertificateError("a length this reader does not take")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise CertificateError("a truncated certificate")
    return tag, pos, end


def spki_der(certificate: bytes) -> bytes:
    """The DER SubjectPublicKeyInfo of a DER certificate (RFC 5280 § 4.1)."""
    tag, start, _ = _element(certificate, 0)
    if tag != 0x30:
        raise CertificateError("not a certificate")
    tag, pos, tbs_end = _element(certificate, start)  # tbsCertificate
    if tag != 0x30:
        raise CertificateError("not a certificate")
    fields: list[tuple[int, int, int]] = []
    while pos < tbs_end and len(fields) < 7:
        t, _, end = _element(certificate, pos)
        fields.append((t, pos, end))
        pos = end
    if fields and fields[0][0] == 0xA0:  # [0] version, when present
        fields = fields[1:]
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < 6 or fields[5][0] != 0x30:
        raise CertificateError("no SubjectPublicKeyInfo")
    _, begin, end = fields[5]
    return certificate[begin:end]


def spki_sha256(certificate: bytes | str) -> str:
    """The fingerprint of a certificate (DER bytes, or PEM text): lower-case hex."""
    der = ssl.PEM_cert_to_DER_cert(certificate) if isinstance(certificate, str) else certificate
    return hashlib.sha256(spki_der(der)).hexdigest()


def short(fingerprint: str) -> str:
    """A fingerprint's short form, for people: its first 16 hex digits, upper-case, in groups of 4."""
    if not SHA256_HEX.match(fingerprint.lower()):
        raise ValueError("a fingerprint is a SHA-256 in hex")
    head = fingerprint[:16].upper()
    return " ".join(head[i : i + 4] for i in range(0, 16, 4))


def check_pin(seen: str, pinned: str) -> bool:
    """Whether the key `seen` is the one `pinned` (both lower-case hex)."""
    return seen.lower() == pinned.lower()
