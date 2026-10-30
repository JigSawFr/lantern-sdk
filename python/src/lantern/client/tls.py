"""TLS for a LAN server's self-signed certificate (SPEC.md § 5.3): before
pairing, a client reads the server's key without a CA to vouch for it (it
sends nothing secret then) and shows its short fingerprint; once paired, it
pins the key's whole SHA-256 and talks only over connections that carry it,
whatever certificate wraps it.

    seen = peer_spki(ssl_socket)                    # the key of a connection
    context = unverified_context()                  # before pairing, or with a pin
    context = pinned_context(certificate)           # httpx: trusts that one certificate
"""

from __future__ import annotations

import socket
import ssl

from lantern.errors import PinMismatch, TransportError
from lantern.spki import CertificateError, spki_sha256


def unverified_context() -> ssl.SSLContext:
    """A context that checks no CA and no host name: the key is checked by its pin instead."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def peer_spki(sock: ssl.SSLSocket | ssl.SSLObject) -> str | None:
    """The fingerprint of the key a TLS connection carries (hex), None when it has no certificate."""
    der = sock.getpeercert(binary_form=True)
    if not der:
        return None
    try:
        return spki_sha256(der)
    except CertificateError:
        return None


def check_pin(seen: str | None, pin: str | None, where: str) -> None:
    """Raises PinMismatch unless the key `seen` is the one pinned (when one is)."""
    if pin is None:
        return
    if seen is None or seen.lower() != pin.lower():
        raise PinMismatch(seen or "0" * 64, pin, where)


def fetch_certificate(host: str, port: int, timeout: float) -> bytes:
    """The DER certificate a server presents, read without checking it."""
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            unverified_context().wrap_socket(raw, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except OSError as e:
        raise TransportError(f"{host}:{port}: {e}") from e
    if not der:
        raise TransportError(f"{host}:{port}: no certificate")
    return der


def pinned_context(certificate: bytes) -> ssl.SSLContext:
    """A context that trusts exactly `certificate` (DER), whatever its names:
    for a transport that cannot see the key before it sends (httpx), once
    the certificate's key was checked against the pin."""
    context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(certificate))
    context.check_hostname = False
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context
