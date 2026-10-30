"""LAN discovery, on the server's side (SPEC.md § 4.1): the reply to a
client's datagram, a responder on UDP 47115, and a DNS-SD advertisement
(`_lantern._tcp`, the `dnssd` extra).

    responder = DiscoveryResponder(app, https_port=443).start()
    ...
    responder.stop()

A server answers only a datagram it can read, only to addresses of local
networks (L-4.1-2), a few times a second at most per address (L-4.1-3),
with its handshake's uid, base and versions and its HTTPS port (L-4.1-1).
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import socket
import threading
from typing import Any

from lantern._base import SCHEMA, JSONValue
from lantern.discovery import PORT, SERVICE
from lantern.limits import DATAGRAM, NAME, clip
from lantern.server.app import LanternApp
from lantern.server.pairing import Limiter


def discovery_reply(app: LanternApp, https_port: int, data: bytes, address: str, limiter: Limiter) -> bytes | None:
    """The reply to one datagram from `address`, or None to stay silent."""
    if len(data) > DATAGRAM:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if ip.is_global:
        return None  # not from a local network
    try:
        doc: JSONValue = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or doc.get("lantern") != "discover":
        return None
    schema = doc.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != SCHEMA:
        return None  # not a request this server can read (SPEC.md § 3.2)
    if limiter.hit(address):
        return None
    reply = {
        "schema": SCHEMA,
        "lantern": "server",
        "uid": app.uid,
        "name": clip(app.name, NAME),
        "port": https_port,
        "base": app.base,
        "versions": [1],
    }
    raw = json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode()
    return raw if len(raw) <= DATAGRAM else None


class DiscoveryResponder:
    """Answers discovery datagrams on UDP `port` (47115) in a thread."""

    def __init__(self, app: LanternApp, https_port: int, *, port: int = PORT, host: str = "") -> None:
        self.app, self.https_port = app, https_port
        self.limiter = Limiter(5, 1.0)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.port: int = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> DiscoveryResponder:
        self._thread.start()
        return self

    def _loop(self) -> None:
        while True:
            try:
                data, peer = self.sock.recvfrom(DATAGRAM + 1)
            except OSError:
                return  # closed
            if not data or not peer:
                return  # shut down
            reply = discovery_reply(self.app, self.https_port, data, peer[0], self.limiter)
            if reply is not None:
                try:
                    self.sock.sendto(reply, peer)
                except OSError:
                    continue

    def stop(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self._thread.join(2)


def advertise_dnssd(app: LanternApp, https_port: int, address: str, *, interfaces: Any = None) -> Any:
    """Advertises the server with DNS-SD as `_lantern._tcp` (L-4.1-4), with the
    TXT keys uid, path and v; gives the zeroconf.Zeroconf to close() when the
    server stops. Needs the `dnssd` extra (the zeroconf package)."""
    try:
        from zeroconf import InterfaceChoice, ServiceInfo, Zeroconf
    except ImportError as e:  # pragma: no cover - the extra is missing
        raise ImportError("DNS-SD needs the dnssd extra: pip install 'lantern-protocol[dnssd]'") from e
    label = "".join(c if c.isalnum() or c in " -" else "-" for c in app.name)[:63].strip() or "Lantern"
    info = ServiceInfo(
        SERVICE,
        f"{label}.{SERVICE}",
        addresses=[socket.inet_aton(address)],
        port=https_port,
        properties={"uid": app.uid, "path": app.base, "v": "1"},
    )
    zc = Zeroconf(interfaces=interfaces if interfaces is not None else InterfaceChoice.All)
    zc.register_service(info)
    return zc
