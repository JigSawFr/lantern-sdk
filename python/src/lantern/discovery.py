"""LAN discovery (SPEC.md § 4.1): the datagram a client sends on UDP 47115,
the replies it reads, and DNS-SD (`_lantern._tcp`) when the `dnssd` extra
is installed.

    for found in discover([directed_broadcast("192.168.1.20", 24)]):
        print(found.name, found.url)       # then the handshake, over TLS

Discovery is a hint: it gives an address and a name, nothing more. A reply
proves nothing; the client trusts a server only through TLS and pairing
(§ 5, L-4.1-5). A reply is read by the `schema` rule: one of a newer schema
is absent, and a reply this library cannot read is left out.
"""

from __future__ import annotations

import ipaddress
import json
import select
import socket
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from lantern._base import SCHEMA, JSONValue
from lantern.limits import DATAGRAM, NAME, printable

PORT = 47115
#: The request a client sends (SPEC.md § 4.1).
REQUEST = json.dumps({"schema": SCHEMA, "lantern": "discover"}, separators=(",", ":")).encode()
#: The DNS-SD service type (RFC 6763).
SERVICE = "_lantern._tcp.local."


@dataclass(frozen=True)
class Found:
    """A server that answered: the reply's source `address`, its HTTPS `port`,
    its `uid`, `name`, `base` and `versions` (the handshake's, unchecked
    until the client reads it)."""

    address: str
    port: int
    uid: str
    name: str
    base: str
    versions: tuple[int, ...]

    @property
    def url(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"https://{host}:{self.port}/" if self.port != 443 else f"https://{host}/"


def directed_broadcast(address: str, prefix: int) -> str:
    """The broadcast address of `address`'s network (`192.168.1.255` for
    `192.168.1.20`/24): where a client sends the datagram, since some
    consoles drop `255.255.255.255`."""
    network = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
    return str(network.broadcast_address)


def _base_ok(base: object) -> bool:
    return (
        isinstance(base, str)
        and base.startswith("/")
        and not base.startswith("//")
        and len(base) <= 256
        and not any(c in base for c in "?#\\ ")
        and all(32 < ord(c) < 127 for c in base)
    )


def read_reply(data: bytes, address: str) -> Found | None:
    """A server's reply (SPEC.md § 4.1), or None when it is not one this
    library reads: above 1200 bytes, not UTF-8 JSON, of a newer schema, not
    a server's, or with a field not of its form."""
    if len(data) > DATAGRAM:
        return None
    try:
        doc: JSONValue = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    schema, port, versions = doc.get("schema"), doc.get("port"), doc.get("versions")
    if not isinstance(schema, int) or isinstance(schema, bool) or not 1 <= schema <= SCHEMA:
        return None
    uid, name, base = doc.get("uid"), doc.get("name"), doc.get("base")
    if doc.get("lantern") != "server" or not isinstance(uid, str) or not 1 <= len(uid) <= 64:
        return None
    if not isinstance(name, str) or not _base_ok(base) or not isinstance(port, int) or isinstance(port, bool):
        return None
    if not 1 <= port <= 65535 or not isinstance(versions, list) or not versions:
        return None
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 1 for v in versions):
        return None
    assert isinstance(base, str)
    return Found(
        address,
        port,
        uid,
        printable(name, NAME).replace("\n", " "),
        base,
        tuple(v for v in versions if isinstance(v, int)),
    )


def discover(
    addresses: Sequence[str] = ("255.255.255.255",),
    *,
    port: int = PORT,
    timeout: float = 2.0,
    socket_factory: Callable[[], socket.socket] | None = None,
) -> list[Found]:
    """Sends the discovery datagram to each of `addresses` (directed
    broadcasts, or a server's own address) and gathers the replies for
    `timeout` seconds; each server once, by uid and address."""
    sock = socket_factory() if socket_factory is not None else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: dict[tuple[str, str], Found] = {}
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for address in addresses:
            sock.sendto(REQUEST, (address, port))
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select([sock], [], [], left)
            if not ready:
                break
            try:
                data, source = sock.recvfrom(DATAGRAM + 1)
            except OSError:
                break
            reply = read_reply(data, source[0])
            if reply is not None:
                found.setdefault((reply.uid, reply.address), reply)
    finally:
        sock.close()
    return list(found.values())


def from_txt(address: str, port: int, txt: Mapping[bytes, bytes | None], name: str) -> Found | None:
    """A DNS-SD advertisement (SPEC.md § 4.1: `uid=`, `path=`, `v=`), or None when it is not one this
    library reads."""

    def text(key: bytes) -> str | None:
        value = txt.get(key)
        try:
            return value.decode("utf-8") if value is not None else None
        except UnicodeDecodeError:
            return None

    uid, path, versions = text(b"uid"), text(b"path"), text(b"v")
    if not uid or not _base_ok(path) or not versions or not 1 <= port <= 65535:
        return None
    try:
        numbers = tuple(int(v) for v in versions.split(","))
    except ValueError:
        return None
    if not numbers or any(v < 1 for v in numbers):
        return None
    assert path is not None
    return Found(address, port, uid, printable(name, NAME).replace("\n", " "), path, numbers)


def browse_dnssd(timeout: float = 2.0, *, interfaces: Any = None) -> list[Found]:
    """The servers advertised with DNS-SD as `_lantern._tcp` (the `dnssd`
    extra: the zeroconf package; the standard library has no mDNS), on
    `interfaces` (every one by default)."""
    try:
        from zeroconf import InterfaceChoice, ServiceBrowser, ServiceListener, Zeroconf
    except ImportError as e:  # pragma: no cover - the extra is missing
        raise ImportError("DNS-SD needs the dnssd extra: pip install 'lantern-protocol[dnssd]'") from e

    names: list[str] = []

    class Listener(ServiceListener):
        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            names.append(name)

        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            return None

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            return None

    zc = Zeroconf(interfaces=interfaces if interfaces is not None else InterfaceChoice.All)
    out: list[Found] = []
    try:
        ServiceBrowser(zc, SERVICE, Listener())
        time.sleep(timeout)
        for name in dict.fromkeys(names):
            info = zc.get_service_info(SERVICE, name, timeout=int(timeout * 1000))
            if info is None or info.port is None:
                continue
            label = name.removesuffix("." + SERVICE)
            for address in info.parsed_addresses():
                found = from_txt(address, info.port, info.properties, label)
                if found is not None:
                    out.append(found)
    finally:
        zc.close()
    return out


def addresses_of(found: Iterable[Found]) -> list[str]:
    """The addresses of the servers found, each once, in order."""
    return list(dict.fromkeys(f.address for f in found))
