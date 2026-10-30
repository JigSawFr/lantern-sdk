"""LAN discovery (SPEC.md § 4.1): the datagram a client sends on UDP 47115,
the replies it reads, and DNS-SD (`_lantern._tcp`) when the `dnssd` extra
is installed; and the peers that share their files (§ 19.5): the same
datagram with `"peers": true`, or DNS-SD's `_lantern-peer._tcp`.

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
#: The request that also asks the peers (SPEC.md § 19.5).
PEERS_REQUEST = json.dumps({"schema": SCHEMA, "lantern": "discover", "peers": True}, separators=(",", ":")).encode()
#: The DNS-SD service types (RFC 6763): servers, and peers.
SERVICE = "_lantern._tcp.local."
PEER_SERVICE = "_lantern-peer._tcp.local."
#: How often a client looks for peers at most (SPEC.md § 19.5, L-19.5-2), in seconds.
PEER_SEARCH_INTERVAL = 60.0


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


@dataclass(frozen=True)
class FoundPeer:
    """A peer that answered (SPEC.md § 19.5): its `address`, `port` and `base`, whether it speaks HTTPS
    (`tls`), its own `uid` and `name`, how many downloads it serves at once (`slots`), and the uids of the
    servers whose grants it takes. A hint, as discovery is: what it serves is checked by its hash."""

    address: str
    port: int
    base: str
    tls: bool
    uid: str
    name: str
    slots: int
    servers: tuple[str, ...]

    @property
    def url(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{'https' if self.tls else 'http'}://{host}:{self.port}{self.base}"

    def blob_url(self, sha256: str) -> str:
        """The address of a file it may hold: <base>/v1/blobs/sha256/<hex> (SPEC.md § 19.4)."""
        return f"{self.url}/v1/blobs/sha256/{sha256}"


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


def read_peer_reply(data: bytes, address: str) -> FoundPeer | None:
    """A peer's reply (SPEC.md § 19.5), or None when it is not one this library reads: above 1200 bytes,
    not UTF-8 JSON, of a newer schema, a server's, or with a field not of its form."""
    if len(data) > DATAGRAM:
        return None
    try:
        doc: JSONValue = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or doc.get("lantern") != "peer":
        return None
    schema, port, slots, servers = doc.get("schema"), doc.get("port"), doc.get("slots"), doc.get("servers")
    if not isinstance(schema, int) or isinstance(schema, bool) or not 1 <= schema <= SCHEMA:
        return None
    uid, name, base, tls = doc.get("uid"), doc.get("name"), doc.get("base"), doc.get("tls")
    if not isinstance(uid, str) or not 1 <= len(uid) <= 64 or not isinstance(name, str) or not _base_ok(base):
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or not isinstance(tls, bool):
        return None
    if not isinstance(slots, int) or isinstance(slots, bool) or not 1 <= slots <= 8:
        return None
    if not isinstance(servers, list) or not 1 <= len(servers) <= 16:
        return None
    if not all(isinstance(x, str) and 0 < len(x) <= 64 for x in servers):
        return None
    assert isinstance(base, str)
    return FoundPeer(
        address,
        port,
        base.rstrip("/"),
        tls,
        uid,
        printable(name, NAME).replace("\n", " "),
        slots,
        tuple(x for x in servers if isinstance(x, str)),
    )


def _gather(
    request: bytes,
    addresses: Sequence[str],
    *,
    port: int,
    timeout: float,
    socket_factory: Callable[[], socket.socket] | None,
    read: Callable[[bytes, str], Any],
) -> list[Any]:
    sock = socket_factory() if socket_factory is not None else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: list[Any] = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for address in addresses:
            sock.sendto(request, (address, port))
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select([sock], [], [], left)
            if not ready:
                break
            try:
                data, source = sock.recvfrom(DATAGRAM + 1)
            except OSError:
                break
            reply = read(data, source[0])
            if reply is not None:
                found.append(reply)
    finally:
        sock.close()
    return found


def discover_peers(
    addresses: Sequence[str] = ("255.255.255.255",),
    *,
    port: int = PORT,
    timeout: float = 2.0,
    server_uid: str | None = None,
    socket_factory: Callable[[], socket.socket] | None = None,
) -> list[FoundPeer]:
    """Sends the datagram that asks for peers (`"peers": true`) and gathers the peers' replies; with
    `server_uid`, only the peers that take the grants of that server. Look at most once a minute
    (PeerFinder does)."""
    found: dict[tuple[str, str, int], FoundPeer] = {}
    for p in _gather(
        PEERS_REQUEST, addresses, port=port, timeout=timeout, socket_factory=socket_factory, read=read_peer_reply
    ):
        if server_uid is None or server_uid in p.servers:
            found.setdefault((p.uid, p.address, p.port), p)
    return list(found.values())


class PeerFinder:
    """The peers of a server, looked for at most once a minute (L-19.5-2), by discovery or any other
    `search` (DNS-SD's browse_dnssd_peers()); between two searches, the last answer."""

    def __init__(
        self,
        search: Callable[[], list[FoundPeer]] | None = None,
        *,
        interval: float = PEER_SEARCH_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.search = search or discover_peers
        self.interval, self.clock = interval, clock
        self._last: float | None = None
        self._found: list[FoundPeer] = []

    def peers(self, server_uid: str) -> list[FoundPeer]:
        now = self.clock()
        if self._last is None or now - self._last >= self.interval:
            self._last = now
            self._found = self.search()
        return [p for p in self._found if server_uid in p.servers]


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
    found: dict[tuple[str, str], Found] = {}
    for reply in _gather(
        REQUEST, addresses, port=port, timeout=timeout, socket_factory=socket_factory, read=read_reply
    ):
        found.setdefault((reply.uid, reply.address), reply)
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


def peer_from_txt(address: str, port: int, txt: Mapping[bytes, bytes | None], name: str) -> FoundPeer | None:
    """A peer's DNS-SD advertisement (SPEC.md § 19.5: `servers=`, `path=`, `v=`, `tls=`), or None."""

    def text(key: bytes) -> str | None:
        value = txt.get(key)
        try:
            return value.decode("utf-8") if value is not None else None
        except UnicodeDecodeError:
            return None

    servers, path, versions, tls = text(b"servers"), text(b"path"), text(b"v"), text(b"tls")
    if not servers or not _base_ok(path) or not versions or tls not in ("0", "1") or not 1 <= port <= 65535:
        return None
    uids = tuple(u for u in servers.split(",") if u)
    if not 1 <= len(uids) <= 16 or "1" not in versions.split(","):
        return None
    assert path is not None
    label = printable(name, NAME).replace("\n", " ")
    return FoundPeer(address, port, path.rstrip("/"), tls == "1", label, label, 1, uids)


def browse_dnssd_peers(timeout: float = 2.0, *, interfaces: Any = None) -> list[FoundPeer]:
    """The peers advertised with DNS-SD as `_lantern-peer._tcp` (the `dnssd` extra). An advertisement says
    no `slots`: such a peer is taken as serving one download at a time."""
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
    out: list[FoundPeer] = []
    try:
        ServiceBrowser(zc, PEER_SERVICE, Listener())
        time.sleep(timeout)
        for name in dict.fromkeys(names):
            info = zc.get_service_info(PEER_SERVICE, name, timeout=int(timeout * 1000))
            if info is None or info.port is None:
                continue
            label = name.removesuffix("." + PEER_SERVICE)
            for address in info.parsed_addresses():
                found = peer_from_txt(address, info.port, info.properties, label)
                if found is not None:
                    out.append(found)
    finally:
        zc.close()
    return out


def addresses_of(found: Iterable[Found]) -> list[str]:
    """The addresses of the servers found, each once, in order."""
    return list(dict.fromkeys(f.address for f in found))
