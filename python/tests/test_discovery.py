"""LAN discovery (SPEC.md § 4.1): the datagram and its replies, both sides,
and DNS-SD when the dnssd extra is installed."""

from __future__ import annotations

import json
import socket

import pytest

from demo import make_lantern
from lantern import discovery
from lantern.server.discovery import DiscoveryResponder, discovery_reply
from lantern.server.pairing import Limiter

REPLY = {
    "schema": 1,
    "lantern": "server",
    "uid": "6f1c2a8e",
    "name": "Living room shelf",
    "port": 443,
    "base": "/api/lantern",
    "versions": [1],
}


def raw(doc: object) -> bytes:
    return json.dumps(doc).encode()


def test_a_reply_read() -> None:
    found = discovery.read_reply(raw({**REPLY, "x-vendor": 1}), "192.0.2.10")  # an unknown field: ignored
    assert found == discovery.Found("192.0.2.10", 443, "6f1c2a8e", "Living room shelf", "/api/lantern", (1,))
    assert found.url == "https://192.0.2.10/"
    assert discovery.Found("::1", 8443, "u", "n", "/", (1,)).url == "https://[::1]:8443/"


@pytest.mark.parametrize(
    "change",
    [
        {"schema": 2},  # newer: absent
        {"schema": True},
        {"lantern": "discover"},
        {"uid": 7},
        {"port": 0},
        {"port": "443"},
        {"base": "https://elsewhere.example.org/"},
        {"base": "//elsewhere"},
        {"versions": []},
        {"versions": ["1"]},
        {"name": None},
    ],
)
def test_replies_left_out(change: dict[str, object]) -> None:
    assert discovery.read_reply(raw({**REPLY, **change}), "192.0.2.10") is None


def test_datagrams_that_are_not_replies() -> None:
    assert discovery.read_reply(b"\xff\xfe", "192.0.2.10") is None
    assert discovery.read_reply(b"[1]", "192.0.2.10") is None
    assert discovery.read_reply(raw({**REPLY, "name": "x" * 1300}), "192.0.2.10") is None  # above 1200 bytes
    assert discovery.read_reply(raw({**REPLY, "name": "Shelf\u0007\nTwo"}), "192.0.2.10").name == "Shelf Two"  # type: ignore[union-attr]


def test_directed_broadcast() -> None:
    assert discovery.directed_broadcast("192.168.1.20", 24) == "192.168.1.255"
    assert discovery.directed_broadcast("10.0.3.7", 16) == "10.0.255.255"
    assert json.loads(discovery.REQUEST) == {"schema": 1, "lantern": "discover"}


def test_the_servers_reply() -> None:
    app = make_lantern()
    limiter = Limiter(2, 1.0)
    request = discovery.REQUEST
    reply = discovery_reply(app, 8443, request, "192.168.1.20", limiter)
    assert reply is not None and discovery.read_reply(reply, "192.168.1.5") == discovery.Found(
        "192.168.1.5", 8443, app.uid, app.name, app.base, (1,)
    )
    assert discovery_reply(app, 8443, request, "8.8.8.8", limiter) is None  # not a local network
    assert discovery_reply(app, 8443, raw({"schema": 2, "lantern": "discover"}), "192.168.1.21", limiter) is None
    assert discovery_reply(app, 8443, b"not json", "192.168.1.21", limiter) is None
    assert discovery_reply(app, 8443, b" " * 1300, "192.168.1.21", limiter) is None
    assert discovery_reply(app, 8443, request, "not an address", limiter) is None
    assert discovery_reply(app, 8443, request, "192.168.1.20", limiter) is not None
    assert discovery_reply(app, 8443, request, "192.168.1.20", limiter) is None  # a few times a second at most


def test_discovery_on_loopback() -> None:
    responder = DiscoveryResponder(make_lantern(), 8443, port=0, host="127.0.0.1").start()
    try:
        found = discovery.discover(["127.0.0.1"], port=responder.port, timeout=0.5)
    finally:
        responder.stop()
    assert [(f.address, f.port, f.name) for f in found] == [("127.0.0.1", 8443, "Demo shelf")]
    assert discovery.addresses_of(found + found) == ["127.0.0.1"]


def test_nothing_answers() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        assert discovery.discover(["127.0.0.1"], port=silent.getsockname()[1], timeout=0.2) == []


def test_dnssd_txt() -> None:
    found = discovery.from_txt(
        "192.0.2.10", 443, {b"uid": b"6f1c2a8e", b"path": b"/api/lantern", b"v": b"1,2"}, "Shelf"
    )
    assert found == discovery.Found("192.0.2.10", 443, "6f1c2a8e", "Shelf", "/api/lantern", (1, 2))
    for txt in (
        {b"uid": b"u", b"path": b"api", b"v": b"1"},
        {b"uid": b"u", b"path": b"/api", b"v": b"one"},
        {b"uid": b"\xff", b"path": b"/api", b"v": b"1"},
        {b"path": b"/api", b"v": b"1"},
        {b"uid": b"u", b"path": b"/api", b"v": b"0"},
    ):
        assert discovery.from_txt("192.0.2.10", 443, txt, "Shelf") is None


@pytest.mark.integration
def test_dnssd_on_loopback() -> None:
    pytest.importorskip("zeroconf")
    from lantern.server.discovery import advertise_dnssd

    app = make_lantern()
    zc = advertise_dnssd(app, 8443, "127.0.0.1", interfaces=["127.0.0.1"])
    try:
        found = discovery.browse_dnssd(1.5, interfaces=["127.0.0.1"])
    finally:
        zc.close()
    assert [(f.uid, f.port, f.base, f.versions) for f in found] == [(app.uid, 8443, app.base, (1,))]
