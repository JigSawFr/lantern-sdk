"""The Python client against the malicious test server (tools/hostile_server.py):
for each scenario, the client refuses what it must, and sends nothing it must not."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

import lantern
from hostile_server import SCENARIOS, HostileServer
from lantern import homebrew as hb
from lantern.client import LanternClient
from lantern.models import App
from lantern.signatures import DeviceKey

AGENT = "LanternHostileTest/1.0"
KEY = DeviceKey(bytes(range(32)))  # a fictional device's


def needs_tls(scenario: str) -> None:
    if SCENARIOS[scenario].tls:
        pytest.importorskip("cryptography")


@pytest.fixture
def hostile(request: pytest.FixtureRequest) -> Iterator[HostileServer]:
    scenario: str = request.param
    needs_tls(scenario)
    with HostileServer(scenario) as server:
        yield server


def client(server: HostileServer, **options: object) -> LanternClient:
    options.setdefault("token", server.token)
    return LanternClient(server.url, user_agent=AGENT, platform="switch", **options)  # type: ignore[arg-type]


def the_app(c: LanternClient) -> App:
    return c.apps().items[0]


COVERED = {
    "spki-wrong",
    "key-changed",
    "manifest-dotdot",
    "manifest-relative",
    "manifest-outside",
    "newer-schema",
    "oversized-document",
    "deep-document",
    "long-string",
    "page-too-long",
    "manifest-too-long",
    "bad-digest",
    "wrong-bytes",
    "extra-bytes",
    "truncated",
    "wrong-content-range",
    "small-order-key",
    "expired-challenge",
    "replayed-challenge",
    "pairing-elsewhere",
    "redirect",
}


def test_every_scenario_is_tested() -> None:
    assert set(SCENARIOS) == COVERED


@pytest.mark.parametrize("hostile", ["spki-wrong"], indirect=True)
def test_a_key_other_than_the_pinned_one(hostile: HostileServer) -> None:
    assert hostile.pin is not None
    with client(hostile, key=KEY, pin=hostile.pin) as c, pytest.raises(lantern.PinMismatch) as e:
        c.handshake()
    assert e.value.pinned == hostile.pin and e.value.seen == hostile.other_pin
    assert hostile.requests == []  # nothing was sent over the connection


@pytest.mark.parametrize("hostile", ["spki-wrong"], indirect=True)
def test_a_key_other_than_the_pinned_one_over_httpx(hostile: HostileServer) -> None:
    pytest.importorskip("httpx")
    from lantern.client.httpx_transport import HttpxTransport

    assert hostile.pin is not None
    with client(hostile, transport=HttpxTransport(pin=hostile.pin)) as c, pytest.raises(lantern.PinMismatch):
        c.handshake()
    assert hostile.requests == []


@pytest.mark.parametrize("hostile", ["key-changed"], indirect=True)
def test_a_key_that_changed(hostile: HostileServer) -> None:
    assert hostile.pin is not None
    with client(hostile, key=KEY, pin=hostile.pin) as c:
        assert c.handshake().uid
        with pytest.raises(lantern.PinMismatch):
            c.apps()
    assert [r["path"] for r in hostile.requests] == ["/.well-known/lantern"]


@pytest.mark.parametrize("hostile", ["manifest-dotdot", "manifest-relative", "manifest-outside"], indirect=True)
def test_a_hostile_manifest(hostile: HostileServer) -> None:
    with client(hostile) as c:
        entry = c.homebrew_entry("org.example.paperlamp")
        assert hb.manifest_problems(hb.manifest_of(entry.package)) or hostile.scenario.name == "manifest-outside"
        with pytest.raises(hb.Refused):
            hb.install_plan(entry)


@pytest.mark.parametrize("hostile", ["newer-schema"], indirect=True)
def test_a_newer_schema(hostile: HostileServer) -> None:
    with client(hostile) as c:
        with pytest.raises(lantern.NewerSchema) as e:
            c.handshake()
        assert e.value.schema == 2 and c.hello is None
        with pytest.raises(lantern.NewerSchema):
            c.homebrew_entry("org.example.paperlamp")


@pytest.mark.parametrize(
    "hostile", ["oversized-document", "deep-document", "long-string", "page-too-long"], indirect=True
)
def test_documents_beyond_the_limits(hostile: HostileServer) -> None:
    with client(hostile) as c:
        c.handshake()
        with pytest.raises(lantern.DocumentError):
            c.apps()


@pytest.mark.parametrize("hostile", ["manifest-too-long"], indirect=True)
def test_a_manifest_beyond_the_limits(hostile: HostileServer) -> None:
    with client(hostile) as c, pytest.raises(lantern.DocumentError):
        c.homebrew_entry("org.example.paperlamp")


@pytest.mark.parametrize("hostile", ["bad-digest", "wrong-bytes", "extra-bytes"], indirect=True)
def test_a_download_that_is_not_its_document(hostile: HostileServer, tmp_path: Path) -> None:
    dest = tmp_path / "frost.nsp"
    with client(hostile) as c:
        app = the_app(c)
        with pytest.raises(lantern.IntegrityError):
            c.download_app(app, dest)
        with pytest.raises(lantern.IntegrityError):
            c.fetch(app.file, sha256=app.sha256, size=app.size)
    assert not dest.exists() and not (tmp_path / "frost.nsp.part").exists()


@pytest.mark.parametrize("hostile", ["truncated"], indirect=True)
def test_a_truncated_download(hostile: HostileServer, tmp_path: Path) -> None:
    dest = tmp_path / "frost.nsp"
    with client(hostile) as c:
        app = the_app(c)
        with pytest.raises(lantern.TransportError):
            c.download_app(app, dest)
        assert not dest.exists() and (tmp_path / "frost.nsp.part").stat().st_size == app.size // 2
        c.download_app(app, dest)  # resumed with a Range, and checked whole
    assert hostile.requests[-1]["path"] == "/api/lantern/v1/files/f_frost"
    assert hashlib.sha256(dest.read_bytes()).hexdigest() == app.sha256


@pytest.mark.parametrize("hostile", ["wrong-content-range"], indirect=True)
def test_a_wrong_content_range(hostile: HostileServer, tmp_path: Path) -> None:
    dest = tmp_path / "frost.nsp"
    with client(hostile) as c:
        app = the_app(c)
        (tmp_path / "frost.nsp.part").write_bytes(b"\x03" * 100)
        with pytest.raises(lantern.UnexpectedResponse):
            c.download_app(app, dest)
    assert not dest.exists()


@pytest.mark.parametrize("hostile", ["small-order-key"], indirect=True)
def test_a_forged_signature_of_a_small_order_key(hostile: HostileServer) -> None:
    with client(hostile) as c:
        entry = c.homebrew_entry("org.example.paperlamp")
    assert entry.signature is not None
    assert hb.verify_signature(entry) is False


@pytest.mark.parametrize("hostile", ["expired-challenge", "replayed-challenge"], indirect=True)
def test_a_signature_refused_again_and_again(hostile: HostileServer) -> None:
    expected = lantern.SignatureExpired if hostile.scenario.name == "expired-challenge" else lantern.SignatureReplayed
    with client(hostile, key=KEY) as c:
        with pytest.raises(expected) as e:
            c.handshake()
        assert e.value.accept_signature is not None and e.value.accept_signature.components[0] == "@method"
    assert len(hostile.requests) == 2  # signed again once, then given up


@pytest.mark.parametrize("hostile", ["pairing-elsewhere"], indirect=True)
def test_a_pairing_code_that_points_elsewhere(hostile: HostileServer) -> None:
    with client(hostile, token=None) as c, pytest.raises(lantern.DocumentError):
        c.pair("Lea's console", ["library"])
    assert [r["path"] for r in hostile.requests] == ["/.well-known/lantern", "/api/lantern/v1/pairing"]
    assert all(r["authorization"] is None for r in hostile.requests)


@pytest.mark.parametrize("hostile", ["redirect"], indirect=True)
def test_a_redirect(hostile: HostileServer) -> None:
    with client(hostile) as c, pytest.raises(lantern.UnexpectedResponse):
        c.handshake()
    assert len(hostile.requests) == 1
