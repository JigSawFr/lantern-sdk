"""What draft 0.11 adds: TLS 1.2 at least on both sides (SPEC.md § 2, L-2-9, L-2-10), Strict-Transport-Security
(L-2-11), a `uid` that is a random UUID of version 4 or 7 (L-4.2-9) and the long, immutable lifetime of what an
address names by its SHA-256 (L-14-5)."""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
import threading
import uuid
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from demo import DEMO_KEY, DEMO_TOKEN, build_library, delta_pair, demo_accounts, make_lantern
from lantern import static
from lantern.client.httpx_transport import AsyncHttpxTransport, HttpxTransport
from lantern.client.stdlib import StdlibTransport
from lantern.client.tls import pinned_context, unverified_context, verified_context
from lantern.errors import TransportError
from lantern.http import Headers
from lantern.peer import Peer
from lantern.server import LanternApp, MemoryLibrary
from lantern.server.http import ServerRequest
from lantern.uid import check_uid, is_valid_uid, new_uid
from test_server import BASE, call
from test_server_auth import call as signed

NEW_SHA = hashlib.sha256(delta_pair()[1]).hexdigest()
GOOD = "6f1c2a8e-2b1d-4c3e-9f00-112233445566"
V7 = "0190a5b2-7c3d-7e1f-8a4b-5c6d7e8f9a0b"


# TLS 1.2 at least, the client (L-2-9).


def test_l_2_9_every_context_the_client_builds_floors_at_tls_12() -> None:
    """[L-2-9] No context offers a protocol older than TLS 1.2."""
    floor = ssl.TLSVersion.TLSv1_2
    assert verified_context().minimum_version >= floor
    assert unverified_context().minimum_version >= floor
    assert pinned_context(ssl.PEM_cert_to_DER_cert(_certificate()[0])).minimum_version >= floor
    assert StdlibTransport().context.minimum_version >= floor
    assert StdlibTransport(pin="0" * 64).context.minimum_version >= floor
    assert StdlibTransport(verify=False).context.minimum_version >= floor


def test_l_2_9_a_context_given_with_an_older_floor_is_raised() -> None:
    """[L-2-9] A context handed to the transport is raised to TLS 1.2, not trusted."""
    given = ssl.create_default_context()
    given.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    assert StdlibTransport(context=given).context.minimum_version >= ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("kwargs", [{}, {"verify": False}, {"pin": "0" * 64}])
def test_l_2_9_httpx_clients_floor_at_tls_12(kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """[L-2-9] The httpx transports build their clients on a context of TLS 1.2 at least."""
    seen: list[ssl.SSLContext] = []
    real = httpx.Client

    def spy(*a: Any, **k: Any) -> httpx.Client:
        if isinstance(k.get("verify"), ssl.SSLContext):
            seen.append(k["verify"])
        return real(*a, **k)

    monkeypatch.setattr(httpx, "Client", spy)
    HttpxTransport(**kwargs).close()
    assert seen and all(c.minimum_version >= ssl.TLSVersion.TLSv1_2 for c in seen)
    a = AsyncHttpxTransport(**kwargs)
    ctx = a.client._transport._pool._ssl_context  # type: ignore[attr-defined]
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def _certificate() -> tuple[str, str]:
    pytest.importorskip("cryptography")
    from hostile_server import make_certificate

    return make_certificate()


@pytest.fixture
def old_tls_server(tmp_path: Path) -> Iterator[int]:
    """A TLS server that speaks nothing newer than TLS 1.1, when this OpenSSL can build one."""
    cert, key = _certificate()
    (tmp_path / "c.pem").write_text(cert, encoding="ascii")
    (tmp_path / "k.pem").write_text(key, encoding="ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version, ctx.maximum_version = ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pytest.skip("this OpenSSL cannot build a TLS 1.1 server")
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.2)
    stop = threading.Event()

    def run() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except OSError:
                pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(2)
        listener.close()


def test_l_2_9_a_server_limited_to_tls_11_is_refused(old_tls_server: int) -> None:
    """[L-2-9] The client does not fall back to TLS 1.1."""
    t = StdlibTransport(verify=False)
    from lantern.client.transport import Request

    with pytest.raises((TransportError, ssl.SSLError, OSError)):
        t.send(Request("GET", f"https://127.0.0.1:{old_tls_server}/", Headers([]), None), timeout=3)


# TLS 1.2 at least, the server (L-2-10).


def test_l_2_10_a_peer_never_negotiates_below_tls_12(tmp_path: Path) -> None:
    """[L-2-10] The context a peer is given is raised to TLS 1.2; the one its command line builds has it."""
    cert, key = _certificate()
    (tmp_path / "c.pem").write_text(cert, encoding="ascii")
    (tmp_path / "k.pem").write_text(key, encoding="ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    peer = Peer(("127.0.0.1", 0), {}, {}, tls=ctx)
    try:
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    finally:
        peer.server_close()
    source = (Path(__file__).parent.parent / "src/lantern/peer.py").read_text(encoding="utf-8")
    assert re.search(r"PROTOCOL_TLS_SERVER\)\n\s+tls\.minimum_version = ssl\.TLSVersion\.TLSv1_2", source)


# HSTS (L-2-11).


def test_l_2_11_hsts_over_tls_and_not_over_plain_http() -> None:
    """[L-2-11] Strict-Transport-Security with a max-age of six months or more where the request came by TLS."""
    app = LanternApp(MemoryLibrary(), uid=GOOD, name="x")
    tls = app.handle(ServerRequest("GET", "/.well-known/lantern", {}, Headers([]), scheme="https"))
    value = tls.headers["Strict-Transport-Security"]
    assert int(re.fullmatch(r"max-age=(\d+)", value).group(1)) >= 15552000  # type: ignore[union-attr]
    plain = app.handle(ServerRequest("GET", "/.well-known/lantern", {}, Headers([]), scheme="http"))
    assert "Strict-Transport-Security" not in plain.headers


def test_l_2_11_hsts_when_told_it_is_served_over_https() -> None:
    """[L-2-11] `hsts=True`: behind a proxy that ends TLS the header goes out, with the age given; errors too."""
    app = LanternApp(MemoryLibrary(), uid=GOOD, name="x", hsts=True, hsts_max_age=20000000)
    for path in ("/.well-known/lantern", "/nothing"):
        r = app.handle(ServerRequest("GET", path, {}, Headers([]), scheme="http"))
        assert r.headers["Strict-Transport-Security"] == "max-age=20000000"
    with pytest.raises(ValueError, match="hsts_max_age"):
        LanternApp(MemoryLibrary(), uid=GOOD, name="x", hsts_max_age=3600)


# uid (L-4.2-9).


@pytest.mark.parametrize("uid", [GOOD, V7, "b7f1c3e2-5a9d-4e6b-8c2f-0a1b2c3d4e5f"])
def test_l_4_2_9_a_random_uuid_is_a_uid(uid: str) -> None:
    """[L-4.2-9] Lower-case UUIDs of version 4 and 7 are accepted."""
    assert is_valid_uid(uid) and check_uid(uid) == uid
    assert LanternApp(MemoryLibrary(), uid=uid, name="x").uid == uid


@pytest.mark.parametrize(
    "uid",
    [
        "u",
        "",
        "6f1c2a8e-2b1d-11ef-9f00-112233445566",  # version 1: a hardware address
        "1ef21d2f-1207-6a60-8a4b-5c6d7e8f9a0b",  # version 6
        GOOD.upper(),
        "6f1c2a8e-2b1d-1c3e-9f00-112233445566",
        "6f1c2a8e-2b1d-4c3e-1f00-112233445566",  # not the RFC variant
        GOOD + "0",
    ],
)
def test_l_4_2_9_anything_else_is_refused_at_configuration(uid: str) -> None:
    """[L-4.2-9] Not a v4 or v7 UUID in lower case: ValueError, by the app and by the static export."""
    assert not is_valid_uid(uid)
    with pytest.raises(ValueError, match="uid"):
        LanternApp(MemoryLibrary(), uid=uid, name="x")
    with pytest.raises(ValueError, match="uid"):
        static.export(MemoryLibrary(), Path("never-written"), uid=uid, name="x")


def test_l_4_2_9_a_generated_uid_is_a_random_v4() -> None:
    """[L-4.2-9] What the toolkit generates is version 4, never 1 or 6."""
    for _ in range(20):
        u = new_uid()
        assert is_valid_uid(u) and uuid.UUID(u).version == 4
    peer = Peer(("127.0.0.1", 0), {}, {})
    try:
        assert is_valid_uid(peer.uid)
    finally:
        peer.server_close()


# Immutable (L-14-5).


def _long(value: str) -> bool:
    age = re.search(r"max-age=(\d+)", value)
    return bool(age) and int(age.group(1)) >= 86400 and "immutable" in value  # type: ignore[union-attr]


def test_l_14_5_a_chunk_index_is_public_immutable_and_private_with_a_token() -> None:
    """[L-14-5] Long max-age and immutable; `private` when the caller authenticates, `public` otherwise; the
    ETag stays, and a 304 repeats the lifetime."""
    app = make_lantern(build_library(delta=True), accounts=demo_accounts())
    try:
        path = f"{BASE}/chunks/sha256/{NEW_SHA}"
        anon = call(app, "GET", path)
        assert (
            anon.status == 200
            and anon.headers["Cache-Control"].startswith("public, ")
            and _long(anon.headers["Cache-Control"])
        )
        etag = anon.headers["ETag"]
        again = call(app, "GET", path, If_None_Match=etag)
        assert again.status == 304 and _long(again.headers["Cache-Control"])
        mine = signed(app, "GET", path, token=DEMO_TOKEN, key=DEMO_KEY)
        assert (
            mine.status == 200
            and mine.headers["Cache-Control"].startswith("private, ")
            and _long(mine.headers["Cache-Control"])
        )
        assert "ETag" in mine.headers
        assert call(app, "GET", f"{BASE}/chunks/sha256/{'0' * 64}").headers["Cache-Control"] in ("no-cache", "private")
    finally:
        app.shutdown()
