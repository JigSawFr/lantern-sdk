"""The client's draft 0.5 against the demo server (the toolkit, served by
Flask and FastAPI): event streams through each adapter, sync with the
user's consent, grants and downloads from a peer and a mirror, deleting an
account."""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import lantern
from demo import DEMO_KEY, DEMO_TOKEN, GRANT_SEED, UID, build_library, demo_accounts, make_lantern, serve
from lantern import e2e, ed25519
from lantern import sync as syncing
from lantern.client import LanternClient
from lantern.discovery import FoundPeer, PeerFinder, discover_peers, read_peer_reply
from lantern.models import Mirror
from lantern.peer import Peer
from lantern.server import LanternApp

AGENT = "LanternV05Test/1.0"


@pytest.fixture(params=["flask", "fastapi"])
def demo(request: pytest.FixtureRequest) -> Iterator[tuple[str, LanternApp]]:
    pytest.importorskip(request.param)
    if request.param == "fastapi":
        pytest.importorskip("uvicorn")
    app = make_lantern(build_library(), accounts=demo_accounts(), stream_probe=0.1)
    with serve(request.param, app) as url:
        yield url, app


def client(url: str, **options: Any) -> LanternClient:
    options.setdefault("token", DEMO_TOKEN)
    options.setdefault("key", DEMO_KEY)
    return LanternClient(url, user_agent=AGENT, platform="switch", **options)


def wish(title_id: str, updated: str | None = None, note: str | None = None) -> syncing.Item:
    value: dict[str, Any] = {"platform": "switch", "title_id": title_id}
    if note:
        value["note"] = note
    return syncing.Item(
        f"switch/{title_id}",
        updated or syncing.ms(__import__("datetime").datetime.now(__import__("datetime").UTC)),
        value,
    )


def test_events_through_the_adapter(demo: tuple[str, LanternApp]) -> None:
    url, app = demo
    with client(url) as c:
        c.sync_consent = syncing.SyncConsent(UID, wishes=True)
        stream = c.events()
        ready = next(stream)
        assert ready.event == "ready" and ready.id
        c.sync_write("wishes", [wish("0100AB1200010000")])
        event = next(stream)
        assert event.event == "sync" and event.data["collection"] == "wishes"
        stream.close()
        # A long poll from ready's id: the same event, with the same id (§ 18.3).
        found, since = c.poll_events(ready.id or "", wait=5)
        assert [(e.event, e.id) for e in found] == [("sync", event.id)]
        assert c.poll_events(since, wait=0)[0] == []
    deadline = time.monotonic() + 5
    while app.hub is not None and app.hub.streams and time.monotonic() < deadline:
        time.sleep(0.05)
    assert app.hub is not None and app.hub.streams == 0  # the adapter saw the client leave: its slot is free


def test_async_events(demo: tuple[str, LanternApp]) -> None:
    pytest.importorskip("httpx")
    url, _ = demo

    async def run() -> list[str]:
        async with lantern.AsyncLanternClient(url, user_agent=AGENT, token=DEMO_TOKEN, key=DEMO_KEY) as c:
            c.sync_consent = syncing.SyncConsent(UID, wishes=True)
            stream = c.events()
            first = await stream.__anext__()
            await c.sync_write("wishes", [wish("0100CD3400020000")])
            second = await stream.__anext__()
            await stream.aclose()
            items, _ = await c.sync_items("wishes")
            assert any(i.key == "switch/0100CD3400020000" for i in items)
            return [first.event, second.event]

    assert asyncio.run(run()) == ["ready", "sync"]


def test_sync_needs_consent(demo: tuple[str, LanternApp]) -> None:
    url, _ = demo
    with client(url) as c:
        with pytest.raises(syncing.ConsentRequired):
            c.sync()  # L-20.1-1: nothing sent
        c.sync_consent = syncing.SyncConsent("another-server", wishes=True)
        with pytest.raises(syncing.ConsentRequired):
            c.sync_items("wishes")
        c.sync_consent = syncing.SyncConsent(UID, wishes=True)
        over = c.sync()
        assert over.device is not None and c.sync_consent.generation == over.generation
        installed = syncing.Item(
            over.device,
            syncing.ms(__import__("datetime").datetime.now(__import__("datetime").UTC)),
            {"device": "Mira's console", "platform": "switch", "apps": []},
        )
        with pytest.raises(syncing.ConsentRequired):
            c.sync_write("installed", [installed])  # installed is agreed to by name (L-20.1-2)
        c.sync_consent.installed = True
        assert c.sync_write("installed", [installed]).items[0].key == over.device
        # The merge rule, and If-Match against the revision last read.
        kept = c.sync_write("wishes", [wish("0100EF5600030000", "2026-10-30T09:00:00.000Z", "First")]).items[0]
        older = c.sync_write("wishes", [wish("0100EF5600030000", "2026-10-30T08:00:00.000Z", "Older")]).items[0]
        assert older.value == kept.value
        items, rev = c.sync_items("wishes")
        assert rev >= 1 and any(i.key == "switch/0100EF5600030000" for i in items)
        c.sync_write("wishes", [wish("0100AB1200010000")], if_match=True)
        with pytest.raises(lantern.PreconditionFailed):
            c.sync_write("wishes", [wish("0100AB1200010000")], if_match=True)  # the collection changed since
        changes, _ = c.sync_items("wishes", since=rev)
        assert changes
        # Another device deletes the data: this one writes nothing back, and asks its user again (L-20.3-2).
        with client(url) as other:
            other.delete_sync()
        with pytest.raises(syncing.SyncReset):
            c.sync_write("wishes", [wish("0100AB1200010000")])
        assert not c.sync_consent  # dropped: the user is asked again
        with pytest.raises(syncing.ConsentRequired):
            c.sync()


def test_a_peer_a_mirror_and_the_server(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, app = demo
    lib = app.library
    apps = [a for a in lib.apps() if a.platform == "switch" and a.size > 1000]
    files = {}
    for a in apps:
        ref = lib.file(a.file.rsplit("/", 1)[1])
        assert ref is not None
        files[a.sha256] = ref
    peer = Peer(("127.0.0.1", 0), files, {UID: ed25519.public_key(GRANT_SEED)}, name="Noor's console")
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    seen: list[dict[str, str | None]] = []

    class Mirror_(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return None

        def do_GET(self) -> None:  # a mirror that serves other bytes
            seen.append({"path": self.path, "authorization": self.headers.get("Authorization")})
            body = bytes(apps[0].size)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    mirror = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mirror_)
    threading.Thread(target=mirror.serve_forever, daemon=True).start()
    try:
        found = FoundPeer("127.0.0.1", peer.port, "/lantern", False, peer.uid, "Noor's console", 2, (UID,))
        with client(url) as c:
            target = apps[0]
            grant = c.grant(target.sha256, target.size)
            assert grant.sha256 == target.sha256
            got = c.download_from(target, tmp_path / "a.nsp", mirrors=False, peers=[found])
            assert hashlib.sha256(got.read_bytes()).hexdigest() == target.sha256 and peer.served == 1
            # A mirror of other bytes: refused, nothing kept of it, the server's file taken (L-19.1-1, L-19.1-3).
            target.mirrors = [Mirror(url=f"http://127.0.0.1:{mirror.server_address[1]}/frost.nsp")]
            got = c.download_from(target, tmp_path / "b.nsp")
            assert hashlib.sha256(got.read_bytes()).hexdigest() == target.sha256
            assert seen and seen[0]["authorization"] is None  # no token to a mirror (L-19.1-2)
            # A peer that holds nothing of it: the server's.
            other = next(a for a in lib.apps() if a.platform == "switch" and a.sha256 not in files)
            assert c.download_from(other, tmp_path / "c.nsp", mirrors=False, peers=[found]).stat().st_size == other.size
            with pytest.raises(lantern.NotFound):
                c.grant("0" * 64, 1)
    finally:
        peer.shutdown()
        peer.server_close()
        mirror.shutdown()
        mirror.server_close()


def test_peer_discovery_on_loopback() -> None:
    peer = Peer(("127.0.0.1", 0), {}, {UID: ed25519.public_key(GRANT_SEED)}, name="Noor's console")
    sock = peer.discovery(0, "127.0.0.1")
    try:
        port = sock.getsockname()[1]
        found = discover_peers(["127.0.0.1"], port=port, timeout=1.0, server_uid=UID)
        assert [(p.name, p.port, p.servers) for p in found] == [("Noor's console", peer.port, (UID,))]
        assert discover_peers(["127.0.0.1"], port=port, timeout=0.3, server_uid="another") == []
        calls: list[int] = []

        def search() -> list[FoundPeer]:
            calls.append(1)
            return found

        finder = PeerFinder(search, clock=lambda: 10.0)
        assert finder.peers(UID) == found and finder.peers(UID) == found and calls == [1]  # once a minute (L-19.5-2)
    finally:
        sock.close()
        peer.server_close()
    assert read_peer_reply(b'{"schema":1,"lantern":"server"}', "192.168.1.2") is None
    assert read_peer_reply(b'{"schema":2,"lantern":"peer"}', "192.168.1.2") is None


def test_deleting_an_account(demo: tuple[str, LanternApp]) -> None:
    url, _ = demo
    with client(url) as admin:
        admin.create_user("ines", ["library"])
        with pytest.raises(lantern.BadRequest):
            admin.delete_user("ines", confirm="Ines")
        with pytest.raises(lantern.Conflict):
            admin.delete_user("mira", confirm="mira")
        admin.delete_user("ines", confirm="ines")
        assert "ines" not in {u.name for u in admin.iter_admin_users()}
        with pytest.raises(lantern.NotFound):
            admin.delete_user("ines", confirm="ines")


def test_encrypted_saves_offline(tmp_path: Path) -> None:
    """What a device does alone: the key, its phrase, a backup sealed and opened (the server keeps bytes)."""
    if not e2e.available():
        pytest.skip("the crypto extra")
    key = e2e.SaveKey.generate()
    again = e2e.SaveKey.from_phrase(key.phrase().lower().replace("-", " "))
    assert again == key
    archive = tmp_path / "save.zip"
    archive.write_bytes(hashlib.shake_256(b"Lea's save").digest(200_000))
    header = e2e.encrypt_file(key, archive, tmp_path / "save.lne")
    assert (tmp_path / "save.lne").stat().st_size == e2e.encrypted_size(200_000)
    assert e2e.key_id_of(header) == key.key_id
    assert e2e.decrypt_file(key, tmp_path / "save.lne", tmp_path / "back.zip").read_bytes() == archive.read_bytes()
    with pytest.raises(e2e.RefusedBackup):
        e2e.decrypt_file(e2e.SaveKey.generate(), tmp_path / "save.lne", tmp_path / "other.zip")
