"""The client's draft 0.5 against the specification's reference server
(spec/server): its event stream and long polls, a peer (spec/server/peer.py)
and its grants, sync, encrypted saves sent and read back, deleting an
account, and the static library it exports (--export), read from its folder
and over HTTP."""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import io
import json
import sys
import threading
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import lantern
from conftest import SPEC
from lantern import e2e
from lantern import sync as syncing
from lantern.client import AsyncLanternClient, LanternClient
from lantern.discovery import FoundPeer
from lantern.models import UploadRequest
from lantern.signatures import DeviceKey
from lantern.static import StaticLibrary

pytestmark = pytest.mark.integration

sys.path.insert(0, str(SPEC))
sys.path.insert(0, str(SPEC / "tests"))
import library as fiction  # noqa: E402  (spec/tests/library.py)
from server import lantern_server as ls  # noqa: E402
from server import peer as reference_peer  # noqa: E402

ls.log = lambda msg: None
AGENT = "LanternPythonTest/1.0"
ADMIN = DeviceKey(hashlib.sha256(b"Ada's fictional phone key, 0.5").digest())
LEA_KEY = DeviceKey(hashlib.sha256(b"Lea's fictional console key, 0.5").digest())
EVERY = ["library", "saves", "cheats", "cheats.write", "requests", "admin", "sync.read", "sync.write"]
LEA = ["library", "saves", "cheats", "requests", "sync.read", "sync.write"]
FROST = "0100ABCD00010000"


def zipped(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, data in files.items():
            z.writestr(zipfile.ZipInfo(name, (2026, 10, 30, 12, 0, 0)), data)
    return out.getvalue()


class Reference:
    """The reference server of draft 0.5, private, plain HTTP on loopback."""

    def __init__(self, root: Path) -> None:
        self.root = fiction.make(root / "library")
        users = root / "users.json"
        password = ls.hash_password("frost-lantern", 1000)
        users.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "public": False,
                    "users": [
                        {"name": "lea", "password": password, "scopes": LEA, "state": "active"},
                        {"name": "ada", "password": password, "scopes": EVERY, "state": "active"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        lib = ls.Library(self.root, root / "state.json")
        self.server = ls.LanternServer(
            ("127.0.0.1", 0),
            lib,
            ls.Accounts(users),
            rescan=0,
            quiet=True,
            sync=ls.Sync(root / "sync.json"),
            heartbeat=5,
        )
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.uid = lib.uid
        self.admin_token = self.server.tokens.issue("ada", "Ada's phone", EVERY, key=ADMIN.public)
        self.lea_token = self.server.tokens.issue("lea", "Lea's console", LEA, key=LEA_KEY.public)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def admin(self, **options: Any) -> LanternClient:
        return LanternClient(self.url, user_agent=AGENT, token=self.admin_token, key=ADMIN, **options)

    def lea(self, **options: Any) -> LanternClient:
        options.setdefault("platform", "switch")
        return LanternClient(self.url, user_agent=AGENT, token=self.lea_token, key=LEA_KEY, **options)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


@pytest.fixture(scope="module")
def ref(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Reference]:
    r = Reference(tmp_path_factory.mktemp("reference-v05"))
    yield r
    r.close()


def test_the_handshake(ref: Reference) -> None:
    with ref.lea() as c:
        hello = c.handshake()
        assert hello.features["events"] and hello.features["peers"] and hello.features["sync"]
        assert hello.features["encrypted_saves"]
        assert hello.limits is not None and hello.limits.heartbeat == 5 and hello.limits.wait
        assert hello.peers is not None and len(lantern.grants.grant_key(hello.peers.key) or b"") == 32


def test_events(ref: Reference) -> None:
    with ref.lea() as c:
        stream = c.events()
        ready = next(stream)
        assert ready.event == "ready" and ready.id
        made = c.request_title("0100FFFF00090000")
        event = next(stream)
        assert event.event == "request" and event.data["id"] == made.id and event.data["status"] == "open"
        stream.close()
        again = c.events(ready.id)  # resumed: the event again, with its id
        assert next(again).id == ready.id
        replayed = next(again)
        assert (replayed.event, replayed.id) == ("request", event.id)
        again.close()
        found, since = c.poll_events(ready.id or "", wait=5)
        assert [(e.event, e.id) for e in found] == [("request", event.id)]
        c.withdraw_request(made.id)
        gone, _ = c.poll_events(since, wait=5)
        assert gone[0].data.get("deleted") is True
        with pytest.raises(lantern.BadRequest):
            next(c.events("s_never-given"))

    async def run() -> str:
        async with AsyncLanternClient(ref.url, user_agent=AGENT, token=ref.lea_token, key=LEA_KEY) as a:
            stream = a.events(ready.id)
            first = await stream.__anext__()
            second = await stream.__anext__()
            await stream.aclose()
            assert first.event == "ready"
            return second.event

    if pytest.importorskip("httpx"):
        assert asyncio.run(run()) == "request"


def test_a_reference_peer(ref: Reference, tmp_path: Path) -> None:
    uid, key, wanted = reference_peer.server_files(ref.url, ref.lea_token, LEA_KEY.seed)
    files = reference_peer.held_files(ref.root, wanted)
    peer = reference_peer.Peer(("127.0.0.1", 0), files, {uid: key}, name="Noor's console")
    taken: list[int] = []
    take = peer.take

    def counted() -> Any:
        taken.append(1)
        return take()

    peer.take = counted
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    try:
        found = FoundPeer(
            "127.0.0.1", peer.server_address[1], reference_peer.BASE, False, peer.uid, "Noor's console", 2, (uid,)
        )
        with ref.lea() as c:
            app = next(a for a in c.iter_apps() if a.size > 1000 and a.sha256 in files)
            got = c.download_from(app, tmp_path / "frost.nsp", peers=[found])
            assert hashlib.sha256(got.read_bytes()).hexdigest() == app.sha256 and taken == [1]
            grant = c.grant(app.sha256, app.size)
            assert lantern.grants.read_grant(grant.grant, {uid: key}) is not None
    finally:
        peer.shutdown()
        peer.server_close()


def test_sync(ref: Reference) -> None:
    now = syncing.ms(datetime.now(UTC))
    with ref.lea() as c:
        with pytest.raises(syncing.ConsentRequired):
            c.sync()
        c.sync_consent = syncing.SyncConsent(ref.uid, wishes=True)
        over = c.sync()
        assert over.device is not None
        item = syncing.Item(f"switch/{FROST}", now, {"platform": "switch", "title_id": FROST, "note": "Lea's"})
        kept = c.sync_write("wishes", [item]).items[0]
        assert kept.rev and kept.value == item.value
        items, _ = c.sync_items("wishes")
        assert [i.key for i in items] == [item.key]
        later = syncing.Item(item.key, syncing.ms(datetime.now(UTC)), None, deleted=True)
        assert c.sync_write("wishes", [later], if_match=True).items[0].deleted is not None
        with pytest.raises(lantern.PreconditionFailed):
            c.sync_write("wishes", [later], if_match=True)
        with ref.admin() as other:
            other.sync_consent = syncing.SyncConsent(ref.uid)
            other.delete_sync()  # ada's own data: lea's stays
        assert c.sync().generation == over.generation
        phone = DeviceKey(hashlib.sha256(b"Lea's fictional phone key, 0.5").digest())
        token = ref.server.tokens.issue("lea", "Lea's phone", LEA, key=phone.public)
        with LanternClient(ref.url, user_agent=AGENT, token=token, key=phone) as other:
            other.delete_sync()  # her other device, at her word
        with pytest.raises(syncing.SyncReset):  # deleted since: nothing written back (L-20.3-2)
            c.sync_write("wishes", [item])
        assert c.sync_consent is None


def test_encrypted_saves(ref: Reference, tmp_path: Path) -> None:
    if not e2e.available():
        pytest.skip("the crypto extra")
    key = e2e.SaveKey.generate()
    archive = zipped({"save/world.bin": hashlib.shake_256(b"Noor's world").digest(3 << 19)})
    path = tmp_path / "save.zip"
    path.write_bytes(archive)
    with ref.lea() as c:
        small = zipped({"save/slot1.bin": b"chapter 4" * 50})
        one = c.save_encrypted(FROST, small, key, kind="account")
        assert one.encryption is not None and one.encryption.key_id == key.key_id
        assert one.size == e2e.encrypted_size(len(small)) and one.profile is None  # L-9.4-6
        back = c.download_encrypted_save(one, key, tmp_path / "one.zip")
        assert back.read_bytes() == small
        # By upload, cut after its first chunk, then resumed to the same bytes from the archive and its header.
        header = e2e.make_header(key)
        whole = b"".join(e2e.iter_encrypted(key, path, header))
        opened = c._send(
            c.core.upload_open(
                FROST,
                UploadRequest(
                    schema=1,
                    size=len(whole),
                    sha256=hashlib.sha256(whole).hexdigest(),
                    encryption=lantern.models.Encryption(scheme=e2e.SCHEME, key_id=key.key_id),
                ),
                None,
            )
        )
        first = whole[: opened.chunk_size]
        assert c._send(c.core.upload_chunk(opened.upload, 0, first)) == len(first)
        resumed = c.upload_encrypted_save(FROST, path, key, resume=opened.upload, header=header)
        assert resumed.sha256 == hashlib.sha256(whole).hexdigest() and resumed.encryption is not None
        fresh = c.upload_encrypted_save(FROST, path, key, kind="account")
        assert fresh.sha256 != resumed.sha256  # a new file key each time (L-9.4-3)
        assert c.download_encrypted_save(fresh, key, tmp_path / "back.zip").read_bytes() == archive
        listed = [s for s in c.saves(title_id=FROST).saves if s.encryption is not None]
        assert {s.save_id for s in listed} >= {one.save_id, resumed.save_id, fresh.save_id}
        with pytest.raises(e2e.RefusedBackup):
            c.download_encrypted_save(fresh, e2e.SaveKey.generate(), tmp_path / "other.zip")
        assert not (tmp_path / "other.zip").exists()
        for s in (one, resumed, fresh):
            c.delete_save(s)


def test_deleting_an_account(ref: Reference) -> None:
    with ref.admin() as admin:
        admin.create_user("ines", ["library"])
        with pytest.raises(lantern.BadRequest):
            admin.delete_user("ines", confirm="ine")
        admin.delete_user("ines", confirm="ines")
        with pytest.raises(lantern.NotFound):
            admin.delete_user("ines", confirm="ines")


def test_the_static_export(ref: Reference, tmp_path: Path) -> None:
    out = tmp_path / "static"
    assert (
        ls.main(
            [
                "--library",
                str(ref.root),
                "--export",
                str(out),
                "--page-size",
                "3",
                "--state",
                str(tmp_path / "state.json"),
            ]
        )
        == 0
    )
    with StaticLibrary(out) as s:
        hello = s.handshake()
        assert hello.static is not None and hello.static.page_size == 3
        apps = list(s.iter_apps("switch"))
        assert len(apps) == fiction.SWITCH
        todo = s.missing([(FROST, 0)], ["update", "dlc"], platform="switch")
        assert {a.app_id for a in todo} == {"0100ABCD00010800", "0100ABCD00011001"}
        assert max(a.version_code for a in todo) == 196608
        got = s.download(todo[0], tmp_path / "update.bin")
        assert hashlib.sha256(got.read_bytes()).hexdigest() == todo[0].sha256
        assert list(s.iter_homebrew("switch"))

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(out), **kwargs)

        def log_message(self, *args: object) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with StaticLibrary(f"http://127.0.0.1:{server.server_address[1]}/") as s:
            assert len(list(s.iter_apps("switch"))) == fiction.SWITCH  # read as JSON, whatever its Content-Type
            assert s.download(apps[0], tmp_path / "base.bin").stat().st_size == apps[0].size
    finally:
        server.shutdown()
        server.server_close()
