"""The client's draft 0.4 against the specification's reference server
(spec/server): pairing with a device key over a self-signed TLS key, bound
tokens and signed requests, the clock's offset, saves sent whole and by
resumable upload, cheat writes, requests, the administration API,
invitations and rating caps."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import ssl
import sys
import threading
import time
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import lantern
from conftest import SPEC
from lantern.client import AsyncLanternClient, LanternClient
from lantern.models import RatingCap
from lantern.pinning import FileServerStore, MemoryServerStore
from lantern.signatures import DeviceKey
from lantern.spki import short

pytestmark = pytest.mark.integration

sys.path.insert(0, str(SPEC))
sys.path.insert(0, str(SPEC / "tests"))
import library as fiction  # noqa: E402  (spec/tests/library.py)
from server import lantern_server as ls  # noqa: E402

ls.log = lambda msg: None
AGENT = "LanternPythonTest/1.0"
ADMIN_KEY = DeviceKey(hashlib.sha256(b"Ada's fictional phone key").digest())
EVERY = ["library", "saves", "cheats", "cheats.write", "requests", "admin"]
LEA = ["library", "saves", "cheats", "cheats.write", "requests"]


def zipped(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, data in files.items():
            z.writestr(zipfile.ZipInfo(name, (2026, 10, 30, 12, 0, 0)), data)
    return out.getvalue()


def nap(seconds: float) -> None:
    """The waits of a poll, short: the server's interval is 1 second here."""
    time.sleep(min(seconds, 1.1))


class Reference:
    """The reference server, private, over TLS with a self-signed key (or plain HTTP on loopback)."""

    def __init__(self, root: Path, *, tls: bool, bound_only: bool = False) -> None:
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
        context = spki = None
        if tls:
            pytest.importorskip("cryptography")
            from hostile_server import make_certificate, server_context, spki_of

            cert, key = make_certificate("Reference shelf")
            context, spki = server_context(cert, key), spki_of(cert)
        self.spki = spki
        lib = ls.Library(self.root, root / "state.json")
        self.server = ls.LanternServer(
            ("127.0.0.1", 0),
            lib,
            ls.Accounts(users),
            rescan=0,
            quiet=True,
            tls=context,
            spki=spki,
            bound_only=bound_only,
        )
        self.server.pairing.interval = 1
        scheme = "https" if tls else "http"
        self.url = f"{scheme}://127.0.0.1:{self.server.server_address[1]}/"
        self.admin_token = self.server.tokens.issue("ada", "Ada's phone", EVERY, key=ADMIN_KEY.public)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def admin(self, **options: Any) -> LanternClient:
        if self.spki is not None:
            options.setdefault("pin", self.spki)
        return LanternClient(self.url, user_agent=AGENT, token=self.admin_token, key=ADMIN_KEY, **options)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Reference]:
    ref = Reference(tmp_path_factory.mktemp("reference-tls"), tls=True)
    yield ref
    ref.close()


@pytest.fixture(scope="module")
def plain(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Reference]:
    ref = Reference(tmp_path_factory.mktemp("reference-plain"), tls=False)
    yield ref
    ref.close()


def pair(ref: Reference, scopes: list[str], *, cap: RatingCap | None = None, **options: Any) -> LanternClient:
    """A device paired with `ref` by its admin, its token bound to a new key."""
    if ref.spki is not None:
        options.setdefault("verify", False)
    client = LanternClient(ref.url, user_agent=AGENT, platform="switch", **options)
    pairing = client.pair("Lea's console", scopes)
    with ref.admin() as admin:
        waiting = [p for p in admin.iter_admin_pairings() if p.code == pairing.code]
        assert len(waiting) == 1 and waiting[0].key == pairing.key.fingerprint  # type: ignore[union-attr]
        admin.approve_pairing(waiting[0].id, user="lea", rating_cap=cap)
    client.wait_for_pairing(pairing, sleep=nap)
    return client


def test_pairing_with_a_key_over_a_pinned_tls_key(tls: Reference, tmp_path: Path) -> None:
    assert tls.spki is not None
    with LanternClient(tls.url, user_agent=AGENT, verify=False, platform="switch") as c:
        assert c.handshake().account.state == "anonymous"
        pairing = c.pair("Lea's console", LEA)
        assert pairing.fingerprint == short(tls.spki)  # what the console shows next to the code
        assert pairing.code in pairing.verify_complete.replace("%2D", "-")
        assert pairing.key is not None and c.poll_pairing(pairing) is None  # 202: waiting
        with tls.admin() as admin:
            found = next(p for p in admin.iter_admin_pairings() if p.code == pairing.code)
            admin.approve_pairing(found.id, user="lea")
        store = FileServerStore(tmp_path / "servers.json")
        record = c.wait_for_pairing(pairing, store=store, sleep=nap)
        assert record.bound and record.spki == tls.spki and record.key is not None
        assert sorted(record.scopes) == sorted(LEA)
        hello = c.handshake()
        assert hello.account.bound and hello.account.name == "lea"
        assert len(list(c.iter_apps(page_size=4))) == fiction.SWITCH
    kept = store.server(record.uid)
    assert kept is not None and kept.token == record.token
    assert os.name == "nt" or (tmp_path / "servers.json").stat().st_mode & 0o077 == 0
    with LanternClient.paired(kept, user_agent=AGENT) as again:
        assert again.handshake().account.bound
        with pytest.raises(lantern.Unauthorized):  # the token without its key is worth nothing
            LanternClient(tls.url, user_agent=AGENT, pin=tls.spki, token=kept.token).apps()


def test_a_pinned_key_over_httpx(tls: Reference) -> None:
    pytest.importorskip("httpx")
    from lantern.client.httpx_transport import HttpxTransport

    assert tls.spki is not None
    with tls.admin(transport=HttpxTransport(pin=tls.spki), pin=None) as admin:
        assert admin.handshake().account.bound
    with (
        LanternClient(tls.url, user_agent=AGENT, transport=HttpxTransport(pin="0" * 64)) as wrong,
        pytest.raises(lantern.PinMismatch),
    ):
        wrong.handshake()


def test_the_clock_offset(plain: Reference) -> None:
    with plain.admin() as admin:
        admin.core.clock_offset = -3600  # a console's clock an hour late
        hello = admin.handshake()  # refused signature_expired, then signed again with the server's Date
        assert hello.account.bound and abs(admin.core.clock_offset) < 60


def test_a_bearer_only_token_and_a_server_that_wants_keys(tmp_path: Path) -> None:
    ref = Reference(tmp_path, tls=False, bound_only=True)
    try:
        with LanternClient(ref.url, user_agent=AGENT) as c:
            hello = c.handshake()
            assert hello.auth is not None and hello.auth.bearer_only is False
            with pytest.raises(lantern.BadRequest) as e:
                c.pair("Lea's console", ["library"], key=False)
            assert e.value.code == "key_required"
        token = ref.server.tokens.issue("lea", "An old console", ["library"])
        with LanternClient(ref.url, user_agent=AGENT, token=token) as old, pytest.raises(lantern.SignatureRequired):
            old.apps()
    finally:
        ref.close()


def test_saves(plain: Reference, tmp_path: Path) -> None:
    with pair(plain, LEA) as c:
        small = zipped({"save/data.bin": b"chapter 4" * 100})
        one = c.save("0100ABCD00010000", small, kind="account", game_version_code=196608, profile="Lea", note="Ch. 4")
        assert one.size == len(small) and one.profile == "Lea" and one.note == "Ch. 4"
        big = tmp_path / "big.zip"
        big.write_bytes(zipped({"save/world.bin": hashlib.shake_256(b"Noor's world").digest(5 << 19)}))
        hello = c.handshake()
        assert hello.limits is not None and hello.limits.save_body is not None
        # An upload cut after its first chunk, then resumed from HEAD's offset.
        from lantern.models import UploadRequest

        opened = c._send(
            c.core.upload_open(
                "0100ABCD00010000",
                UploadRequest(schema=1, size=big.stat().st_size, sha256=hashlib.sha256(big.read_bytes()).hexdigest()),
                None,
            )
        )
        first = big.read_bytes()[: opened.chunk_size]
        assert c._send(c.core.upload_chunk(opened.upload, 0, first)) == len(first)
        assert c.upload_offset(opened.upload) == (len(first), big.stat().st_size)
        seen: list[int] = []
        resumed = c.upload_save("0100ABCD00010000", big, resume=opened.upload, progress=lambda n, t: seen.append(n))
        assert resumed.size == big.stat().st_size and seen[-1] == big.stat().st_size
        whole = c.upload_save("0100ABCD00010000", big, kind="account", profile="Noor")
        listed = c.saves(title_id="0100ABCD00010000").saves
        assert {s.save_id for s in listed} >= {one.save_id, resumed.save_id, whole.save_id}
        back = c.download_save(whole, tmp_path / "back.zip")
        assert back.read_bytes() == big.read_bytes()
        for save in (one, resumed, whole):
            c.delete_save(save)
        with pytest.raises(lantern.NotFound):
            c.delete_save(one)


def test_cheats_written(plain: Reference) -> None:
    with pair(plain, LEA) as c:
        text = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n"
        made = c.create_cheat("switch", "0100ABCD00010000", text, build_id="4A1B2C3D4E5F6071", source="Lea tests")
        assert made.source == "Lea tests"
        with pytest.raises(lantern.Conflict):
            c.create_cheat("switch", "0100ABCD00010000", text, build_id="4A1B2C3D4E5F6071", source="Lea tests")
        again = text + "[Brighter lamp]\n04000000 00ABCDF0 00000001\n"
        c.replace_cheat(made.id, "switch", "0100ABCD00010000", again, build_id="4A1B2C3D4E5F6071", source="Lea tests")
        listed = next(s for s in c.cheats(title_id="0100ABCD00010000").cheats if s.id == made.id)
        assert c.cheat_text(listed) == again
        c.delete_cheat(made.id)
        assert made.id not in {s.id for s in c.cheats().cheats}


def test_requests(plain: Reference) -> None:
    with pair(plain, LEA) as c:
        first = c.request_title("0100FFFF00090000")
        assert first.status == "open" and first.platform == "switch"
        assert c.request_title("0100FFFF00090000").id == first.id  # the open one again
        assert first.id in {r.id for r in c.requests().requests}
        c.withdraw_request(first.id)
        with pytest.raises(lantern.NotFound):
            c.withdraw_request(first.id)


def test_administration(plain: Reference) -> None:
    with plain.admin() as admin:
        name = "noor-" + hashlib.sha256(str(datetime.now(UTC)).encode()).hexdigest()[:6]
        made = admin.create_user(name, ["library"])
        assert made.name == name and made.state == "active"
        with pytest.raises(lantern.Conflict):
            admin.create_user(name, ["library"])
        assert name in {u.name for u in admin.iter_admin_users(page_size=1)}
        frozen = admin.update_user(name, state="frozen")
        assert frozen.state == "frozen"
        device = pair(plain, ["library"])
        mine = [d for d in admin.iter_admin_devices(user="lea") if d.device == "Lea's console"]
        assert mine and all(d.bound and d.key for d in mine)
        for d in mine:
            admin.revoke_device(d.id)
        with device, pytest.raises(lantern.Unauthorized):
            device.apps()
        refused = LanternClient(plain.url, user_agent=AGENT)
        pairing = refused.pair("Someone's console", ["library"])
        waiting = next(p for p in admin.iter_admin_pairings() if p.code == pairing.code)
        admin.refuse_pairing(waiting.id)
        with pytest.raises(lantern.Gone):
            refused.poll_pairing(pairing)


def test_invitations_and_a_rating_cap(tls: Reference) -> None:
    assert tls.spki is not None
    expires = (datetime.now(UTC) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with tls.admin() as admin:
        invitation = admin.create_invitation(
            "lea", ["library"], expires=expires, devices=1, rating_cap=RatingCap(age=6), note="Ines's console"
        )
        assert tls.spki in invitation.link and invitation.code in invitation.link
        store = MemoryServerStore()
        child, record = LanternClient.from_invitation(
            invitation.link, "Ines's console", ["library", "cheats"], store=store, user_agent=AGENT
        )
        with child:
            assert record.spki == tls.spki and record.scopes == ["library"] and record.rating_cap == {"age": 6}
            assert child.rating_cap is not None and child.rating_cap.age == 6  # what the account shows
            seen = {a.title_id for a in child.iter_apps()}
            with admin_view(admin) as every:
                assert seen < every
        with pytest.raises(lantern.Gone):  # used up
            LanternClient.from_invitation(invitation.link, "Another console", ["library"], user_agent=AGENT)
        listed = {i.id for i in admin.iter_admin_invitations()}
        assert invitation.id not in listed


class admin_view:
    def __init__(self, admin: LanternClient) -> None:
        self.admin = admin

    def __enter__(self) -> set[str]:
        return {a.title_id for a in self.admin.iter_apps()}

    def __exit__(self, *exc: object) -> None:
        return None


def test_async_pairing_and_signed_requests(plain: Reference) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        async with AsyncLanternClient(plain.url, user_agent=AGENT, platform="switch") as c:
            pairing = await c.pair("Lea's tablet", ["library", "requests"])
            with plain.admin() as admin:
                found = next(p for p in admin.iter_admin_pairings() if p.code == pairing.code)
                admin.approve_pairing(found.id, user="lea")
            record = await c.wait_for_pairing(pairing, sleep=lambda s: asyncio.sleep(min(s, 1.1)))
            assert record.bound
            assert (await c.handshake()).account.bound
            assert len([a async for a in c.iter_apps(page_size=5)]) == fiction.SWITCH
            made = await c.request_title("0100FFFF00090000")
            await c.withdraw_request(made.id)

    asyncio.run(run())


def test_the_pinned_key_never_carries_a_ca(tls: Reference) -> None:
    with (
        LanternClient(tls.url, user_agent=AGENT) as strict,
        pytest.raises(lantern.TransportError) as e,
    ):
        strict.handshake()  # a self-signed certificate: no CA vouches for it
    assert isinstance(e.value.__cause__, ssl.SSLError | OSError)
