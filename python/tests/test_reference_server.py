"""The client against the specification's reference server (spec/server),
started in this process on loopback over its fictional library
(spec/tests/library.py), with each transport: the standard library's, and
httpx's, sync and async."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import lantern
from conftest import SPEC
from lantern import homebrew as hb
from lantern.client import AsyncLanternClient, LanternClient, StdlibTransport

pytestmark = pytest.mark.integration

sys.path.insert(0, str(SPEC))
sys.path.insert(0, str(SPEC / "tests"))
import library as fiction  # noqa: E402  (spec/tests/library.py)
from server import lantern_server as ls  # noqa: E402

ls.log = lambda msg: None
AGENT = "LanternPythonTest/1.0"


class Reference:
    def __init__(self, root: Path) -> None:
        self.root = fiction.make(root / "library")
        users = root / "users.json"
        users.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "public": True,
                    "users": [
                        {
                            "name": "lea",
                            "password": ls.hash_password("frost-lantern", 1000),
                            "scopes": ["library", "cheats"],
                            "state": "active",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.lib = ls.Library(self.root, root / "state.json")
        self.server = ls.LanternServer(("127.0.0.1", 0), self.lib, ls.Accounts(users), rescan=0, quiet=True)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.token = self.server.tokens.issue("lea", "Lea's test device", ["library", "cheats"])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Reference]:
    ref = Reference(tmp_path_factory.mktemp("reference"))
    yield ref
    ref.close()


def transports() -> list[Callable[[], Any]]:
    out: list[Callable[[], Any]] = [StdlibTransport]
    try:
        from lantern.client.httpx_transport import HttpxTransport
    except ImportError:
        return out
    return [*out, HttpxTransport]


@pytest.fixture(params=transports(), ids=lambda t: t.__name__)
def client(request: pytest.FixtureRequest, reference: Reference) -> Iterator[LanternClient]:
    with LanternClient(reference.url, user_agent=AGENT, token=reference.token, transport=request.param()) as c:
        yield c


def test_handshake(client: LanternClient) -> None:
    hello = client.handshake()
    assert hello.base == "/api/lantern" and hello.account.state == "active"
    assert sorted(hello.platforms) == ["3ds", "android", "linux", "switch"]
    for family in ("library", "titles", "changes", "homebrew", "cheats"):
        assert client.offers(family), family
    assert not client.offers("saves") and client.offers("pairing")  # a server with accounts pairs


def test_apps_pages_and_platforms(client: LanternClient) -> None:
    every = list(client.iter_apps(page_size=2))
    assert len(every) == fiction.SERVED and len({a.id for a in every}) == fiction.SERVED
    assert len(list(client.iter_apps(platform="switch"))) == fiction.SWITCH
    page = client.apps(page_size=3, sort="added")
    assert len(page.items) == 3 and page.next is not None and page.total == fiction.SERVED
    assert {a.type for a in client.iter_apps(type="update")} == {"update"}


def test_missing(client: LanternClient) -> None:
    got = {(a.app_id, a.version_code) for a in client.iter_missing([("0100ABCD00010000", 0)], platform="switch")}
    assert got == {("0100ABCD00010800", 196608), ("0100ABCD00011001", 0)}
    bases = list(client.iter_missing([], ["base"], platform="android"))
    assert [a.title_id for a in bases] == ["org.example.frostlinetales"]


def test_changes(client: LanternClient) -> None:
    first = client.changes()
    assert first.added == [] and first.removed == []
    assert client.changes(first.since).since
    with pytest.raises(lantern.BadRequest):
        client.changes("s_never_given")


def test_titles(client: LanternClient) -> None:
    title = client.title("0100ABCD00010000", platform="switch")
    assert title.name == "Frostline Tales" and title.effective_genres == ["adventure", "puzzle"]
    assert title.video is not None and title.video.external
    bulk = client.titles(["0100ABCD00010000", "0100EFEF00020000", "0500000000000000"], platform="switch")
    assert {t.title_id for t in bulk.titles} == {"0100ABCD00010000", "0100EFEF00020000"}
    assert bulk.unknown == ["0500000000000000"]
    with pytest.raises(lantern.NotFound):
        client.title("0500000000000000", platform="switch")
    changes = list(client.iter_title_changes())
    assert changes and not changes[-1].more


def test_homebrew(client: LanternClient) -> None:
    entries = list(client.iter_homebrew(page_size=2))
    assert len(entries) == fiction.SERVED_HOMEBREW
    assert all(e.package.manifest is None for e in entries)
    kinds = {e.id: e.effective_kind for e in entries if e.platform == "switch"}
    assert kinds["org.example.ember-widget"] == "app"  # a kind this library does not know
    lamp = client.homebrew_entry(fiction.PAPERLAMP, platform="switch")
    assert hb.verify_signature(lamp) is True
    plan = hb.install_plan(lamp)
    assert plan.free == [f"/switch/{fiction.PAPERLAMP}/{fiction.PAPERLAMP}.nro"] and not plan.consent
    frost = client.homebrew_entry(fiction.FROSTLINE, platform="switch")
    assert hb.install_plan(frost).free and frost.requires is not None
    assert hb.offer(frost, {"atmosphere": "1.8.0"}).decision == "offer"
    assert hb.offer(frost, {"atmosphere": "1.6.2"}).decision == "refuse"
    overlay = client.homebrew_entry("org.example.ember-overlay", platform="switch")
    assert hb.install_plan(overlay).consent


def test_homebrew_ports_and_architectures(client: LanternClient) -> None:
    harbor = client.homebrew_entry(fiction.HARBOR, platform="linux")
    assert hb.port_problems(harbor) == []
    for package in [harbor.package, *(harbor.packages or [])]:
        assert hb.verify_signature(harbor, package) is True
        assert hb.install_plan(harbor, package).consent == ["/Harbor Lights.sh"]
    picked = hb.pick_package(harbor, "x86_64")
    assert picked is not None and picked.arch == ["x86_64"]
    assert hb.pick_package(harbor, "x86") is None
    offer = hb.offer(harbor, {"glibc": "2.31", "ram_mb": 2048, "screen": "1280x720", "gpu": ["gles2"]})
    assert offer.decision == "warn" and any("kernel" in r for r in offer.reasons)
    port = client.homebrew_entry(fiction.PORT, platform="switch")
    pak = fiction.FROST_PAK[1]
    present = {"data/frost.pak": hb.file_hashes(pak), "music/demo.pak": hb.file_hashes(b"demo")}
    assert hb.launch_check(port, present).ok
    assert not hb.launch_check(port, {"data/frost.pak": hb.file_hashes(b"another")}).ok


def test_homebrew_updates(client: LanternClient) -> None:
    updates = list(
        client.iter_homebrew_updates([(fiction.FROSTLINE, 10000), (fiction.PAPERLAMP, 902)], platform="switch")
    )
    assert [e.id for e in updates] == [fiction.FROSTLINE]
    with pytest.raises(lantern.BadRequest):
        client.homebrew_entry(fiction.FROSTLINE)  # on two platforms: name one


def test_cheats(client: LanternClient) -> None:
    sets = client.cheats(platform="switch").cheats
    assert len(sets) == 3
    some = client.cheats(title_id="0100ABCD00010000", build_id="4A1B2C3D4E5F6071")
    assert {c.source for c in some.cheats} == {"Community list", "Noor"}
    text = client.cheat_text(some.cheats[0])
    assert text.startswith("[")


def test_downloads(client: LanternClient, tmp_path: Path) -> None:
    apps = sorted(client.iter_apps(platform="switch"), key=lambda a: a.size)
    app = apps[-1]
    dest = client.download_app(app, tmp_path / "game.nsp")
    data = dest.read_bytes()
    assert hashlib.sha256(data).hexdigest() == app.sha256
    (tmp_path / "again.nsp.part").write_bytes(data[: len(data) // 3])
    client.download_app(app, tmp_path / "again.nsp")
    assert (tmp_path / "again.nsp").read_bytes() == data
    lamp = client.homebrew_entry(fiction.PAPERLAMP, platform="switch")
    package = client.download_package(lamp.package, tmp_path / "lamp.nro")
    assert package.read_bytes() == fiction.PAPERLAMP_NRO
    with pytest.raises(lantern.IntegrityError):
        client.download(app.file, tmp_path / "wrong.nsp", sha256="0" * 64, size=app.size)


def test_credentials(reference: Reference) -> None:
    with (
        LanternClient(reference.url, user_agent=AGENT, token="et_not-a-token") as c,
        pytest.raises(lantern.Unauthorized),
    ):
        c.handshake()
    with LanternClient(reference.url, user_agent=AGENT) as anonymous:
        assert anonymous.handshake().account.state == "anonymous"
        assert not anonymous.offers("cheats")
        with pytest.raises(lantern.Forbidden):
            anonymous.cheats()


def test_async(reference: Reference, tmp_path: Path) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        async with AsyncLanternClient(reference.url, user_agent=AGENT, token=reference.token, platform="switch") as c:
            hello = await c.handshake()
            assert hello.account.state == "active"
            apps = [a async for a in c.iter_apps(page_size=3)]
            assert len(apps) == fiction.SWITCH
            assert [e async for e in c.iter_homebrew_updates([(fiction.FROSTLINE, 1)])]
            entry = await c.homebrew_entry(fiction.PAPERLAMP)
            assert hb.verify_signature(entry)
            biggest = max(apps, key=lambda a: a.size)
            await c.download_app(biggest, tmp_path / "async.nsp")
            assert hashlib.sha256((tmp_path / "async.nsp").read_bytes()).hexdigest() == biggest.sha256
            sets = (await c.cheats()).cheats
            assert (await c.cheat_text(sets[0])).startswith("[")
            with pytest.raises(lantern.NotFound):
                await c.title("0500000000000000")

    asyncio.run(run())
