"""The client's calls that write (save backups, encrypted ones, cheat sets,
requests) and sections, against the demo server built from the toolkit,
served by Flask and by FastAPI over HTTP."""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import lantern
from demo import DEMO_KEY, DEMO_TOKEN, build_library, demo_accounts, make_lantern, serve
from lantern import e2e
from lantern.client import LanternClient
from lantern.server import LanternApp

AGENT = "LanternWritesTest/1.0"
TITLE = "0500ABCDEF120000"  # a Switch title none of the demo's games has


@pytest.fixture(params=["flask", "fastapi"])
def demo(request: pytest.FixtureRequest) -> Iterator[tuple[str, LanternApp]]:
    pytest.importorskip(request.param)
    if request.param == "fastapi":
        pytest.importorskip("uvicorn")
    app = make_lantern(build_library(), accounts=demo_accounts())
    with serve(request.param, app) as url:
        yield url, app


def client(url: str, **options: Any) -> LanternClient:
    return LanternClient(url, user_agent=AGENT, platform="switch", token=DEMO_TOKEN, key=DEMO_KEY, **options)


def archive(size: int) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr("frostline/slot1.dat", bytes(i % 251 for i in range(size)))
    return out.getvalue()


def test_saves(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    small = archive(1000)
    with client(url) as c:
        hello = c.handshake()
        assert hello.features["saves"] == 1 and hello.limits is not None and hello.limits.save_body == 8 << 20
        one = c.save(TITLE, small, kind="account", slot="slot-1", game_version_code=65536, profile="Léa", note="Ch. 4")
        assert (one.size, one.sha256, one.profile, one.device) == (
            len(small),
            hashlib.sha256(small).hexdigest(),
            "Léa",
            "Mira's console",
        )
        big = tmp_path / "big.zip"
        big.write_bytes(archive(2_500_000))  # three chunks of 1 MiB at most
        progress: list[int] = []
        two = c.upload_save(TITLE, big, kind="account", progress=lambda done, total: progress.append(done))
        assert two.size == big.stat().st_size and len(progress) == 3 and progress[-1] == two.size
        listed = c.saves(title_id=TITLE).saves
        assert [s.save_id for s in listed] == [two.save_id, one.save_id]  # newest first
        back = c.download_save(two, tmp_path / "back.zip")
        assert back.read_bytes() == big.read_bytes()
        c.delete_save(one)
        with pytest.raises(lantern.NotFound):
            c.delete_save(one)
        assert [s.save_id for s in c.saves().saves] == [two.save_id]
        # An upload left half-way, resumed from where HEAD says.
        third = tmp_path / "third.zip"
        third.write_bytes(archive(1_500_000))
        with pytest.raises(Cut):  # the connection lost after the first chunk
            c.upload_save(TITLE, third, kind="account", progress=cut)
        assert c.last_upload is not None
        offset, length = c.upload_offset(c.last_upload)
        assert offset == 1 << 20 and length == third.stat().st_size
        done = c.upload_save(TITLE, third, resume=c.last_upload)
        assert done.sha256 == hashlib.sha256(third.read_bytes()).hexdigest()
        # Abandoned.
        fourth = tmp_path / "fourth.zip"
        fourth.write_bytes(archive(1_200_000))
        with pytest.raises(Cut):
            c.upload_save(TITLE, fourth, progress=cut)
        assert c.last_upload is not None
        c.abandon_upload(c.last_upload)
        with pytest.raises(lantern.NotFound):
            c.upload_offset(c.last_upload)


class Cut(Exception):
    """A connection lost half-way."""


def cut(done: int, total: int) -> None:
    raise Cut


@pytest.mark.skipif(not e2e.available(), reason="the crypto extra")
def test_encrypted_saves(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, app = demo
    key = e2e.SaveKey.generate()
    plain = archive(30000)
    (tmp_path / "save.zip").write_bytes(plain)
    with client(url) as c:
        assert c.handshake().features["encrypted_saves"] == 1
        one = c.save_encrypted(TITLE, plain, key, kind="account")
        assert one.encryption is not None and one.encryption.key_id == key.key_id
        two = c.upload_encrypted_save(TITLE, tmp_path / "save.zip", key, kind="account")
        assert two.size == e2e.encrypted_size(len(plain))
        for s in (one, two):
            assert c.download_encrypted_save(s, key, tmp_path / f"{s.save_id}.zip").read_bytes() == plain
        with pytest.raises(e2e.RefusedBackup):
            c.download_encrypted_save(one, e2e.SaveKey.generate(), tmp_path / "other.zip")
    assert app.saves is not None
    kept = app.saves.archive("mira", one.save_id)
    assert kept is not None and kept.data is not None and kept.data[:8] == e2e.MAGIC  # kept as sent, never opened


def test_cheats_written(demo: tuple[str, LanternApp]) -> None:
    url, _ = demo
    text = "[Moon jump]\n04000000 00ABC010 0000FFFF\n"
    with client(url) as c:
        made = c.create_cheat("switch", TITLE, text, build_id="0123456789ABCDEF", source="Mira", note="Jump")
        assert made.size == len(text) and c.cheat_text(made) == text
        with pytest.raises(lantern.Conflict):
            c.create_cheat("switch", TITLE, text, build_id="0123456789ABCDEF", source="Mira")
        new = text + "[Slow fall]\n04000000 00ABC020 00000001\n"
        c.replace_cheat(made.id, "switch", TITLE, new, build_id="0123456789ABCDEF", source="Mira")
        now = next(s for s in c.cheats(title_id=TITLE).cheats if s.id == made.id)
        assert c.cheat_text(now) == new
        with pytest.raises(lantern.BadRequest):
            c.create_cheat("switch", TITLE, "not a code\n", build_id="0123456789ABCDEF", source="Noor")
        c.delete_cheat(made.id)
        with pytest.raises(lantern.NotFound):
            c.delete_cheat(made.id)


def test_requests_and_sections(demo: tuple[str, LanternApp]) -> None:
    url, app = demo
    with client(url) as c:
        made = c.request_title(TITLE)
        assert made.status == "open" and c.request_title(TITLE).id == made.id
        assert [r.id for r in c.requests().requests] == [made.id]
        app.answer_request(made.id, "declined")
        assert c.requests().requests[0].status == "declined"
        c.withdraw_request(made.id)
        with pytest.raises(lantern.NotFound):
            c.withdraw_request(made.id)
        assert c.requests().requests == []
        sections = c.sections().sections
        assert [s.id for s in sections] == ["new", "co-op"]
        assert all(a.platform == "switch" for s in sections for a in c.iter_apps() if a.id in s.apps)
