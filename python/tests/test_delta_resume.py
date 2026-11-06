"""A differential download resumes from what an interrupted call left (SPEC.md § 22.3): `<dest>.part` holds a
verified prefix of the file, the next call takes it as one more seed, so the chunks already there are not read
again; a stale or foreign part shares nothing and is harmless. The client of the sync and of the async kind."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from lantern._generated.models import App
from lantern.client import AsyncLanternClient, LanternClient
from lantern.server import LanternApp
from test_client_v07 import NEW, OLD, AsyncSpy, Spy, aclient, client, demo, versions

__all__ = ["demo"]
pytestmark = pytest.mark.conformance

#: Past the changes of the newer version (at 150,000 and 260,000): the part holds what had to be read.
CUT = 300_000


def stop_after(done: int) -> Callable[[int, int], None]:
    def progress(now: int, total: int) -> None:
        if now >= done:
            raise KeyboardInterrupt

    return progress


def leftovers(dest: Path) -> list[str]:
    return sorted(p.name for p in dest.parent.iterdir() if p.name.startswith(dest.name + "."))


def interrupted(c: LanternClient, new: App, dest: Path) -> None:
    with pytest.raises(KeyboardInterrupt):
        c.download_delta(new, dest, seeds=[OLD], progress=stop_after(CUT))
    part = dest.with_name(dest.name + ".part")
    assert part.stat().st_size >= CUT and NEW.startswith(part.read_bytes())


def test_a_second_call_resumes_from_the_part(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    with client(url, Spy()) as c:
        _, new = versions(c)
        assert c.download_delta(new, tmp_path / "fresh", seeds=[OLD]).read_bytes() == NEW
        assert c.last_delta is not None
        fresh = c.last_delta.read
        assert fresh > 0 and c.last_delta.resumed == 0

        dest = tmp_path / "update.nsz"
        interrupted(c, new, dest)
        assert c.download_delta(new, dest, seeds=[OLD]).read_bytes() == NEW
        report = c.last_delta
        assert report is not None and report.used and report.resumed > 0 and report.read < fresh
        assert leftovers(dest) == []


def test_without_seeds_of_the_caller_the_part_is_the_seed(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    with client(url, Spy()) as c:
        _, new = versions(c)
        dest = tmp_path / "update.nsz"
        interrupted(c, new, dest)
        assert c.download_delta(new, dest, seeds=[]).read_bytes() == NEW
        report = c.last_delta
        assert report is not None and report.used and report.resumed >= CUT and report.read <= new.size - CUT
        assert leftovers(dest) == []
        assert hashlib.sha256(dest.read_bytes()).hexdigest() == new.sha256


def test_a_garbage_part_is_ignored(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    with client(url, Spy()) as c:
        _, new = versions(c)
        dest = tmp_path / "update.nsz"
        dest.with_name("update.nsz.part").write_bytes(b"\x07garbage" * 40_000)
        assert c.download_delta(new, dest, seeds=[OLD]).read_bytes() == NEW
        first = c.last_delta
        assert first is not None and first.used and first.resumed == 0
        assert leftovers(dest) == []
        # Alone, it shares nothing: the whole file is read.
        dest.unlink()
        dest.with_name("update.nsz.part").write_bytes(b"\x07garbage" * 40_000)
        assert c.download_delta(new, dest, seeds=[]).read_bytes() == NEW
        assert c.last_delta is not None and not c.last_delta.used and c.last_delta.reason
        assert leftovers(dest) == []


def test_no_seed_when_there_is_truly_none(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    with client(url, Spy()) as c:
        _, new = versions(c)
        dest = tmp_path / "update.nsz"
        dest.with_name("update.nsz.part").write_bytes(b"")
        assert c.download_delta(new, dest, seeds=[]).read_bytes() == NEW
        assert c.last_delta is not None and c.last_delta.reason == "no seed"


def test_the_larger_of_a_part_and_a_seed_is_kept(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    with client(url, Spy()) as c:
        _, new = versions(c)
        dest = tmp_path / "update.nsz"
        dest.with_name("update.nsz.part").write_bytes(NEW[:50_000])
        dest.with_name("update.nsz.seed").write_bytes(NEW[:CUT])
        assert c.download_delta(new, dest, seeds=[]).read_bytes() == NEW
        assert c.last_delta is not None and c.last_delta.resumed > 50_000
        assert leftovers(dest) == []


def test_async_a_second_call_resumes_from_the_part(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        url, _ = demo
        async with aclient(url, AsyncSpy()) as c:
            found = {a.sha256: a async for a in c.iter_apps() if a.chunks is not None}
            new = found[hashlib.sha256(NEW).hexdigest()]
            await c.download_delta(new, tmp_path / "fresh", seeds=[OLD])
            assert c.last_delta is not None
            fresh = c.last_delta.read
            dest = tmp_path / "update.nsz"
            with pytest.raises(KeyboardInterrupt):
                await c.download_delta(new, dest, seeds=[OLD], progress=stop_after(CUT))
            assert NEW.startswith(dest.with_name("update.nsz.part").read_bytes())
            await _finish(c, new, dest, fresh)

            # No seed of the caller's.
            dest2 = tmp_path / "second.nsz"
            with pytest.raises(KeyboardInterrupt):
                await c.download_delta(new, dest2, seeds=[OLD], progress=stop_after(CUT))
            assert (await c.download_delta(new, dest2, seeds=[])).read_bytes() == NEW
            assert c.last_delta is not None and c.last_delta.used and c.last_delta.resumed >= CUT
            assert leftovers(dest2) == []

            # A garbage part is ignored.
            dest3 = tmp_path / "third.nsz"
            dest3.with_name("third.nsz.part").write_bytes(b"\x07garbage" * 40_000)
            assert (await c.download_delta(new, dest3, seeds=[OLD])).read_bytes() == NEW
            assert c.last_delta is not None and c.last_delta.used and c.last_delta.resumed == 0
            assert leftovers(dest3) == []

    asyncio.run(run())


async def _finish(c: AsyncLanternClient, new: App, dest: Path, fresh: int) -> None:
    assert (await c.download_delta(new, dest, seeds=[OLD])).read_bytes() == NEW
    report = c.last_delta
    assert report is not None and report.used and report.resumed > 0 and report.read < fresh
    assert leftovers(dest) == []
