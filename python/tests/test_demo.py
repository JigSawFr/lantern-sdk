"""The client against the demo server, through each framework adapter, over HTTP."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import lantern
from demo import DEMO_TOKEN, serve
from lantern import homebrew as hb
from lantern.client import LanternClient

pytestmark = pytest.mark.conformance


@pytest.mark.parametrize("framework", ["flask", "fastapi"])
def test_client_and_adapters(framework: str, tmp_path: Path) -> None:
    pytest.importorskip(framework)
    with serve(framework) as url, LanternClient(url, user_agent="DemoTest/1.0", token=DEMO_TOKEN) as c:
        assert c.handshake().account.name == "mira"
        apps = list(c.iter_apps(page_size=2))
        assert len(apps) == 8
        biggest = max(apps, key=lambda a: a.size)
        whole = c.download_app(biggest, tmp_path / f"{framework}.nsp").read_bytes()
        (tmp_path / f"{framework}-2.nsp.part").write_bytes(whole[:1000])
        assert c.download_app(biggest, tmp_path / f"{framework}-2.nsp").read_bytes() == whole
        assert hashlib.sha256(whole).hexdigest() == biggest.sha256
        star = c.homebrew_entry("org.example.starjar", platform="switch")
        assert hb.verify_signature(star) is True and hb.install_plan(star).free
        assert [e.id for e in c.iter_homebrew_updates([("org.example.starjar", 1)], platform="3ds")] == [
            "org.example.starjar"
        ]
        cheats = c.cheats(platform="switch").cheats
        assert c.cheat_text(cheats[0]).startswith("[")
        with pytest.raises(lantern.NotFound):
            c.title("0100AB1200099000")
        request = urllib.request.Request(
            url + "api/lantern/v1/apps/missing",
            data=b"{" * (2 << 20),
            method="POST",
            headers={"Content-Type": "application/json", "Lantern-Platform": "switch"},
        )
        with pytest.raises(urllib.error.HTTPError) as too_large:
            urllib.request.urlopen(request, timeout=10)
        with too_large.value as error:
            assert error.code == 413
            assert json.loads(error.read())["code"] == "too_large"
        head = urllib.request.Request(url + "api/lantern/v1/apps", method="HEAD")
        with urllib.request.urlopen(head, timeout=10) as r:
            assert r.status == 200 and int(r.headers["Content-Length"]) > 0 and r.read() == b""
