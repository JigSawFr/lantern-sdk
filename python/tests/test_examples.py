"""The files of examples/, run as a user would run them: the readers against the demo server, the servers
from their command line (answering the handshake), the static library written then read. The site and the
README show these files, so they cannot drift from the library."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from demo import free_port, serve

pytestmark = pytest.mark.examples

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def run(name: str, *args: str) -> str:
    done = subprocess.run(
        [sys.executable, str(EXAMPLES / name), *args], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    return done.stdout


@pytest.mark.parametrize("framework", ["flask", "fastapi"])
def test_read_library_against_the_demo(framework: str) -> None:
    pytest.importorskip(framework)
    with serve(framework) as url:
        out = run("read_library.py", url)
    assert out.startswith("Demo shelf: ")
    assert "Copper Moth" in out and "matched" in out


def test_static_library_is_written_then_read(tmp_path: Path) -> None:
    out = run("static_library.py", str(tmp_path / "shelf"))
    assert "Shelf on a stick ['Frost Garden']" in out
    assert json.loads((tmp_path / "shelf" / "lantern.json").read_text())["name"] == "Shelf on a stick"


@contextmanager
def running(name: str, tmp_path: Path) -> Iterator[str]:
    port = free_port()
    log = tmp_path / f"{name}.log"
    with log.open("wb") as sink:
        proc = subprocess.Popen([sys.executable, str(EXAMPLES / name), str(port)], stdout=sink, stderr=sink)
    url = f"http://127.0.0.1:{port}/"
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(url + ".well-known/lantern", timeout=5):
                    break
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                said = f"{name} on port {port}, last error {error!r}, its output:\n{log.read_text(errors='replace')}"
                assert proc.poll() is None and time.monotonic() < deadline, said
                time.sleep(0.2)
        yield url
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.parametrize("name", ["serve_flask.py", "serve_fastapi.py"])
def test_the_servers_answer_the_client(name: str, tmp_path: Path) -> None:
    pytest.importorskip(name.removeprefix("serve_").removesuffix(".py"))
    import lantern

    with running(name, tmp_path) as url, lantern.LanternClient(url, platform="switch") as client:
        assert client.handshake().name == "Living room shelf"
        assert [a.name for a in client.iter_apps()] == ["Frost Garden"]
