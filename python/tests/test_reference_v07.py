"""The client's draft 0.7 against the specification's reference server (spec/server): its chunk indexes are
the bytes this library cuts (lantern-cdc-1, canonical JSON), a newer version of its fictional update is put
together from the older one, and the same through its static export (--export)."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import SPEC
from lantern import chunks
from lantern.client import LanternClient
from lantern.static import StaticLibrary

pytestmark = pytest.mark.integration

sys.path.insert(0, str(SPEC))
sys.path.insert(0, str(SPEC / "tests"))
import library as fiction  # noqa: E402  (spec/tests/library.py)
from server import lantern_server as ls  # noqa: E402
from server import static as reference_static  # noqa: E402

ls.log = lambda msg: None
AGENT = "LanternPythonTest/1.0"
ORIGIN = "https://app.example.org"


class Reference:
    def __init__(self, root: Path) -> None:
        self.root = fiction.make(root / "library")
        users = root / "users.json"
        users.write_text(
            json.dumps({"schema": 1, "public": True, "users": []}),
            encoding="utf-8",
        )
        self.lib = ls.Library(self.root, root / "state.json")
        self.server = ls.LanternServer(
            ("127.0.0.1", 0), self.lib, ls.Accounts(users), rescan=0, quiet=True, cors_origins=[ORIGIN]
        )
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


@pytest.fixture(scope="module")
def ref(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Reference]:
    r = Reference(tmp_path_factory.mktemp("reference-v07"))
    yield r
    r.close()


def test_the_reference_servers_indexes_are_the_bytes_this_library_cuts(ref: Reference) -> None:
    """[L-22.1-1] A file has the same index wherever it is cut: the reference server's, and this library's."""
    old, new = fiction.delta_pair()
    with LanternClient(ref.url, user_agent=AGENT, platform="switch") as c:
        found = {a.sha256: a for a in c.iter_apps() if a.chunks is not None}
        assert {hashlib.sha256(old).hexdigest(), hashlib.sha256(new).hexdigest()} <= set(found)
        for data in (old, new):
            app = found[hashlib.sha256(data).hexdigest()]
            assert app.chunks is not None
            index = c.chunk_index(app)
            raw = c.fetch(app.chunks.url, sha256=app.chunks.sha256, size=app.chunks.size)
            assert raw == chunks.build_index(data)[1]
            assert c.chunk_index_of(app.sha256, app.size) == index


def test_a_newer_version_from_the_older_one(ref: Reference, tmp_path: Path) -> None:
    old, new = fiction.delta_pair()
    with LanternClient(ref.url, user_agent=AGENT, platform="switch") as c:
        found = {a.sha256: a for a in c.iter_apps() if a.chunks is not None}
        app = found[hashlib.sha256(new).hexdigest()]
        out = c.download_delta(app, tmp_path / "update.nsz", seeds=[old])
        assert out.read_bytes() == new and c.last_delta is not None and c.last_delta.used
        assert c.last_delta.read < app.size // 2


def test_the_reference_exports_a_static_library_with_indexes(ref: Reference, tmp_path: Path) -> None:
    out = tmp_path / "static"
    reference_static.export(ls, ref.lib, out)
    _, new = fiction.delta_pair()
    with StaticLibrary(out) as lib:
        assert lib.handshake().features["deltas"] == 1
        found = {a.sha256: a for a in lib.iter_apps("switch") if a.chunks is not None}
        app = found[hashlib.sha256(new).hexdigest()]
        assert app.chunks is not None and app.chunks.url.startswith("v1/chunks/sha256/")
        index = lib.chunk_index(app)
        assert sum(n for n, _ in index.chunks) == len(new)
        assert (out / app.chunks.url).read_bytes() == chunks.build_index(new)[1]
