"""The client against a fake transport: what it sends, how it reads the
answers, and how it checks downloads."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

import lantern
from fakes import AsyncFakeTransport, FakeTransport, doc, hello
from lantern.client import AsyncLanternClient, LanternClient, Request
from lantern.digest import format_digest
from lantern.models import CheatSet

APP = {
    "id": "a_1",
    "platform": "switch",
    "title_id": "0100ABCD00010000",
    "app_id": "0100ABCD00010000",
    "type": "base",
    "version_code": 0,
    "name": "Frostline Tales",
    "size": 3,
    "format": "nsp",
    "sha256": "0" * 64,
    "file": "/api/lantern/v1/files/f_1",
}


def page(items: list[Any], nxt: str | None = None) -> dict[str, Any]:
    return {"schema": 1, "items": items, "total": len(items), "next": nxt}


def client(answer: Any, **options: Any) -> tuple[LanternClient, FakeTransport]:
    transport = FakeTransport(answer)
    options.setdefault("user_agent", "LanternTest/1.0")
    return LanternClient("http://127.0.0.1:8080/", transport=transport, **options), transport


def query(request: Request) -> dict[str, list[str]]:
    return parse_qs(urlsplit(request.url).query)


def test_the_handshake_gives_the_base_and_features() -> None:
    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=hello(**{"x-example": 1}))
        return doc(body=page([APP]))

    c, t = client(answer, platform="switch", accept_language="fr, en;q=0.5")
    assert [a.id for a in c.iter_apps()] == ["a_1"]
    assert t.requests[0].url == "http://127.0.0.1:8080/.well-known/lantern"
    assert t.requests[1].url == "http://127.0.0.1:8080/api/lantern/v1/apps"
    headers = t.requests[1].headers
    assert headers["User-Agent"] == "LanternTest/1.0"
    assert headers["Lantern-Platform"] == "switch"
    assert headers["Accept-Language"] == "fr, en;q=0.5"
    assert "library=1" in headers["Accept-Schema"]
    assert "Authorization" not in headers
    assert c.hello is not None and c.hello.extra == {"x-example": 1}
    assert c.offers("library") and not c.offers("cheats")
    assert not c.offers("homebrew")  # a newer schema than this library reads


def test_bearer_token_only_to_the_server() -> None:
    c, t = client(lambda r: doc(body=hello()) if "well-known" in r.url else (200, {}, b"abc"), token="et_secret")
    c.handshake()
    assert t.requests[0].headers["Authorization"] == "Bearer et_secret"
    with pytest.raises(lantern.IntegrityError):
        c.fetch("https://cdn.example.org/x", sha256="0" * 64, size=3)
    assert "Authorization" not in t.requests[1].headers
    c.set_token(None)
    c.handshake()
    assert "Authorization" not in t.requests[2].headers
    with pytest.raises(ValueError, match="token"):
        lantern.BearerToken("has space")
    with pytest.raises(ValueError, match="not both"):
        LanternClient("http://127.0.0.1/", token="a", credentials=lantern.BearerToken("b"))


def test_a_signer_runs_after_the_credentials_on_the_origin_only() -> None:
    seen: list[str] = []

    class Signer:
        def sign(self, request: Request) -> None:
            seen.append(request.headers.get("Authorization", "none"))
            request.headers["Signature"] = "sig1=:AA==:"

    c, t = client(lambda r: doc(body=hello()), token="et_a", signer=Signer())
    c.handshake()
    assert seen == ["Bearer et_a"] and t.requests[0].headers["Signature"] == "sig1=:AA==:"
    with pytest.raises(lantern.LanternError):
        c.fetch("https://other.example.org/f", sha256="0" * 64, size=1)
    assert "Signature" not in t.requests[1].headers and len(seen) == 1


def test_plain_http_only_to_loopback() -> None:
    with pytest.raises(lantern.InsecureTransport):
        LanternClient("http://192.0.2.10/")
    c, _ = client(lambda r: doc(body=hello()))
    with pytest.raises(lantern.InsecureTransport):
        c.fetch("http://192.0.2.10/file", sha256="0" * 64, size=1)
    assert LanternClient("shelf.example.org").core.root == "https://shelf.example.org"
    assert LanternClient("http://[::1]:8080/").core.root == "http://[::1]:8080"


def test_arguments_are_checked() -> None:
    with pytest.raises(ValueError, match="platform"):
        LanternClient("http://127.0.0.1/", platform="Switch!")
    with pytest.raises(ValueError, match="User-Agent"):
        LanternClient("http://127.0.0.1/", user_agent="no version")
    c, _ = client(lambda r: doc(body=hello()), base="/api/lantern")
    with pytest.raises(ValueError, match="needs a platform"):
        c.missing([("0100ABCD00010000", 0)])
    with pytest.raises(ValueError, match="want"):
        c.missing([], ["everything"], platform="switch")
    with pytest.raises(ValueError, match="sort"):
        c.apps(sort="random")
    with pytest.raises(ValueError, match="page_size"):
        c.apps(page_size=0)
    with pytest.raises(ValueError, match="title id"):
        c.title("changes")
    with pytest.raises(ValueError, match="homebrew id"):
        c.homebrew_entry("Not An Id")
    with pytest.raises(ValueError, match="need a platform"):
        c.homebrew_updates([])
    with pytest.raises(ValueError, match="title id"):
        c.titles(["ok", "not ok"])


def test_errors_and_schemas() -> None:
    answers = {
        "/v1/titles/0100ABCD00010000": doc(404, {"schema": 1, "status": 404, "code": "not_found"}),
        "/v1/apps": doc(410, {"schema": 1, "status": 410, "code": "gone"}),
        "/v1/sections": doc(body={"schema": 2, "sections": "a later shape"}),
        "/v1/changes": (302, {"Location": "https://elsewhere.example.org/"}, b""),
        "/v1/cheats": (200, {"Content-Type": "text/html"}, b"<html>"),
        "/v1/homebrew": doc(body={"schema": 1, "items": "not a list", "next": None}),
    }
    c, _ = client(lambda r: answers[urlsplit(r.url).path.removeprefix("/api/lantern")], base="/api/lantern")
    with pytest.raises(lantern.NotFound):
        c.title("0100ABCD00010000")
    with pytest.raises(lantern.Gone):
        c.apps(cursor="c_old")
    with pytest.raises(lantern.NewerSchema) as newer:
        c.sections()
    assert newer.value.schema == 2
    with pytest.raises(lantern.UnexpectedResponse, match="redirect"):
        c.changes()
    with pytest.raises(lantern.UnexpectedResponse, match="Content-Type"):
        c.cheats()
    with pytest.raises(lantern.DocumentError):
        c.homebrew()


def test_a_handshake_without_version_1_or_with_another_origin() -> None:
    c, _ = client(lambda r: doc(body=hello(versions=[2])))
    with pytest.raises(lantern.LanternError, match="version 1"):
        c.handshake()
    c, _ = client(lambda r: doc(body=hello(base="https://elsewhere.example.org/api")))
    with pytest.raises(lantern.DocumentError, match="base"):
        c.handshake()


def test_pages_follow_cursors_and_refuse_a_loop() -> None:
    pages = {None: page([APP], "c_2"), "c_2": page([{**APP, "id": "a_2"}], "c_3"), "c_3": page([], "c_2")}

    def answer(r: Request) -> Any:
        return doc(body=pages[query(r).get("cursor", [None])[0]])

    c, t = client(answer, base="/api/lantern")
    with pytest.raises(lantern.UnexpectedResponse, match="same cursor"):
        list(c.iter_apps(type="base", page_size=1))
    assert query(t.requests[1]) == {"type": ["base"], "page_size": ["1"], "cursor": ["c_2"]}


def test_missing_and_updates_send_their_documents() -> None:
    c, t = client(lambda r: doc(body=page([])), base="/api/lantern", platform="switch")
    assert list(c.iter_missing([("0100ABCD00010000", 0)], ["update"])) == []
    sent = json.loads(t.requests[0].body or b"")
    assert sent == {"schema": 1, "installed": [{"app_id": "0100ABCD00010000", "version_code": 0}], "want": ["update"]}
    assert t.requests[0].headers["Content-Type"] == "application/json"
    homebrew = {"schema": 1, "items": [], "next": None}
    c, t = client(lambda r: doc(body=homebrew), base="/api/lantern")
    assert list(c.iter_homebrew_updates([("org.example.frostline", 3)], platform="switch")) == []
    assert json.loads(t.requests[0].body or b"") == {
        "schema": 1,
        "installed": [{"id": "org.example.frostline", "build": 3}],
    }
    assert query(t.requests[0]) == {"platform": ["switch"]}


def test_titles_are_asked_for_by_hundreds() -> None:
    def answer(r: Request) -> Any:
        ids = query(r)["ids"][0].split(",")
        return doc(body={"schema": 1, "titles": [], "unknown": ids})

    c, t = client(answer, base="/api/lantern")
    ids = [f"05{i:014X}" for i in range(250)] + ["0500000000000000"]
    titles = c.titles(ids)
    assert len(t.requests) == 3 and len(titles.unknown) == 250
    assert c.titles([]).titles == []


def test_title_changes_until_more_is_false() -> None:
    steps = {None: ("t_1", True), "t_1": ("t_2", True), "t_2": ("t_3", False)}

    def answer(r: Request) -> Any:
        nxt, more = steps[query(r).get("since", [None])[0]]
        return doc(body={"schema": 1, "titles": [], "removed": [], "since": nxt, "more": more})

    c, _ = client(answer, base="/api/lantern")
    assert [x.since for x in c.iter_title_changes()] == ["t_1", "t_2", "t_3"]


def test_cheat_text_is_verified() -> None:
    text = b"[Endless lamp oil]\n04000000 0123A4B0 00000063\n"
    cheat = CheatSet(
        id="cs_1",
        platform="switch",
        title_id="0100ABCD00010000",
        build_id="AB",
        size=len(text),
        sha256=hashlib.sha256(text).hexdigest(),
    )
    served = format_digest(cheat.sha256)
    c, t = client(lambda r: (200, {"Repr-Digest": served}, text), base="/api/lantern")
    assert c.cheat_text(cheat) == text.decode()
    assert t.requests[0].url == "http://127.0.0.1:8080/api/lantern/v1/cheats/cs_1"
    cheat.sha256 = "0" * 64
    with pytest.raises(lantern.IntegrityError, match="Repr-Digest"):
        c.cheat_text(cheat)
    cheat.size = 2 << 20
    with pytest.raises(lantern.DocumentError, match="above"):
        c.cheat_text(cheat)


class FileServer:
    """Answers a file with ranges, as SPEC.md § 6.6 wants, or misbehaves on demand."""

    def __init__(self, data: bytes) -> None:
        self.data, self.ignore_range, self.lie = data, False, False
        self.cut_after: int | None = None
        self.digest = format_digest(hashlib.sha256(data).hexdigest())

    def __call__(self, r: Request) -> Any:
        rng = r.headers.get("Range")
        data = self.data if not self.lie else b"x" * len(self.data)
        headers = {"Repr-Digest": self.digest, "Accept-Ranges": "bytes", "ETag": '"e"'}
        if rng and not self.ignore_range:
            start = int(rng.removeprefix("bytes=").rstrip("-"))
            if start >= len(data):
                return 416, {"Content-Range": f"bytes */{len(data)}"}, b""
            headers["Content-Range"] = f"bytes {start}-{len(data) - 1}/{len(data)}"
            return 206, headers, data[start:]
        body = data if self.cut_after is None else data[: self.cut_after]
        return 200, {**headers, "Content-Length": str(len(data))}, body


def test_download_resumes_and_verifies(tmp_path: Path) -> None:
    data = bytes(range(256)) * 40
    sha = hashlib.sha256(data).hexdigest()
    server = FileServer(data)
    c, t = client(server, base="/api/lantern")
    dest = tmp_path / "frostline.nsp"
    part = tmp_path / "frostline.nsp.part"
    # A connection cut: the part is kept.
    server.cut_after = 1000
    with pytest.raises(lantern.IntegrityError):
        c.download("/api/lantern/v1/files/f_1", dest, sha256=sha, size=len(data))
    assert not part.exists()  # what arrived was short: the part is not trusted
    part.write_bytes(data[:1000])
    server.cut_after = None
    progress: list[int] = []
    c.download("/api/lantern/v1/files/f_1", dest, sha256=sha, size=len(data), progress=lambda d, n: progress.append(d))
    assert dest.read_bytes() == data and not part.exists()
    assert t.requests[-1].headers["Range"] == "bytes=1000-" and progress[-1] == len(data)
    # A server that ignores the range: written from the start.
    part.write_bytes(data[:500])
    server.ignore_range = True
    c.download("/api/lantern/v1/files/f_1", dest, sha256=sha, size=len(data))
    assert dest.read_bytes() == data
    # A part already whole.
    part.write_bytes(data)
    n = len(t.requests)
    c.download("/api/lantern/v1/files/f_1", dest, sha256=sha, size=len(data))
    assert len(t.requests) == n
    # A part longer than the file, or a 416: started again.
    server.ignore_range = False
    part.write_bytes(data + b"extra")
    c.download("/api/lantern/v1/files/f_1", dest, sha256=sha, size=len(data))
    assert dest.read_bytes() == data


def test_download_refuses_what_is_not_the_file(tmp_path: Path) -> None:
    data = b"frost" * 100
    sha = hashlib.sha256(data).hexdigest()
    server = FileServer(data)
    c, _ = client(server, base="/api/lantern")
    server.lie = True
    server.digest = format_digest(hashlib.sha256(b"x" * len(data)).hexdigest())
    with pytest.raises(lantern.IntegrityError, match="Repr-Digest"):
        c.download("/f", tmp_path / "a", sha256=sha, size=len(data))
    server.digest = format_digest(sha)
    with pytest.raises(lantern.IntegrityError, match="SHA-256"):
        c.download("/f", tmp_path / "a", sha256=sha, size=len(data))
    assert not (tmp_path / "a").exists() and not (tmp_path / "a.part").exists()
    with pytest.raises(lantern.IntegrityError, match="bytes"):
        c.download("/f", tmp_path / "b", sha256=sha, size=len(data) - 1)
    with pytest.raises(ValueError, match="SHA-256"):
        c.download("/f", tmp_path / "c", sha256="ABC", size=1)
    c, _ = client(lambda r: doc(404, {"schema": 1, "status": 404, "code": "not_found"}), base="/api/lantern")
    with pytest.raises(lantern.NotFound):
        c.download("/f", tmp_path / "d", sha256=sha, size=len(data))


def test_more_bytes_than_the_size_deletes_the_part(tmp_path: Path) -> None:
    data = b"lamp" * 50
    sha = hashlib.sha256(data).hexdigest()
    c, _ = client(lambda r: (200, {}, data + b"extra"), base="/api/lantern")
    with pytest.raises(lantern.IntegrityError, match="more bytes"):
        c.download("/f", tmp_path / "f", sha256=sha, size=len(data))
    assert not (tmp_path / "f.part").exists()

    async def run() -> None:
        transport = AsyncFakeTransport(lambda r: (200, {}, data + b"extra"))
        async with AsyncLanternClient("http://127.0.0.1:1/", transport=transport, base="/api/lantern") as ac:
            with pytest.raises(lantern.IntegrityError, match="more bytes"):
                await ac.download("/f", tmp_path / "g", sha256=sha, size=len(data))
            with pytest.raises(lantern.IntegrityError, match="more bytes"):
                await ac.fetch("/f", sha256=sha, size=len(data))
        assert not (tmp_path / "g.part").exists()

    asyncio.run(run())


def test_a_bad_content_range_is_refused(tmp_path: Path) -> None:
    data = b"moss" * 50
    sha = hashlib.sha256(data).hexdigest()
    (tmp_path / "f.part").write_bytes(data[:10])
    c, _ = client(lambda r: (206, {"Content-Range": f"bytes 0-{len(data) - 1}/{len(data)}"}, data), base="/api/lantern")
    with pytest.raises(lantern.UnexpectedResponse, match="Content-Range"):
        c.download("/f", tmp_path / "f", sha256=sha, size=len(data))


def test_async_client(tmp_path: Path) -> None:
    data = b"ember" * 300
    sha = hashlib.sha256(data).hexdigest()
    files = FileServer(data)

    def answer(r: Request) -> Any:
        path = urlsplit(r.url).path
        if path.endswith("well-known/lantern"):
            return doc(body=hello())
        if path.endswith("/apps"):
            cursor = query(r).get("cursor", [None])[0]
            return doc(body=page([APP], "c_2") if cursor is None else page([{**APP, "id": "a_2"}]))
        if path.endswith("/titles"):
            return doc(body={"schema": 1, "titles": [], "unknown": ["0100ABCD00010000"]})
        if path.endswith("/f"):
            return files(r)
        return doc(404, {"schema": 1, "status": 404, "code": "not_found"})

    async def run() -> None:
        transport = AsyncFakeTransport(answer)
        async with AsyncLanternClient("http://127.0.0.1:1/", transport=transport, platform="switch") as c:
            assert (await c.offers("library")) is True
            assert [a.id async for a in c.iter_apps()] == ["a_1", "a_2"]
            assert (await c.titles(["0100ABCD00010000"])).unknown == ["0100ABCD00010000"]
            with pytest.raises(lantern.NotFound):
                await c.title("0100ABCD00010000")
            (tmp_path / "e.part").write_bytes(data[:100])
            await c.download("/f", tmp_path / "e", sha256=sha, size=len(data))
            assert (tmp_path / "e").read_bytes() == data
            files.lie = True
            with pytest.raises(lantern.IntegrityError):
                await c.download("/f", tmp_path / "g", sha256=sha, size=len(data))
            assert c.hello is not None
        assert transport.closed

    asyncio.run(run())


def test_the_package_exports() -> None:
    assert lantern.NotFound is lantern.errors.NotFound
    assert lantern.__version__ and lantern.SPEC_DRAFT == "0.5"
