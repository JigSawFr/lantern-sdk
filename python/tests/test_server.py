"""The server toolkit's routes, called directly (no framework)."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from conftest import EXAMPLES, load
from demo import DEMO_TOKEN, build_library, make_lantern
from lantern import schema
from lantern._base import DocumentError
from lantern.http import Headers
from lantern.models import App, Homebrew, Signature, Title
from lantern.server import (
    Account,
    FileRef,
    LanternApp,
    MemoryLibrary,
    ServerRequest,
    ServerResponse,
    check_homebrew,
    make_package,
    missing,
    parse_range,
)
from lantern.server.paging import Cursors, Sealer, page_size

BASE = "/api/lantern/v1"


@pytest.fixture(scope="module")
def app() -> LanternApp:
    return make_lantern()


def call(
    app: LanternApp, method: str, path: str, *, query: dict[str, str] | None = None, body: Any = None, **headers: str
) -> ServerResponse:
    raw = b""
    if body is not None:
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    hdrs = Headers({k.replace("_", "-"): v for k, v in headers.items()})
    return app.handle(ServerRequest(method, path, query or {}, hdrs, raw))


def body(r: ServerResponse) -> Any:
    assert isinstance(r.body, bytes)
    return json.loads(r.body)


def problem(r: ServerResponse, status: int, code: str) -> dict[str, Any]:
    assert r.status == status, (r.status, r.body)
    assert r.headers["Content-Type"] == "application/problem+json"
    doc: dict[str, Any] = body(r)
    assert doc["code"] == code and doc["status"] == status
    assert schema.validate("problem", doc) == []
    return doc


def test_handshake(app: LanternApp) -> None:
    for path in ("/.well-known/lantern", BASE, BASE + "/"):
        r = call(app, "GET", path)
        assert r.status == 200 and schema.validate("handshake", body(r)) == []
    hello = body(call(app, "GET", "/.well-known/lantern"))
    assert hello["account"] == {"state": "anonymous", "scopes": ["cheats", "library"]}
    assert hello["features"] == {
        "library": 1,
        "titles": 1,
        "changes": 1,
        "sections": 0,
        "homebrew": 1,
        "saves": 0,
        "cheats": 1,
        "requests": 0,
        "pairing": 0,
        "signatures": 0,
        "admin": 0,
        "events": 1,
        "peers": 1,
        "sync": 0,
        "encrypted_saves": 0,
    }
    assert hello["platforms"] == ["3ds", "android", "linux", "switch"]
    mine = body(call(app, "GET", "/.well-known/lantern", Authorization=f"Bearer {DEMO_TOKEN}"))
    assert mine["account"]["state"] == "active" and mine["account"]["name"] == "mira"
    problem(call(app, "POST", "/.well-known/lantern"), 405, "bad_request")


def test_credentials(app: LanternApp) -> None:
    r = call(app, "GET", BASE + "/apps", Authorization="Basic bGVhOmZyb3N0")
    problem(r, 401, "unauthorized")
    assert r.headers["WWW-Authenticate"] == 'Bearer realm="lantern"'
    r = call(app, "GET", BASE + "/", Authorization="Bearer et_unknown")
    problem(r, 401, "unauthorized")
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]
    ok = call(app, "GET", BASE + "/apps", Authorization=f"Bearer {DEMO_TOKEN}")
    assert ok.status == 200 and ok.headers["Cache-Control"] == "private"
    assert "Authorization" in ok.headers["Vary"] and "Lantern-Platform" in ok.headers["Vary"]


def test_private_and_frozen_accounts() -> None:
    frozen = Account(scopes=frozenset({"library"}), state="frozen")
    reader = Account(scopes=frozenset({"cheats"}))
    tokens = {"Bearer et_frozen": frozen, "Bearer et_reader": reader}
    app = LanternApp(
        MemoryLibrary(),
        uid="3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f",
        name="Private shelf",
        public=False,
        authenticate=lambda r: tokens.get(r.header("Authorization") or ""),
    )
    hello = body(call(app, "GET", BASE))
    assert hello["account"]["state"] == "anonymous" and not any(hello["features"].values())
    problem(call(app, "GET", BASE + "/apps"), 401, "unauthorized")
    problem(call(app, "GET", BASE + "/apps", Authorization="Bearer et_frozen"), 403, "account_frozen")
    problem(call(app, "GET", BASE + "/apps", Authorization="Bearer et_reader"), 403, "forbidden")
    assert body(call(app, "GET", BASE, Authorization="Bearer et_reader"))["features"]["cheats"] == 1


def test_apps_pages_and_filters(app: LanternApp) -> None:
    every = body(call(app, "GET", BASE + "/apps", query={"page_size": "1000"}))
    assert len(every["items"]) == every["total"] == 8 and every["next"] is None
    for sort in ("name", "added", "release"):
        seen: list[str] = []
        cursor: str | None = None
        while True:
            q = {"page_size": "3", "sort": sort} | ({"cursor": cursor} if cursor else {})
            doc = body(call(app, "GET", BASE + "/apps", query=q))
            assert schema.validate("apps", doc) == []
            seen += [a["id"] for a in doc["items"]]
            cursor = doc["next"]
            if cursor is None:
                break
        assert sorted(seen) == sorted(a["id"] for a in every["items"]) and len(set(seen)) == len(seen)
    added = body(call(app, "GET", BASE + "/apps", query={"sort": "added"}))["items"]
    assert [a["added"] for a in added] == sorted((a["added"] for a in added), reverse=True)
    switch = body(call(app, "GET", BASE + "/apps", Lantern_Platform="switch"))["items"]
    assert {a["platform"] for a in switch} == {"switch"} and len(switch) == 7
    android = body(call(app, "GET", BASE + "/apps", query={"platform": "android"}, Lantern_Platform="switch"))
    assert [a["platform"] for a in android["items"]] == ["android"]
    assert body(call(app, "GET", BASE + "/apps", Lantern_Platform="x-nothing"))["items"] == []
    assert {a["type"] for a in body(call(app, "GET", BASE + "/apps", query={"type": "dlc"}))["items"]} == {"dlc"}
    assert len(body(call(app, "GET", BASE + "/apps", query={"q": "COPPER"}))["items"]) == 2
    small = body(call(app, "GET", BASE + "/apps", query={"page_size": "5000"}))
    assert len(small["items"]) == 8
    for q in (
        {"type": "Base"},
        {"sort": "random"},
        {"title_id": "not an id"},
        {"page_size": "0"},
        {"page_size": "x"},
        {"cursor": "c_forged.AAAA"},
        {"platform": "Not a platform!"},
    ):
        problem(call(app, "GET", BASE + "/apps", query=q), 400, "bad_request")


def test_a_cursor_of_another_listing_or_expired() -> None:
    now = [1000.0]
    cursors = Cursors(Sealer(b"k" * 32), lifetime=60, clock=lambda: now[0])
    page = cursors.page(list(range(10)), lambda i: (i,), size=3, cursor=None, scope="a")
    assert page.items == [0, 1, 2] and page.next is not None
    assert cursors.page(list(range(10)), lambda i: (i,), size=3, cursor=page.next, scope="a").items == [3, 4, 5]
    with pytest.raises(Exception, match="another listing"):
        cursors.page([], lambda i: (i,), size=3, cursor=page.next, scope="b")
    now[0] += 61
    with pytest.raises(Exception, match="expired"):
        cursors.page([], lambda i: (i,), size=3, cursor=page.next, scope="a")
    other = Cursors(Sealer(b"o" * 32))
    with pytest.raises(Exception, match="never gave"):
        other.page([], lambda i: (i,), size=3, cursor=page.next, scope="a")
    assert page_size(None, 100, 50) == 50 and page_size("7", 100, 50) == 7


def test_missing(app: LanternApp) -> None:
    def ask(installed: list[Any], want: list[str], platform: str | None = "switch") -> ServerResponse:
        doc = {"schema": 1, "installed": installed, "want": want}
        if platform is None:
            return call(app, "POST", BASE + "/apps/missing", body=doc)
        return call(app, "POST", BASE + "/apps/missing", body=doc, Lantern_Platform=platform)

    r = ask([{"app_id": "0100AB1200010000", "version_code": 0}], ["update", "dlc"])
    names = sorted((a["app_id"], a["version_code"]) for a in body(r)["items"])
    assert names == [("0100AB1200010800", 131072), ("0100AB1200011001", 0)]
    current = ask(
        [{"app_id": "0100AB1200010000", "version_code": 0}, {"app_id": "0100AB1200010800", "version_code": 131072}],
        ["update"],
    )
    assert body(current)["items"] == []
    unknown_update = ask([{"app_id": "0100AB1200010800", "version_code": 65536}], ["update"])
    assert [a["version_code"] for a in body(unknown_update)["items"]] == [131072]
    bases = ask([], ["base"])
    assert {a["title_id"] for a in body(bases)["items"]} == {"0100AB1200010000", "0100CD3400020000", "0100EF5600030000"}
    problem(ask([], ["base"], platform=None), 400, "bad_request")
    problem(ask([{"app_id": 5}], ["update"]), 400, "bad_request")
    problem(ask([], ["everything"]), 400, "bad_request")
    problem(
        call(app, "POST", BASE + "/apps/missing", body=b'{"schema": 1, "installed": [', Lantern_Platform="switch"),
        400,
        "bad_request",
    )
    problem(
        call(app, "POST", BASE + "/apps/missing", body={"schema": 2}, Lantern_Platform="switch"),
        422,
        "unsupported_schema",
    )
    problem(call(app, "POST", BASE + "/apps/missing", body=b"{}", Content_Type="text/plain"), 400, "bad_request")
    problem(call(app, "POST", BASE + "/apps/missing", body=b"x" * (2 << 20)), 413, "too_large")
    problem(call(app, "GET", BASE + "/apps/missing"), 405, "bad_request")


def test_missing_on_android_where_a_newer_base_replaces() -> None:
    def app_(version: int) -> App:
        return App(
            id=f"a_{version}",
            platform="android",
            title_id="org.example.a",
            app_id="org.example.a",
            type="base",
            version_code=version,
            size=1,
            format="apk",
            sha256="0" * 64,
            file="/f",
        )

    apps = [app_(10), app_(12)]
    assert [a.id for a in missing(apps, "android", [("org.example.a", 10)], {"update"})] == ["a_12"]
    assert missing(apps, "android", [("org.example.a", 12)], {"update"}) == []


def test_files_and_ranges(app: LanternApp) -> None:
    apps = body(call(app, "GET", BASE + "/apps", query={"page_size": "100"}))["items"]
    a = next(x for x in apps if x["size"] > 100)
    whole = call(app, "GET", a["file"])
    data = b"".join(whole.iter_body())
    assert whole.status == 200 and hashlib.sha256(data).hexdigest() == a["sha256"]
    assert whole.headers["Accept-Ranges"] == "bytes" and whole.headers["ETag"].startswith('"')
    assert whole.headers["Repr-Digest"].startswith("sha-256=:")
    part = call(app, "GET", a["file"], Range="bytes=10-19")
    assert part.status == 206 and b"".join(part.iter_body()) == data[10:20]
    assert part.headers["Content-Range"] == f"bytes 10-19/{a['size']}" and part.headers["Content-Length"] == "10"
    assert part.headers["Repr-Digest"] == whole.headers["Repr-Digest"]
    head = call(app, "HEAD", a["file"])
    assert head.status == 200 and head.body == b"" and head.headers["Content-Length"] == str(a["size"])
    stale = call(app, "GET", a["file"], Range="bytes=0-0", If_Range='"another"')
    assert stale.status == 200
    r = call(app, "GET", a["file"], Range=f"bytes={a['size']}-")
    problem(r, 416, "bad_request")
    assert r.headers["Content-Range"] == f"bytes */{a['size']}"
    problem(call(app, "GET", BASE + "/files/f_unknown"), 404, "not_found")
    empty = next(x for x in apps if x["size"] == 0)
    assert call(app, "GET", empty["file"]).headers["Content-Length"] == "0"


@pytest.mark.parametrize(
    ("header", "size", "expected"),
    [
        ("bytes=0-0", 10, (0, 0)),
        ("bytes=5-", 10, (5, 9)),
        ("bytes=-3", 10, (7, 9)),
        ("bytes=8-100", 10, (8, 9)),
        ("bytes=10-", 10, "unsatisfiable"),
        ("bytes=-0", 10, "unsatisfiable"),
        ("bytes=5-2", 10, None),
        ("bytes=0-1,4-5", 10, None),
        ("items=0-1", 10, None),
        ("bytes=-", 10, None),
        ("bytes=0-", 0, "unsatisfiable"),
    ],
)
def test_parse_range(header: str, size: int, expected: Any) -> None:
    assert parse_range(header, size) == expected


def test_file_ref(tmp_path: Any) -> None:
    path = tmp_path / "f.bin"
    path.write_bytes(b"lantern" * 100)
    ref = FileRef.of(path)
    assert ref.size == 700 and ref.sha256 == hashlib.sha256(b"lantern" * 100).hexdigest()
    with pytest.raises(ValueError, match="sha256"):
        FileRef("x", 1, "ABC")
    app = LanternApp(MemoryLibrary(), uid="3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name="x")
    lib = app.library
    assert isinstance(lib, MemoryLibrary)
    url = lib.add_file(ref)
    r = call(app, "GET", url, Range="bytes=-7")
    assert b"".join(r.iter_body()) == b"lantern"


def test_etag_and_304(app: LanternApp) -> None:
    first = call(app, "GET", BASE + "/apps", query={"page_size": "1"})
    again = call(app, "GET", BASE + "/apps", query={"page_size": "1"}, If_None_Match=first.headers["ETag"])
    assert again.status == 304 and again.body == b""


def test_changes(app: LanternApp) -> None:
    lib = build_library()
    app = make_lantern(lib)
    token = body(call(app, "GET", BASE + "/changes"))
    assert token["added"] == [] and token["removed"] == []
    added = lib.add_app_file(
        data=b"new",
        platform="switch",
        title_id="0100EF5600030000",
        app_id="0100EF5600030800",
        type="update",
        version_code=65536,
        name="Quiet Tide",
        format="nsp",
    )
    gone = lib.apps()[0]
    lib.remove_app(gone.id)
    later = body(call(app, "GET", BASE + "/changes", query={"since": token["since"]}))
    assert schema.validate("changes", later) == []
    assert [a["id"] for a in later["added"]] == [added.id] and later["removed"] == [gone.id]
    only_android = body(
        call(app, "GET", BASE + "/changes", query={"since": token["since"]}, Lantern_Platform="android")
    )
    assert only_android["added"] == []
    problem(call(app, "GET", BASE + "/changes", query={"since": "s_forged"}), 400, "bad_request")
    other = make_lantern(build_library())
    problem(call(other, "GET", BASE + "/changes", query={"since": token["since"]}), 400, "bad_request")
    stale = make_lantern(lib, secret=b"s" * 32)
    t = body(call(stale, "GET", BASE + "/changes"))["since"]
    assert lib._journal is not None
    lib._journal.floor = lib._journal.seq + 1
    problem(call(stale, "GET", BASE + "/changes", query={"since": t}), 410, "gone")


def test_titles(app: LanternApp) -> None:
    one = body(call(app, "GET", BASE + "/titles/0100AB1200010000"))
    assert schema.validate("title", one) == [] and one["name"] == "Lumen Drift"
    problem(call(app, "GET", BASE + "/titles/0100AB1200099000"), 404, "not_found")
    bulk = body(call(app, "GET", BASE + "/titles", query={"ids": "0100AB1200010000,0500000000000000,0100AB1200010000"}))
    assert [t["title_id"] for t in bulk["titles"]] == ["0100AB1200010000"]
    assert bulk["unknown"] == ["0500000000000000"]
    problem(
        call(app, "GET", BASE + "/titles", query={"ids": ",".join(f"05{i:014X}" for i in range(101))}),
        400,
        "bad_request",
    )
    problem(call(app, "GET", BASE + "/titles"), 400, "bad_request")
    problem(call(app, "GET", BASE + "/titles", query={"ids": "a b"}), 400, "bad_request")
    lib = build_library()
    app2 = make_lantern(lib)
    token = body(call(app2, "GET", BASE + "/titles/changes"))["since"]
    lib.add_title(Title(platform="switch", title_id="0100CD3400020000", name="Copper Moth Deluxe"))
    lib.remove_title("switch", "0100EF5600030000")
    later = body(call(app2, "GET", BASE + "/titles/changes", query={"since": token}))
    assert schema.validate("title-changes", later) == []
    assert [t["name"] for t in later["titles"]] == ["Copper Moth Deluxe"]
    assert later["removed"] == [{"platform": "switch", "title_id": "0100EF5600030000"}]
    problem(call(app2, "GET", BASE + "/titles/changes", query={"since": "nope"}), 400, "bad_request")


def test_titles_without_a_journal() -> None:
    app = make_lantern(MemoryLibrary(journal=False))
    assert body(call(app, "GET", BASE))["features"]["changes"] == 0
    token = body(call(app, "GET", BASE + "/titles/changes"))["since"]
    problem(call(app, "GET", BASE + "/titles/changes", query={"since": token}), 410, "gone")
    problem(call(app, "GET", BASE + "/changes"), 404, "not_found")


def test_homebrew(app: LanternApp) -> None:
    listing = body(call(app, "GET", BASE + "/homebrew", query={"page_size": "100"}))
    assert schema.validate("homebrew-page", listing) == []
    assert all("manifest" not in e["package"] for e in listing["items"])
    assert all("manifest" not in p for e in listing["items"] for p in e.get("packages", []))
    names = [e["name"] for e in listing["items"]]
    assert names == sorted(names, key=str.casefold)
    entry = body(call(app, "GET", BASE + "/homebrew/org.example.starjar", Lantern_Platform="switch"))
    assert schema.validate("homebrew", entry) == [] and entry["package"]["manifest"]
    problem(call(app, "GET", BASE + "/homebrew/org.example.starjar"), 400, "bad_request")  # two platforms
    problem(call(app, "GET", BASE + "/homebrew/org.example.nothing"), 404, "not_found")
    problem(call(app, "GET", BASE + "/homebrew/Not-an-id"), 404, "not_found")
    ports = body(call(app, "GET", BASE + "/homebrew", query={"kind": "port"}))["items"]
    assert {e["id"] for e in ports} == {"org.example.tidewalk-port", "org.example.harborglow"}
    assert [e["id"] for e in body(call(app, "GET", BASE + "/homebrew", query={"genre": "puzzle"}))["items"]] == [
        "org.example.mothclock"
    ]
    assert body(call(app, "GET", BASE + "/homebrew", query={"kind": "widget"}))["items"] == []
    for q in ({"kind": "Not a kind"}, {"genre": "Not a genre"}, {"sort": "added"}):
        problem(call(app, "GET", BASE + "/homebrew", query=q), 400, "bad_request")
    upd = call(
        app,
        "POST",
        BASE + "/homebrew/updates",
        Lantern_Platform="switch",
        body={
            "schema": 1,
            "installed": [{"id": "org.example.starjar", "build": 1}, {"id": "org.example.mothclock", "build": 400}],
        },
    )
    assert [e["id"] for e in body(upd)["items"]] == ["org.example.starjar"]
    problem(call(app, "POST", BASE + "/homebrew/updates", body={"schema": 1, "installed": []}), 400, "bad_request")
    problem(
        call(
            app,
            "POST",
            BASE + "/homebrew/updates",
            Lantern_Platform="switch",
            body={"schema": 1, "installed": [{"id": "Bad", "build": 1}]},
        ),
        400,
        "bad_request",
    )
    problem(
        call(app, "POST", BASE + "/homebrew/updates", Lantern_Platform="switch", body={"schema": 2}),
        422,
        "unsupported_schema",
    )


def test_cheats(app: LanternApp) -> None:
    sets = body(call(app, "GET", BASE + "/cheats"))
    assert schema.validate("cheats", sets) == [] and len(sets["cheats"]) == 3
    some = body(
        call(app, "GET", BASE + "/cheats", query={"title_id": "0100AB1200010000", "build_id": "AB12CD34EF560789"})
    )
    assert len(some["cheats"]) == 2
    first = sets["cheats"][0]
    text = call(app, "GET", BASE + f"/cheats/{first['id']}")
    raw = b"".join(text.iter_body())
    assert hashlib.sha256(raw).hexdigest() == first["sha256"] and text.headers["Content-Type"].startswith("text/plain")
    problem(call(app, "GET", BASE + f"/cheats/{first['id']}", Lantern_Platform="android"), 404, "not_found")
    problem(call(app, "GET", BASE + "/cheats/cs_nothing"), 404, "not_found")
    problem(call(app, "GET", BASE + "/cheats", query={"build_id": "not a build"}), 400, "bad_request")
    r = call(app, "POST", BASE + "/cheats", body={"schema": 1})
    problem(r, 405, "bad_request")
    assert r.headers["Allow"] == "GET, HEAD"


def test_families_at_zero_and_unknown_routes(app: LanternApp) -> None:
    for path in ("/sections", "/saves", "/requests", "/pairing", "/nothing/here"):
        problem(call(app, "GET", BASE + path), 404, "not_found")
    problem(call(app, "GET", "/api/elsewhere"), 404, "not_found")
    head = call(app, "HEAD", BASE + "/nothing")
    assert head.status == 404 and head.body == b"" and int(head.headers["Content-Length"]) > 0
    assert app.owns("/.well-known/lantern") and app.owns(BASE + "/apps") and not app.owns("/api/lanternx")


def test_a_failure_of_the_server_answers_500() -> None:
    class Broken(MemoryLibrary):
        def apps(self) -> list[App]:
            raise RuntimeError("the disk caught fire")

    errors: list[BaseException] = []
    app = LanternApp(Broken(), uid="3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name="Broken shelf")
    app.on_error = errors.append
    problem(call(app, "GET", BASE + "/apps"), 500, "internal")
    assert len(errors) == 1


def test_options() -> None:
    with pytest.raises(ValueError, match="path"):
        LanternApp(MemoryLibrary(), uid="u", name="n", base="api")
    with pytest.raises(ValueError, match="page_limit"):
        LanternApp(MemoryLibrary(), uid="u", name="n", page_limit=5000)
    app = LanternApp(MemoryLibrary(), uid="u", name="n", platforms=["switch", "switch"], motd="Hello")
    hello = body(call(app, "GET", BASE))
    assert hello["platforms"] == ["switch"] and hello["motd"] == "Hello"


# MemoryLibrary refuses what must not be served.


def test_memory_library_refuses() -> None:
    lib = MemoryLibrary()
    with pytest.raises(ValueError, match="app"):
        lib.add_app_file(
            data=b"x",
            platform="switch",
            title_id="0100AB1200010800",
            app_id="0100AB1200010800",
            type="base",
            version_code=0,
            name="Wrong",
            format="nsp",
        )
    with pytest.raises(ValueError, match="path or data"):
        lib.add_app_file(
            platform="switch", title_id="a", app_id="a", type="base", version_code=0, name="n", format="nsp"
        )
    good = App(
        id="a_1",
        platform="switch",
        title_id="0100AB1200010000",
        app_id="0100AB1200010000",
        type="base",
        version_code=0,
        size=3,
        format="nsp",
        sha256="0" * 64,
        file="",
    )
    with pytest.raises(ValueError, match="not its file"):
        lib.add_app(good, FileRef.of_bytes(b"abc"))
    with pytest.raises(ValueError, match="title"):
        lib.add_title(Title(platform="switch", title_id="0100AB1200010800", name="An update's id"))
    with pytest.raises(ValueError, match="1048576"):
        lib.add_cheat(
            platform="switch", title_id="0100AB1200010000", build_id="AB", source="x", text="x" * (1 << 20 + 1)
        )
    with pytest.raises(ValueError, match="cheat"):
        lib.add_cheat(platform="switch", title_id="0100AB1200010000", source="no build id", text="[x]\n")


def _starjar() -> tuple[Homebrew, dict[str, FileRef]]:
    from demo import zipped

    data = zipped({"switch/org.example.starjar/s.nro": b"nro"})
    package, file = make_package(data, "zip", platform="switch", homebrew_id="org.example.starjar")
    return Homebrew(
        id="org.example.starjar", platform="switch", kind="tool", name="Star Jar", version="1", build=1, package=package
    ), {package.file: file}


def test_check_homebrew() -> None:
    entry, files = _starjar()
    assert check_homebrew(entry) == []
    outside, _ = _starjar()
    assert outside.package.manifest is not None
    outside.package.manifest[0].path = "/bootloader/x.ini"
    assert check_homebrew(outside)
    forged, _ = _starjar()
    forged.signature = Signature(alg="ed25519", public_key="A" * 43 + "=", value="A" * 86 + "==")
    assert any("signature" in p for p in check_homebrew(forged))
    lib = MemoryLibrary()
    with pytest.raises(ValueError, match="manifest_sha256"):
        lib.add_homebrew(outside)
    other = FileRef.of_bytes(b"another file")
    with pytest.raises(ValueError, match="not its package"):
        lib.add_homebrew(entry, {entry.package.file: other})
    assert lib.add_homebrew(entry, files).package.file.startswith("/api/lantern/v1/files/f_")


def test_refused_homebrew_examples_are_refused() -> None:
    """Each refused homebrew of the specification: the models cannot read it,
    or check_homebrew() finds why it must not be served."""
    for path in sorted((EXAMPLES / "invalid").glob("homebrew.*.json")):
        doc = load(path)
        try:
            entry = Homebrew.from_json(copy.deepcopy(doc))
        except DocumentError:
            continue
        assert check_homebrew(entry), path.name
