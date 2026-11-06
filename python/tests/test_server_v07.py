"""What draft 0.7 adds to the server toolkit, called directly: chunk indexes and their route (SPEC.md § 22), the
answers to a browser's page (§ 2.5), no platform `web` (Annex A.7), an upload's chunk size (§ 9.3), and the static
library's chunk indexes (§ 21.1)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from demo import DEMO_KEY, DEMO_ORIGIN, DEMO_TOKEN, build_library, delta_pair, demo_accounts, make_lantern
from lantern import chunks, schema, static
from lantern.models import App, Rating, RatingCap, Title
from lantern.server import LanternApp, MemoryLibrary, ServerResponse
from test_server import BASE, call
from test_server_auth import KEY
from test_server_auth import call as signed
from test_server_auth import doc as document

OLD, NEW = delta_pair()
OLD_SHA, NEW_SHA = hashlib.sha256(OLD).hexdigest(), hashlib.sha256(NEW).hexdigest()


@pytest.fixture(scope="module")
def app() -> Any:
    a = make_lantern(build_library(delta=True), cors_origins=[DEMO_ORIGIN])
    yield a
    a.shutdown()


def body(r: ServerResponse) -> bytes:
    assert isinstance(r.body, bytes)
    return r.body


def apps(app: LanternApp) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = json.loads(body(call(app, "GET", BASE + "/apps", query={"page_size": "1000"})))[
        "items"
    ]
    return items


# Chunk indexes (SPEC.md § 22).


def test_the_files_of_chunked_size_carry_chunks(app: LanternApp) -> None:
    """[L-22.1-1] An app of 128 KiB to 64 MiB has `chunks`, a smaller one none; the index is the canonical bytes."""
    every = apps(app)
    chunked = [a for a in every if "chunks" in a]
    assert {a["sha256"] for a in chunked} == {OLD_SHA, NEW_SHA}
    assert all(a["size"] < 128 << 10 for a in every if "chunks" not in a)
    for a in chunked:
        assert schema.definition("app", a) == []
        ref = a["chunks"]
        assert ref["url"] == f"{BASE}/chunks/sha256/{a['sha256']}"
        r = call(app, "GET", ref["url"])
        raw = body(r)
        assert r.status == 200 and r.headers["Content-Type"] == "application/json"
        assert (len(raw), hashlib.sha256(raw).hexdigest()) == (ref["size"], ref["sha256"])
        assert schema.validate("chunk-index", json.loads(raw)) == []
        data = NEW if a["sha256"] == NEW_SHA else OLD
        assert raw == chunks.build_index(data)[1]  # cut as lantern-cdc-1 cuts it, in canonical JSON


def test_the_index_route(app: LanternApp) -> None:
    """[L-22.1-2] By the SHA-256 alone: 200, HEAD like GET; an unknown file, a file without an index, an upper-case
    SHA-256 and a platform it is not of are 404."""
    path = f"{BASE}/chunks/sha256/{NEW_SHA}"
    got, head = call(app, "GET", path), call(app, "HEAD", path)
    assert got.status == head.status == 200 and body(head) == b""
    assert head.headers["Content-Length"] == got.headers["Content-Length"] or "Content-Encoding" in got.headers
    assert head.headers["ETag"] == got.headers["ETag"]
    assert call(app, "GET", path, query={"platform": "switch"}).status == 200
    assert call(app, "GET", path, query={"platform": "android"}).status == 404
    assert call(app, "GET", path.replace(NEW_SHA, NEW_SHA.upper())).status == 404
    assert call(app, "GET", f"{BASE}/chunks/sha256/{'0' * 64}").status == 404
    small = next(a for a in apps(app) if "chunks" not in a)
    assert call(app, "GET", f"{BASE}/chunks/sha256/{small['sha256']}").status == 404
    assert call(app, "POST", path).status == 405
    assert call(app, "GET", f"{BASE}/chunks/sha256").status == 404


def test_the_index_is_sent_as_kept_even_when_compressed(app: LanternApp) -> None:
    path = f"{BASE}/chunks/sha256/{NEW_SHA}"
    plain = body(call(app, "GET", path))
    packed = call(app, "GET", path, Accept_Encoding="gzip")
    assert packed.headers.get("Content-Encoding") == "gzip"
    import gzip

    assert gzip.decompress(body(packed)) == plain


def test_the_family_is_offered_with_the_library(app: LanternApp) -> None:
    assert json.loads(body(call(app, "GET", "/.well-known/lantern")))["features"]["deltas"] == 1
    plain = LanternApp(MemoryLibrary(), uid="6f1c2a8e-2b1d-4c3e-9f00-112233445566", name="No deltas")
    assert json.loads(body(call(plain, "GET", "/.well-known/lantern")))["features"]["deltas"] == 0
    assert call(plain, "GET", f"{BASE}/chunks/sha256/{NEW_SHA}").status == 404


def test_a_library_without_deltas_cuts_nothing() -> None:
    lib = MemoryLibrary(deltas=None)
    lib.add_app_file(data=NEW, platform="switch", title_id="0100AA7800040000", app_id="0100AA7800040800",
                     type="update", version_code=65536, name="Glass Orchard", format="nsz")  # fmt: skip
    assert lib.apps()[0].chunks is None and lib.chunk_index(NEW_SHA) is None and "deltas" not in lib.families


def test_files_outside_the_sizes_are_not_cut() -> None:
    lib = MemoryLibrary(deltas=(1 << 20, 2 << 20))  # NEW is 402,000 bytes
    lib.add_app_file(data=NEW, platform="switch", title_id="0100AA7800040000", app_id="0100AA7800040800",
                     type="update", version_code=65536, name="Glass Orchard", format="nsz")  # fmt: skip
    assert lib.apps()[0].chunks is None and "deltas" in lib.families


def test_an_index_goes_with_its_app() -> None:
    lib = build_library(delta=True)
    new = next(a for a in lib.apps() if a.sha256 == NEW_SHA)
    assert lib.chunk_index(NEW_SHA) is not None
    lib.remove_app(new.id)
    assert lib.chunk_index(NEW_SHA) is None and lib.chunk_index(OLD_SHA) is not None


def test_a_rating_cap_hides_the_index_with_its_file() -> None:
    """[L-22.1-2] An index is for whoever may read the file (§ 5.6): 404 above the cap, as for the file."""
    lib = build_library(delta=True)
    new = next(a for a in lib.apps() if a.sha256 == NEW_SHA)
    lib.add_title(
        Title(platform="switch", title_id=new.title_id, name="Glass Orchard", release="2025-09-12",
              ratings=[Rating(system="PEGI", rating="18")]),
    )  # fmt: skip
    accounts = demo_accounts()
    accounts.add_token(
        "et_capped-0000000000000000000000000000", "mira", "Ines's console", ["library"], key=KEY.public,
        rating_cap=RatingCap(age=3),
    )  # fmt: skip
    capped = make_lantern(lib, accounts=accounts)
    path = f"{BASE}/chunks/sha256/{NEW_SHA}"
    assert signed(capped, "GET", path, token=DEMO_TOKEN, key=DEMO_KEY).status == 200
    assert signed(capped, "GET", path, token="et_capped-0000000000000000000000000000", key=KEY).status == 404
    capped.shutdown()


def test_an_account_without_the_library_scope_is_refused() -> None:
    accounts = demo_accounts()
    accounts.add_token("et_nolib-00000000000000000000000000000", "noor", "Noor's", ["saves"], key=KEY.public)
    a = make_lantern(build_library(delta=True), accounts=accounts)
    r = signed(a, "GET", f"{BASE}/chunks/sha256/{NEW_SHA}", token="et_nolib-00000000000000000000000000000", key=KEY)
    assert r.status == 403
    a.shutdown()


# Browsers (SPEC.md § 2.5).

ASKED = "authorization, content-type, lantern-platform, if-match, x-not-lantern"


def test_a_preflight_is_204_without_a_token_on_any_route(app: LanternApp) -> None:
    """[L-2.5-3] The method and the headers asked, named; no credential allowed; kept 600 seconds at least."""
    for method, path in (
        ("GET", "/.well-known/lantern"),
        ("GET", BASE + "/apps"),
        ("PATCH", BASE + "/sync/wishes"),
        ("DELETE", BASE + "/uploads/u_1"),
        ("GET", BASE + "/no-such-route"),
    ):
        r = call(
            app, "OPTIONS", path, Origin=DEMO_ORIGIN, Access_Control_Request_Method=method,
            Access_Control_Request_Headers=ASKED,
        )  # fmt: skip
        assert r.status == 204, (path, r.status)
        assert r.headers["Access-Control-Allow-Origin"] == DEMO_ORIGIN and "Origin" in r.headers["Vary"]
        assert method in r.headers["Access-Control-Allow-Methods"]
        allowed = {h.strip().lower() for h in r.headers["Access-Control-Allow-Headers"].split(",")}
        assert {"authorization", "content-type", "lantern-platform", "if-match"} <= allowed
        assert "x-not-lantern" not in allowed  # only what this text's requests carry
        assert int(r.headers["Access-Control-Max-Age"]) >= 600
        assert "Access-Control-Allow-Credentials" not in r.headers and "Set-Cookie" not in r.headers
        assert "Access-Control-Expose-Headers" not in r.headers and body(r) == b""
        assert r.headers["Cache-Control"] == "no-store" and r.headers["Content-Length"] == "0"


def test_a_preflight_asks_nothing_it_may_not(app: LanternApp) -> None:
    every = call(app, "OPTIONS", BASE + "/apps", Origin=DEMO_ORIGIN, Access_Control_Request_Method="GET")
    assert "Authorization" in every.headers["Access-Control-Allow-Headers"]
    private = call(
        app, "OPTIONS", BASE + "/apps", Origin=DEMO_ORIGIN, Access_Control_Request_Method="GET",
        Access_Control_Request_Private_Network="true",
    )  # fmt: skip
    assert private.headers["Access-Control-Allow-Private-Network"] == "true"


def test_an_options_that_is_not_a_preflight_is_a_method_no_route_takes(app: LanternApp) -> None:
    requests: list[dict[str, Any]] = [
        {},
        {"Origin": DEMO_ORIGIN},
        {"Origin": "https://other.example.org", "Access_Control_Request_Method": "GET"},
    ]
    for headers in requests:
        r = call(app, "OPTIONS", BASE + "/apps", **headers)
        assert r.status == 405 and "GET" in r.headers["Allow"]
        assert "Access-Control-Allow-Origin" not in r.headers or r.headers["Access-Control-Allow-Origin"] == DEMO_ORIGIN
    r = call(app, "OPTIONS", "/elsewhere", Origin=DEMO_ORIGIN, Access_Control_Request_Method="GET")
    assert r.status == 404 and "Access-Control-Allow-Origin" not in r.headers


def test_every_answer_to_an_allowed_origin_names_it_and_what_a_page_reads(app: LanternApp) -> None:
    """[L-2.5-2] Errors included; Vary: Origin; the headers of this text exposed."""
    probes = [
        ("GET", "/.well-known/lantern", 200),
        ("GET", BASE + "/apps", 200),
        ("HEAD", BASE + "/apps", 200),
        ("GET", BASE + "/no-such-route", 404),
        ("POST", BASE + "/apps", 405),
        ("GET", BASE + "/saves", 401),
    ]
    for method, path, status in probes:
        r = call(app, method, path, Origin=DEMO_ORIGIN)
        assert r.status == status, (method, path, r.status)
        assert r.headers["Access-Control-Allow-Origin"] == DEMO_ORIGIN
        assert "origin" in {v.strip().lower() for v in r.headers["Vary"].split(",")}
        exposed = {h.strip() for h in r.headers["Access-Control-Expose-Headers"].split(",")}
        assert {"ETag", "Content-Range", "Repr-Digest", "Retry-After", "Upload-Offset", "Lantern-Chunk-Size"} <= exposed
        assert "Access-Control-Allow-Credentials" not in r.headers and "Set-Cookie" not in r.headers


def test_an_origin_not_allowed_gets_no_header_of_its_own(app: LanternApp) -> None:
    for origin in ("https://other.example.org", "http://app.example.org", "null", ""):
        r = call(app, "GET", BASE + "/apps", Origin=origin)
        assert r.status == 200 and "Access-Control-Allow-Origin" not in r.headers
        assert "Access-Control-Expose-Headers" not in r.headers
        assert "Origin" in r.headers["Vary"]  # the answer depends on it: caches keep them apart
    r = call(app, "GET", BASE + "/apps")
    assert "Access-Control-Allow-Origin" not in r.headers


def test_a_page_of_another_route_than_the_texts_is_not_given_cors(app: LanternApp) -> None:
    r = call(app, "GET", "/pair", Origin=DEMO_ORIGIN)
    assert "Access-Control-Allow-Origin" not in r.headers


def test_by_default_no_origin_is_allowed() -> None:
    a = make_lantern(build_library())
    r = call(a, "GET", BASE + "/apps", Origin=DEMO_ORIGIN)
    assert r.status == 200 and "Access-Control-Allow-Origin" not in r.headers and "Vary" in r.headers
    assert "Origin" not in r.headers["Vary"]
    pre = call(a, "OPTIONS", BASE + "/apps", Origin=DEMO_ORIGIN, Access_Control_Request_Method="GET")
    assert pre.status == 405
    a.shutdown()


def test_every_origin() -> None:
    a = make_lantern(build_library(), cors_origins=["*"])
    r = call(a, "GET", BASE + "/apps", Origin="https://anywhere.example.net")
    assert r.headers["Access-Control-Allow-Origin"] == "*" and "Origin" not in r.headers["Vary"]
    assert "Access-Control-Allow-Credentials" not in r.headers
    pre = call(a, "OPTIONS", BASE + "/apps", Origin="https://anywhere.example.net", Access_Control_Request_Method="GET")
    assert pre.status == 204 and pre.headers["Access-Control-Allow-Origin"] == "*"
    assert "Access-Control-Allow-Origin" not in call(a, "GET", BASE + "/apps").headers  # no Origin: no header
    a.shutdown()


@pytest.mark.parametrize(
    "bad", ["app.example.org", "https://app.example.org/", "https://app.example.org/path", "ftp://x.example.org", "**"]
)
def test_an_origin_is_a_scheme_a_host_and_a_port(bad: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        make_lantern(build_library(), cors_origins=[bad])


def test_origins_with_a_port_or_an_address() -> None:
    a = make_lantern(
        build_library(), cors_origins=["http://localhost:8080", "https://[::1]:8443", "https://a-b.example.org"]
    )
    assert len(a.cors_origins) == 3
    a.shutdown()


# No platform `web` (Annex A.7).


def test_nothing_is_served_of_web() -> None:
    """[L-A.7-1] A library refuses an app, a title, a homebrew or a cheat set of `web`; the handshake never lists it."""
    lib = MemoryLibrary()
    web: dict[str, Any] = {"platform": "web", "title_id": "org.example.game", "app_id": "org.example.game"}
    with pytest.raises(ValueError, match="web"):
        lib.add_app_file(data=b"x", type="base", version_code=0, name="Game", format="zip", **web)
    with pytest.raises(ValueError, match="web"):
        lib.add_title(Title(platform="web", title_id="org.example.game", name="Game"))
    with pytest.raises(ValueError, match="web"):
        lib.add_cheat(platform="web", title_id="org.example.game", text="[x]\n", source="Mira")
    with pytest.raises(ValueError, match="web"):
        LanternApp(lib, uid="6f1c2a8e-2b1d-4c3e-9f00-112233445566", name="x", platforms=["switch", "web"])
    with pytest.raises(ValueError, match="web"):
        lib.add_app(
            App(id="a_1", platform="web", title_id="x", app_id="x", type="base", version_code=0, name="x",
                size=1, format="zip", sha256="0" * 64, added="2026-01-01T00:00:00Z", file=""),
        )  # fmt: skip
    assert (
        "web" not in json.loads(body(call(make_lantern(build_library()), "GET", "/.well-known/lantern")))["platforms"]
    )
    listing = json.loads(body(call(make_lantern(build_library()), "GET", BASE + "/apps", query={"platform": "web"})))
    assert listing["items"] == []


def test_the_platform_web_has_no_title_id() -> None:
    from lantern import profiles

    assert profiles.title_id_ok("web", "org.example.game") is False and not profiles.served("web")
    assert profiles.served("switch") and "web" not in profiles.OPEN_PLATFORMS


# An upload's chunk size (SPEC.md § 9.3).


def test_head_of_an_upload_says_its_chunk_size() -> None:
    """[L-9.3-3] Upload-Offset, Upload-Length and Lantern-Chunk-Size: where to resume, and in what chunks."""
    a = make_lantern(build_library(), accounts=demo_accounts())
    opened = signed(
        a, "POST", f"{BASE}/saves/0500ABCDEF120000/uploads", token=DEMO_TOKEN, key=DEMO_KEY, Lantern_Platform="switch",
        body={"schema": 1, "size": 3000, "sha256": "0" * 64},
    )  # fmt: skip
    assert opened.status == 201
    upload = document(opened)
    head = signed(a, "HEAD", upload["upload"], token=DEMO_TOKEN, key=DEMO_KEY)
    assert head.status == 204
    assert head.headers["Lantern-Chunk-Size"] == str(upload["chunk_size"])
    assert (head.headers["Upload-Offset"], head.headers["Upload-Length"]) == ("0", "3000")
    a.shutdown()


# A static library with chunk indexes (SPEC.md § 21.1, § 22).


def test_the_export_holds_the_indexes(tmp_path: Path) -> None:
    """[L-21.1-1] `chunks.url` is the index's path, v1/chunks/sha256/<hex>.json: its bytes as kept; deltas at 1."""
    out = tmp_path / "library"
    summary = static.export(build_library(delta=True), out, uid="6f1c2a8e-2b1d-4c3e-9f00-112233445566", name="Shelf")
    assert summary["indexes"] == 2
    hello = json.loads((out / "lantern.json").read_text())
    assert hello["features"]["deltas"] == 1 and schema.validate("handshake", hello) == []
    with static.StaticLibrary(out) as lib:
        found = [a for a in lib.iter_apps("switch") if a.chunks is not None]
        assert {a.sha256 for a in found} == {OLD_SHA, NEW_SHA}
        for a in found:
            assert a.chunks is not None
            assert a.chunks.url == f"v1/chunks/sha256/{a.sha256}.json" and static.relative_ok(a.chunks.url)
            raw = (out / a.chunks.url).read_bytes()
            assert (len(raw), hashlib.sha256(raw).hexdigest()) == (a.chunks.size, a.chunks.sha256)
            index = lib.chunk_index(a)
            assert index.sha256 == a.sha256 and sum(n for n, _ in index.chunks) == a.size
        small = next(a for a in lib.iter_apps("switch") if a.chunks is None)
        with pytest.raises(chunks.UnusableIndex):
            lib.chunk_index(small)


def test_the_export_without_an_index_has_none(tmp_path: Path) -> None:
    out = tmp_path / "library"
    lib = MemoryLibrary()
    lib.add_app_file(data=NEW, platform="switch", title_id="0100AA7800040000", app_id="0100AA7800040800",
                     type="update", version_code=65536, name="Glass Orchard", format="nsz")  # fmt: skip
    lib.add_title(Title(platform="switch", title_id="0100AA7800040000", name="Glass Orchard"))
    static.export(lib, out, uid="6f1c2a8e-2b1d-4c3e-9f00-112233445566", name="Shelf")
    assert json.loads((out / "lantern.json").read_text())["features"]["deltas"] == 0
    assert not (out / "v1" / "chunks").exists()


def test_a_static_index_that_is_altered_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "library"
    static.export(build_library(delta=True), out, uid="6f1c2a8e-2b1d-4c3e-9f00-112233445566", name="Shelf")
    with static.StaticLibrary(out) as lib:
        found = next(a for a in lib.iter_apps("switch") if a.sha256 == NEW_SHA)
        assert found.chunks is not None
        path = out / found.chunks.url
        path.write_bytes(path.read_bytes().replace(b'"schema":1', b'"schema":2'))
        with pytest.raises(chunks.UnusableIndex):
            lib.chunk_index(found)
