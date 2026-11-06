"""Packages a device cannot use and variants of one game (draft 0.9, SPEC.md § 6.1, § 6.2, § 6.3, Annex B.15):
the specification's vectors (app-requires.json) against lantern.variants and lantern.missing, then the server
toolkit (requires, includes, variants, the `format` filter, `formats` and `satisfies`), the library API, the static
export, and the client, sync and async, against the demo server."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import SPEC
from demo import DEMO_TOKEN, build_library, make_lantern, serve
from lantern import DocumentError, schema, static
from lantern.client import AsyncLanternClient, LanternClient
from lantern.client.core import ClientCore
from lantern.missing import missing
from lantern.models import App, MissingRequest
from lantern.server import LanternApp, MemoryLibrary, ServerResponse
from lantern.variants import included, install_decision, prefer_variant
from test_server import BASE, body, call, problem

VECTORS = json.loads((SPEC / "vectors" / "app-requires.json").read_text(encoding="utf-8"))
NSP = ["nsp", "nsz", "xci", "xcz"]


def app_of(doc: dict[str, Any]) -> App:
    """A vector's app, with the fields the vectors leave out (they are not what is tested)."""
    return App.from_json({"sha256": "0" * 64, "file": "files/x", **doc})


# The vectors.


@pytest.mark.parametrize("case", VECTORS["install"], ids=lambda c: c["name"])
def test_install_decision_vectors(case: dict[str, Any]) -> None:
    """[L-6.1-3] [L-6.1-4] [L-6.1-5] The decision and the number of reasons of each vector."""
    verdict, why = install_decision(
        app_of(case["app"]), case["formats"], case["satisfies"], [app_of(a) for a in case["installed"]]
    )
    assert verdict == case["decision"] and len(why) == case["reasons"]


def test_prefer_variant_vector() -> None:
    """[B.15] The fewest requires, then the smallest size, then the smaller id."""
    apps = [app_of(a) for a in VECTORS["variants"]["apps"]]
    assert prefer_variant(apps).id == VECTORS["variants"]["preferred"]
    assert prefer_variant(reversed(apps)).id == VECTORS["variants"]["preferred"]


def test_prefer_variant_tie_and_order() -> None:
    twins = [app_of({**VECTORS["variants"]["apps"][0], "id": i, "size": 5}) for i in ("b", "a", "c")]
    assert prefer_variant(twins).id == "a"
    heavy = app_of({**VECTORS["variants"]["apps"][0], "id": "z", "size": 1, "requires": ["x", "y"]})
    light = app_of({**VECTORS["variants"]["apps"][0], "id": "y", "size": 999, "requires": ["x"]})
    assert prefer_variant([heavy, light]).id == "y"
    with pytest.raises(ValueError):
        prefer_variant([])


@pytest.mark.parametrize("case", VECTORS["missing"], ids=lambda c: c["name"])
def test_missing_vectors(case: dict[str, Any]) -> None:
    """[L-6.3-3] [L-6.3-4] What is missing, by lantern.missing and by the server toolkit with the same library."""
    apps = [app_of(a) for a in VECTORS["library"]]
    installed = [(i["app_id"], i["version_code"]) for i in case["installed"]]
    formats, satisfies = case.get("formats"), case.get("satisfies")
    got = missing(apps, "switch", installed, set(case["want"]), formats=formats, satisfies=satisfies)
    assert sorted(a.id for a in got) == sorted(case["missing"])
    keyed = {a["id"]: (a["app_id"], a["version_code"], a["format"]) for a in VECTORS["library"]}
    app = vector_app()
    extra: dict[str, Any] = {k: case[k] for k in ("formats", "satisfies") if k in case}
    doc = {"schema": 1, "installed": case["installed"], "want": case["want"], **extra}
    r = call(app, "POST", BASE + "/apps/missing", body=doc, Lantern_Platform="switch")
    assert r.status == 200
    served = body(r)["items"]
    assert sorted((a["app_id"], a["version_code"], a["format"]) for a in served) == sorted(
        keyed[i] for i in case["missing"]
    )


def vector_app() -> LanternApp:
    lib = MemoryLibrary(base=BASE)
    for a in VECTORS["library"]:
        lib.add_app_file(
            data=a["id"].encode(),
            platform=a["platform"],
            title_id=a["title_id"],
            app_id=a["app_id"],
            type=a["type"],
            version_code=a["version_code"],
            name=a["id"],
            format=a["format"],
            requires=a.get("requires", ()),
            includes=[(i["app_id"], i["version_code"]) for i in a.get("includes", ())],
        )
    return make_lantern(lib)


# Helpers beyond the vectors.


def test_included_only_updates_and_not_above() -> None:
    """[L-6.1-5] Only an update can be included, at its version or above, and by an app installed."""
    host = app_of({**VECTORS["install"][6]["installed"][0]})
    update = VECTORS["install"][6]["app"]
    assert included(app_of(update), [host])
    assert not included(app_of(update), [])
    assert not included(app_of({**update, "version_code": 196609}), [host])
    assert not included(app_of({**update, "type": "dlc"}), [host])
    assert not included(app_of({**update, "app_id": "0100ABCD00010801"}), [host])


def test_unknown_format_and_token_are_refused_with_every_reason() -> None:
    """[L-6.1-3] [L-6.1-4] Nothing unknown is installed, and each reason is given."""
    doc = {**VECTORS["install"][0]["app"], "format": "x-new", "requires": ["time-travel", "sigpatch", "fs-compression"]}
    verdict, why = install_decision(app_of(doc), NSP, ["sigpatch"])
    assert verdict == "unavailable"
    assert why == ["format 'x-new'", "requires 'time-travel'", "requires 'fs-compression'"]
    assert install_decision(app_of(doc), [], [])[0] == "unavailable"
    assert install_decision(app_of(VECTORS["install"][0]["app"]), [], [])[0] == "unavailable"


# The server toolkit.


def test_demo_library_has_variants() -> None:
    apps = {(a.app_id, a.version_code, a.format): a for a in build_library().apps()}
    plain = apps[("0100EF5600030000", 0, "nsp")]
    packed = apps[("0100EF5600030000", 0, "nsz")]
    assert plain.requires is None and packed.requires == ["fs-compression"]
    assert apps[("0100CD3400020000", 0, "xcz")].includes is not None


def test_library_deduplicates_requires_and_checks_its_limits() -> None:
    """[L-6.1-1] requires: at most 8 tokens of a-z, 0-9 and -, listed once; includes: at most 16."""
    lib = MemoryLibrary()
    ident = {"platform": "switch", "title_id": "0100AB1200010000", "app_id": "0100AB1200010000"}
    kw: dict[str, Any] = {"type": "base", "version_code": 0, "name": "G", "format": "nsp", **ident}
    ok = lib.add_app_file(data=b"x", requires=["sigpatch", "sigpatch", "fs-compression"], **kw)
    assert ok.requires == ["sigpatch", "fs-compression"]
    assert lib.add_app_file(data=b"y", requires=[], **kw).requires is None
    assert lib.add_app_file(data=b"z", requires=[f"t{n}" for n in range(8)], **kw).requires is not None
    for bad in (
        [f"t{n}" for n in range(9)],
        ["Upper"],
        ["-lead"],
        ["a" * 33],
        [""],
        ["with space"],
        ["ünï"],
    ):
        with pytest.raises(ValueError):
            lib.add_app_file(data=b"x", requires=bad, **kw)
    lib.add_app_file(data=b"i", includes=[("0100AB1200010800", n) for n in range(16)], **kw)
    for bad_includes in (
        [("0100AB1200010800", n) for n in range(17)],
        [("", 1)],
        [("bad id!", 1)],
        [("0100AB1200010800", -1)],
    ):
        with pytest.raises(ValueError):
            lib.add_app_file(data=b"x", includes=bad_includes, **kw)


def test_add_app_checks_requires_of_a_document() -> None:
    lib = MemoryLibrary()
    doc: dict[str, Any] = {
        "id": "a_1",
        "platform": "switch",
        "title_id": "0100AB1200010000",
        "app_id": "0100AB1200010000",
        "type": "base",
        "version_code": 0,
        "size": 1,
        "format": "nsp",
        "sha256": "0" * 64,
        "file": "x",
    }
    lib.add_app(App.from_json({**doc, "requires": ["sigpatch"], "includes": [{"app_id": "a", "version_code": 1}]}))
    bad: list[dict[str, Any]] = [{"requires": ["Sig"]}, {"requires": ["a"] * 9}, {"includes": [{"app_id": "a"}]}]
    for extra in bad:
        with pytest.raises((ValueError, DocumentError)):
            lib.add_app(App.from_json({**doc, "id": "a_2", **extra}))


@pytest.fixture(scope="module")
def demo() -> LanternApp:
    return make_lantern()


def listing(app: LanternApp, **query: str) -> ServerResponse:
    return call(app, "GET", BASE + "/apps", query={"page_size": "1000", **query})


def test_listing_shows_every_variant_with_requires_and_includes(demo: LanternApp) -> None:
    """[L-6.1-1] Variants of one game are all listed, with their requires and includes; the document is valid."""
    r = listing(demo, platform="switch")
    items = body(r)["items"]
    assert schema.validate("apps", body(r)) == []
    moth = [a for a in items if a["app_id"] == "0100CD3400020000"]
    assert sorted(a["format"] for a in moth) == ["xci", "xcz"]
    xcz = next(a for a in moth if a["format"] == "xcz")
    assert xcz["requires"] == ["fs-compression", "sigpatch"]
    assert xcz["includes"] == [{"app_id": "0100CD3400020800", "version_code": 196608}]
    assert "requires" not in next(a for a in moth if a["format"] == "xci")


def test_format_filter(demo: LanternApp) -> None:
    """[L-6.2-7] format keeps the apps of that format; one no app has is an empty list, never an error."""
    for fmt in ("nsp", "nsz", "xci", "xcz", "apk"):
        items = body(listing(demo, format=fmt))["items"]
        assert items and {a["format"] for a in items} == {fmt}
    for odd in ("zzlantern", "x-lantern-conformance", "NSP", "a" * 500, "%00"):
        r = listing(demo, format=odd)
        assert r.status == 200 and body(r)["items"] == []
    assert len(body(listing(demo, format=""))["items"]) == 10  # an empty value is absent (§ 2.4)
    both = body(listing(demo, format="nsz", platform="switch", type="update"))["items"]
    assert {(a["format"], a["type"]) for a in both} == {("nsz", "update")}


def test_cursor_and_etag_scope_include_the_format(demo: LanternApp) -> None:
    """A cursor of one format's listing is refused by another's; the ETags differ."""
    first = listing(demo, platform="switch", format="nsp", page_size="1")
    nxt = body(first)["next"]
    assert nxt
    problem(listing(demo, platform="switch", format="nsz", page_size="1", cursor=nxt), 400, "bad_request")
    assert listing(demo, platform="switch", format="nsp", page_size="1", cursor=nxt).status == 200
    other = listing(demo, platform="switch", format="nsz", page_size="1")
    assert first.headers.get("ETag") != other.headers.get("ETag")


def ask(app: LanternApp, installed: list[Any], want: list[str], **extra: Any) -> ServerResponse:
    doc = {"schema": 1, "installed": installed, "want": want, **extra}
    return call(app, "POST", BASE + "/apps/missing", body=doc, Lantern_Platform="switch")


def ids_of(r: ServerResponse) -> set[tuple[str, str]]:
    assert r.status == 200, r.body
    return {(a["app_id"], a["format"]) for a in body(r)["items"]}


def test_missing_formats_and_satisfies(demo: LanternApp) -> None:
    """[L-6.3-3] absent: no filter; empty: filters everything it needs; both applied last."""
    every = ids_of(ask(demo, [], ["base"]))
    assert ("0100EF5600030000", "nsz") in every and ("0100EF5600030000", "nsp") in every
    assert ids_of(ask(demo, [], ["base"], formats=["nsp"])) == {a for a in every if a[1] == "nsp"}
    assert ids_of(ask(demo, [], ["base"], formats=[])) == set()
    assert ids_of(ask(demo, [], ["base"], formats=["zzlantern"])) == set()
    no_tokens = ids_of(ask(demo, [], ["base"], satisfies=[]))
    assert ("0100EF5600030000", "nsz") not in no_tokens and ("0100EF5600030000", "nsp") in no_tokens
    assert ids_of(ask(demo, [], ["base"], satisfies=["fs-compression"])) == no_tokens | {("0100EF5600030000", "nsz")}
    assert ids_of(ask(demo, [], ["base"], satisfies=["fs-compression", "sigpatch"])) == every
    assert ids_of(ask(demo, [], ["base"], formats=["nsz"], satisfies=["fs-compression"])) == {
        ("0100EF5600030000", "nsz")
    }
    # Variants of one game: each is a candidate; the device's filters pick.
    assert ids_of(ask(demo, [], ["base"], formats=["xci", "xcz"], satisfies=[])) == {("0100CD3400020000", "xci")}


HOSTILE: list[tuple[str, Any]] = [
    ("formats", "nsp"),
    ("formats", [1]),
    ("formats", ["NSP"]),
    ("formats", ["a" * 17]),
    ("formats", [f"w{n}" for n in range(17)]),
    ("formats", {"nsp": 1}),
    ("formats", None),
    ("formats", [None]),
    ("formats", [["nsp"]]),
    ("formats", ["n-sp"]),
    ("formats", [""]),
    ("satisfies", "sigpatch"),
    ("satisfies", ["Sig_Patch"]),
    ("satisfies", ["-x"]),
    ("satisfies", ["a" * 33]),
    ("satisfies", [f"w{n}" for n in range(17)]),
    ("satisfies", [["x"]]),
    ("satisfies", None),
    ("satisfies", 7),
    ("satisfies", [True]),
]


@pytest.mark.parametrize(("key", "value"), HOSTILE, ids=lambda v: json.dumps(v)[:30])
def test_missing_refuses_bad_arrays(demo: LanternApp, key: str, value: Any) -> None:
    """[L-6.3-2] Not an array of at most 16 words of the right pattern: 400, never a failure."""
    problem(ask(demo, [], ["base"], **{key: value}), 400, "bad_request")


def test_missing_accepts_sixteen_words_and_duplicates(demo: LanternApp) -> None:
    r = ask(demo, [], ["base"], formats=[f"w{n}" for n in range(16)], satisfies=[f"t{n}" for n in range(16)])
    assert r.status == 200
    assert ids_of(ask(demo, [], ["base"], formats=["nsp", "nsp"])) == ids_of(ask(demo, [], ["base"], formats=["nsp"]))


def test_missing_includes_count_as_installed(demo: LanternApp) -> None:
    """[L-6.3-4] An installed app also installs what it includes: its update is not offered again."""
    # The game's base at version 0 is a variant that includes the update: the update is not offered again.
    assert ids_of(ask(demo, [{"app_id": "0100CD3400020000", "version_code": 0}], ["update"])) == set()
    # A version no app has carries no includes: nothing is counted for it, and the game is not known at that version.
    assert ids_of(ask(demo, [{"app_id": "0100CD3400020000", "version_code": 5}], ["update"])) == {
        ("0100CD3400020800", "nsp")
    }
    # The update's own version is above or equal: nothing newer than the included one.
    assert ids_of(ask(demo, [{"app_id": "0100CD3400020800", "version_code": 196608}], ["update"])) == set()


def test_missing_cursor_scope_includes_the_filters(demo: LanternApp) -> None:
    first = ask(demo, [], ["base"], formats=["nsp", "nsz", "xci"], page_size="1")
    del first
    doc: dict[str, Any] = {"schema": 1, "installed": [], "want": ["base"], "formats": ["nsp", "nsz", "xci", "xcz"]}
    page = call(demo, "POST", BASE + "/apps/missing", query={"page_size": "1"}, body=doc, Lantern_Platform="switch")
    nxt = body(page)["next"]
    assert nxt
    changes: list[dict[str, Any]] = [
        {"formats": ["nsp"]},
        {"satisfies": []},
        {"formats": ["xcz", "xci", "nsz", "nsp", "x"]},
    ]
    for changed in changes:
        r = call(
            demo,
            "POST",
            BASE + "/apps/missing",
            query={"page_size": "1", "cursor": nxt},
            body={**doc, **changed},
            Lantern_Platform="switch",
        )
        assert r.status == 400, changed
    same = call(
        demo,
        "POST",
        BASE + "/apps/missing",
        query={"page_size": "1", "cursor": nxt},
        body={**doc, "formats": ["xcz", "xci", "nsz", "nsp"]},
        Lantern_Platform="switch",
    )
    assert same.status == 200  # the same set in another order is the same listing


# The static export keeps requires and includes, and the client reads what is missing from it.


def test_static_export_and_missing(tmp_path: Path) -> None:
    """[L-21.3-2] A static library carries requires and includes, and what is missing is computed with the filters."""
    out = tmp_path / "lib"
    static.export(build_library(), out, uid="u_demo", name="Demo")
    with static.StaticLibrary(out) as s:
        apps = list(s.iter_apps("switch"))
        xcz = next(a for a in apps if a.format == "xcz")
        assert xcz.requires == ["fs-compression", "sigpatch"] and xcz.includes is not None
        everything = s.missing([], ["base"], platform="switch")
        free = s.missing([], ["base"], platform="switch", satisfies=[])
        assert xcz.id in {a.id for a in everything} and xcz.id not in {a.id for a in free}
        assert s.missing([], ["base"], platform="switch", formats=[]) == []
        have = s.missing([("0100CD3400020000", 0)], ["update"], platform="switch", formats=["xcz"])
        assert have == []
        with pytest.raises(ValueError):
            s.missing([], [], platform="switch")


def test_static_generator_reads_requires_and_includes(tmp_path: Path) -> None:
    folder = tmp_path / "in"
    (folder / "games").mkdir(parents=True)
    (folder / "games" / "a.nsz").write_bytes(b"data")
    app = {
        "path": "games/a.nsz",
        "platform": "switch",
        "title_id": "0100ABCD00010000",
        "app_id": "0100ABCD00010000",
        "type": "base",
        "version_code": 0,
        "name": "A",
        "format": "nsz",
        "requires": ["fs-compression", "fs-compression"],
        "includes": [{"app_id": "0100ABCD00010800", "version_code": 1}],
    }

    def build(meta_app: dict[str, Any]) -> Any:
        return static.build_library(folder, {"schema": 1, "apps": [meta_app]})

    lib = build(app)
    got = next(iter(lib.apps()))
    assert got.requires == ["fs-compression"] and got.includes is not None
    for bad in (
        {"requires": "sigpatch"},
        {"requires": [1]},
        {"requires": ["Bad"]},
        {"requires": ["t"] * 0 + [f"t{n}" for n in range(9)]},
        {"includes": [{"app_id": "x"}]},
        {"includes": "x"},
        {"includes": [True]},
        {"includes": [{"app_id": "0100ABCD00010800", "version_code": True}]},
    ):
        with pytest.raises(static.MetadataError):
            build({**app, **bad})


# The client.


def test_client_core_builds_the_requests() -> None:
    """[L-6.2-7] [L-6.3-1] format is a query parameter; formats and satisfies are in the body, only when given."""
    core = ClientCore("https://shelf.example.org/", platform="switch")
    call_ = core.apps(
        platform=None, type=None, format="nsz", title_id=None, q=None, sort=None, page_size=None, cursor=None
    )
    assert ("format", "nsz") in call_.query
    plain = core.apps(platform=None, type=None, title_id=None, q=None, sort=None, page_size=None, cursor=None)
    assert all(k != "format" for k, _ in plain.query)

    def sent(**kw: Any) -> dict[str, Any]:
        c = core.missing([("0100AB1200010000", 0)], ["update"], platform=None, page_size=None, cursor=None, **kw)
        assert isinstance(c.body, dict)
        return c.body

    assert "formats" not in sent() and "satisfies" not in sent()
    assert sent(formats=["nsz", "nsz"], satisfies=[])["formats"] == ["nsz"]
    assert sent(formats=["nsz"], satisfies=[])["satisfies"] == []
    assert sent(formats=[])["formats"] == []
    assert MissingRequest.from_json(sent(formats=["a"], satisfies=["b"])).satisfies == ["b"]
    for bad in (
        {"formats": "nsz"},
        {"formats": ["NSZ"]},
        {"satisfies": ["-x"]},
        {"satisfies": [f"t{n}" for n in range(17)]},
    ):
        with pytest.raises(ValueError):
            sent(**bad)


def test_sync_client_against_the_demo() -> None:
    with serve("flask") as url, LanternClient(url, token=DEMO_TOKEN, platform="switch") as c:
        nsz = list(c.iter_apps(format="nsz"))
        assert nsz and {a.format for a in nsz} == {"nsz"}
        assert c.apps(format="zzlantern").items == []
        got = list(c.iter_missing([], ["base"], formats=["nsp", "nsz"], satisfies=[]))
        assert {(a.app_id, a.format) for a in got} == {("0100AB1200010000", "nsp"), ("0100EF5600030000", "nsp")}
        page = c.missing([], ["base"], formats=[], satisfies=None)
        assert page.items == []
        chosen = [a for a in c.iter_apps() if a.app_id == "0100EF5600030000"]
        assert prefer_variant(chosen).format == "nsp"
        gate = [install_decision(a, ["nsp"], [], []) for a in chosen]
        assert sorted(g[0] for g in gate) == ["install", "unavailable"]


def test_async_client_against_the_demo() -> None:
    async def run(url: str) -> None:
        async with AsyncLanternClient(url, token=DEMO_TOKEN, platform="switch") as c:
            assert {a.format async for a in c.iter_apps(format="xcz")} == {"xcz"}
            assert (await c.apps(format="zzlantern")).items == []
            got = [a async for a in c.iter_missing([], ["base"], formats=["nsp", "nsz"], satisfies=[])]
            assert {(a.app_id, a.format) for a in got} == {("0100AB1200010000", "nsp"), ("0100EF5600030000", "nsp")}
            assert (await c.missing([], ["base"], formats=[])).items == []
            with pytest.raises(ValueError):
                await c.missing([], ["base"], satisfies=["Bad Token"])

    with serve("flask") as url:
        asyncio.run(run(url))
