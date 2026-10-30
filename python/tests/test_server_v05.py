"""The server toolkit's draft 0.5, called directly: events (the stream, long
polls, who sees what), grants, sync, deleting an account; the minimal peer
(lantern.peer); and static libraries, written by the generator and read
back."""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import lantern
from demo import DEMO_KEY, DEMO_TOKEN, GRANT_SEED, UID, build_library, demo_accounts, make_lantern
from lantern import ed25519, grants, schema, static
from lantern.models import RatingCap
from lantern.peer import Peer, held_files
from lantern.server import LanternApp, ServerResponse
from lantern.server.files import FileRef
from lantern.server.sync import MemorySync
from lantern.store import NewerOnDisk
from test_server import problem
from test_server_auth import call, doc

NOW = "2026-10-30T09:00:00.000Z"


def lantern_app(**options: Any) -> LanternApp:
    options.setdefault("accounts", demo_accounts())
    return make_lantern(build_library(), **options)


def device(app: LanternApp, user: str, scopes: tuple[str, ...], cap: RatingCap | None = None) -> str:
    assert app.accounts is not None
    token, _ = app.accounts.issue(user, f"{user}'s console", scopes, rating_cap=cap)
    return token


class Reader:
    """A stream's body, read in a thread as an adapter would: its pieces, as they come."""

    def __init__(self, response: ServerResponse) -> None:
        self.response = response
        self.text = ""
        self.lock = threading.Lock()
        self.done = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        for piece in self.response.iter_body():
            with self.lock:
                self.text += piece.decode()
        self.done.set()

    def wait_for(self, needle: str, seconds: float = 5.0) -> str:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            with self.lock:
                if needle in self.text:
                    return self.text
            time.sleep(0.02)
        raise AssertionError(f"{needle!r} not in {self.text!r}")

    def close(self) -> None:
        self.response.close()


@pytest.fixture
def app() -> Iterator[LanternApp]:
    a = lantern_app(stream_probe=0.05)
    yield a
    a.shutdown()


def test_the_handshake_of_0_5(app: LanternApp) -> None:
    hello = doc(call(app, "GET", "/.well-known/lantern", token=DEMO_TOKEN, key=DEMO_KEY))
    assert schema.validate("handshake", hello) == []
    f = hello["features"]
    assert (f["events"], f["peers"], f["sync"], f["encrypted_saves"]) == (1, 1, 1, 0)
    assert hello["limits"] == {"page_size": 500, "heartbeat": 5, "event_streams": 2, "wait": 60, "sync_items": 10000}
    assert base64.b64decode(hello["peers"]["key"]) == ed25519.public_key(GRANT_SEED)
    anon = doc(call(app, "GET", "/.well-known/lantern"))
    assert anon["peers"] == hello["peers"] and anon["features"]["sync"] == 0  # the key, the same for every caller
    with pytest.raises(ValueError, match="heartbeat"):
        lantern_app(heartbeat=2)
    with pytest.raises(ValueError, match="900"):
        lantern_app(grant_lifetime=901)


def test_the_stream(app: LanternApp) -> None:
    r = call(app, "GET", "/api/lantern/v1/events", token=DEMO_TOKEN, key=DEMO_KEY)
    assert r.status == 200 and r.streaming and r.headers["Content-Type"].startswith("text/event-stream")
    assert "Content-Length" not in r.headers and "Content-Encoding" not in r.headers
    reader = Reader(r)
    text = reader.wait_for("event: ready")
    assert text.startswith("retry: 5000\n\n")
    ready = text.split("id: ", 1)[1].split("\n", 1)[0]
    # The id of ready is a token of /v1/changes (L-18.1-1).
    assert call(app, "GET", f"/api/lantern/v1/changes?since={ready}", token=DEMO_TOKEN, key=DEMO_KEY).status == 200
    gen = doc(call(app, "GET", "/api/lantern/v1/sync", token=DEMO_TOKEN, key=DEMO_KEY))["generation"]
    item = {"key": "switch/0100AB1200010000", "value": {"platform": "switch", "title_id": "0100AB1200010000"}}
    w = call(
        app,
        "PATCH",
        "/api/lantern/v1/sync/wishes",
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        body={"schema": 1, "generation": gen, "items": [{**item, "updated": NOW}]},
    )
    assert w.status == 200
    text = reader.wait_for("event: sync")
    block = text.split("event: sync", 1)[0].rsplit("id: ", 1)[1].split("\n", 1)[0]
    assert '"collection":"wishes","rev":1' in text
    # Resumed with Last-Event-ID: the same event, with its id (L-18.1-3).
    again = Reader(call(app, "GET", "/api/lantern/v1/events", token=DEMO_TOKEN, key=DEMO_KEY, Last_Event_ID=ready))
    assert f"id: {block}\nevent: sync" in again.wait_for("event: sync")
    # A third stream of the token: 429, Retry-After within the heartbeat (L-18.4-2).
    third = call(app, "GET", "/api/lantern/v1/events", token=DEMO_TOKEN, key=DEMO_KEY)
    assert problem(third, 429, "slow_down") and int(third.headers["Retry-After"]) <= 5
    again.close()
    reader.close()
    assert app.hub is not None and app.hub.streams == 0  # the slots are free once the clients left
    # Every stream gets shutdown when the server stops (L-18.2-2).
    last = Reader(call(app, "GET", "/api/lantern/v1/events", token=DEMO_TOKEN, key=DEMO_KEY))
    last.wait_for("event: ready")
    app.shutdown()
    assert '"retry":5' in last.wait_for("event: shutdown")
    assert last.done.wait(2)


def test_who_sees_what(app: LanternApp) -> None:
    noor = device(app, "noor", ("library",))
    capped = device(app, "noor", ("library",), RatingCap(age=3))
    anon = Reader(call(app, "GET", "/api/lantern/v1/events"))
    mine = Reader(call(app, "GET", "/api/lantern/v1/events", token=noor))
    small = Reader(call(app, "GET", "/api/lantern/v1/events", token=capped, Lantern_Platform="switch"))
    for r in (anon, mine, small):
        r.wait_for("event: ready")
    gen = doc(call(app, "GET", "/api/lantern/v1/sync", token=DEMO_TOKEN, key=DEMO_KEY))["generation"]
    call(
        app,
        "PATCH",
        "/api/lantern/v1/sync/wishes",
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        body={
            "schema": 1,
            "generation": gen,
            "items": [
                {
                    "key": "switch/0100AB1200010000",
                    "value": {"platform": "switch", "title_id": "0100AB1200010000"},
                    "updated": NOW,
                }
            ],
        },
    )
    lib = app.library
    assert hasattr(lib, "add_app_file")
    lib.add_app_file(
        data=b"glow",
        platform="android",
        title_id="org.example.glow",
        app_id="org.example.glow",
        type="base",
        version_code=1,
        name="Glow",
        format="apk",
    )
    lib.add_app_file(
        data=b"drift dlc",
        platform="switch",
        title_id="0100AB1200010000",
        app_id="0100AB1200011002",
        type="dlc",
        version_code=0,
        name="Lumen Drift: Nebula Pack",
        format="nsp",
    )
    text = anon.wait_for("event: library")
    assert '"families":["apps"],"platforms":["android"]' in text
    anon.wait_for('"platforms":["switch"]')
    assert "event: sync" not in anon.text and "event: sync" not in mine.text  # another account's (L-18.2-1)
    time.sleep(0.3)
    assert "android" not in small.text  # its platform only
    # Lumen Drift is rated above the cap (PEGI 7): a change the caller cannot see gives it no event.
    assert '"platforms":["switch"]' not in small.text and "event: sync" not in small.text
    for r in (anon, mine, small):
        r.close()


def test_a_revoked_device_and_a_deleted_account_end_their_streams(app: LanternApp) -> None:
    assert app.accounts is not None
    token = device(app, "noor", ("library",))
    r = Reader(call(app, "GET", "/api/lantern/v1/events", token=token))
    r.wait_for("event: ready")
    found = next(d for d in app.accounts.devices("noor"))
    assert (
        call(app, "DELETE", f"/api/lantern/v1/admin/devices/{found.id}", token=DEMO_TOKEN, key=DEMO_KEY).status == 204
    )
    assert r.done.wait(3)  # L-18.1-8
    token = device(app, "noor", ("library",))
    r = Reader(call(app, "GET", "/api/lantern/v1/events", token=token))
    r.wait_for("event: ready")
    assert (
        call(app, "DELETE", "/api/lantern/v1/admin/users/noor?confirm=noor", token=DEMO_TOKEN, key=DEMO_KEY).status
        == 204
    )
    assert r.done.wait(3)


def test_bad_tokens_and_long_polls(app: LanternApp) -> None:
    r = call(app, "GET", "/api/lantern/v1/events", token=DEMO_TOKEN, key=DEMO_KEY, Last_Event_ID="s_nope")
    problem(r, 400, "bad_request")
    other = lantern_app()
    token = doc(call(other, "GET", "/api/lantern/v1/changes"))["since"]
    problem(call(app, "GET", "/api/lantern/v1/events", Last_Event_ID=token), 400, "bad_request")  # another secret
    for query in ("wait=5", "since=x&wait=soon"):
        problem(call(app, "GET", f"/api/lantern/v1/changes?{query}"), 400, "bad_request")
    since = doc(call(app, "GET", "/api/lantern/v1/changes"))["since"]
    t0 = time.monotonic()
    empty = doc(call(app, "GET", f"/api/lantern/v1/changes?since={since}&wait=0"))
    assert empty["events"] == [] and time.monotonic() - t0 < 1 and schema.validate("changes", empty) == []

    def later() -> None:
        time.sleep(0.3)
        lib = app.library
        assert hasattr(lib, "add_app_file")
        lib.add_app_file(
            data=b"x",
            platform="switch",
            title_id="0100EF5600030000",
            app_id="0100EF5600030800",
            type="update",
            version_code=65536,
            name="Quiet Tide",
            format="nsp",
        )

    threading.Thread(target=later).start()
    t0 = time.monotonic()
    found = doc(call(app, "GET", f"/api/lantern/v1/changes?since={since}&wait=30"))
    assert time.monotonic() - t0 < 5  # answered as soon as the event came (L-18.3-1)
    assert [e["event"] for e in found["events"]] == ["library"] and len(found["added"]) == 1
    assert doc(call(app, "GET", f"/api/lantern/v1/changes?since={found['since']}&wait=0"))["events"] == []
    quiet = lantern_app(events=False)
    assert doc(call(quiet, "GET", "/.well-known/lantern"))["features"]["events"] == 0
    problem(call(quiet, "GET", "/api/lantern/v1/events"), 404, "not_found")


def test_grants(app: LanternApp) -> None:
    lib = app.library
    a = next(x for x in lib.apps() if x.name == "Lumen Drift")
    r = call(app, "GET", f"/api/lantern/v1/grants/sha256/{a.sha256}")
    g = doc(r)
    assert schema.validate("grant", g) == [] and r.headers["Cache-Control"] == "no-store"
    found = grants.read_grant(g["grant"], {UID: ed25519.public_key(GRANT_SEED)})
    assert found is not None and (found.sha256, found.size) == (a.sha256, a.size)
    assert found.exp <= time.time() + 600 + 5
    package = next(e for e in lib.homebrew(()) if e.platform == "linux").package
    assert doc(call(app, "GET", f"/api/lantern/v1/grants/sha256/{package.sha256}"))["size"] == package.size
    problem(call(app, "GET", f"/api/lantern/v1/grants/sha256/{'0' * 64}"), 404, "not_found")
    problem(call(app, "GET", f"/api/lantern/v1/grants/sha256/{a.sha256}?platform=android"), 404, "not_found")
    problem(call(lantern_app(grant_seed=None), "GET", f"/api/lantern/v1/grants/sha256/{a.sha256}"), 404, "not_found")


def test_sync(app: LanternApp) -> None:
    def sync(method: str, path: str, body: Any = None, **h: str) -> ServerResponse:
        return call(app, method, "/api/lantern/v1/sync" + path, token=DEMO_TOKEN, key=DEMO_KEY, body=body, **h)

    problem(call(app, "GET", "/api/lantern/v1/sync"), 401, "unauthorized")
    over = doc(sync("GET", ""))
    assert schema.validate("sync", over) == [] and over["device"].startswith("d_") and len(over["device"]) == 18
    gen = over["generation"]
    wish = {
        "key": "switch/0100AB1200010000",
        "value": {"platform": "switch", "title_id": "0100AB1200010000", "note": "For the holidays"},
        "updated": NOW,
    }
    out = doc(sync("PATCH", "/wishes", {"schema": 1, "generation": gen, "items": [wish]}))
    assert schema.validate("sync-collection", out) == [] and out["items"][0]["rev"] == 1
    older = {**wish, "value": {"platform": "switch", "title_id": "0100AB1200010000"}, "updated": "2026-10-30T08:00:00Z"}
    assert (
        doc(sync("PATCH", "/wishes", {"schema": 1, "generation": gen, "items": [older]}))["items"][0] == out["items"][0]
    )
    gone = {"key": wish["key"], "deleted": True, "updated": NOW}
    assert doc(sync("PATCH", "/wishes", {"schema": 1, "generation": gen, "items": [gone]}))["rev"] == 2
    since = doc(sync("GET", "/wishes?since=1"))
    assert [i.get("deleted") for i in since["items"]] == [True]
    assert doc(sync("GET", "/wishes"))["items"] == []  # without since: no deletions
    problem(
        sync("PATCH", "/wishes", {"schema": 1, "generation": gen, "items": [wish]}, If_Match=f'"{gen}-1"'),
        412,
        "precondition_failed",
    )
    assert (
        sync(
            "PATCH",
            "/wishes",
            {"schema": 1, "generation": gen, "items": [{**wish, "updated": "2026-10-30T09:00:01Z"}]},
            If_Match=f'"{gen}-2"',
        ).status
        == 200
    )
    problem(sync("PATCH", "/wishes", {"schema": 1, "generation": "g_other", "items": [wish]}), 409, "conflict")
    for bad in (
        {"key": "Frostline Tales", "value": {}, "updated": NOW},
        {**gone, "updated": "yesterday"},
        {**wish, "deleted": True},
        {**wish, "rev": 3},
        {**wish, "value": {"platform": "switch", "title_id": "0100EF5600030000"}},
    ):
        problem(sync("PATCH", "/wishes", {"schema": 1, "generation": gen, "items": [bad]}), 400, "bad_request")
    problem(sync("PATCH", "/wishes", {"schema": 1, "generation": gen, "items": [wish, wish]}), 400, "bad_request")
    mine = {
        "key": over["device"],
        "value": {
            "device": "Mira's console",
            "platform": "switch",
            "apps": [{"app_id": "0100AB1200010000", "version_code": 0}],
        },
        "updated": NOW,
    }
    assert sync("PATCH", "/installed", {"schema": 1, "generation": gen, "items": [mine]}).status == 200
    other = {**mine, "key": "d_0000000000000000"}
    problem(sync("PATCH", "/installed", {"schema": 1, "generation": gen, "items": [other]}), 403, "forbidden")
    problem(sync("GET", "/bookmarks"), 404, "not_found")
    problem(sync("GET", "/wishes?since=99"), 400, "bad_request")
    assert sync("DELETE", "/installed").status == 204
    after = doc(sync("GET", ""))
    assert after["generation"] != gen and after["collections"]["installed"] == {"rev": 0, "items": 0}
    assert sync("DELETE", "").status == 204
    assert all(c["items"] == 0 for c in doc(sync("GET", ""))["collections"].values())
    noor = device(app, "noor", ("library",))
    problem(call(app, "GET", "/api/lantern/v1/sync", token=noor), 403, "forbidden")


def test_sync_pages_tombstones_and_limits() -> None:
    store = MemorySync(limit=3)
    a = lantern_app(sync=store)
    gen = doc(call(a, "GET", "/api/lantern/v1/sync", token=DEMO_TOKEN, key=DEMO_KEY))["generation"]
    items = [
        {
            "key": f"switch/0100AB12000{i}0000",
            "value": {"platform": "switch", "title_id": f"0100AB12000{i}0000"},
            "updated": NOW,
        }
        for i in range(1, 4)
    ]
    w = call(
        a,
        "PATCH",
        "/api/lantern/v1/sync/wishes",
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        body={"schema": 1, "generation": gen, "items": items},
    )
    assert w.status == 200
    page = doc(call(a, "GET", "/api/lantern/v1/sync/wishes?page_size=2", token=DEMO_TOKEN, key=DEMO_KEY))
    assert len(page["items"]) == 2 and page["next"]
    rest = doc(
        call(a, "GET", f"/api/lantern/v1/sync/wishes?page_size=2&cursor={page['next']}", token=DEMO_TOKEN, key=DEMO_KEY)
    )
    assert len(rest["items"]) == 1 and rest["next"] is None
    more = [
        {
            "key": "switch/0100AB1200050000",
            "value": {"platform": "switch", "title_id": "0100AB1200050000"},
            "updated": NOW,
        }
    ]
    problem(
        call(
            a,
            "PATCH",
            "/api/lantern/v1/sync/wishes",
            token=DEMO_TOKEN,
            key=DEMO_KEY,
            body={"schema": 1, "generation": gen, "items": more},
        ),
        413,
        "too_large",
    )
    # A deletion kept longer than its retention is dropped, and a since before it gives 410 (§ 20.3).
    short = MemorySync(retention=__import__("datetime").timedelta(seconds=-1))
    b = lantern_app(sync=short)
    gen = doc(call(b, "GET", "/api/lantern/v1/sync", token=DEMO_TOKEN, key=DEMO_KEY))["generation"]
    call(
        b,
        "PATCH",
        "/api/lantern/v1/sync/wishes",
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        body={"schema": 1, "generation": gen, "items": [{"key": items[0]["key"], "deleted": True, "updated": NOW}]},
    )
    problem(call(b, "GET", "/api/lantern/v1/sync/wishes?since=0", token=DEMO_TOKEN, key=DEMO_KEY), 410, "gone")


def test_deleting_an_account(app: LanternApp) -> None:
    assert app.accounts is not None and app.sync is not None
    token = device(app, "noor", ("library",))
    app.sync.merge(
        "noor",
        "wishes",
        app.sync.overview("noor")[0],
        [lantern.sync.Item("switch/0100AB1200010000", NOW, {"platform": "switch", "title_id": "0100AB1200010000"})],
        if_match=None,
        now=__import__("datetime").datetime.now(__import__("datetime").UTC),
        skew=300,
    )
    path = "/api/lantern/v1/admin/users/noor"
    problem(call(app, "DELETE", path, token=DEMO_TOKEN, key=DEMO_KEY), 400, "bad_request")
    problem(call(app, "DELETE", path + "?confirm=noorx", token=DEMO_TOKEN, key=DEMO_KEY), 400, "bad_request")
    problem(
        call(app, "DELETE", "/api/lantern/v1/admin/users/mira?confirm=mira", token=DEMO_TOKEN, key=DEMO_KEY),
        409,
        "conflict",
    )
    assert call(app, "DELETE", path + "?confirm=noor", token=DEMO_TOKEN, key=DEMO_KEY).status == 204
    problem(call(app, "GET", "/api/lantern/v1/", token=token), 401, "unauthorized")
    problem(call(app, "DELETE", path + "?confirm=noor", token=DEMO_TOKEN, key=DEMO_KEY), 404, "not_found")
    assert app.accounts.user("noor") is None and app.accounts.devices("noor") == []
    assert app.sync.overview("noor")[1]["wishes"] == (0, 0)  # an account made again with the name inherits nothing


def test_pairings_waiting_are_events(app: LanternApp) -> None:
    r = Reader(call(app, "GET", "/api/lantern/v1/events", token=DEMO_TOKEN, key=DEMO_KEY))
    r.wait_for("event: ready")
    body = {
        "schema": 1,
        "device": "Ines's console",
        "scopes": ["library"],
        "key": {"alg": "ed25519", "public_key": base64.b64encode(bytes(DEMO_KEY.public)).decode()},
    }
    code = doc(call(app, "POST", "/api/lantern/v1/pairing", body=body))["code"]
    text = r.wait_for("event: pairing")
    data = json.loads(text.split("event: pairing\ndata: ", 1)[1].split("\n", 1)[0])
    assert data["code"] == code and data["device"] == "Ines's console" and data["key"] == DEMO_KEY.fingerprint
    r.close()


# The peer (SPEC.md § 19.4).


def peer_of(app: LanternApp, **options: Any) -> Peer:
    lib = app.library
    files: dict[str, FileRef] = {}
    for a in lib.apps():
        ref = lib.file(a.file.rsplit("/", 1)[1])
        assert ref is not None
        files[a.sha256] = ref
    return Peer(("127.0.0.1", 0), files, {UID: ed25519.public_key(GRANT_SEED)}, **options)


def ask(peer: Peer, path: str, remote: str = "192.168.1.30", method: str = "GET", **headers: str) -> ServerResponse:
    from lantern.http import Headers
    from lantern.server import ServerRequest

    h = Headers({k.replace("_", "-"): v for k, v in headers.items()})
    try:
        return peer.answer(ServerRequest(method, path, {}, h, remote=remote, target=path))
    except lantern.server.ProblemError as e:
        return lantern.server.problem_response(ServerRequest(method, path, {}, h), e)


def test_the_peer(app: LanternApp) -> None:
    peer = peer_of(app, rate=(100, 1.0), slots=1)
    try:
        a = next(x for x in app.library.apps() if x.size > 100)
        grant = doc(call(app, "GET", f"/api/lantern/v1/grants/sha256/{a.sha256}"))["grant"]
        path = f"/lantern/v1/blobs/sha256/{a.sha256}"
        r = ask(peer, path)
        assert problem(r, 403, "forbidden") and "WWW-Authenticate" not in r.headers  # L-19.4-5
        problem(ask(peer, path, Lantern_Grant=grant + "x"), 403, "forbidden")
        problem(ask(peer, f"/lantern/v1/blobs/sha256/{'f' * 64}", Lantern_Grant=grant), 403, "forbidden")
        problem(ask(peer, path, remote="203.0.113.9", Lantern_Grant=grant), 403, "forbidden")  # not its network
        problem(ask(peer, "/lantern/v1/saves/x", Lantern_Grant=grant), 404, "not_found")
        ok = ask(peer, path, Lantern_Grant=grant, Range="bytes=1-")
        assert ok.status == 206 and ok.headers["Repr-Digest"]
        body = b"".join(ok.iter_body())
        assert len(body) == a.size - 1
        held = ask(peer, path, Lantern_Grant=grant)
        problem(ask(peer, path, Lantern_Grant=grant), 429, "slow_down")  # one slot, taken
        b"".join(held.iter_body())
        assert ask(peer, path, method="HEAD", Lantern_Grant=grant).status == 200
        other = doc(
            call(
                app,
                "GET",
                f"/api/lantern/v1/grants/sha256/{next(iter(e for e in app.library.homebrew(()))).package.sha256}",
            )
        )
        problem(
            ask(peer, f"/lantern/v1/blobs/sha256/{other['sha256']}", Lantern_Grant=other["grant"]), 404, "not_found"
        )
        reply = peer.reply(
            b'{"schema":1,"lantern":"discover","peers":true}',
            "192.168.1.30",
            __import__("lantern.server.pairing", fromlist=["Limiter"]).Limiter(5, 1.0),
        )
        assert reply is not None and schema.validate("discovery-peer", json.loads(reply)) == []
        assert (
            peer.reply(
                b'{"schema":1,"lantern":"discover"}',
                "192.168.1.30",
                __import__("lantern.server.pairing", fromlist=["Limiter"]).Limiter(5, 1.0),
            )
            is None
        )
    finally:
        peer.server_close()
    limited = peer_of(app, rate=(3, 60.0))
    try:
        for _ in range(3):
            ask(limited, "/lantern/v1/blobs/sha256/" + "0" * 64)
        r = ask(limited, "/lantern/v1/blobs/sha256/" + "0" * 64)
        assert problem(r, 429, "slow_down") and r.headers["Retry-After"].isdigit()
    finally:
        limited.server_close()
    with pytest.raises(ValueError, match="plain HTTP"):
        Peer(("192.0.2.10", 0), {}, {})


def test_held_files(tmp_path: Path) -> None:
    (tmp_path / "games").mkdir()
    (tmp_path / "games" / "frost.nsp").write_bytes(b"frostline")
    (tmp_path / ".saves").mkdir()
    (tmp_path / ".saves" / "save.zip").write_bytes(b"frostline")
    (tmp_path / "other.bin").write_bytes(b"other")
    sha = __import__("hashlib").sha256(b"frostline").hexdigest()
    found = held_files(tmp_path, {(sha, 9)})
    assert list(found) == [sha] and found[sha].path.endswith("frost.nsp")


# Static libraries (SPEC.md § 21): the generator, and the reader.


def test_export_and_read_back(tmp_path: Path) -> None:
    lib = build_library()
    out = tmp_path / "library"
    done = static.export(lib, out, uid=UID, name="Demo shelf", page_size=3)
    assert done["platforms"] == ["3ds", "android", "linux", "switch"]
    hello = json.loads((out / "lantern.json").read_text())
    assert schema.validate("handshake", hello) == [] and hello["base"] == "."
    assert all(hello["features"][f] == 0 for f in static.NOT_STATIC)
    with static.StaticLibrary(out) as s:
        assert s.handshake().static is not None
        apps = list(s.iter_apps("switch"))
        assert len(apps) == 7 and all(static.relative_ok(a.file) for a in apps)
        assert [a.name for a in s.missing([("0100AB1200010000", 0)], ["update", "dlc"], platform="switch")] == [
            "Lumen Drift",
            "Lumen Drift: Comet Pack",
        ]
        assert s.title("switch", "0100AB1200010000").name == "Lumen Drift"
        entry = s.homebrew_entry("linux", "org.example.harborglow")
        assert entry.package.manifest  # the entry's file keeps its manifests; its page does not
        assert all(e.package.manifest is None for e in s.iter_homebrew("linux"))
        assert [e.id for e in s.homebrew_updates([("org.example.harborglow", 1)], platform="linux")] == [entry.id]
        sets = s.cheats("switch", "0100AB1200010000")
        assert sets and s.cheat_text(sets[0])
        assert s.cheats("switch", "0100EF5600030000") == []  # no file of them
        got = s.download(apps[0], tmp_path / "a.bin")
        assert got.stat().st_size == apps[0].size
        assert list(s.iter_apps("ps4")) == []  # not one of its platforms
    with static.StaticLibrary(out.as_uri()) as s:
        assert len(list(s.iter_apps("switch"))) == 7


def test_the_reader_refuses(tmp_path: Path) -> None:
    out = tmp_path / "library"
    static.export(build_library(), out, uid=UID, name="Demo shelf")
    page = out / "v1/apps/switch/pages/1.json"
    doc_ = json.loads(page.read_text())
    doc_["items"][0]["file"] = "https://elsewhere.example.org/x.nsp"
    doc_["x-later"] = {"a field": "of a later version"}
    page.write_text(json.dumps(doc_))
    s = static.StaticLibrary(out)
    first = next(iter(s.iter_apps("switch")))
    with pytest.raises(lantern.DocumentError):
        s.download(first, tmp_path / "x")  # a file not relative to the root (L-21.1-2)
    doc_["schema"] = 2
    page.write_text(json.dumps(doc_))
    with pytest.raises(lantern.NewerSchema):
        list(s.iter_apps("switch"))
    hello = json.loads((out / "lantern.json").read_text())
    (out / "lantern.json").write_text(json.dumps({**hello, "x-later": 1}))
    assert static.StaticLibrary(out).handshake().extra == {"x-later": 1}  # an unknown field, kept and skipped
    (out / "lantern.json").write_text(json.dumps({**hello, "schema": 2}))
    with pytest.raises(lantern.NewerSchema):
        static.StaticLibrary(out).handshake()
    (out / "lantern.json").unlink()
    with pytest.raises(lantern.NotFound):
        static.StaticLibrary(out).handshake()
    with pytest.raises(lantern.InsecureTransport):
        static.StaticLibrary("http://lea.example.org/library/")
    first_app = json.loads(page.read_text())["items"][1]
    blob = out / first_app["file"]
    blob.write_bytes(b"another file")
    (out / "lantern.json").write_text(json.dumps(hello))
    page.write_text(json.dumps({**doc_, "schema": 1, "items": json.loads(page.read_text())["items"]}))
    victim = next(a for a in static.StaticLibrary(out).iter_apps("switch") if a.file.endswith(blob.name))
    with pytest.raises(lantern.IntegrityError):
        static.StaticLibrary(out).download(victim, tmp_path / "y")
    assert not (tmp_path / "y").exists() and not (tmp_path / "y.part").exists()


def test_an_export_keeps_what_it_must(tmp_path: Path) -> None:
    out = tmp_path / "library"
    static.export(build_library(), out, uid=UID, name="Demo shelf")
    hello = json.loads((out / "lantern.json").read_text())
    (out / "lantern.json").write_text(json.dumps({**hello, "x-mirror-note": "kept"}))
    (out / "index.html").write_text("Lea's page")
    static.export(build_library(), out, uid=UID, name="Demo shelf")
    again = json.loads((out / "lantern.json").read_text())
    assert again["x-mirror-note"] == "kept" and (out / "index.html").exists()  # unknown keys, and what is not its own
    (out / "lantern.json").write_text(json.dumps({**hello, "schema": 2}))
    with pytest.raises(NewerOnDisk):
        static.export(build_library(), out, uid=UID, name="Demo shelf")
    assert json.loads((out / "lantern.json").read_text())["schema"] == 2  # never written over
    other = tmp_path / "not-mine"
    (other / "v1").mkdir(parents=True)
    with pytest.raises(ValueError, match="not an earlier export"):
        static.export(build_library(), other, uid=UID, name="Demo shelf")


def metadata(folder: Path) -> dict[str, Any]:
    (folder / "games").mkdir(parents=True)
    (folder / "games" / "frost.nsz").write_bytes(b"Frostline Tales, a fictional game" * 10)
    (folder / "cheats").mkdir()
    (folder / "cheats" / "frost.txt").write_text("[Infinite lanterns]\n04000000 0000AAAA 00000063\n")
    import zipfile

    with zipfile.ZipFile(folder / "lamp.zip", "w") as z:
        z.writestr("switch/org.example.paperlamp/paperlamp.nro", b"a fictional homebrew")
    return {
        "schema": 1,
        "name": "Lea's library",
        "x-later": "a field of a later version, skipped",
        "apps": [
            {
                "path": "games/frost.nsz",
                "platform": "switch",
                "title_id": "0100ABCD00010000",
                "app_id": "0100ABCD00010000",
                "type": "base",
                "version_code": 0,
                "name": "Frostline Tales",
                "format": "nsz",
                "mirrors": ["https://mirror.example.org/frost.nsz"],
            }
        ],
        "titles": [
            {
                "platform": "switch",
                "title_id": "0100ABCD00010000",
                "name": "Frostline Tales",
                "icon": {"url": "https://images.example.org/frost.png"},
            }
        ],
        "homebrew": [
            {
                "path": "lamp.zip",
                "format": "zip",
                "entry": {
                    "id": "org.example.paperlamp",
                    "platform": "switch",
                    "kind": "app",
                    "name": "Paper Lamp",
                    "version": "1.0",
                    "build": 1,
                },
            }
        ],
        "cheats": [
            {
                "platform": "switch",
                "title_id": "0100ABCD00010000",
                "build_id": "4A1B2C3D4E5F6071",
                "source": "Lea",
                "path": "cheats/frost.txt",
            }
        ],
    }


def test_the_generator_from_the_command_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src, out = tmp_path / "src", tmp_path / "out"
    meta = metadata(src)
    (src / static.METADATA).write_text(json.dumps(meta))
    assert static.main([str(src), "--out", str(out), "--page-size", "10"]) == 0
    hello = json.loads((out / "lantern.json").read_text())
    assert hello["name"] == "Lea's library" and hello["features"]["cheats"] == 1
    uid = hello["uid"]
    with static.StaticLibrary(out) as s:
        (app_,) = list(s.iter_apps("switch"))
        assert app_.mirrors and app_.mirrors[0].url.startswith("https://")
        assert s.title("switch", "0100ABCD00010000").icon.external is True  # type: ignore[union-attr]
        assert s.homebrew_entry("switch", "org.example.paperlamp").package.manifest
    assert static.main([str(src), "--out", str(out)]) == 0
    assert json.loads((out / "lantern.json").read_text())["uid"] == uid  # the uid an earlier export gave
    # The metadata file: absent, of a newer schema, without one: nothing written.
    before = (out / "lantern.json").read_bytes()
    assert static.main([str(src), "--out", str(out), "--metadata", str(src / "none.json")]) == 2
    (src / "newer.json").write_text(json.dumps({**meta, "schema": 2}))
    assert static.main([str(src), "--out", str(out), "--metadata", str(src / "newer.json")]) == 2
    (src / "bare.json").write_text(json.dumps({"apps": []}))
    assert static.main([str(src), "--out", str(out), "--metadata", str(src / "bare.json")]) == 2
    (src / "bad.json").write_text(json.dumps({**meta, "apps": [{**meta["apps"][0], "path": "../outside.nsz"}]}))
    assert static.main([str(src), "--out", str(out), "--metadata", str(src / "bad.json")]) == 2
    assert (out / "lantern.json").read_bytes() == before
    err = capsys.readouterr().err
    assert "newer" in err and "no metadata file" in err
