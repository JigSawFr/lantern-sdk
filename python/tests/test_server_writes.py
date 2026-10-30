"""The server toolkit's families that clients write, called directly:
save backups (one request, resumable uploads, pruning, encrypted backups
kept as sent), cheat sets written, requests and their answers, sections;
their events, rating caps and scopes; an account deleted with its data; and
the file-backed save store and its index's schema."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from demo import DEMO_KEY, DEMO_TOKEN, build_library, demo_accounts, make_lantern
from lantern import e2e, schema
from lantern._base import DocumentError
from lantern.digest import format_digest
from lantern.models import RatingCap
from lantern.server import FileSaveStore, LanternApp, MemoryLibrary, MemorySaveStore, SaveLimits, ServerResponse
from lantern.server import app as app_module
from test_server import problem
from test_server_auth import call, doc
from test_server_v05 import Reader, device

V1 = "/api/lantern/v1"
TITLE = "0500ABCDEF120000"  # a Switch title id none of the demo's games has


def lantern_app(**options: Any) -> LanternApp:
    options.setdefault("accounts", demo_accounts())
    options.setdefault("stream_probe", 0.05)
    return make_lantern(build_library(), **options)


@pytest.fixture
def app() -> Any:
    a = lantern_app()
    yield a
    a.shutdown()


def member(app: LanternApp, name: str, scopes: tuple[str, ...]) -> str:
    """A token of `name`'s, whose account now holds `scopes`."""
    assert app.accounts is not None
    app.accounts.update_user(name, scopes=scopes)
    return device(app, name, scopes)


def mira(app: LanternApp, method: str, path: str, **options: Any) -> ServerResponse:
    return call(app, method, path, token=DEMO_TOKEN, key=DEMO_KEY, **options)


def archive(size: int = 300, label: str = "save") -> bytes:
    """A small zip, as a save's archive (fictional bytes)."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"{label}/slot.dat", hashlib.sha256(label.encode()).digest() * (size // 32 + 1))
    return out.getvalue()


def post_save(
    app: LanternApp, data: bytes, title: str = TITLE, *, token: str | None = None, **headers: str | None
) -> Any:
    headers.setdefault("Content_Digest", format_digest(hashlib.sha256(data).hexdigest()))
    headers.setdefault("Content_Type", "application/zip")
    headers.setdefault("Lantern_Platform", "switch")
    path = f"{V1}/saves/{title}"
    if token is not None:
        return raw_call(app, "POST", path, data, token=token, **headers)
    return raw_call(app, "POST", path, data, token=DEMO_TOKEN, key=DEMO_KEY, **headers)


def raw_call(app: LanternApp, method: str, path: str, data: bytes, **options: Any) -> ServerResponse:
    """A request with a body of bytes, signed when given a key (its Content-Digest then the body's own)."""
    from lantern import signatures as sig
    from lantern.http import Headers
    from lantern.server import ServerRequest

    key = options.pop("key", None)
    token = options.pop("token", None)
    h = Headers({"Host": "shelf.example.org", **{k.replace("_", "-"): v for k, v in options.items() if v is not None}})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    if key is not None:
        given = h.get("Content-Digest")
        sig.sign_request(key, method, f"https://shelf.example.org{path}", h, data or None)
        if given is not None:
            h["Content-Digest"] = given  # the test's own, even a wrong one (its signature then refused)
    return app.handle(ServerRequest(method, path, {}, h, data, scheme="https", target=path, remote="192.0.2.7"))


def test_the_handshake_offers_every_family(app: LanternApp) -> None:
    hello = doc(mira(app, "GET", "/.well-known/lantern"))
    assert schema.validate("handshake", hello) == []
    assert all(v == 1 for v in hello["features"].values()), hello["features"]
    limits = hello["limits"]
    assert (limits["save_body"], limits["save_size"], limits["saves_kept_per_title"]) == (8 << 20, 1 << 30, 10)
    anon = doc(call(app, "GET", "/.well-known/lantern"))["features"]
    assert (anon["saves"], anon["requests"], anon["encrypted_saves"], anon["sections"]) == (0, 0, 0, 1)
    noor = device(app, "noor", ("library",))
    f = doc(call(app, "GET", "/.well-known/lantern", token=noor))["features"]
    assert (f["saves"], f["requests"], f["cheats"], f["encrypted_saves"]) == (0, 0, 0, 0)
    off = doc(mira(lantern_app(encrypted_saves=False), "GET", "/.well-known/lantern"))["features"]
    assert (off["saves"], off["encrypted_saves"]) == (1, 0)
    bare = make_lantern(build_library(), accounts=demo_accounts(), saves=None, requests=None)
    f = doc(mira(bare, "GET", "/.well-known/lantern"))
    assert (f["features"]["saves"], f["features"]["requests"], f["features"]["encrypted_saves"]) == (0, 0, 0)
    assert "save_body" not in f["limits"]
    problem(mira(bare, "GET", V1 + "/saves"), 404, "not_found")
    problem(mira(bare, "GET", V1 + "/requests"), 404, "not_found")
    with pytest.raises(ValueError, match="save limits"):
        SaveLimits(body=2, size=1)


def test_sections(app: LanternApp) -> None:
    r = call(app, "GET", V1 + "/sections")
    found = doc(r)
    assert schema.validate("sections", found) == []
    assert [s["id"] for s in found["sections"]] == ["new", "co-op"]
    apps = {a.id: a for a in app.library.apps()}
    assert all(i in apps for s in found["sections"] for i in s["apps"])
    android = doc(call(app, "GET", V1 + "/sections", Lantern_Platform="android"))["sections"]
    assert [s["id"] for s in android] == ["new"]  # a shelf with nothing of the platform is left out
    assert all(apps[i].platform == "android" for i in android[0]["apps"])
    capped = device(app, "noor", ("library",), RatingCap(age=3))
    shown = doc(call(app, "GET", V1 + "/sections", token=capped))["sections"]
    assert all(apps[i].title_id != "0100AB1200010000" for s in shown for i in s["apps"])  # rated PEGI 7
    assert "co-op" not in [s["id"] for s in shown]
    lib = app.library
    assert isinstance(lib, MemoryLibrary)
    with pytest.raises(ValueError):
        lib.add_section("", "Nothing", [])
    bare = make_lantern(MemoryLibrary(families=("library",)), accounts=demo_accounts())
    assert doc(call(bare, "GET", "/.well-known/lantern"))["features"]["sections"] == 0
    problem(call(bare, "GET", V1 + "/sections"), 404, "not_found")


def test_a_save_in_one_request(app: LanternApp) -> None:
    data = archive()
    r = post_save(
        app,
        data,
        Lantern_Save_Kind="account",
        Lantern_Save_Slot="slot-1",
        Lantern_Game_Version="65536",
        Lantern_Profile=quote("Léa"),
        Lantern_Note=quote("Chapter 4"),
    )
    assert r.status == 201, r.body
    entry = doc(r)
    assert schema.validate("save", entry) == []
    assert (entry["size"], entry["sha256"]) == (len(data), hashlib.sha256(data).hexdigest())
    assert (entry["kind"], entry["slot"], entry["game_version_code"], entry["profile"], entry["note"]) == (
        "account",
        "slot-1",
        65536,
        "Léa",
        "Chapter 4",
    )
    assert entry["device"] == "Mira's console" and entry["platform"] == "switch"
    listed = doc(mira(app, "GET", f"{V1}/saves?title_id={TITLE}"))
    assert schema.validate("saves", listed) == [] and [s["save_id"] for s in listed["saves"]] == [entry["save_id"]]
    path = f"{V1}/saves/{TITLE}/{entry['save_id']}"
    whole = mira(app, "GET", path)
    assert whole.status == 200 and whole.body == data
    assert whole.headers["Repr-Digest"] == format_digest(entry["sha256"])
    part = mira(app, "GET", path, Range="bytes=10-19")
    assert part.status == 206 and part.body == data[10:20]
    assert mira(app, "DELETE", path).status == 204
    problem(mira(app, "GET", path), 404, "not_found")
    problem(mira(app, "DELETE", path), 404, "not_found")


def test_what_a_save_in_one_request_refuses(app: LanternApp) -> None:
    data = archive()
    t = device(app, "mira", ("library", "saves"))  # not bound to a key: its requests are not signed
    problem(post_save(app, data, token=t, Content_Digest=None), 400, "bad_request")
    wrong = format_digest(hashlib.sha256(data + b"!").hexdigest())
    problem(post_save(app, data, token=t, Content_Digest=wrong), 422, "digest_mismatch")
    problem(post_save(app, data, token=t, Lantern_Platform=""), 400, "bad_request")  # a platform is needed (L-4.3-4)
    problem(post_save(app, data, token=t, title="not-a-switch-id"), 400, "bad_request")
    problem(post_save(app, data, token=t, Lantern_Save_Kind="memory"), 400, "bad_request")
    problem(post_save(app, data, token=t, Lantern_Save_Slot="a/b"), 400, "bad_request")
    problem(post_save(app, data, token=t, Lantern_Game_Version="1.2"), 400, "bad_request")
    problem(post_save(app, data, token=t, Lantern_Profile=quote("L" * 65)), 400, "bad_request")
    problem(post_save(app, data, token=t, Lantern_Note="%FF"), 400, "bad_request")
    problem(post_save(app, b"not a zip at all", token=t), 400, "bad_request")
    small = lantern_app(save_limits=SaveLimits(body=100, size=1000))
    problem(post_save(small, data), 413, "too_large")
    noor = device(app, "noor", ("library",))
    problem(post_save(app, data, token=noor), 403, "forbidden")
    problem(raw_call(app, "POST", f"{V1}/saves/{TITLE}", data, Lantern_Platform="switch"), 401, "unauthorized")
    assert doc(mira(app, "GET", V1 + "/saves"))["saves"] == []


def test_resumable_uploads(app: LanternApp) -> None:
    app.save_limits = SaveLimits(chunk=1000)
    data = archive(2500)
    sha = hashlib.sha256(data).hexdigest()
    opened = mira(
        app,
        "POST",
        f"{V1}/saves/{TITLE}/uploads",
        Lantern_Platform="switch",
        body={"schema": 1, "size": len(data), "sha256": sha, "kind": "device", "profile": "Noor"},
    )
    assert opened.status == 201, opened.body
    up = doc(opened)
    assert schema.validate("upload", up) == [] and up["chunk_size"] == 1000 and up["offset"] == 0
    assert opened.headers["Location"] == up["upload"]
    address = up["upload"]

    def patch(offset: int, chunk: bytes, **headers: str) -> ServerResponse:
        headers.setdefault("Content_Type", "application/offset+octet-stream")
        return raw_call(
            app, "PATCH", address, chunk, token=DEMO_TOKEN, key=DEMO_KEY, Upload_Offset=str(offset), **headers
        )

    r = patch(0, data[:1000])
    assert r.status == 204 and r.headers["Upload-Offset"] == "1000"
    head = mira(app, "HEAD", address)
    assert head.status == 204 and (head.headers["Upload-Offset"], head.headers["Upload-Length"]) == (
        "1000",
        str(len(data)),
    )
    wrong = patch(0, data[:1000])
    problem(wrong, 409, "conflict")
    assert wrong.headers["Upload-Offset"] == "1000"
    problem(patch(1000, data[1000:2001]), 413, "too_large")
    problem(patch(1000, data[1000:2000], Content_Type="application/octet-stream"), 400, "bad_request")
    problem(patch(1000, data[1000:2000], Content_Digest=format_digest("0" * 64)), 422, "digest_mismatch")
    assert mira(app, "HEAD", address).headers["Upload-Offset"] == "1000"  # a chunk refused is not kept
    noor = member(app, "noor", ("library", "saves"))
    assert call(app, "HEAD", address, token=noor).status == 404  # only its account sees an upload
    assert patch(1000, data[1000:2000]).status == 204
    done = patch(2000, data[2000:])
    assert done.status == 201 and done.headers["Upload-Offset"] == str(len(data))
    entry = doc(done)
    assert (entry["sha256"], entry["kind"], entry["profile"]) == (sha, "device", "Noor")
    assert mira(app, "HEAD", address).status == 404
    assert mira(app, "GET", f"{V1}/saves/{TITLE}/{entry['save_id']}").body == data
    # An archive that does not match its sha256: 422, and the upload is gone.
    up = doc(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": 100, "sha256": "0" * 64},
        )
    )
    address = up["upload"]
    problem(patch(0, data[:100]), 422, "digest_mismatch")
    assert mira(app, "HEAD", address).status == 404
    # Abandoned, and too large.
    address = doc(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": 10, "sha256": "0" * 64},
        )
    )["upload"]
    assert mira(app, "DELETE", address).status == 204
    assert mira(app, "HEAD", address).status == 404
    problem(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": (1 << 30) + 1, "sha256": "0" * 64},
        ),
        413,
        "too_large",
    )
    problem(
        mira(app, "POST", f"{V1}/saves/{TITLE}/uploads", body={"schema": 1, "size": 1, "sha256": "0" * 64}),
        400,
        "bad_request",
    )
    problem(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 2, "size": 1, "sha256": "0" * 64},
        ),
        422,
        "unsupported_schema",
    )
    problem(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": 1, "sha256": "ABC"},
        ),
        400,
        "bad_request",
    )
    # An upload not finished in time is gone.
    address = doc(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": 10, "sha256": "0" * 64},
        )
    )["upload"]
    assert app.saves is not None
    session = app.saves.upload(address.rsplit("/", 1)[1])
    assert session is not None
    store = app.saves
    assert isinstance(store, MemorySaveStore)
    store._uploads[session.id][0].expires = "2020-01-01T00:00:00Z"
    assert mira(app, "HEAD", address).status == 404
    assert store.uploads() == []


def test_an_empty_save_by_upload(app: LanternApp) -> None:
    out = io.BytesIO()
    zipfile.ZipFile(out, "w").close()
    data = out.getvalue()
    up = doc(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        )
    )
    r = raw_call(
        app,
        "PATCH",
        up["upload"],
        data,
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        Upload_Offset="0",
        Content_Type="application/offset+octet-stream",
    )
    assert r.status == 201, r.body


def test_newest_first_and_the_oldest_dropped(app: LanternApp) -> None:
    app.save_limits = SaveLimits(kept=2)
    made = []
    for i in range(3):
        made.append(doc(post_save(app, archive(100, f"save{i}")))["save_id"])
    other = doc(post_save(app, archive(100, "other"), title="0500ABCDEF130000"))["save_id"]
    listed = doc(mira(app, "GET", V1 + "/saves"))["saves"]
    assert [s["save_id"] for s in listed if s["title_id"] == TITLE] == [made[2], made[1]]  # newest first
    assert other in [s["save_id"] for s in listed]
    problem(mira(app, "GET", f"{V1}/saves/{TITLE}/{made[0]}"), 404, "not_found")  # dropped (§ 9.1)
    assert doc(mira(app, "GET", V1 + "/saves", Lantern_Platform="android"))["saves"] == []
    noor = member(app, "noor", ("library", "saves"))
    assert doc(call(app, "GET", V1 + "/saves", token=noor))["saves"] == []  # another account's
    problem(call(app, "GET", f"{V1}/saves/{TITLE}/{made[2]}", token=noor), 404, "not_found")
    problem(mira(app, "GET", V1 + "/saves?title_id=a%20b".replace("%20", " ")), 400, "bad_request")


def test_encrypted_backups_kept_as_sent(app: LanternApp) -> None:
    key = e2e.SaveKey(bytes(range(32)))
    plain = archive(4000)
    sealed = e2e.encrypt(key, plain) if e2e.available() else e2e.MAGIC + bytes.fromhex(key.key_id) + b"\0" * 200
    encryption = {"scheme": e2e.SCHEME, "key_id": key.key_id}
    r = post_save(
        app, sealed, Content_Type="application/octet-stream", Lantern_Save_Encryption=e2e.encryption_header(key.key_id)
    )
    assert r.status == 201, r.body
    entry = doc(r)
    assert entry["encryption"] == encryption and entry["sha256"] == hashlib.sha256(sealed).hexdigest()
    back = mira(app, "GET", f"{V1}/saves/{TITLE}/{entry['save_id']}")
    assert back.body == sealed and back.headers["Content-Type"] == "application/octet-stream"
    if e2e.available():
        assert isinstance(back.body, bytes) and e2e.decrypt(key, back.body) == plain
    up = doc(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={
                "schema": 1,
                "size": len(sealed),
                "sha256": hashlib.sha256(sealed).hexdigest(),
                "encryption": encryption,
            },
        )
    )
    r = raw_call(
        app,
        "PATCH",
        up["upload"],
        sealed,
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        Upload_Offset="0",
        Content_Type="application/offset+octet-stream",
    )
    assert r.status == 201 and doc(r)["encryption"] == encryption
    listed = doc(mira(app, "GET", V1 + "/saves"))["saves"]
    assert sum(s.get("encryption") == encryption for s in listed) == 2
    # Bytes that are not of the scheme, or of another key; another scheme; a zip with an encryption.
    other = e2e.encryption_header("0" * 16)
    problem(post_save(app, sealed, Lantern_Save_Encryption=other), 400, "bad_request")
    problem(post_save(app, plain, Lantern_Save_Encryption=e2e.encryption_header(key.key_id)), 400, "bad_request")
    problem(post_save(app, sealed, Lantern_Save_Encryption="age-v1; key_id=" + key.key_id), 400, "bad_request")
    problem(post_save(app, sealed, Lantern_Save_Encryption=e2e.SCHEME), 400, "bad_request")
    # A server that keeps no encrypted backup refuses one rather than keep it as an archive (L-9.4-5).
    off = lantern_app(encrypted_saves=False)
    problem(post_save(off, sealed, Lantern_Save_Encryption=e2e.encryption_header(key.key_id)), 400, "bad_request")
    problem(
        mira(
            off,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": 10, "sha256": "0" * 64, "encryption": encryption},
        ),
        400,
        "bad_request",
    )


def test_save_events(app: LanternApp) -> None:
    noor = member(app, "noor", ("library", "saves"))
    mine = Reader(mira(app, "GET", V1 + "/events"))
    hers = Reader(call(app, "GET", V1 + "/events", token=noor))
    for r in (mine, hers):
        r.wait_for("event: ready")
    entry = doc(post_save(app, archive()))
    text = mine.wait_for("event: save")
    line = next(x for x in text.splitlines() if x.startswith("data:") and "save_id" in x)
    data = json.loads(line[5:])
    assert data == {
        "schema": 1,
        "platform": "switch",
        "title_id": TITLE,
        "save_id": entry["save_id"],
        "created": entry["created"],
        "device": "Mira's console",
    }
    assert "event: save" not in hers.text  # another account's backup (L-18.2-1)
    for r in (mine, hers):
        r.close()


def test_cheats_written(app: LanternApp) -> None:
    text = "[Moon jump]\n04000000 00ABC010 0000FFFF\n"
    body = {
        "schema": 1,
        "platform": "switch",
        "title_id": TITLE,
        "build_id": "0123456789ABCDEF",
        "source": "Mira",
        "note": "Moon jump",
        "text": text,
    }
    r = mira(app, "POST", V1 + "/cheats", body=body)
    assert r.status == 201, r.body
    made = doc(r)
    assert schema.validate("cheat", made) == []
    assert made["size"] == len(text.encode()) and made["note"] == "Moon jump"
    path = f"{V1}/cheats/{made['id']}"
    assert mira(app, "GET", path).body == text.encode()
    problem(mira(app, "POST", V1 + "/cheats", body=body), 409, "conflict")
    new = text + "[Slow fall]\n04000000 00ABC020 00000001\n"
    assert mira(app, "PUT", path, body={**body, "text": new}).status == 204
    listed = doc(mira(app, "GET", f"{V1}/cheats?title_id={TITLE}"))["cheats"]
    assert [(c["id"], c["sha256"]) for c in listed] == [(made["id"], hashlib.sha256(new.encode()).hexdigest())]
    problem(mira(app, "PUT", path, body={**body, "source": "Noor"}), 400, "bad_request")
    problem(mira(app, "PUT", f"{V1}/cheats/cs_nothing", body=body), 404, "not_found")
    assert mira(app, "DELETE", path).status == 204
    problem(mira(app, "GET", path), 404, "not_found")
    problem(mira(app, "DELETE", path), 404, "not_found")


def test_what_cheat_writes_refuse(app: LanternApp) -> None:
    body = {
        "schema": 1,
        "platform": "switch",
        "title_id": TITLE,
        "build_id": "0123456789ABCDEF",
        "source": "Mira",
        "text": "[Moon jump]\n04000000 00ABC010 0000FFFF\n",
    }
    for change in (
        {"platform": "android", "title_id": "org.example.lumendrift"},  # no cheats on Android (Annex A)
        {"title_id": "lumen"},
        {"build_id": None},
        {"build_id": "not hex"},
        {"source": " Mira"},
        {"source": "a/b"},
        {"note": "x" * 121},
        {"text": "[Moon jump]\nnot a code\n"},
        {"text": "[Moon jump]\x00\n"},
        {"platform": "Not a platform"},
    ):
        problem(mira(app, "POST", V1 + "/cheats", body={**body, **change}), 400, "bad_request")
    problem(mira(app, "POST", V1 + "/cheats", body={**body, "text": "[x]\n" + "0" * (1 << 20)}), 413, "too_large")
    problem(mira(app, "POST", V1 + "/cheats", body={**body, "schema": 2}), 422, "unsupported_schema")
    ps4 = {"platform": "ps4", "title_id": "CUSA00001", "build_id": "01.00", "text": "not json"}
    problem(mira(app, "POST", V1 + "/cheats", body={**body, **ps4}), 400, "bad_request")
    assert mira(app, "POST", V1 + "/cheats", body={**body, **ps4, "text": "{}"}).status == 201
    vita = {"platform": "vita", "title_id": "PCSE00001", "build_id": None, "text": "_V0 Moon jump\n"}
    assert mira(app, "POST", V1 + "/cheats", body={**body, **vita}).status == 201
    # Without the scope, anonymously, and on a library that writes none: 403, 401 or 403, 405.
    noor = member(app, "noor", ("library", "cheats"))
    problem(call(app, "POST", V1 + "/cheats", token=noor, body=body), 403, "forbidden")
    assert call(app, "POST", V1 + "/cheats", body=body).status in (401, 403)
    closed = lantern_app(cheat_writes=False)
    r = mira(closed, "POST", V1 + "/cheats", body=body)
    problem(r, 405, "bad_request")
    assert r.headers["Allow"] == "GET, HEAD"
    problem(mira(closed, "DELETE", V1 + "/cheats/cs_x"), 405, "bad_request")
    # A capped device writes nothing for a title it does not see.
    capped = device(app, "mira", ("library", "cheats", "cheats.write"), RatingCap(age=3))
    hidden = {**body, "title_id": "0100AB1200010000", "source": "Capped"}
    problem(call(app, "POST", V1 + "/cheats", token=capped, body=hidden), 404, "not_found")
    some = next(c for c in app.library.cheats() if c.title_id == "0100AB1200010000")
    problem(call(app, "DELETE", f"{V1}/cheats/{some.id}", token=capped), 404, "not_found")


def test_a_cheat_written_is_a_library_event(app: LanternApp) -> None:
    stream = Reader(call(app, "GET", V1 + "/events"))
    stream.wait_for("event: ready")
    body = {
        "schema": 1,
        "platform": "switch",
        "title_id": TITLE,
        "build_id": "0123456789ABCDEF",
        "source": "Mira",
        "text": "[Moon jump]\n04000000 00ABC010 0000FFFF\n",
    }
    assert mira(app, "POST", V1 + "/cheats", body=body).status == 201
    assert '"families":["cheats"],"platforms":["switch"]' in stream.wait_for('"families":["cheats"]')
    stream.close()


def test_requests(app: LanternApp) -> None:
    made = mira(app, "POST", V1 + "/requests", body={"schema": 1, "platform": "switch", "title_id": TITLE})
    assert made.status == 201, made.body
    first = doc(made)
    assert schema.validate("request", first) == [] and first["status"] == "open"
    again = mira(app, "POST", V1 + "/requests", Lantern_Platform="switch", body={"schema": 1, "title_id": TITLE})
    assert again.status == 200 and doc(again)["id"] == first["id"]
    named = doc(
        mira(
            app,
            "POST",
            V1 + "/requests",
            body={"schema": 1, "platform": "android", "title_id": "org.example.lumendrift"},
        )
    )
    assert named["name"] == "Lumen Drift"  # the library knows its name
    listed = doc(mira(app, "GET", V1 + "/requests"))
    assert schema.validate("requests", listed) == [] and len(listed["requests"]) == 2
    switch = doc(mira(app, "GET", V1 + "/requests", Lantern_Platform="switch"))["requests"]
    assert [q["id"] for q in switch] == [first["id"]]
    noor = member(app, "noor", ("library", "requests"))
    assert doc(call(app, "GET", V1 + "/requests", token=noor))["requests"] == []
    problem(call(app, "DELETE", f"{V1}/requests/{first['id']}", token=noor), 404, "not_found")  # not hers
    problem(mira(app, "POST", V1 + "/requests", body={"schema": 1, "title_id": TITLE}), 400, "bad_request")
    problem(
        mira(app, "POST", V1 + "/requests", body={"schema": 1, "platform": "switch", "title_id": "x y"}),
        400,
        "bad_request",
    )
    problem(
        mira(app, "POST", V1 + "/requests", body={"schema": 2, "platform": "switch", "title_id": TITLE}),
        422,
        "unsupported_schema",
    )
    assert mira(app, "DELETE", f"{V1}/requests/{first['id']}").status == 204
    problem(mira(app, "DELETE", f"{V1}/requests/{first['id']}"), 404, "not_found")
    problem(call(app, "GET", V1 + "/requests"), 401, "unauthorized")


def test_answering_requests_and_their_events(app: LanternApp) -> None:
    stream = Reader(mira(app, "GET", V1 + "/events"))
    other = Reader(mira(app, "GET", V1 + "/events?platform=android"))
    for s in (stream, other):
        s.wait_for("event: ready")
    rid = doc(mira(app, "POST", V1 + "/requests", body={"schema": 1, "platform": "switch", "title_id": TITLE}))["id"]
    stream.wait_for(f'"id":"{rid}","platform":"switch","title_id":"{TITLE}","status":"open"')
    declined = app.answer_request(rid, "declined")
    assert declined is not None and declined.status == "declined"
    stream.wait_for('"status":"declined"')
    assert app.answer_request("r_nothing", "done") is None
    with pytest.raises(ValueError):
        app.answer_request(rid, "maybe")
    # Asked again once declined: a new request, which the title's arrival marks done.
    again = doc(mira(app, "POST", V1 + "/requests", body={"schema": 1, "platform": "switch", "title_id": TITLE}))
    assert again["id"] != rid
    lib = app.library
    assert isinstance(lib, MemoryLibrary)
    lib.add_app_file(
        data=b"new game",
        platform="switch",
        title_id=TITLE,
        app_id=TITLE,
        type="base",
        version_code=0,
        name="Frostline Tales",
        format="nsp",
    )
    stream.wait_for(f'"id":"{again["id"]}","platform":"switch","title_id":"{TITLE}","status":"done"')
    assert sorted(r.status for r in app.all_requests()) == ["declined", "done"]
    assert mira(app, "DELETE", f"{V1}/requests/{rid}").status == 204
    stream.wait_for(f'"id":"{rid}","platform":"switch","title_id":"{TITLE}","deleted":true')
    assert "event: request" not in other.text  # another platform's stream (L-18.2-1)
    for s in (stream, other):
        s.close()


def test_open_requests_are_bounded(app: LanternApp, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "OPEN_LIMIT", 1)
    assert (
        mira(app, "POST", V1 + "/requests", body={"schema": 1, "platform": "switch", "title_id": TITLE}).status == 201
    )
    r = mira(app, "POST", V1 + "/requests", body={"schema": 1, "platform": "switch", "title_id": "0500ABCDEF130000"})
    problem(r, 429, "slow_down")


def test_deleting_an_account_erases_its_backups_and_requests(app: LanternApp) -> None:
    assert app.accounts is not None
    app.accounts.create_user("lea", ("library", "saves", "requests"), "active")
    lea = device(app, "lea", ("library", "saves", "requests"))
    assert post_save(app, archive(), token=lea).status == 201
    assert (
        call(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            token=lea,
            Lantern_Platform="switch",
            body={"schema": 1, "size": 10, "sha256": "0" * 64},
        ).status
        == 201
    )
    assert (
        call(
            app, "POST", V1 + "/requests", token=lea, body={"schema": 1, "platform": "switch", "title_id": TITLE}
        ).status
        == 201
    )
    assert mira(app, "DELETE", V1 + "/admin/users/lea?confirm=lea").status == 204
    assert app.saves is not None and app.saves.saves("lea") == [] and app.saves.uploads() == []
    assert app.all_requests() == []
    app.accounts.create_user("lea", ("library", "saves", "requests"), "active")
    lea = device(app, "lea", ("library", "saves", "requests"))
    assert doc(call(app, "GET", V1 + "/saves", token=lea))["saves"] == []  # a new account inherits nothing


def test_bodies_the_adapters_read(app: LanternApp) -> None:
    assert app.body_limit == 8 << 20
    assert make_lantern(build_library(), saves=None).body_limit == 3 << 20  # a cheat set's document
    assert make_lantern(build_library(), saves=None, cheat_writes=False).body_limit == 1 << 20


# The file-backed store.


def test_the_file_store(tmp_path: Path) -> None:
    folder = tmp_path / "saves"
    app = lantern_app(saves=FileSaveStore(folder), save_limits=SaveLimits(chunk=1000))
    data = archive(2500)
    entry = doc(post_save(app, data))
    up = doc(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        )
    )
    for offset in range(0, len(data), 1000):
        r = raw_call(
            app,
            "PATCH",
            up["upload"],
            data[offset : offset + 1000],
            token=DEMO_TOKEN,
            key=DEMO_KEY,
            Upload_Offset=str(offset),
            Content_Type="application/offset+octet-stream",
        )
        if offset == 0:
            # Restarted mid-upload: another store on the same folder resumes it.
            app.saves = FileSaveStore(folder)
            assert mira(app, "HEAD", up["upload"]).headers["Upload-Offset"] == "1000"
    assert r.status == 201
    second = doc(r)
    again = FileSaveStore(folder)
    assert [s.save_id for s in again.saves("mira")] == [entry["save_id"], second["save_id"]]
    file = again.archive("mira", second["save_id"])
    assert file is not None and Path(file.path).read_bytes() == data
    index = json.loads((folder / "index.json").read_text())
    assert index["schema"] == 1 and index["uploads"] == {}
    assert sorted(p.name for p in (folder / "uploads").iterdir()) == []
    app.saves = again
    assert mira(app, "DELETE", f"{V1}/saves/{TITLE}/{entry['save_id']}").status == 204
    assert not (folder / "archives" / entry["save_id"]).exists()
    again.forget("mira")
    assert again.saves("mira") == [] and not (folder / "archives" / second["save_id"]).exists()


def test_the_file_stores_index_absent_newer_and_unknown(tmp_path: Path) -> None:
    # Absent: no backup, and the first one writes it.
    store = FileSaveStore(tmp_path / "absent")
    assert store.saves("mira") == [] and store.writable
    # Newer: read as absent, never written over (every write answers 503).
    newer = tmp_path / "newer"
    newer.mkdir()
    text = json.dumps({"schema": 2, "saves": [{"user": "mira", "platform": "switch"}], "backups": {}})
    (newer / "index.json").write_text(text)
    store = FileSaveStore(newer)
    assert store.saves("mira") == [] and store.uploads() == [] and not store.writable
    app = lantern_app(saves=store)
    problem(post_save(app, archive()), 503, "unavailable")
    problem(
        mira(
            app,
            "POST",
            f"{V1}/saves/{TITLE}/uploads",
            Lantern_Platform="switch",
            body={"schema": 1, "size": 1, "sha256": "0" * 64},
        ),
        503,
        "unavailable",
    )
    assert (newer / "index.json").read_text() == text
    # Unknown keys, the index's and an entry's: kept when the index is written again.
    known = tmp_path / "known"
    (known / "archives").mkdir(parents=True)
    old = {
        "user": "mira",
        "platform": "switch",
        "title_id": TITLE,
        "save_id": "s_old",
        "created": "2026-10-01T09:00:00Z",
        "size": 3,
        "sha256": hashlib.sha256(b"old").hexdigest(),
        "stars": 3,
    }
    (known / "archives" / "s_old").write_bytes(b"old")
    (known / "index.json").write_text(json.dumps({"schema": 1, "saves": [old, "junk"], "shelf": "kept"}))
    store = FileSaveStore(known)
    listed = store.saves("mira")
    assert [s.save_id for s in listed] == ["s_old"] and listed[0].extra == {}  # what clients see: no unknown key
    app = lantern_app(saves=store)
    assert post_save(app, archive()).status == 201
    index = json.loads((known / "index.json").read_text())
    assert index["shelf"] == "kept" and index["saves"][0] == old and index["saves"][1] == "junk"
    assert len(index["saves"]) == 3
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "index.json").write_text("[]")
    with pytest.raises(DocumentError, match="integer schema"):
        FileSaveStore(tmp_path / "bad")


def test_a_file_stores_index_that_is_not_json(tmp_path: Path) -> None:
    (tmp_path / "index.json").write_text("{")
    with pytest.raises(DocumentError, match="not JSON"):
        FileSaveStore(tmp_path)


def test_the_demo_key_is_the_one_tests_sign_with() -> None:
    assert base64.b64decode(DEMO_KEY.seed_b64()) == DEMO_KEY.seed
