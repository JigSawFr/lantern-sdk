"""The client's draft 0.4 against a fake transport: pairing, signing, the
clock, the servers it keeps, and the write routes' requests."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import pytest

import lantern
from fakes import FakeTransport, doc, hello
from lantern import signatures as sig
from lantern.client import LanternClient, Request
from lantern.client.auth import invitation_link
from lantern.models import Save
from lantern.pinning import FileServerStore, MemoryServerStore, ServerRecord
from lantern.store import NewerOnDisk

KEY = sig.DeviceKey(bytes(range(32)))
ROOT = "http://127.0.0.1:8080"
CODE: dict[str, Any] = {
    "schema": 1,
    "code": "KQ4M-7TXD",
    "verify": f"{ROOT}/pair",
    "verify_complete": f"{ROOT}/pair?code=KQ4M-7TXD",
    "poll": "/api/lantern/v1/pairing/p_secret",
    "interval": 1,
    "expires": 600,
}
SAVE = {
    "schema": 1,
    "platform": "switch",
    "title_id": "0100ABCD00010000",
    "save_id": "s_1",
    "created": "2026-10-30T09:12:00Z",
    "size": 10,
    "sha256": "0" * 64,
}


def signed_hello(**changes: Any) -> dict[str, Any]:
    return hello(
        features={"library": 1, "pairing": 1, "signatures": 1, "saves": 1},
        auth={"bearer_only": True, "skew": 300},
        **changes,
    )


def client(answer: Any, **options: Any) -> tuple[LanternClient, FakeTransport]:
    transport = FakeTransport(answer)
    options.setdefault("user_agent", "LanternTest/1.0")
    return LanternClient(ROOT + "/", transport=transport, platform="switch", **options), transport


def test_pairing_with_a_key() -> None:
    polls = iter([doc(202, None), doc(body={"schema": 1, "token": "et_new", "scopes": ["library"], "bound": True})])

    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        if r.url.endswith("/pairing"):
            return doc(body=CODE)
        if "/pairing/" in r.url:
            status, headers, body = next(polls)
            return (status, headers, b"") if status == 202 else (status, headers, body)
        return doc(body={"schema": 1, "items": [], "total": 0, "next": None})

    c, t = client(answer, token="et_old")
    pairing = c.pair("Lea's console", ["library", "library"], key=KEY)
    sent = t.requests[1]
    assert "Authorization" not in sent.headers and "Signature" not in sent.headers
    assert json.loads(sent.body or b"") == {
        "schema": 1,
        "device": "Lea's console",
        "scopes": ["library"],
        "key": {"alg": "ed25519", "public_key": KEY.public_b64},
    }
    assert pairing.code == "KQ4M-7TXD" and pairing.verify_complete == CODE["verify_complete"]
    assert pairing.fingerprint is None  # plain HTTP on loopback: no key to show
    store = MemoryServerStore()
    record = c.wait_for_pairing(pairing, store=store, sleep=lambda s: None)
    poll = t.requests[2]
    assert poll.url == ROOT + CODE["poll"] and "Authorization" not in poll.headers
    assert '("@method" "@target-uri")' in poll.headers["Signature-Input"]
    assert record.token == "et_new" and record.bound and record.key == KEY.seed_b64()
    assert store.server(record.uid) == record
    c.apps()
    last = t.requests[-1]
    assert last.headers["Authorization"] == "Bearer et_new" and KEY.keyid in last.headers["Signature-Input"]


@pytest.mark.parametrize(
    "change",
    [
        {"verify": "http://192.0.2.10/pair"},
        {"verify_complete": "https://192.0.2.10/pair?code=KQ4M-7TXD"},
        {"verify_complete": f"{ROOT}/pair?code=OTHER"},
        {"poll": "https://192.0.2.10/api/lantern/v1/pairing/p_secret"},
        {"expires": 3600},
    ],
)
def test_a_pairing_code_that_is_not_shown(change: dict[str, Any]) -> None:
    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        return doc(body={**CODE, **change})

    c, t = client(answer)
    with pytest.raises(lantern.DocumentError):
        c.pair("Lea's console", ["library"])
    assert len(t.requests) == 2


def test_a_refused_pairing_and_a_slow_down() -> None:
    answers = iter(
        [
            doc(429, {"schema": 1, "type": "about:blank", "title": "Slow down", "status": 429, "code": "slow_down"}),
            doc(410, {"schema": 1, "type": "about:blank", "title": "Gone", "status": 410, "code": "gone"}),
        ]
    )

    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        if r.url.endswith("/pairing"):
            return doc(body=CODE)
        status, headers, body = next(answers)
        return status, {**headers, "Retry-After": "9"}, body

    c, _ = client(answer)
    pairing = c.pair("Lea's console", ["library"], key=False)
    assert pairing.key is None
    waits: list[float] = []
    with pytest.raises(lantern.Gone):
        c.wait_for_pairing(pairing, sleep=waits.append)
    assert waits == [9.0]


def test_a_signature_expired_signs_again_once_with_the_servers_clock() -> None:
    server = datetime.now(UTC) + timedelta(hours=5)
    count = {"apps": 0}

    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        count["apps"] += 1
        created = int(r.headers["Signature-Input"].split("created=")[1].split(";")[0])
        if abs(created - server.timestamp()) > 300:
            problem = {"schema": 1, "type": "about:blank", "title": "x", "status": 401, "code": "signature_expired"}
            return doc(401, problem, Date=format_datetime(server, usegmt=True))
        return doc(body={"schema": 1, "items": [], "total": 0, "next": None})

    c, _ = client(answer, token="et_lea", key=KEY)
    c.handshake()
    assert c.apps().items == [] and count["apps"] == 2
    assert abs(c.core.clock_offset - 5 * 3600) < 5


def test_the_handshake_s_date_sets_the_clock() -> None:
    later = datetime.now(UTC) + timedelta(minutes=20)

    def answer(r: Request) -> Any:
        return doc(body=signed_hello(), Date=format_datetime(later, usegmt=True))

    c, _ = client(answer, token="et_lea", key=KEY)
    c.handshake()
    assert abs(c.core.clock_offset - 1200) < 5
    near, _ = client(lambda r: doc(body=signed_hello(), Date=format_datetime(datetime.now(UTC), usegmt=True)))
    near.handshake()
    assert near.core.clock_offset == 0


def test_signatures_go_to_the_origin_alone() -> None:
    c, t = client(
        lambda r: doc(body=signed_hello()) if "well-known" in r.url else (200, {}, b"abc"), token="et_lea", key=KEY
    )
    c.handshake()
    assert "Signature" in t.requests[0].headers
    with pytest.raises(lantern.IntegrityError):
        c.fetch("https://cdn.example.org/x", sha256="0" * 64, size=3)
    assert "Signature" not in t.requests[1].headers and "Authorization" not in t.requests[1].headers
    with pytest.raises(ValueError, match="not both"):
        LanternClient(ROOT, key=KEY, signer=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="default transport"):
        LanternClient(ROOT, pin="0" * 64, transport=FakeTransport(lambda r: doc()))


def test_a_save_in_one_request() -> None:
    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        return doc(201, SAVE)

    c, t = client(answer, token="et_lea", key=KEY)
    data = b"PK\x03\x04 a save"
    saved = c.save("0100ABCD00010000", data, kind="account", game_version_code=3, profile="Léa", note="Ch. 4")
    assert saved.save_id == "s_1"
    sent = t.requests[-1]
    assert sent.headers["Content-Type"] == "application/zip" and sent.body == data
    assert sent.headers["Lantern-Profile"] == "L%C3%A9a" and sent.headers["Lantern-Note"] == "Ch.%204"
    assert sent.headers["Lantern-Game-Version"] == "3" and sent.headers["Lantern-Save-Kind"] == "account"
    assert (
        sent.headers["Content-Digest"] == "sha-256=:" + base64.b64encode(hashlib.sha256(data).digest()).decode() + ":"
    )
    assert '"content-digest"' in sent.headers["Signature-Input"]
    with pytest.raises(ValueError):
        c.save("0100ABCD00010000", data, profile="x" * 65)


def test_a_resumable_upload(tmp_path: Path) -> None:
    data = bytes(range(256)) * 10
    source = tmp_path / "save.zip"
    source.write_bytes(data)
    got = bytearray()

    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        if r.url.endswith("/uploads"):
            return doc(
                201,
                {
                    "schema": 1,
                    "upload": "/api/lantern/v1/uploads/u_1",
                    "chunk_size": 1000,
                    "offset": 0,
                    "expires": "2026-10-31T09:12:00Z",
                },
            )
        if r.method == "HEAD":
            return 204, {"Upload-Offset": str(len(got)), "Upload-Length": str(len(data))}, b""
        assert int(r.headers["Upload-Offset"]) == len(got)
        got.extend(r.body or b"")
        if len(got) == len(data):
            return doc(201, {**SAVE, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        return 204, {"Upload-Offset": str(len(got))}, b""

    c, t = client(answer, token="et_lea", key=KEY)
    marks: list[int] = []
    saved = c.upload_save("0100ABCD00010000", source, profile="Lea", progress=lambda n, total: marks.append(n))
    assert isinstance(saved, Save) and bytes(got) == data and marks == [1000, 2000, 2560]
    opened = json.loads(t.requests[1].body or b"")
    assert opened["size"] == len(data) and opened["sha256"] == hashlib.sha256(data).hexdigest()
    assert all(r.headers["Content-Type"] == "application/offset+octet-stream" for r in t.requests[2:])
    got.clear()
    got.extend(data[:2000])
    again = c.upload_save("0100ABCD00010000", source, resume="/api/lantern/v1/uploads/u_1")
    assert again.size == len(data)
    with pytest.raises(lantern.UnexpectedResponse):
        c.upload_save("0100ABCD00010000", source, resume="https://192.0.2.10/api/lantern/v1/uploads/u_1")


def test_an_upload_whose_offset_goes_back(tmp_path: Path) -> None:
    source = tmp_path / "save.zip"
    source.write_bytes(b"x" * 3000)

    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        if r.url.endswith("/uploads"):
            return doc(
                201,
                {
                    "schema": 1,
                    "upload": "/api/lantern/v1/uploads/u_1",
                    "chunk_size": 1000,
                    "offset": 0,
                    "expires": "2026-10-31T09:12:00Z",
                },
            )
        return 204, {"Upload-Offset": "0"}, b""

    c, _ = client(answer)
    with pytest.raises(lantern.UnexpectedResponse, match="offset"):
        c.upload_save("0100ABCD00010000", source)


def test_writes_and_the_administration() -> None:
    def answer(r: Request) -> Any:
        if r.url.endswith("/.well-known/lantern"):
            return doc(body=signed_hello())
        if r.method == "DELETE" or r.method == "PUT" or "/admin/pairings/" in r.url:
            return 204, {}, b""
        if r.url.endswith("/cheats"):
            return doc(
                201,
                {
                    "schema": 1,
                    "id": "cs_1",
                    "platform": "switch",
                    "title_id": "0100ABCD00010000",
                    "size": 3,
                    "sha256": "0" * 64,
                },
            )
        if r.url.endswith("/requests") and r.method == "POST":
            return doc(
                200,
                {
                    "schema": 1,
                    "id": "r_1",
                    "platform": "switch",
                    "title_id": "0100ABCD00010000",
                    "status": "open",
                    "created": "2026-10-30T09:12:00Z",
                },
            )
        if "/admin/users" in r.url:
            return doc(
                201 if r.method == "POST" else 200,
                {"schema": 1, "name": "ines", "state": "active", "scopes": ["library"]},
            )
        return doc(404, {"schema": 1, "type": "about:blank", "title": "x", "status": 404, "code": "not_found"})

    c, t = client(answer, token="et_lea", key=KEY)
    assert c.create_cheat("switch", "0100ABCD00010000", "[x]\n", source="Lea").id == "cs_1"
    c.replace_cheat("cs_1", "switch", "0100ABCD00010000", "[y]\n")
    c.delete_cheat("cs_1")
    assert c.request_title("0100ABCD00010000").status == "open"
    c.withdraw_request("r_1")
    assert c.create_user("ines", ["library"]).name == "ines"
    assert c.update_user("ines", state="frozen").name == "ines"
    c.approve_pairing("pr_1", user="ines", scopes=["library"])
    c.refuse_pairing("pr_2")
    c.revoke_device("d_1")
    c.revoke_invitation("i_1")
    methods = [(r.method, r.url.split("/v1", 1)[-1]) for r in t.requests[1:]]
    assert methods == [
        ("POST", "/cheats"),
        ("PUT", "/cheats/cs_1"),
        ("DELETE", "/cheats/cs_1"),
        ("POST", "/requests"),
        ("DELETE", "/requests/r_1"),
        ("POST", "/admin/users"),
        ("PATCH", "/admin/users/ines"),
        ("POST", "/admin/pairings/pr_1"),
        ("POST", "/admin/pairings/pr_2"),
        ("DELETE", "/admin/devices/d_1"),
        ("DELETE", "/admin/invitations/i_1"),
    ]
    assert json.loads(t.requests[8].body or b"") == {
        "schema": 1,
        "decision": "approve",
        "user": "ines",
        "scopes": ["library"],
    }
    assert all("Signature" in r.headers for r in t.requests)
    with pytest.raises(lantern.NotFound):
        c.saves()
    with pytest.raises(ValueError):
        c.update_user("ines")
    with pytest.raises(ValueError):
        c.create_cheat("switch", "0100ABCD00010000", "x" * ((1 << 20) + 1))


def test_invitation_links() -> None:
    spki = "3f9a1c07" + "0" * 56
    link = invitation_link(f"https://shelf.example.org/pair?invitation=MZ7Q-4KHP-XW2N-8TRD&spki={spki.upper()}")
    assert link.url == "https://shelf.example.org/" and link.code == "MZ7Q-4KHP-XW2N-8TRD" and link.spki == spki
    assert invitation_link("https://shelf.example.org/pair?invitation=MZ7Q-4KHP-XW2N-8TRD").spki is None
    for bad in (
        "http://192.0.2.10/pair?invitation=MZ7Q-4KHP-XW2N-8TRD",
        "https://shelf.example.org/pair?invitation=SHORT",
        "https://shelf.example.org/pair?invitation=MZ7Q-4KHP-XW2N-8TRD&spki=nothex",
        "https://shelf.example.org/pair",
    ):
        with pytest.raises(ValueError):
            invitation_link(bad)


RECORD = ServerRecord(uid="6f1c2a8e", url="https://192.0.2.10/", token="et_lea", key=KEY.seed_b64(), bound=True)


def test_the_servers_a_client_keeps(tmp_path: Path) -> None:
    path = tmp_path / "servers.json"
    store = FileServerStore(path)
    assert store.server("6f1c2a8e") is None and store.servers() == []  # absent
    store.save(RECORD)
    assert store.server("6f1c2a8e") == RECORD and path.stat().st_mode & 0o077 == 0
    raw = json.loads(path.read_text())
    raw["x-other-app"] = {"kept": True}
    raw["servers"]["6f1c2a8e"]["x-note"] = "living room"
    path.write_text(json.dumps(raw))
    read = store.server("6f1c2a8e")
    assert read is not None and read.extra == {"x-note": "living room"}  # an unknown field, kept
    store.save(read)
    kept = json.loads(path.read_text())
    assert kept["x-other-app"] == {"kept": True} and kept["servers"]["6f1c2a8e"]["x-note"] == "living room"
    store.forget("6f1c2a8e")
    assert store.servers() == []
    path.write_text(json.dumps({"schema": 2, "servers": {"6f1c2a8e": RECORD.to_json()}}))
    assert store.server("6f1c2a8e") is None  # newer: absent
    with pytest.raises(NewerOnDisk):
        store.save(RECORD)  # and never written over
    assert json.loads(path.read_text())["schema"] == 2
    assert ServerRecord.from_json({"uid": 1}) is None and "et_lea" not in repr(RECORD)
    memory = MemoryServerStore()
    memory.save(RECORD)
    assert memory.servers() == [RECORD]
    memory.forget(RECORD.uid)
    assert memory.server(RECORD.uid) is None


def test_a_paired_client() -> None:
    c = LanternClient.paired(RECORD, user_agent="LanternTest/1.0")
    assert c.core.pipeline.signer is not None and c.transport.verify is True  # type: ignore[attr-defined]
    pinned = LanternClient.paired(
        ServerRecord(uid="u", url="https://192.0.2.10/", token="et_lea", spki="0" * 64), user_agent="LanternTest/1.0"
    )
    assert pinned.transport.pin == "0" * 64 and pinned.core.pipeline.signer is None  # type: ignore[attr-defined]


def test_deprecations_are_recorded(caplog: pytest.LogCaptureFixture) -> None:
    link = '<https://lantern.boreale.dev/spec/#34-deprecation-and-sunset>; rel="deprecation"'
    headers = {"Deprecation": "@1793318400", "Sunset": "Sun, 01 Aug 2027 00:00:00 GMT", "Link": link}
    c, _ = client(lambda r: doc(200, signed_hello(), **headers))
    c.handshake()
    c.handshake()
    assert c.core.deprecations == [
        lantern.client.Deprecation(
            "handshake",
            "@1793318400",
            "Sun, 01 Aug 2027 00:00:00 GMT",
            "https://lantern.boreale.dev/spec/#34-deprecation-and-sunset",
        )
    ]
    assert len([r for r in caplog.records if "deprecated" in r.getMessage()]) == 1


def test_what_fits() -> None:
    from lantern.client import what_fits
    from lantern.models import App

    def app(size: int, installed: int | None) -> App:
        return App(
            id=f"a_{size}",
            platform="switch",
            title_id="t",
            app_id="t",
            type="base",
            version_code=0,
            size=size,
            format="nsp",
            sha256="0" * 64,
            file="/f",
            installed_size=installed,
        )

    small, big, unknown = app(10, 20), app(10, 2000), app(500, None)
    assert what_fits([small, big, unknown], 600) == ([small, unknown], [big])
