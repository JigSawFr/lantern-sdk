"""The server toolkit's SPEC.md § 5, called directly: pairing with and
without a key, signed requests, invitations, rating caps and the
administration API, over MemoryAccounts."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from demo import DEMO_KEY, DEMO_TOKEN, build_library, demo_accounts, make_lantern
from lantern import schema
from lantern import signatures as sig
from lantern.http import Headers
from lantern.models import RatingCap
from lantern.server import LanternApp, ServerRequest, ServerResponse
from lantern.server.accounts import AccountError, MemoryAccounts, User, typed_code
from lantern.server.pairing import Limiter, approval_page

HOST = "shelf.example.org"
BASE = "/api/lantern/v1"
KEY = sig.DeviceKey(bytes(range(32)))


def lantern(**options: Any) -> LanternApp:
    options.setdefault("accounts", demo_accounts())
    return make_lantern(build_library(), **options)


def call(
    app: LanternApp,
    method: str,
    path: str,
    *,
    body: Any = None,
    token: str | None = None,
    key: sig.DeviceKey | None = None,
    remote: str = "192.0.2.7",
    **headers: str,
) -> ServerResponse:
    raw = b""
    if body is not None:
        raw = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    h = Headers({"Host": HOST, **{k.replace("_", "-"): v for k, v in headers.items()}})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    path, _, query = path.partition("?")
    target = path + (f"?{query}" if query else "")
    if key is not None:
        sig.sign_request(key, method, f"https://{HOST}{target}", h, raw or None)
    params = dict(p.split("=", 1) for p in query.split("&") if p)
    return app.handle(ServerRequest(method, path, params, h, raw, scheme="https", target=target, remote=remote))


def doc(r: ServerResponse) -> Any:
    assert isinstance(r.body, bytes)
    return json.loads(r.body)


def code(r: ServerResponse) -> str:
    assert r.headers["Content-Type"] == "application/problem+json"
    value: str = doc(r)["code"]
    return value


def mira(app: LanternApp, method: str, path: str, **options: Any) -> ServerResponse:
    return call(app, method, path, token=DEMO_TOKEN, key=DEMO_KEY, **options)


def start(app: LanternApp, key: sig.DeviceKey | None = KEY, **fields: Any) -> dict[str, Any]:
    body = {"schema": 1, "device": "Lea's console", "scopes": ["library", "cheats"], **fields}
    if key is not None:
        body["key"] = key.document()
    r = call(app, "POST", BASE + "/pairing", body=body)
    assert r.status == 200, r.body
    out: dict[str, Any] = doc(r)
    assert schema.validate("pairing-code", out) == []
    return out


def test_the_handshake_offers_pairing_and_signatures_to_everyone() -> None:
    app = lantern(skew=120)
    anonymous = doc(call(app, "GET", BASE))
    assert anonymous["features"]["pairing"] == anonymous["features"]["signatures"] == 1
    assert anonymous["features"]["admin"] == 0 and anonymous["auth"] == {"bearer_only": True, "skew": 120}
    mine = doc(mira(app, "GET", BASE))
    assert mine["account"]["bound"] is True and mine["features"]["admin"] == 1
    assert schema.validate("handshake", mine) == []
    with pytest.raises(ValueError, match="skew"):
        lantern(skew=30)
    with pytest.raises(ValueError, match="not both"):
        LanternApp(build_library(), uid="u", name="n", accounts=MemoryAccounts(), authenticate=lambda r: None)


def test_pairing_with_a_key() -> None:
    app = lantern()
    code_doc = start(app)
    assert code_doc["verify"] == f"https://{HOST}/pair"
    assert code_doc["verify_complete"] == f"https://{HOST}/pair?code={code_doc['code']}"
    poll = code_doc["poll"]
    r = call(app, "GET", poll)
    assert r.status == 401 and code(r) == "signature_required" and "Accept-Signature" in r.headers
    assert code(call(app, "GET", poll, key=sig.DeviceKey(bytes(32)))) == "signature_invalid"
    assert call(app, "GET", poll, key=KEY).status == 202
    assert app.desk is not None
    entry = app.desk.by_code(code_doc["code"].lower().replace("-", " "))
    assert entry is not None and typed_code(entry.code) == typed_code(code_doc["code"])
    assert app.desk.approve(entry, "noor") == ("library",)  # what Noor's account holds
    app.desk._pending[entry.poll].polled = None  # as if `interval` had passed
    token = call(app, "GET", poll, key=KEY)
    assert token.status == 200 and token.headers["Cache-Control"] == "no-store"
    granted = doc(token)
    assert granted["bound"] is True and granted["scopes"] == ["library"]
    assert code(call(app, "GET", poll, key=KEY)) == "gone"  # given once
    unsigned = call(app, "GET", BASE + "/apps", token=granted["token"])
    assert code(unsigned) == "signature_required"
    assert unsigned.headers["Accept-Signature"] == sig.accept_signature(True, False, KEY.keyid)
    assert call(app, "GET", BASE + "/apps", token=granted["token"], key=KEY).status == 200


def test_pairing_requests_that_are_refused() -> None:
    app = lantern()
    for public in ("AAAA", base64.b64encode(bytes([1]) + bytes(31)).decode()):
        body = {"schema": 1, "device": "x", "scopes": ["library"], "key": {"alg": "ed25519", "public_key": public}}
        assert code(call(app, "POST", BASE + "/pairing", body=body)) == "bad_request"
    for bad in ({"device": "a\x01b"}, {"scopes": ["nothing"]}, {"device": ""}):
        body = {"schema": 1, "device": "Lea's console", "scopes": ["library"], **bad}
        assert code(call(app, "POST", BASE + "/pairing", body=body)) == "bad_request"
    assert code(call(app, "POST", BASE + "/pairing", body={"schema": 2, "device": "x", "scopes": []})) == (
        "unsupported_schema"
    )
    bound = lantern(bound_only=True)
    r = call(bound, "POST", BASE + "/pairing", body={"schema": 1, "device": "x", "scopes": ["library"]})
    assert r.status == 400 and code(r) == "key_required"
    assert doc(call(bound, "GET", BASE))["auth"]["bearer_only"] is False


def test_pairing_without_a_key_and_the_limits() -> None:
    app = lantern()
    app.pair_limiter = Limiter(2, 60)
    first = start(app, key=None)
    assert call(app, "GET", first["poll"]).status == 202
    r = call(app, "GET", first["poll"])
    assert code(r) == "slow_down" and r.headers["Retry-After"]
    start(app, key=None)
    assert code(call(app, "POST", BASE + "/pairing", body={"schema": 1, "device": "x", "scopes": ["library"]})) == (
        "slow_down"
    )
    assert code(call(app, "GET", BASE + "/pairing/p_unknown")) == "gone"


def test_a_bearer_only_token_on_a_server_that_wants_keys() -> None:
    accounts = demo_accounts()
    accounts.add_token("et_old-console-token-0000000000000000", "noor", "Noor's old console", ["library"])
    app = lantern(accounts=accounts, bound_only=True)
    r = call(app, "GET", BASE + "/apps", token="et_old-console-token-0000000000000000")
    assert r.status == 401 and code(r) == "signature_required"
    open_app = lantern(accounts=accounts)
    assert call(open_app, "GET", BASE + "/apps", token="et_old-console-token-0000000000000000").status == 200


def test_a_body_is_checked_against_its_digest() -> None:
    app = lantern()
    body = {"schema": 1, "installed": [], "want": ["base"]}
    r = mira(app, "POST", BASE + "/apps/missing?platform=switch", body=body)
    assert r.status == 200
    h = Headers({"Host": HOST, "Authorization": f"Bearer {DEMO_TOKEN}", "Content-Type": "application/json"})
    raw = json.dumps(body).encode()
    sig.sign_request(DEMO_KEY, "POST", f"https://{HOST}{BASE}/apps/missing?platform=switch", h, raw + b" ")
    request = ServerRequest(
        "POST", BASE + "/apps/missing", {"platform": "switch"}, h, raw, target=BASE + "/apps/missing?platform=switch"
    )
    assert code(app.handle(request)) == "digest_mismatch"


def test_the_administration_api() -> None:
    app = lantern()
    assert code(call(app, "GET", BASE + "/admin/users")) == "unauthorized"
    users = doc(mira(app, "GET", BASE + "/admin/users?page_size=1"))
    assert users["total"] == 2 and users["next"] and schema.validate("admin-users", users) == []
    made = mira(app, "POST", BASE + "/admin/users", body={"schema": 1, "name": "ines", "scopes": ["library"]})
    assert made.status == 201 and doc(made)["devices"] == 0
    again = mira(app, "POST", BASE + "/admin/users", body={"schema": 1, "name": "ines", "scopes": ["library"]})
    assert code(again) == "conflict"
    with_password = {"schema": 1, "name": "sam", "scopes": ["library"], "password": "x"}
    assert code(mira(app, "POST", BASE + "/admin/users", body=with_password)) == "bad_request"
    assert code(mira(app, "PATCH", BASE + "/admin/users/ines", body={"schema": 1})) == "bad_request"
    assert code(mira(app, "PATCH", BASE + "/admin/users/nobody", body={"schema": 1, "state": "frozen"})) == "not_found"
    frozen = mira(app, "PATCH", BASE + "/admin/users/ines", body={"schema": 1, "state": "frozen"})
    assert doc(frozen)["state"] == "frozen"
    devices = doc(mira(app, "GET", BASE + "/admin/devices?user=mira"))
    assert devices["items"][0]["key"] == DEMO_KEY.fingerprint
    assert "token" not in json.dumps(devices).replace('"token":', "")  # no token, no hash
    assert schema.validate("admin-devices", devices) == []
    pending = start(app)
    pairings = doc(mira(app, "GET", BASE + "/admin/pairings"))
    assert [p["code"] for p in pairings["items"]] == [pending["code"]] and pairings["items"][0][
        "key"
    ] == KEY.fingerprint
    decision = {"schema": 1, "decision": "approve", "user": "noor", "rating_cap": {"age": 6}}
    pid = pairings["items"][0]["id"]
    assert mira(app, "POST", f"{BASE}/admin/pairings/{pid}", body=decision).status == 204
    assert code(mira(app, "POST", f"{BASE}/admin/pairings/{pid}", body=decision)) == "not_found"
    bad = {"schema": 1, "decision": "approve", "rating_cap": {"age": 6, "system": "PEGI"}}
    pid2 = doc(mira(app, "GET", BASE + "/admin/pairings"))
    assert pid2["items"] == []
    other = start(app)
    pid2 = doc(mira(app, "GET", BASE + "/admin/pairings"))["items"][0]["id"]
    assert code(mira(app, "POST", f"{BASE}/admin/pairings/{pid2}", body=bad)) == "bad_request"
    assert mira(app, "POST", f"{BASE}/admin/pairings/{pid2}", body={"schema": 1, "decision": "refuse"}).status == 204
    assert code(call(app, "GET", other["poll"], key=KEY)) == "gone"
    revoked = doc(mira(app, "GET", BASE + "/admin/devices?user=mira"))["items"][0]["id"]
    assert mira(app, "DELETE", f"{BASE}/admin/devices/{revoked}").status == 204
    assert code(mira(app, "GET", BASE + "/apps")) == "unauthorized"  # at once (L-5.7-3)


def test_invitations() -> None:
    app = lantern(spki="3f9a1c07" + "0" * 56)
    expires = (datetime.now(UTC) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"schema": 1, "user": "noor", "scopes": ["library"], "expires": expires, "devices": 1, "note": "Ines"}
    r = mira(app, "POST", BASE + "/admin/invitations", body=body)
    assert r.status == 201
    inv = doc(r)
    assert schema.validate("invitation", inv) == []
    assert inv["link"] == f"https://{HOST}/pair?invitation={inv['code']}&spki=3f9a1c07{'0' * 56}"
    for wrong in (
        {"scopes": ["admin"]},
        {"user": "nobody"},
        {"expires": "2020-01-01T00:00:00Z"},
        {"expires": (datetime.now(UTC) + timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        {"note": "a\nb"},
    ):
        assert code(mira(app, "POST", BASE + "/admin/invitations", body={**body, **wrong})) == "bad_request"
    paired = start(app, invitation=inv["code"])
    token = doc(call(app, "GET", paired["poll"], key=KEY))
    assert token["scopes"] == ["library"] and token["bound"]
    r = call(
        app,
        "POST",
        BASE + "/pairing",
        body={"schema": 1, "device": "y", "scopes": ["library"], "invitation": inv["code"]},
    )
    assert r.status == 410 and code(r) == "gone"  # used up
    listed = doc(mira(app, "GET", BASE + "/admin/invitations"))
    assert listed["items"] == []
    second = doc(mira(app, "POST", BASE + "/admin/invitations", body={**body, "devices": 2}))
    assert mira(app, "DELETE", f"{BASE}/admin/invitations/{second['id']}").status == 204
    assert code(mira(app, "DELETE", f"{BASE}/admin/invitations/{second['id']}")) == "not_found"


def test_a_rating_cap_hides_what_is_above_it() -> None:
    accounts = demo_accounts()
    accounts.add_token(
        "et_capped-0000000000000000000000000000",
        "mira",
        "Ines's console",
        ["library", "cheats"],
        key=KEY.public,
        rating_cap=RatingCap(age=3),
    )
    app = lantern(accounts=accounts)
    every = doc(mira(app, "GET", BASE + "/apps?page_size=1000"))["items"]

    def capped(method: str, path: str) -> ServerResponse:
        return call(app, method, path, token="et_capped-0000000000000000000000000000", key=KEY)

    hello = doc(capped("GET", BASE))
    assert hello["account"]["rating_cap"] == {"age": 3}
    seen = doc(capped("GET", BASE + "/apps?page_size=1000"))
    hidden = [a for a in every if a["id"] not in {s["id"] for s in seen["items"]}]
    assert hidden and seen["total"] == len(seen["items"])
    title = hidden[0]["title_id"]
    assert capped("GET", f"{BASE}/titles/{title}?platform=switch").status == 404
    assert title in doc(capped("GET", f"{BASE}/titles?ids={title}"))["unknown"]
    file_id = hidden[0]["file"].rsplit("/", 1)[-1]
    assert capped("GET", f"{BASE}/files/{file_id}").status == 404
    assert all(c["title_id"] != title for c in doc(capped("GET", BASE + "/cheats"))["cheats"])


def test_the_approval_page() -> None:
    app = lantern(spki="79315e024cf7f6e0f2553884fd098ac59df2e2a72f139d8e03b6ee62a2d13fd0")
    assert app.owns("/pair") and app.verify_path == "/pair"
    page = call(app, "GET", "/pair?code=KQ4M-7TXD")
    assert page.status == 200 and page.headers["Content-Type"].startswith("text/html")
    text = page.body.decode() if isinstance(page.body, bytes) else ""
    assert "7931 5E02 4CF7 F6E0" in text and "KQ4M-7TXD" in text
    assert call(app, "POST", "/pair").status == 405
    assert "&lt;script&gt;" in approval_page(fingerprint=None, code="<script>")
    own = lantern(pair_page=lambda r: ServerResponse(204))
    assert call(own, "GET", "/pair").status == 204
    assert not lantern(accounts=None).owns("/pair")


def test_memory_accounts() -> None:
    accounts = MemoryAccounts([User("lea", ("library", "saves"))])
    with pytest.raises(AccountError) as e:
        accounts.create_user("lea", ["library"])
    assert e.value.status == 409
    with pytest.raises(AccountError):
        accounts.create_user("not a name!", ["library"])
    token, device = accounts.issue("lea", "Lea's console", ["library", "saves", "nothing"], lifetime=3600)
    assert device.scopes == ("library", "saves") and device.expires and accounts.device_of(token) == device
    assert device.token_hash != token and token not in repr(device)
    accounts.update_user("lea", scopes=["library"])
    assert accounts.devices("lea")[0].scopes == ("library",)
    expired, _ = accounts.issue("lea", "x", ["library"], lifetime=-1)
    assert accounts.device_of(expired) is None
    assert accounts.revoke(device.id) and not accounts.revoke(device.id)
    inv = accounts.create_invitation("lea", ["library"], "2999-01-01T00:00:00Z", 1)
    assert accounts.redeem(inv.code.lower()) is not None and accounts.redeem(inv.code) is None
