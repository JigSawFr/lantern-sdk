"""Signed requests (lantern.signatures) beyond the vectors: the target URI,
what a server refuses, the replay cache and Accept-Signature."""

from __future__ import annotations

import pytest

from lantern import signatures as sig
from lantern.http import Headers

KEY = sig.DeviceKey(bytes(range(32)))
OTHER = sig.DeviceKey(bytes(range(1, 33)))
URL = "https://shelf.example.org/api/lantern/v1/apps?page_size=5"


@pytest.mark.parametrize(
    ("url", "uri"),
    [
        ("HTTPS://Shelf.Example.org:443/a?b=%20c", "https://shelf.example.org/a?b=%20c"),
        ("http://127.0.0.1:80/x", "http://127.0.0.1/x"),
        ("http://127.0.0.1:8080/x", "http://127.0.0.1:8080/x"),
        ("https://[::1]:8443/v1/", "https://[::1]:8443/v1/"),
        ("https://shelf.example.org", "https://shelf.example.org/"),
    ],
)
def test_target_uri(url: str, uri: str) -> None:
    assert sig.target_uri(url) == uri


def test_target_uri_refuses_what_is_not_one() -> None:
    for url in ("ftp://shelf.example.org/", "/relative", "https://lea@shelf.example.org/"):
        with pytest.raises(ValueError):
            sig.target_uri(url)
    with pytest.raises(ValueError):
        sig.received_uri("https", "evil/host", "/x")
    assert sig.received_uri("https", "Shelf.example.org:443", "/a?b") == "https://shelf.example.org/a?b"


def signed(method: str = "GET", url: str = URL, body: bytes | None = None, key: sig.DeviceKey = KEY) -> Headers:
    h = Headers({"Authorization": "Bearer et_lea"})
    sig.sign_request(key, method, url, h, body, created=1_800_000_000)
    return h


def check(
    h: Headers, *, method: str = "GET", url: str = URL, body: bool = False, nonces: sig.NonceCache | None = None
) -> sig.Verified:
    return sig.verify_request(
        method,
        sig.target_uri(url),
        h,
        KEY.public,
        with_token=True,
        with_body=body,
        nonces=nonces if nonces is not None else sig.NonceCache(),
        now=1_800_000_000,
    )


def code_of(h: Headers, **options: object) -> str:
    with pytest.raises(sig.Refused) as e:
        check(h, **options)  # type: ignore[arg-type]
    return e.value.code


def test_a_body_is_covered_by_its_digest() -> None:
    h = signed("POST", body=b'{"schema":1}')
    assert h["Content-Digest"].startswith("sha-256=:") and '"content-digest"' in h["Signature-Input"]
    assert check(h, method="POST", body=True).keyid == KEY.keyid


def test_what_a_server_refuses() -> None:
    assert code_of(Headers({"Authorization": "Bearer et_lea"})) == "signature_required"
    assert code_of(signed(key=OTHER)) == "signature_invalid"  # keyid not the token's
    h = signed()
    h["Signature-Input"] = h["Signature-Input"].replace('alg="ed25519"', 'alg="rsa"')
    assert code_of(h) == "signature_invalid"
    h = signed()
    h["Signature"] = "lantern=:" + "A" * 86 + "==:"
    assert code_of(h) == "signature_invalid"
    h = signed()
    h["Signature-Input"] = h["Signature-Input"] + "x" * 1100
    assert code_of(h) == "signature_invalid"
    h = signed()
    h["Signature"] = h["Signature"] + ", other=:AA==:"
    assert code_of(h) == "signature_invalid"  # the lantern member alone
    assert code_of(signed(), url=URL + "&more=1") == "signature_invalid"
    assert code_of(signed("POST", body=b"{}")) == "signature_invalid"  # signed with a body, sent without


def test_the_window_and_the_nonces() -> None:
    h = Headers({"Authorization": "Bearer et_lea"})
    sig.sign_request(KEY, "GET", URL, h, None, created=1_800_000_000 - 301)
    assert code_of(h) == "signature_expired"
    h = Headers({"Authorization": "Bearer et_lea"})
    sig.sign_request(KEY, "GET", URL, h, None, created=1_800_000_000 + 301)
    assert code_of(h) == "signature_expired"
    nonces = sig.NonceCache()
    h = signed()
    check(h, nonces=nonces)
    assert code_of(h, nonces=nonces) == "signature_replayed"


def test_the_nonce_cache_is_bounded_and_forgets() -> None:
    clock = [0.0]
    nonces = sig.NonceCache(keep=10, limit=10, clock=lambda: clock[0])
    assert nonces.take("k", "n") and not nonces.take("k", "n") and nonces.take("other", "n")
    for i in range(20):
        nonces.take("k", f"n{i}")
    assert len(nonces) <= 10
    clock[0] = 11
    assert nonces.take("k", "n")  # out of the window: a server takes it, and refuses it by its created


def test_nonces_are_new_and_of_their_form() -> None:
    made = {sig.new_nonce() for _ in range(100)}
    assert len(made) == 100 and all(len(n) == 22 for n in made)
    with pytest.raises(ValueError):
        sig.sign_request(KEY, "GET", URL, Headers(), None, nonce="short")


def test_accept_signature() -> None:
    value = sig.accept_signature(True, False, KEY.keyid)
    read = sig.parse_accept_signature(value)
    assert read == sig.AcceptSignature(("@method", "@target-uri", "authorization"), KEY.keyid, "ed25519")
    assert sig.parse_accept_signature('other=("@method"), lantern=("@method" "@target-uri");alg="ed25519"') == (
        sig.AcceptSignature(("@method", "@target-uri"), None, "ed25519")
    )
    for nothing in (None, "", "lantern=nothing", "x" * 2000):
        assert sig.parse_accept_signature(nothing) is None


def test_device_keys() -> None:
    made = sig.DeviceKey.generate()
    assert sig.DeviceKey.from_b64(made.seed_b64()).public == made.public
    assert made.document() == {"alg": "ed25519", "public_key": made.public_b64}
    for bad in ("not base64!", "AAAA"):
        with pytest.raises(ValueError):
            sig.DeviceKey.from_b64(bad)
