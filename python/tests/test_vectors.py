"""The specification's test vectors (spec/vectors) of draft 0.4: signed
requests byte for byte, Ed25519 signatures every verifier refuses, SPKI
fingerprints and rating caps."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from conftest import SPEC
from lantern import JSONValue, ed25519, ratings, spki
from lantern import signatures as sig
from lantern.http import Headers
from lantern.models import Rating, RatingCap

VECTORS = SPEC / "vectors"


def vectors(name: str) -> Any:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


SIGNED = vectors("signatures")
KEY = sig.DeviceKey(bytes.fromhex(SIGNED["key"]["seed"]))


def test_the_vector_key() -> None:
    assert KEY.public_b64 == SIGNED["key"]["public_key"]
    assert KEY.keyid == SIGNED["key"]["keyid"]
    assert KEY.fingerprint == SIGNED["key"]["short_fingerprint"]
    assert SIGNED["key"]["seed"] not in repr(KEY) and KEY.seed_b64() not in repr(KEY)


@pytest.mark.parametrize("case", SIGNED["accepted"], ids=lambda c: c["name"])
def test_signing_gives_the_vector_bytes(case: dict[str, Any]) -> None:
    sent = case["headers"]
    params = sent["Signature-Input"]
    headers = Headers({"Authorization": sent["Authorization"]} if "Authorization" in sent else {})
    sig.sign_request(
        KEY,
        case["method"],
        case["uri"],
        headers,
        case["body"].encode() or None,
        created=int(re.search(r"created=(\d+)", params).group(1)),  # type: ignore[union-attr]
        nonce=re.search(r'nonce="([^"]+)"', params).group(1),  # type: ignore[union-attr]
    )
    assert dict(headers.items()) == sent
    base = sig.signature_base(
        case["method"],
        sig.target_uri(case["uri"]),
        sent.get("Authorization"),
        sent.get("Content-Digest"),
        params[len("lantern=") :],
    )
    assert base == case["signature_base"]


def test_a_server_takes_the_accepted_and_refuses_the_others_in_order() -> None:
    nonces = sig.NonceCache()
    taken: dict[str, sig.Verified] = {}
    for case in SIGNED["accepted"]:
        taken[case["name"]] = sig.verify_request(
            case["method"],
            sig.target_uri(case["uri"]),
            case["headers"],
            KEY.public,
            with_token="Authorization" in case["headers"],
            with_body=bool(case["body"]),
            nonces=nonces,
            skew=SIGNED["skew"],
            now=SIGNED["server_time"],
        )
    assert {v.keyid for v in taken.values()} == {KEY.keyid}
    for refused in SIGNED["refused"]:
        assert all(name in taken for name in refused.get("after", []))
        request = refused["request"]
        with pytest.raises(sig.Refused) as e:
            sig.verify_request(
                request["method"],
                sig.target_uri(request["uri"]),
                request["headers"],
                KEY.public,
                with_token=True,
                with_body=bool(request["body"]),
                nonces=nonces,
                skew=SIGNED["skew"],
                now=SIGNED["server_time"],
            )
        assert e.value.code == refused["code"], refused["name"]


REFUSED = vectors("ed25519-refused")


@pytest.mark.parametrize("case", REFUSED["cases"], ids=lambda c: c["name"])
def test_ed25519_cases(case: dict[str, Any]) -> None:
    public, signature = bytes.fromhex(case["public_key"]), bytes.fromhex(case["signature"])
    message = case["message"].encode()
    assert ed25519.verify(public, message, signature) is case["verifies"]
    assert ed25519.verify_pure(public, message, signature) is case["verifies"]


def test_small_order_keys_never_verify() -> None:
    for key in REFUSED["small_order"]:
        public = bytes.fromhex(key)
        assert not ed25519.is_public_key(public)
        for r in REFUSED["small_order"]:
            forged = bytes.fromhex(r) + bytes(32)
            for message in REFUSED["messages"]:
                assert not ed25519.verify(public, message.encode(), forged)


@pytest.mark.parametrize("cert", vectors("spki")["certificates"], ids=lambda c: c["name"])
def test_spki_fingerprints(cert: dict[str, str]) -> None:
    assert spki.spki_sha256(cert["pem"]) == cert["spki_sha256"]
    assert spki.short(cert["spki_sha256"]) == cert["short"]


def test_spki_refuses_what_is_not_a_certificate() -> None:
    for der in (b"", b"\x30", b"\x02\x01\x00", b"\x30\x03\x30\x01\x00", b"\x30\x84\xff\xff\xff\xff"):
        with pytest.raises(spki.CertificateError):
            spki.spki_der(der)
    with pytest.raises(ValueError, match="SHA-256"):
        spki.short("not hex")


CAPS = vectors("rating-caps")


def test_the_table_of_ages() -> None:
    assert {k: dict(v) for k, v in ratings.AGES.items()} == CAPS["ages"]


@pytest.mark.parametrize("case", CAPS["cases"], ids=lambda c: c["name"])
def test_rating_caps(case: dict[str, Any]) -> None:
    cap = RatingCap.from_json(case["cap"])
    rated = [Rating.from_json(r) for r in case["ratings"]]
    assert ratings.age_of(rated, cap) == case["age"]
    assert ratings.hidden(rated, cap) is case["hidden"]


def test_rating_caps_read_and_refused() -> None:
    assert ratings.read_cap(None) is None
    assert ratings.read_cap({"age": 12, "unrated": "hide"}) == RatingCap(age=12, unrated="hide")
    bad_caps: list[JSONValue] = [
        {"age": 12, "system": "PEGI"},
        {"system": "PEGI"},
        {"age": 120},
        {"age": 3, "unrated": "x"},
    ]
    for bad in bad_caps:
        with pytest.raises(ValueError):
            ratings.read_cap(bad)
    assert not ratings.hidden([Rating(system="PEGI", rating="18")], None)
    # A cap the table cannot read never loosens: everything rated is hidden.
    assert ratings.hidden([Rating(system="PEGI", rating="3")], RatingCap(system="OFLC", rating="M"))


def test_every_vector_file_is_read() -> None:
    names = {p.stem for p in Path(VECTORS).glob("*.json")}
    assert {"signatures", "ed25519-refused", "spki", "rating-caps"} <= names
