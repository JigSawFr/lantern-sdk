"""The specification's test vectors of draft 0.5 (spec/vectors), byte for
byte: encrypted saves and recovery phrases (§ 9.4), grants (§ 19.3), sync's
merge rule (§ 20.4) and the static layout (§ 21.1)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import SPEC
from lantern import e2e, ed25519, grants, static
from lantern import sync as syncing

VECTORS = SPEC / "vectors"


def vectors(name: str) -> Any:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


E2E = vectors("encrypted-saves")
GRANTS = vectors("grants")
MERGE = vectors("sync-merge")
LAYOUT = vectors("static-layout")
BACKUPS = {b["name"]: b for b in E2E["backups"]}
needs_crypto = pytest.mark.skipif(not e2e.available(), reason="encrypted saves need the crypto extra")


def archive_of(case: dict[str, Any]) -> bytes:
    a = case["archive"]
    if isinstance(a, str):
        return bytes.fromhex(a)
    assert a["byte_i"] == "i % 251"
    return bytes(i % 251 for i in range(a["size"]))


# Encrypted saves (SPEC.md § 9.4).


def test_the_constants() -> None:
    assert (E2E["chunk"], E2E["header"]) == (e2e.CHUNK, e2e.HEADER)


@pytest.mark.parametrize("case", E2E["primitives"]["hkdf_sha256"], ids=lambda c: c["info"])
def test_hkdf(case: dict[str, Any]) -> None:
    okm = e2e.hkdf_sha256(
        bytes.fromhex(case["ikm"]), case["info"].encode(), case["length"], bytes.fromhex(case["salt"])
    )
    assert okm.hex() == case["okm"]


def test_hchacha20() -> None:
    for case in E2E["primitives"]["hchacha20"]:
        assert e2e.hchacha20(bytes.fromhex(case["key"]), bytes.fromhex(case["nonce"])).hex() == case["subkey"]
    # draft-irtf-cfrg-xchacha-03 § 2.2.1
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    assert e2e.hchacha20(key, nonce).hex() == expected
    with pytest.raises(ValueError, match="32-byte key"):
        e2e.hchacha20(key[:16], nonce)


@needs_crypto
@pytest.mark.parametrize("case", E2E["primitives"]["xchacha20poly1305"], ids=lambda c: c["nonce"][:8])
def test_xchacha20poly1305(case: dict[str, Any]) -> None:
    key, nonce, aad = (bytes.fromhex(case[k]) for k in ("key", "nonce", "aad"))
    sealed = e2e.xchacha20poly1305_seal(key, nonce, bytes.fromhex(case["plaintext"]), aad)
    assert sealed.hex() == case["sealed"]
    assert e2e.xchacha20poly1305_open(key, nonce, sealed, aad) == bytes.fromhex(case["plaintext"])
    assert e2e.xchacha20poly1305_open(key, nonce, sealed[:-1] + bytes([sealed[-1] ^ 1]), aad) is None
    assert e2e.xchacha20poly1305_open(key, nonce, sealed, aad + b"x") is None


def test_xchacha20poly1305_against_draft_a3() -> None:
    """draft-irtf-cfrg-xchacha-03 § A.3.1: the AEAD's own test vector, its tag."""
    if not e2e.available():
        pytest.skip("the crypto extra")
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    text = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    sealed = e2e.xchacha20poly1305_seal(key, nonce, text, aad)
    assert sealed[-16:].hex() == "c0875924c1c7987947deafd8780acf49"
    assert sealed[:8].hex() == "bd6d179d3e83d43b"


@pytest.mark.parametrize("case", E2E["keys"], ids=lambda c: c["key_id"])
def test_save_keys(case: dict[str, Any]) -> None:
    key = e2e.SaveKey(bytes.fromhex(case["save_key"]))
    assert key.key_id == case["key_id"]
    assert key.wrapping_key.hex() == case["wrapping_key"]
    assert key.phrase() == case["phrase"]
    assert key.qr() == case["qr"]
    assert e2e.SaveKey.from_phrase(case["phrase"]) == key
    assert e2e.SaveKey.from_qr(case["qr"]) == key
    assert case["save_key"] not in repr(key) and case["key_id"] in repr(key)


@pytest.mark.parametrize("case", E2E["phrases"], ids=lambda c: c["name"])
def test_phrases(case: dict[str, Any]) -> None:
    if case["accepted"]:
        assert e2e.SaveKey.from_phrase(case["phrase"]).phrase() == E2E["keys"][0]["phrase"]
    else:
        with pytest.raises(e2e.BadPhrase):
            e2e.SaveKey.from_phrase(case["phrase"])


def test_a_qr_code_of_another_form() -> None:
    with pytest.raises(e2e.BadPhrase, match="LANTERN-SAVE-KEY-1"):
        e2e.SaveKey.from_qr(E2E["keys"][0]["phrase"])


@needs_crypto
@pytest.mark.parametrize("case", E2E["backups"], ids=lambda c: c["name"])
def test_backups(case: dict[str, Any], tmp_path: Path) -> None:
    key = e2e.SaveKey(bytes.fromhex(case["save_key"]))
    archive = archive_of(case)
    header = e2e.make_header(key, bytes.fromhex(case["file_key"]), bytes.fromhex(case["wrap_nonce"]))
    assert header.hex() == case["header"]
    data = e2e.encrypt(key, archive, header=header)
    assert len(data) == case["size"] == e2e.encrypted_size(len(archive))
    assert hashlib.sha256(data).hexdigest() == case["sha256"]
    if "encrypted" in case:
        assert data.hex() == case["encrypted"]
    tags, pos = [], e2e.HEADER
    while pos < len(data):
        piece = data[pos : pos + e2e.CHUNK + e2e.TAG]
        tags.append(piece[-e2e.TAG :].hex())
        pos += len(piece)
    assert tags == case["chunk_tags"]
    assert e2e.decrypt(key, data) == archive
    # Streamed, from a file, and again from any offset (a resumed upload): the same bytes.
    src = tmp_path / "save.zip"
    src.write_bytes(archive)
    assert e2e.encrypt_file(key, src, tmp_path / "save.lne", header=header) == header
    assert (tmp_path / "save.lne").read_bytes() == data
    for start in sorted({0, 1, 87, 88, 89, len(data) // 2, e2e.HEADER + e2e.CHUNK + e2e.TAG, len(data) - 1}):
        if start <= len(data):
            assert b"".join(e2e.iter_encrypted(key, src, header, start)) == data[start:]
    assert e2e.decrypt_file(key, tmp_path / "save.lne", tmp_path / "back.zip").read_bytes() == archive


def refused_bytes(case: dict[str, Any]) -> bytes:
    if case["backup"] is None:
        return bytes.fromhex(BACKUPS["An empty zip: one chunk"]["archive"])
    b = BACKUPS[case["backup"]]
    key = e2e.SaveKey(bytes.fromhex(b["save_key"]))
    header = e2e.make_header(key, bytes.fromhex(b["file_key"]), bytes.fromhex(b["wrap_nonce"]))
    data = bytearray(e2e.encrypt(key, archive_of(b), header=header))
    op = case["operation"]
    if op.startswith("flip bit 0 of byte "):
        data[int(op.rsplit(" ", 1)[1])] ^= 1
    elif op == "flip bit 0 of the last byte":
        data[-1] ^= 1
    elif op == "drop the last byte":
        del data[-1]
    elif op.startswith("keep the first 88 + "):
        del data[88 + int(op.rsplit(" ", 2)[1]) :]
    elif op == "append 16 zero bytes":
        data += bytes(16)
    elif op == "swap the two chunks":
        first, second = data[88 : 88 + 65552], data[88 + 65552 :]
        data = data[:88] + second + first
    elif op != "read with the second key":
        raise AssertionError(op)
    return bytes(data)


@needs_crypto
@pytest.mark.parametrize("case", E2E["refused"], ids=lambda c: c["name"])
def test_what_a_reader_refuses(case: dict[str, Any], tmp_path: Path) -> None:
    data = refused_bytes(case)
    assert hashlib.sha256(data).hexdigest() == case["sha256"]
    key = e2e.SaveKey(bytes.fromhex(case["save_key"]))
    assert case["opens"] is False
    with pytest.raises(e2e.RefusedBackup):
        e2e.decrypt(key, data)
    (tmp_path / "bad.lne").write_bytes(data)
    with pytest.raises(e2e.RefusedBackup):
        e2e.decrypt_file(key, tmp_path / "bad.lne", tmp_path / "back.zip")
    assert not (tmp_path / "back.zip").exists() and not (tmp_path / "back.zip.part").exists()  # nothing restored


@needs_crypto
def test_a_new_file_key_and_nonce_for_each_backup() -> None:
    key = e2e.SaveKey.generate()
    one, two = e2e.make_header(key), e2e.make_header(key)
    assert one[:16] == two[:16] and one[16:] != two[16:]  # L-9.4-3
    assert e2e.encrypt(key, b"save") != e2e.encrypt(key, b"save")
    assert e2e.key_id_of(one) == key.key_id
    assert e2e.encryption_header(key.key_id) == f"lantern-save-e2e-1; key_id={key.key_id}"


# Grants (SPEC.md § 19.3, § 19.4).


def test_the_grant_key_and_its_grant() -> None:
    seed = bytes.fromhex(GRANTS["key"]["seed"])
    assert base64.b64encode(ed25519.public_key(seed)).decode() == GRANTS["key"]["public_key"]
    found = grants.parse_grant(GRANTS["grant"])
    assert found is not None
    payload, _, _ = found
    assert grants.grant_payload(payload.uid, payload.sha256, payload.size, payload.exp) == GRANTS["payload"].encode()
    assert grants.make_grant(seed, payload.uid, payload.sha256, payload.size, payload.exp) == GRANTS["grant"]
    assert grants.grant_key(GRANTS["key"]["public_key"]) == ed25519.public_key(seed)
    assert grants.grant_key("not base64") is None


@pytest.mark.parametrize("case", GRANTS["cases"], ids=lambda c: c["name"])
def test_what_a_peer_decides(case: dict[str, Any]) -> None:
    keys = {uid: base64.b64decode(k) for uid, k in case["servers"].items()}
    found = grants.read_grant(case["grant"], keys, now=case["peer_time"])
    serves = found is not None and found.sha256 == case["path_sha256"]
    assert serves is case["serves"]


def test_plain_http_to_private_networks_only() -> None:
    assert grants.plain_http_to("https://mirror.example.org/frostline.nsz")
    for url in ("http://192.168.1.20:47116/lantern", "http://10.0.0.2/x", "http://[fd00::1]/x", "http://127.0.0.1/x"):
        assert grants.plain_http_to(url), url
    for url in ("http://mirror.example.org/x", "http://192.0.2.10/x", "ftp://192.168.1.2/x", "http://172.32.0.1/x"):
        assert not grants.plain_http_to(url), url
    assert grants.mirror_ok("https://mirror.example.org/a.nsz")
    assert not grants.mirror_ok("https://lea:secret@mirror.example.org/a.nsz")  # no credential in a mirror
    assert not grants.mirror_ok("https://mirror.example.org/a b")


# Sync's merge rule (SPEC.md § 20.4).


def item(doc: dict[str, Any] | None, key: str = "switch/0100ABCD00010000") -> syncing.Item | None:
    if doc is None:
        return None
    return syncing.Item(key, doc["updated"], doc.get("value"), bool(doc.get("deleted")))


@pytest.mark.parametrize("case", MERGE["cases"], ids=lambda c: c["name"])
def test_the_merge_rule(case: dict[str, Any]) -> None:
    now = datetime.fromisoformat(MERGE["server_time"].replace("Z", "+00:00"))
    sent = item(case["sent"])
    assert sent is not None
    kept, replaced = syncing.merge(item(case["have"]), sent, now=now, skew=MERGE["skew"])
    assert replaced is case["replaced"]
    want = case["kept"]
    assert (kept.updated, kept.deleted) == (want["updated"], bool(want.get("deleted")))
    assert kept.value == want.get("value")
    for side, text in (case.get("canonical") or {}).items():
        assert syncing.canonical(case[side]["value"]).decode() == text


def test_updated_times() -> None:
    assert syncing.parse_updated("2026-10-30T09:12:03.250Z") is not None
    for bad in (
        "2026-10-30T09:12:03+01:00",
        "yesterday",
        "2026-10-30 09:12:03Z",
        1793346000,
        "2026-10-30T09:12:03.2500Z",
    ):
        assert syncing.parse_updated(bad) is None, bad


# The static layout (SPEC.md § 21.1).

ROUTES = {
    "The handshake": ("handshake", None, None, None),
    "Apps of the Switch, page 1": ("apps", "switch", None, 1),
    "Apps of the Switch, the page after cursor 2": ("apps", "switch", None, 2),
    "A title": ("title", "switch", "0100ABCD00010000", None),
    "Every title of Android, page 1": ("titles", "android", None, 1),
    "Homebrew of Linux, page 1": ("homebrew", "linux", None, 1),
    "A homebrew entry": ("entry", "switch", "org.example.frostline", None),
    "A title's cheat sets": ("cheats", "switch", "0100ABCD00010000", None),
    "A cheat set's text": ("cheat", None, "cs_Jt3Vx0", None),
    "A file": ("blob", None, "3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817", None),
}


@pytest.mark.parametrize("case", LAYOUT["routes"], ids=lambda c: c["name"])
def test_the_layout(case: dict[str, Any]) -> None:
    kind, platform, ident, page = ROUTES[case["name"]]
    assert static.layout_path(kind, platform, ident, page) == case["file"]


@pytest.mark.parametrize("case", LAYOUT["paths"], ids=lambda c: c["path"])
def test_relative_paths(case: dict[str, Any]) -> None:
    assert static.relative_ok(case["path"]) is case["accepted"]
