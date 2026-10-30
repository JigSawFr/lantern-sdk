"""Files kept by the `schema` rule, and the key pins over them."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from lantern import pinning, store
from lantern.models import Handshake, Homebrew, Signature


def test_load_and_save(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    assert store.load_document(path) is None
    store.save_document(path, {"schema": 1, "pins": {"a": "b"}})
    assert store.load_document(path) == {"schema": 1, "pins": {"a": "b"}}
    path.write_text('{"schema": 1, "pins": {}, "x-later": [1]}', encoding="utf-8")
    store.save_document(path, {"pins": {"c": "d"}})
    assert json.loads(path.read_text(encoding="utf-8")) == {"x-later": [1], "pins": {"c": "d"}, "schema": 1}


def test_a_newer_file_is_absent_and_never_written_over(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"schema": 2, "pins": {"secret": "kept"}}', encoding="utf-8")
    assert store.load_document(path) is None
    with pytest.raises(store.NewerOnDisk):
        store.save_document(path, {"schema": 1, "pins": {}})
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 2


@pytest.mark.parametrize("content", ["not json", "[1]", '{"no": "schema"}', '{"schema": "1"}', '{"schema": 0}'])
def test_unreadable_files_are_absent(tmp_path: Path, content: str) -> None:
    path = tmp_path / "f.json"
    path.write_text(content, encoding="utf-8")
    assert store.load_document(path) is None
    assert store.load_model(Handshake, path) is None


def test_models(tmp_path: Path, example: object) -> None:
    hello = Handshake.from_json(example("handshake"))  # type: ignore[operator]
    hello.extra["x-example"] = True
    path = tmp_path / "hello.json"
    store.save_model(path, hello)
    again = store.load_model(Handshake, path)
    assert again is not None and again.extra == {"x-example": True} and again.uid == hello.uid
    path.write_text('{"schema": 1, "uid": 3}', encoding="utf-8")
    assert store.load_model(Handshake, path) is None


def _signed(key: bytes | None) -> Homebrew:
    e = Homebrew.from_json(
        {
            "id": "org.example.frostline",
            "platform": "switch",
            "kind": "app",
            "name": "F",
            "version": "1",
            "build": 1,
            "package": {"format": "zip", "file": "/f", "size": 1, "sha256": "a" * 64, "manifest_sha256": "b" * 64},
        }
    )
    if key is not None:
        e.signature = Signature(alg="ed25519", public_key=base64.b64encode(key).decode(), value="")
    return e


@pytest.mark.parametrize("make", [lambda p: pinning.MemoryKeyPins(), lambda p: pinning.FileKeyPins(p / "pins.json")])
def test_key_pins(tmp_path: Path, make: object) -> None:
    pins = make(tmp_path)  # type: ignore[operator]
    first = pinning.check_key(pins, _signed(b"\x01" * 32))
    assert first.change == "pin" and not first.needs_consent and first.pinned_fingerprint is None
    pins.pin("switch", "org.example.frostline", first.offered)
    assert pinning.check_key(pins, _signed(b"\x01" * 32)).change == "same"
    other = pinning.check_key(pins, _signed(b"\x02" * 32))
    assert other.change == "changed" and other.needs_consent
    assert other.pinned_fingerprint != other.offered_fingerprint
    unsigned = pinning.check_key(pins, _signed(None))
    assert unsigned.change == "changed" and unsigned.offered_fingerprint is None
    pins.forget("switch", "org.example.frostline")
    assert pinning.check_key(pins, _signed(None)).change == "pin"
    pins.pin("switch", "org.example.frostline", "")
    assert pinning.check_key(pins, _signed(None)).change == "same"
    assert pins.pinned("3ds", "org.example.frostline") is None


def test_file_pins_keep_a_newer_file(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    path.write_text('{"schema": 2, "pins": {"switch/org.example.frostline": "x"}}', encoding="utf-8")
    pins = pinning.FileKeyPins(path)
    assert pins.pinned("switch", "org.example.frostline") is None
    with pytest.raises(store.NewerOnDisk):
        pins.pin("switch", "org.example.frostline", "y")
