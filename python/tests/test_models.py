"""The generated models against the specification's examples, and the
`schema` rule (SPEC.md § 3.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from conftest import examples, load
from lantern import documents
from lantern._base import DocumentError
from lantern.models import (
    DOCUMENTS,
    ERROR_CODES,
    GENRES,
    Homebrew,
    Port,
    RequiredDataGroup,
    RequiredFile,
    Title,
    read_required_data,
)


@pytest.mark.parametrize("path", examples(), ids=lambda p: p.stem)
def test_every_example_reads_and_writes_back_unchanged(path: Path) -> None:
    doc = load(path)
    model = DOCUMENTS[path.stem].from_json(doc)
    assert model.to_json() == doc


@pytest.mark.parametrize("path", examples(), ids=lambda p: p.stem)
def test_unknown_fields_are_kept_on_a_rewrite(path: Path) -> None:
    doc = load(path)
    doc["x-example-shelf"] = {"kept": [1, 2]}
    model = DOCUMENTS[path.stem].from_json(doc)
    assert model.extra["x-example-shelf"] == {"kept": [1, 2]}
    assert model.to_json() == doc


def test_nested_unknown_fields_are_kept(example: Any) -> None:
    doc = example("homebrew")
    doc["package"]["manifest"][0]["x-vendor-mode"] = "0644"
    doc["requires"]["x-vendor-gpu"] = "anything"
    entry = Homebrew.from_json(doc)
    assert entry.package.manifest is not None
    assert entry.package.manifest[0].extra == {"x-vendor-mode": "0644"}
    assert entry.to_json() == doc


def test_a_missing_required_field_is_refused(example: Any) -> None:
    doc = example("apps")
    del doc["items"][0]["sha256"]
    with pytest.raises(DocumentError, match=r"items\[0\]: no sha256"):
        DOCUMENTS["apps"].from_json(doc)


@pytest.mark.parametrize(("key", "value"), [("build", "10400"), ("build", True), ("name", 7), ("tags", "journal")])
def test_a_field_of_the_wrong_type_is_refused(example: Any, key: str, value: Any) -> None:
    doc = example("homebrew")
    doc[key] = value
    with pytest.raises(DocumentError):
        Homebrew.from_json(doc)


def test_a_newer_schema_is_absent(example: Any) -> None:
    doc = example("handshake")
    assert documents.read(DOCUMENTS["handshake"], doc) is not None
    doc["schema"] = 2
    assert documents.read(DOCUMENTS["handshake"], doc) is None
    assert documents.is_newer(doc)


@pytest.mark.parametrize("schema", [None, "1", 0, True, -1])
def test_a_document_needs_an_integer_schema(example: Any, schema: Any) -> None:
    doc = example("cheats")
    doc["schema"] = schema
    with pytest.raises(DocumentError, match="schema"):
        documents.read(DOCUMENTS["cheats"], doc)


def test_parse_reads_bytes_within_the_limits(example: Any) -> None:
    import json

    raw = json.dumps(example("titles")).encode()
    titles = documents.parse(DOCUMENTS["titles"], raw)
    assert titles is not None
    with pytest.raises(DocumentError):
        documents.parse(DOCUMENTS["titles"], b"{not json")


def test_an_unknown_kind_or_none_reads_as_app(example: Any) -> None:
    doc = example("homebrew")
    for kind, read in (("widget", "app"), ("port", "port"), ("tool", "tool")):
        doc["kind"] = kind
        assert Homebrew.from_json(doc).effective_kind == read
    del doc["kind"]
    entry = Homebrew.from_json(doc)
    assert entry.kind is None and entry.effective_kind == "app"
    assert "kind" not in entry.to_json()


def test_an_unknown_assets_reads_as_user_owned(example: Any) -> None:
    port: dict[str, Any] = {
        "original": {"name": "Harbor Lights"},
        "engine": {"name": "Lighthouse"},
        "data_root": "/switch/h/",
        "assets": "streamed",
        "requires_data": [],
    }
    assert Port.from_json(port).effective_assets == "user_owned"
    port["assets"] = "included"
    assert Port.from_json(port).effective_assets == "included"


def test_an_unknown_genre_reads_as_other(example: Any) -> None:
    doc = example("title")
    doc["genres"] = ["adventure", "roguelite", "puzzle", "deckbuilder"]
    title = Title.from_json(doc)
    assert title.effective_genres == ["adventure", "other", "puzzle"]
    assert title.to_json()["genres"] == ["adventure", "roguelite", "puzzle", "deckbuilder"]


def test_required_data_is_a_file_or_a_group() -> None:
    assert isinstance(read_required_data({"path": "a.pak", "hint": "here"}, "d"), RequiredFile)
    group = read_required_data({"one_of": [[{"path": "a", "hint": "h"}], [{"path": "b", "hint": "h"}]]}, "d")
    assert isinstance(group, RequiredDataGroup)
    assert [o[0].path for o in group.one_of] == ["a", "b"]


def test_vocabularies_come_from_the_schemas() -> None:
    assert "adventure" in GENRES and GENRES[-1] == "other"
    assert "account_frozen" in ERROR_CODES and "digest_mismatch" in ERROR_CODES
