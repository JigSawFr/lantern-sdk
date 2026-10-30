"""SHA-256, streamed, and RFC 9530's digest fields."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from lantern import digest


def test_streaming_matches_hashlib(tmp_path: Path) -> None:
    data = bytes(range(256)) * 5000
    h = digest.Sha256()
    for i in range(0, len(data), 777):
        h.update(data[i : i + 777])
    assert h.hexdigest() == hashlib.sha256(data).hexdigest() and h.size == len(data)
    assert digest.sha256_chunks([data[:10], data[10:]]).digest() == hashlib.sha256(data).digest()
    copy = h.copy()
    copy.update(b"x")
    assert h.size == len(data) and copy.size == len(data) + 1
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    assert digest.sha256_file(path).hexdigest() == hashlib.sha256(data).hexdigest()
    assert digest.sha256_file(path, 1000).hexdigest() == hashlib.sha256(data[:1000]).hexdigest()
    assert digest.sha256_hex(b"") == hashlib.sha256(b"").hexdigest()
    assert digest.Sha256(b"abc").hexdigest() == hashlib.sha256(b"abc").hexdigest()


def test_rfc9530_example() -> None:
    # RFC 9530 § 2: the SHA-256 of the content {"hello": "world"}.
    body = b'{"hello": "world"}'
    value = digest.format_digest(hashlib.sha256(body).hexdigest())
    assert value == "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
    assert digest.format_digest(hashlib.sha256(body).digest()) == value
    assert digest.digest_sha256(value) == hashlib.sha256(body).hexdigest()


def test_parse_several_and_parameters() -> None:
    sha = hashlib.sha256(b"x").digest()
    sha512 = hashlib.sha512(b"x").digest()
    import base64

    value = (
        f"sha-512=:{base64.b64encode(sha512).decode()}:, "
        f"sha-256=:{base64.b64encode(sha).decode()}:;x=1, broken, unknown=?1, bad=:%%%:"
    )
    parsed = digest.parse_digest(value)
    assert parsed == {"sha-512": sha512, "sha-256": sha}


@pytest.mark.parametrize("value", [None, "", "sha-256=abc", "sha-256=:AAAA:", "md5=:AAAAAAAAAAAAAAAAAAAAAA==:"])
def test_no_sha256(value: str | None) -> None:
    assert digest.digest_sha256(value) is None


@pytest.mark.parametrize("bad", ["0" * 63, "g" * 64, b"short"])
def test_format_refuses_what_is_not_a_sha256(bad: str | bytes) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        digest.format_digest(bad)
