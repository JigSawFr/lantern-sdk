"""Ed25519 (RFC 8032 § 7.1's vectors), both backends, and the
specification's signed example."""

from __future__ import annotations

from typing import Any

import pytest

from lantern import ed25519
from lantern import homebrew as hb
from lantern.models import Homebrew

# RFC 8032 § 7.1, tests 1 to 3: (secret seed, public key, message, signature).
VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize(("seed", "public", "message", "signature"), VECTORS)
def test_rfc8032(seed: str, public: str, message: str, signature: str) -> None:
    s, p, m, sig = (bytes.fromhex(x) for x in (seed, public, message, signature))
    assert ed25519.public_key(s) == p
    assert ed25519.sign(s, m) == sig
    assert ed25519.verify_pure(p, m, sig)
    assert ed25519.verify(p, m, sig)
    tampered = bytes([sig[0] ^ 1]) + sig[1:]
    assert not ed25519.verify_pure(p, m, tampered)
    assert not ed25519.verify(p, m, tampered)
    assert not ed25519.verify_pure(p, m + b"!", sig)


def test_malformed_keys_and_signatures() -> None:
    p = bytes.fromhex(VECTORS[0][1])
    sig = bytes.fromhex(VECTORS[0][3])
    assert not ed25519.verify(p[:31], b"", sig)
    assert not ed25519.verify(p, b"", sig[:63])
    assert not ed25519.verify_pure(b"\xff" * 32, b"", sig)  # not a point
    high_s = sig[:32] + (int.from_bytes(sig[32:], "little") + ed25519.L).to_bytes(32, "little")
    assert not ed25519.verify_pure(p, b"", high_s)
    with pytest.raises(ValueError, match="32 bytes"):
        ed25519.sign(b"short", b"")


def test_backend() -> None:
    assert ed25519.backend() in ("cryptography", "python")


def test_the_specification_example_verifies(example: Any) -> None:
    entry = Homebrew.from_json(example("homebrew"))
    assert hb.verify_signature(entry) is True
    entry.build += 1
    assert hb.verify_signature(entry) is False


# The eight encodings of points of small order (the identity, and the points
# of order 2, 4 and 8, with both signs where they differ).
SMALL_ORDER = [
    bytes.fromhex(h)
    for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
]


@pytest.mark.parametrize("key", SMALL_ORDER)
def test_small_order_keys_never_verify(key: bytes) -> None:
    # A key of small order with R of small order and S = 0 satisfies the
    # verification equation for a quarter of messages or more: whatever the
    # backend, it must be refused for every message.
    for r in SMALL_ORDER:
        forged = r + bytes(32)
        for n in range(16):
            message = b"Frostline Tales %d" % n
            assert not ed25519.verify(key, message, forged)
            assert not ed25519.verify_pure(key, message, forged)


def test_small_order_r_with_a_real_key_never_verifies() -> None:
    key = ed25519.public_key(bytes(range(32)))
    for r in SMALL_ORDER:
        assert not ed25519.verify(key, b"Lea", r + bytes(32))
