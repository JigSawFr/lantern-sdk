"""What a client checks of a homebrew (SPEC.md § 8), with the specification's
examples and refused examples."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest

from conftest import EXAMPLES, load
from lantern import ed25519
from lantern import homebrew as hb
from lantern._base import DocumentError
from lantern.models import (
    AcceptedVersion,
    Homebrew,
    ManifestEntry,
    Package,
    Port,
    PortEngine,
    PortOriginal,
    RequiredDataGroup,
    RequiredFile,
    Requires,
    Signature,
)

SHA = "a" * 64


def refused(name: str) -> Any:
    return load(EXAMPLES / "invalid" / f"homebrew.{name}.json")


def entry(platform: str = "switch", hid: str = "org.example.frostline", **package: Any) -> Homebrew:
    manifest = package.pop("manifest", [ManifestEntry(path=f"/switch/{hid}/{hid}.nro", size=10, sha256=SHA)])
    fields = {"format": "zip", "file": "/f", "size": 10, "sha256": SHA, **package}
    if fields["format"] == "zip":
        fields["manifest"] = manifest
    fields["manifest_sha256"] = hb.manifest_sha256(hb.manifest_of(Package(manifest_sha256="", **fields)))
    return Homebrew(
        id=hid, platform=platform, kind="app", name="Frostline", version="1.0", build=100, package=Package(**fields)
    )


# Paths (SPEC.md § 8.2).


@pytest.mark.parametrize("path", ["/switch/x/y.nro", "/config/x/é.ini", "/a b/c", "/" + "a" * 255])
def test_good_paths(path: str) -> None:
    assert hb.path_problem(path) is None


@pytest.mark.parametrize(
    "path",
    [
        "switch/x",
        "/switch//x",
        "/switch/./x",
        "/switch/../atmosphere",
        "/a\\b",
        "/C:/x",
        '/a"b',
        "/a\x00b",
        "/a\x1fb",
        "/a\x7fb",
        "/" + "a" * 256,
        "/a/" * 300,
        "/",
    ],
)
def test_bad_paths(path: str) -> None:
    assert hb.path_problem(path) is not None


@pytest.mark.parametrize("name", ["dotdot-path", "drive-path", "unc-path", "relative-path"])
def test_refused_manifests_of_the_specification(name: str) -> None:
    e = Homebrew.from_json(refused(name))
    assert hb.manifest_problems(hb.manifest_of(e.package))
    with pytest.raises(hb.Refused):
        hb.install_plan(e)


def test_paths_twice_when_case_is_ignored() -> None:
    m = [
        ManifestEntry(path="/switch/x/A.nro", size=1, sha256=SHA),
        ManifestEntry(path="/switch/x/a.nro", size=1, sha256=SHA),
    ]
    assert any("twice" in p for p in hb.manifest_problems(m))
    assert hb.manifest_problems([ManifestEntry(path="/a", size=-1, sha256="x")])
    assert hb.manifest_problems([ManifestEntry(path=f"/a/{i}", size=1, sha256=SHA) for i in range(4097)])


def test_manifest_sha256_of_the_example(example: Any) -> None:
    e = Homebrew.from_json(example("homebrew"))
    assert e.package.manifest is not None
    assert hb.manifest_sha256(e.package.manifest) == e.package.manifest_sha256
    assert hb.manifest_sha256(reversed(e.package.manifest)) == e.package.manifest_sha256


def test_manifest_canonical_form() -> None:
    m = [ManifestEntry(path="/b/é", size=2, sha256=SHA), ManifestEntry(path="/a", size=1, sha256=SHA)]
    canonical = f'[{{"path":"/a","sha256":"{SHA}","size":1}},{{"path":"/b/é","sha256":"{SHA}","size":2}}]'
    assert hb.manifest_sha256(m) == hashlib.sha256(canonical.encode()).hexdigest()


def test_signed_message() -> None:
    e = entry()
    assert (
        hb.signed_message(e)
        == (
            '{"build":100,"id":"org.example.frostline","manifest_sha256":"'
            + e.package.manifest_sha256
            + '","platform":"switch","purpose":"lantern-homebrew-1","sha256":"'
            + SHA
            + '"}'
        ).encode()
    )


# Signatures and pinning (SPEC.md § 8.4).


def _sign(e: Homebrew, seed: bytes, package: Package | None = None) -> Signature:
    value = ed25519.sign(seed, hb.signed_message(e, package))
    return Signature(
        alg="ed25519",
        public_key=base64.b64encode(ed25519.public_key(seed)).decode(),
        value=base64.b64encode(value).decode(),
    )


def test_signatures() -> None:
    seed, other = b"\x01" * 32, b"\x02" * 32
    e = entry()
    assert hb.verify_signature(e) is None
    e.signature = _sign(e, seed)
    assert hb.verify_signature(e) is True
    e.signature.alg = "rsa"
    assert hb.verify_signature(e) is False
    e.signature = _sign(e, seed)
    e.signature.value = "not base64!"
    assert hb.verify_signature(e) is False
    # A package of `packages`: its own signature, by the entry's key.
    e.signature = _sign(e, seed)
    extra = Package(format="zip", file="/g", size=3, sha256="b" * 64, manifest_sha256="c" * 64, arch=["x86_64"])
    assert hb.verify_signature(e, extra) is False  # unsigned after a signed entry
    extra.signature = _sign(e, other, extra)
    assert hb.verify_signature(e, extra) is False  # another key
    extra.signature = _sign(e, seed, extra)
    assert hb.verify_signature(e, extra) is True


def test_key_change_and_fingerprint() -> None:
    e = entry()
    assert hb.key_change(None, e) == "pin"
    assert hb.key_change("", e) == "same"
    e.signature = _sign(e, b"\x01" * 32)
    assert hb.key_change("", e) == "changed"
    assert hb.key_change(e.signature.public_key, e) == "same"
    fp = hb.key_fingerprint(e.signature.public_key)
    assert len(fp) == 19 and fp == fp.upper() and fp.count(" ") == 3
    with pytest.raises(ValueError, match="base64"):
        hb.key_fingerprint("%%%")


# Install plans (SPEC.md § 8.3, Annex A).


def test_install_plan_free_and_consent() -> None:
    hid = "org.example.frostline"
    e = entry(
        manifest=[
            ManifestEntry(path=f"/switch/{hid}/f.nro", size=1, sha256=SHA),
            ManifestEntry(path=f"/config/{hid}/s.ini", size=1, sha256=SHA),
            ManifestEntry(path="/atmosphere/contents/0100000000001000/exefs.nsp", size=1, sha256=SHA),
        ]
    )
    plan = hb.install_plan(e)
    assert plan.free == [f"/switch/{hid}/f.nro", f"/config/{hid}/s.ini"]
    assert plan.consent == ["/atmosphere/contents/0100000000001000/exefs.nsp"]
    assert plan.needs_consent


@pytest.mark.parametrize(
    "path", ["/switch/org.example.other/x.nro", "/bootloader/hekate_ipl.ini", "/switch/org.example.frostline.evil/x"]
)
def test_install_plan_refuses_a_path_outside_the_roots(path: str) -> None:
    with pytest.raises(hb.Refused, match="outside"):
        hb.install_plan(entry(manifest=[ManifestEntry(path=path, size=1, sha256=SHA)]))


def test_install_plan_on_linux_and_3ds() -> None:
    hid = "org.example.harborlights"
    e = entry(
        "linux",
        hid,
        manifest=[
            ManifestEntry(path=f"/{hid}/harbor", size=1, sha256=SHA),
            ManifestEntry(path="/Harbor Lights.sh", size=1, sha256=SHA),
        ],
    )
    plan = hb.install_plan(e)
    assert plan.free == [f"/{hid}/harbor"] and plan.consent == ["/Harbor Lights.sh"]
    boot = entry("3ds", manifest=[ManifestEntry(path="/boot.firm", size=1, sha256=SHA)])
    assert hb.install_plan(boot).consent == ["/boot.firm"]
    with pytest.raises(hb.Refused):
        hb.install_plan(entry("3ds", manifest=[ManifestEntry(path="/boot.firmware", size=1, sha256=SHA)]))


def test_install_plan_refuses() -> None:
    with pytest.raises(hb.Refused, match="no profile"):
        hb.install_plan(entry("windows"))
    e = entry()
    e.package.manifest_sha256 = "0" * 64
    with pytest.raises(hb.Refused, match="digest"):
        hb.install_plan(e)
    e = entry()
    e.package.manifest = None
    with pytest.raises(hb.Refused, match="without its manifest"):
        hb.install_plan(e)
    with pytest.raises(hb.Refused, match="not a homebrew format"):
        hb.install_plan(entry(format="exe"))
    single = entry(format="nro", path="/switch/org.example.frostline/org.example.frostline.nro")
    assert hb.install_plan(single).free == ["/switch/org.example.frostline/org.example.frostline.nro"]
    with pytest.raises(hb.Refused, match="without its path"):
        hb.install_plan(entry(format="nro"))
    single.package.manifest = [ManifestEntry(path="/switch/org.example.frostline/other.nro", size=10, sha256=SHA)]
    with pytest.raises(hb.Refused, match="not that one file"):
        hb.install_plan(single)
    apk = entry("android", "org.example.mossremote", format="apk")
    assert hb.install_plan(apk).free == [] and hb.install_plan(apk).consent == []
    apk.package.path = "/data/x.apk"
    with pytest.raises(hb.Refused, match="installer"):
        hb.install_plan(apk)


# Architectures (SPEC.md § 8.2).


def test_arch_and_pick_package() -> None:
    e = entry("linux", "org.example.harbor", manifest=[], arch=["aarch64", "armhf"])
    x86 = Package(format="zip", file="/g", size=1, sha256=SHA, manifest_sha256=SHA, arch=["x86_64"], manifest=[])
    future = Package(
        format="zip", file="/h", size=1, sha256=SHA, manifest_sha256=SHA, arch=["loongarch64"], manifest=[]
    )
    e.packages = [x86, future]
    assert hb.pick_package(e, "x86_64") is x86
    assert hb.pick_package(e, "armhf") is e.package
    assert hb.pick_package(e, "loongarch64") is None  # a name it does not know is never its own
    assert hb.pick_package(e, "riscv64") is None
    generic = Package(format="zip", file="/i", size=1, sha256=SHA, manifest_sha256=SHA, manifest=[])
    e.packages = [x86, generic]
    assert hb.pick_package(e, "riscv64") is generic
    assert hb.arch_ok(future, "linux") and not hb.arch_ok(future, "linux", "loongarch64")
    assert not hb.arch_ok(
        Package(format="nro", file="/", size=1, sha256=SHA, manifest_sha256=SHA, arch=["aarch64"]), "switch"
    )
    assert not hb.arch_ok(
        Package(format="zip", file="/", size=1, sha256=SHA, manifest_sha256=SHA, arch=["ARM64"]), "linux"
    )


def test_refused_arches_of_the_specification() -> None:
    with pytest.raises(DocumentError):
        Homebrew.from_json(refused("arch-not-a-list"))
    e = Homebrew.from_json(refused("unknown-arch-format"))
    assert not all(hb.arch_ok(p, e.platform) for p in [e.package, *(e.packages or [])])


# Ports (SPEC.md § 8.6).


def port_entry(**port: Any) -> Homebrew:
    e = entry(
        hid="org.example.frostline-port",
        manifest=[ManifestEntry(path="/switch/org.example.frostline-port/p.nro", size=10, sha256="d" * 64)],
    )
    e.kind = "port"
    fields = {
        "original": PortOriginal(name="Frostline Tales"),
        "engine": PortEngine(name="Lanternlight"),
        "data_root": "/switch/frostline/",
        "assets": "user_owned",
        "requires_data": [RequiredFile(path="data/frost.pak", hint="In the game's folder.")],
        **port,
    }
    e.port = Port(**fields)
    return e


def test_a_good_port() -> None:
    assert hb.port_problems(port_entry()) == []


@pytest.mark.parametrize(
    "name",
    [
        "port-absolute-data",
        "port-backslash-data",
        "port-dotdot-data-root",
        "port-dotdot-data",
        "port-dotdot-in-group",
        "port-drive-data",
        "port-relative-data-root",
    ],
)
def test_refused_ports_of_the_specification(name: str) -> None:
    assert hb.port_problems(Homebrew.from_json(refused(name)))


def test_port_problems() -> None:
    assert hb.port_problems(port_entry(data_root="/atmosphere/frost/"))
    assert hb.port_problems(port_entry(data_root="/switch/"))
    assert hb.port_problems(port_entry(data_root="/switch/frostline"))
    lonely = RequiredDataGroup(one_of=[[RequiredFile(path="a", hint="h")]])
    assert any("two alternatives" in p for p in hb.port_problems(port_entry(requires_data=[lonely])))
    twice = [RequiredFile(path="a", hint="h"), RequiredFile(path="a", hint="h")]
    assert any("twice" in p for p in hb.port_problems(port_entry(requires_data=twice)))
    shipped = port_entry(
        data_root="/switch/org.example.frostline-port/", requires_data=[RequiredFile(path="p.nro", hint="h")]
    )
    assert any("in the package" in p for p in hb.port_problems(shipped))
    hashed = port_entry(
        requires_data=[RequiredFile(path="x", hint="h", accept=[AcceptedVersion(label="1", sha256="d" * 64)])]
    )
    assert any("accepted hash" in p for p in hb.port_problems(hashed))
    no_hash = port_entry(requires_data=[RequiredFile(path="x", hint="h", accept=[AcceptedVersion(label="1")])])
    assert any("known form" in p for p in hb.port_problems(no_hash))
    assert hb.port_problems(port_entry(requires_data=[RequiredFile(path="x", hint="")]))
    no_port = entry()
    no_port.kind = "port"
    assert hb.port_problems(no_port) == ["no port object"]


def test_launch_check() -> None:
    pak = b"frost.pak 1.1"
    e = port_entry(
        requires_data=[
            RequiredFile(
                path="data/frost.pak",
                hint="h",
                accept=[
                    AcceptedVersion(label="1.0", sha256="0" * 64),
                    AcceptedVersion(label="1.1", md5=hashlib.md5(pak).hexdigest()),
                ],
            ),
            RequiredDataGroup(
                one_of=[
                    [RequiredFile(path="music/full.pak", hint="h"), RequiredFile(path="music/full.idx", hint="h")],
                    [RequiredFile(path="music/demo.pak", hint="h")],
                ]
            ),
            RequiredFile(path="Extras/Bonus.pak", hint="h", optional=True),
        ]
    )
    hashes = hb.file_hashes(pak)
    nothing = hb.launch_check(e, {})
    assert not nothing.ok
    assert nothing.missing == ["data/frost.pak", "music/full.pak", "music/full.idx"]
    assert nothing.absent_optional == ["Extras/Bonus.pak"]
    assert nothing.choices == [[["music/full.pak", "music/full.idx"], ["music/demo.pak"]]]
    ready = hb.launch_check(e, {"data/frost.pak": hashes, "music/demo.pak": hb.file_hashes(b"m")})
    assert ready.ok
    wrong = hb.launch_check(e, {"data/frost.pak": hb.file_hashes(b"other"), "music/demo.pak": {}})
    assert wrong.wrong == ["data/frost.pak"] and not wrong.ok
    assert hb.launch_check(entry(), {}).ok


def test_launch_check_optional_group() -> None:
    e = port_entry(
        requires_data=[
            RequiredDataGroup(
                one_of=[[RequiredFile(path="a", hint="h")], [RequiredFile(path="b", hint="h")]], optional=True
            )
        ]
    )
    result = hb.launch_check(e, {})
    assert result.ok and result.absent_optional == ["a"]


# Requirements (SPEC.md § 8.7).


@pytest.mark.parametrize("name", ["glibc-not-dotted", "ram-as-text", "screen-form", "gpu-empty"])
def test_refused_requirements_of_the_specification(name: str) -> None:
    assert hb.requires_problems(Homebrew.from_json(refused(name)))


def with_requires(**fields: Any) -> Homebrew:
    e = entry("linux", "org.example.harbor", manifest=[])
    e.requires = Requires(text="glibc 2.30", **fields)
    return e


def test_offer() -> None:
    e = with_requires(min={"glibc": "2.30", "ram_mb": 512, "screen": "640x480"}, gpu=["gles2", "vulkan"])
    good = {"glibc": "2.31", "ram_mb": 1024, "screen": "1280x720", "gpu": ["gles2"]}
    assert hb.offer(e, good) == hb.Offer("offer")
    old = hb.offer(e, {**good, "glibc": "2.28"})
    assert old.decision == "refuse" and "this device has 2.28" in old.reasons[0]
    assert hb.offer(e, {**good, "screen": "320x240"}).decision == "refuse"
    assert hb.offer(e, {**good, "ram_mb": 256}).decision == "refuse"
    assert hb.offer(e, {**good, "gpu": ["gl"]}).decision == "refuse"
    unknown = hb.offer(e, {})
    assert unknown.decision == "warn" and len(unknown.reasons) == 4
    assert hb.offer(entry(), {}) == hb.Offer("offer")


def test_offer_warns_for_what_it_cannot_read() -> None:
    e = with_requires(min={"kernel": "5.10", "glibc": "2.30"}, gpu=["gles2", "metal"])
    e.requires.extra = {"vram_mb": 256, "x-example-boost": True}  # type: ignore[union-attr]
    result = hb.offer(e, {"glibc": "2.31", "gpu": ["gl"]})
    assert result.decision == "warn"
    assert any("kernel" in r for r in result.reasons) and any("metal" in r for r in result.reasons)
    assert "vram_mb" in result.reasons and not any("x-example" in r for r in result.reasons)
    refused_first = hb.offer(e, {"glibc": "2.20", "gpu": ["gl"]})
    assert refused_first.decision == "refuse"


def test_compare_dotted() -> None:
    assert hb.compare_dotted("2.30", "2.30.0") == 0
    assert hb.compare_dotted("2.9", "2.30") == -1
    assert hb.compare_dotted("18.0.1", "18.0.0") == 1


def test_data_files() -> None:
    e = port_entry()
    assert e.port is not None
    assert [f.path for f in hb.data_files(e.port.requires_data)] == ["data/frost.pak"]
