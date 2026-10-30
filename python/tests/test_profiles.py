"""Platform profiles (SPEC.md Annex A)."""

from __future__ import annotations

import pytest

from lantern import profiles


def test_known_and_open_platforms() -> None:
    assert set(profiles.PROFILES) == {"switch", "3ds", "vita", "ps4", "android", "linux"}
    assert not profiles.SWITCH.draft and all(p.draft for k, p in profiles.PROFILES.items() if k != "switch")
    for name in profiles.OPEN_PLATFORMS:
        assert profiles.profile(name) is None and profiles.is_platform(name)
    assert profiles.is_platform("x-example-handheld")
    assert not profiles.is_platform("Switch") and not profiles.is_platform("-switch") and not profiles.is_platform("")


@pytest.mark.parametrize(
    ("platform", "title_id", "ok"),
    [
        ("switch", "0100ABCD00010000", True),
        ("switch", "0100ABCD00010800", False),
        ("switch", "0100abcd00010000", False),
        ("3ds", "0004000000123400", True),
        ("3ds", "0004000E00123400", False),
        ("vita", "PCSE00000", True),
        ("vita", "pcse00000", False),
        ("ps4", "CUSA00000", True),
        ("ps4", "CUSA0000", False),
        ("android", "org.example.frostlinetales", True),
        ("android", "frostline", False),
        ("windows", "anything-goes_1.0", True),
        ("windows", "not an id", False),
        ("linux", "a.b", True),
    ],
)
def test_title_ids(platform: str, title_id: str, ok: bool) -> None:
    assert profiles.title_id_ok(platform, title_id) is ok


@pytest.mark.parametrize(
    ("platform", "app_id", "kind", "ok"),
    [
        ("switch", "0100ABCD00010800", "update", True),
        ("switch", "0100ABCD00010000", "update", False),
        ("switch", "0100ABCD00011001", "dlc", True),
        ("switch", "0100ABCD00010800", "base", False),
        ("3ds", "0004000E00123400", "update", True),
        ("3ds", "0004008C00123400", "dlc", True),
        ("3ds", "0004000000123400", "dlc", False),
        ("vita", "EP0000-PCSE00000_00-FROSTLINEPACK001", "dlc", True),
        ("vita", "PCSE00000", "dlc", False),
        ("ps4", "UP0000-CUSA00000_00-FROSTLINEPACK001", "dlc", True),
        ("ps4", "CUSA00000", None, True),
        ("android", "org.example.a", "base", True),
        ("macos", "x", None, True),
    ],
)
def test_app_ids(platform: str, app_id: str, kind: str | None, ok: bool) -> None:
    assert profiles.app_id_ok(platform, app_id, kind) is ok


def test_switch_ids() -> None:
    assert profiles.switch_ids("0100ABCD00010000") == ("0100ABCD00010000", "base")
    assert profiles.switch_ids("0100ABCD00010800") == ("0100ABCD00010000", "update")
    assert profiles.switch_ids("0100ABCD00011001") == ("0100ABCD00010000", "dlc")
    assert profiles.switch_update_id("0100ABCD00010000") == "0100ABCD00010800"
    with pytest.raises(ValueError, match="Switch"):
        profiles.switch_ids("0100abcd00010000")
    with pytest.raises(ValueError, match="title id"):
        profiles.switch_update_id("0100ABCD00010800")


def test_version_codes() -> None:
    assert profiles.switch_version_code("v196608") == 196608
    assert profiles.switch_version_code("65536") == 65536
    assert profiles.app_ver_code("01.03") == 103
    assert profiles.n3ds_version_name(2069) == "2.1.5"
    for bad, fn in (
        ("1.3", profiles.app_ver_code),
        ("v-1", profiles.switch_version_code),
        ("v99999999999", profiles.switch_version_code),
    ):
        with pytest.raises(ValueError):
            fn(bad)
    with pytest.raises(ValueError):
        profiles.n3ds_version_name(70000)


def test_roots_and_files() -> None:
    sw = profiles.SWITCH
    assert sw.roots("org.example.x") == (
        ["/switch/org.example.x/", "/config/org.example.x/"],
        ["/atmosphere/", "/switch/.overlays/"],
    )
    assert sw.single_file_path("nro", "org.example.x") == "/switch/org.example.x/org.example.x.nro"
    assert sw.single_file_path("ovl", "org.example.x", "x.ovl") == "/switch/.overlays/x.ovl"
    assert sw.single_file_path("zip", "org.example.x") is None and sw.is_single_file("nro")
    assert profiles.VITA.single_file_path("vpk", "x") is None and not profiles.VITA.is_single_file("vpk")
    assert sw.one_arch and not profiles.LINUX.one_arch
    assert profiles.ANDROID.newer_base_replaces and not profiles.LINUX.installs_apps


def test_cheat_paths() -> None:
    assert (
        profiles.cheat_path("switch", "0100ABCD00010000", "4A1B2C3D4E5F60718293")
        == "/atmosphere/contents/0100ABCD00010000/cheats/4A1B2C3D4E5F6071.txt"
    )
    assert profiles.cheat_path("3ds", "0004000000123400") == "/cheats/0004000000123400.txt"
    assert profiles.cheat_path("vita", "PCSE00000") == "/ux0/vitacheat/db/PCSE00000.psv"
    assert profiles.cheat_path("ps4", "CUSA00000", "01.03", "shn") == "/data/GoldHEN/cheats/shn/CUSA00000_01.03.shn"
    for args in (
        ("android", "org.example.a"),
        ("switch", "0100ABCD00010000", "zz"),
        ("switch", "0100ABCD00010800", "AB"),
        ("switch", "0100ABCD00010000"),
    ):
        with pytest.raises(ValueError):
            profiles.cheat_path(*args)
