"""Platform profiles (SPEC.md Annex A): what the core leaves open, per
platform. The Switch's is complete; the 3DS's, the Vita's, the PS4's,
Android's and Linux's are drafts (`draft` is True), still to be reviewed by
someone who knows the platform. The other platforms have no profile yet:
`profile()` gives None, and a client installs nothing of them (SPEC.md § 4.3).

    from lantern import profiles
    p = profiles.profile("switch")
    p.title_id_ok("0100ABCD00010000")         # True
    profiles.switch_ids("0100ABCD00010800")   # ("0100ABCD00010000", "update")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from lantern.vocabulary import ARCH_NAMES, CORE_ID, PLATFORM

#: A homebrew format the platform's own installer installs: no path, an empty manifest (SPEC.md § 8.2).
SYSTEM: Final = "system"
#: A homebrew format that is an archive with a manifest (SPEC.md § 8.2).
ARCHIVE: Final = "archive"


@dataclass(frozen=True)
class Cheats:
    """Where a client writes a cheat set (Annex A): `path` with {title_id},
    {build_id} (Atmosphère's first 16 digits on a Switch) and {format}."""

    format: str
    path: str
    build_id: re.Pattern[str] | None


@dataclass(frozen=True)
class Profile:
    """One platform's profile (Annex A)."""

    platform: str
    draft: bool
    #: A game's title id.
    title_id: re.Pattern[str] | None
    #: An app's id, by its type (None: any type).
    app_ids: dict[str | None, re.Pattern[str]]
    #: The app types, and the package formats; None where the profile has no apps (Linux).
    types: tuple[str, ...] | None
    formats: tuple[str, ...] | None
    #: A newer package of the same app_id replaces the base: it is the update (Android, SPEC.md § 6.3).
    newer_base_replaces: bool = False
    #: Each homebrew format: a single file's path ({id}, {file}), ARCHIVE or SYSTEM.
    homebrew_formats: dict[str, str] = field(default_factory=dict)
    #: The roots a homebrew writes to without asking ({id}: its id), and those that need consent.
    free_roots: tuple[str, ...] = ()
    consent_roots: tuple[str, ...] = ()
    #: Where a port's data_root may lie; None where the user picks a folder (Android).
    data_areas: tuple[str, ...] | None = ()
    #: The architectures of `arch`; None on a platform of one architecture, where a package has none.
    arches: tuple[str, ...] | None = None
    #: The platform's own keys of requires.min (SPEC.md § 8.7).
    requires_min: tuple[str, ...] = ()
    #: The platform's own id of installed software (SPEC.md § 8.1).
    system_id: bool = False
    #: The save kinds (SPEC.md § 9.1); none where saves have no profile.
    save_kinds: tuple[str, ...] = ()
    cheats: Cheats | None = None
    #: Whether a client may install apps of it (Linux: homebrew only, Annex A.6).
    installs_apps: bool = True

    def title_id_ok(self, title_id: str) -> bool:
        """A title id of the core's form and of this profile's."""
        return bool(CORE_ID.match(title_id)) and (self.title_id is None or bool(self.title_id.match(title_id)))

    def app_id_ok(self, app_id: str, app_type: str | None = None) -> bool:
        """An app id of the core's form and of this profile's, for its type when given."""
        if not CORE_ID.match(app_id):
            return False
        pattern = self.app_ids.get(app_type) or self.app_ids.get(None)
        return pattern is None or bool(pattern.match(app_id))

    def is_single_file(self, fmt: str) -> bool:
        place = self.homebrew_formats.get(fmt)
        return place is not None and place not in (SYSTEM, ARCHIVE)

    def single_file_path(self, fmt: str, homebrew_id: str, file_name: str = "") -> str | None:
        """Where a single-file package of `fmt` goes (Annex A), or None for an archive or the system's installer."""
        place = self.homebrew_formats.get(fmt)
        if place is None or place in (SYSTEM, ARCHIVE):
            return None
        return place.format(id=homebrew_id, file=file_name)

    def roots(self, homebrew_id: str) -> tuple[list[str], list[str]]:
        """(free, consent): the roots of a homebrew's manifest, its id put in."""
        return (
            [r.format(id=homebrew_id) for r in self.free_roots],
            [r.format(id=homebrew_id) for r in self.consent_roots],
        )

    @property
    def one_arch(self) -> bool:
        return self.arches is None


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


_SWITCH_ID = _re(r"^[0-9A-F]{16}$")
_SWITCH_TITLE = _re(r"^[0-9A-F]{12}[02468ACE]000$")
_3DS_TITLE = _re(r"^0004000[02][0-9A-F]{8}$")
_VITA_TITLE = _re(r"^[A-Z0-9]{9}$")
_VITA_CONTENT = _re(r"^[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}$")
_PS4_TITLE = _re(r"^[A-Z]{4}[0-9]{5}$")
_PS4_CONTENT = _re(r"^[A-Z]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}$")
_ANDROID = _re(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
_BASE_TYPES = ("base", "update", "dlc")

SWITCH = Profile(
    platform="switch",
    draft=False,
    title_id=_SWITCH_TITLE,
    app_ids={None: _SWITCH_ID, "base": _SWITCH_TITLE, "update": _re(r"^[0-9A-F]{12}[02468ACE]800$")},
    types=_BASE_TYPES,
    formats=("nsp", "nsz", "xci", "xcz"),
    homebrew_formats={"nro": "/switch/{id}/{id}.nro", "ovl": "/switch/.overlays/{file}", "zip": ARCHIVE},
    free_roots=("/switch/{id}/", "/config/{id}/"),
    consent_roots=("/atmosphere/", "/switch/.overlays/"),
    data_areas=("/switch/", "/config/"),
    requires_min=("firmware", "atmosphere"),
    save_kinds=("account", "device", "bcat", "cache", "other"),
    cheats=Cheats("atmosphere", "/atmosphere/contents/{title_id}/cheats/{build_id}.txt", _re(r"^[0-9A-F]{1,64}$")),
)
N3DS = Profile(
    platform="3ds",
    draft=True,
    title_id=_3DS_TITLE,
    app_ids={
        None: _re(r"^0004(0000|0002|000E|008C)[0-9A-F]{8}$"),
        "base": _3DS_TITLE,
        "update": _re(r"^0004000E[0-9A-F]{8}$"),
        "dlc": _re(r"^0004008C[0-9A-F]{8}$"),
    },
    types=_BASE_TYPES,
    formats=("cia",),
    homebrew_formats={"3dsx": "/3ds/{id}/{id}.3dsx", "zip": ARCHIVE, "cia": SYSTEM},
    free_roots=("/3ds/{id}/",),
    consent_roots=("/luma/", "/boot.firm", "/boot.3dsx", "/gm9/"),
    data_areas=("/3ds/",),
    requires_min=("firmware", "luma"),
    system_id=True,
    save_kinds=("device", "other"),
    cheats=Cheats("gateshark", "/cheats/{title_id}.txt", None),
)
VITA = Profile(
    platform="vita",
    draft=True,
    title_id=_VITA_TITLE,
    app_ids={
        None: _re(f"{_VITA_TITLE.pattern}|{_VITA_CONTENT.pattern}"),
        "base": _VITA_TITLE,
        "update": _VITA_TITLE,
        "dlc": _VITA_CONTENT,
    },
    types=_BASE_TYPES,
    formats=("vpk", "pkg"),
    homebrew_formats={"vpk": SYSTEM},
    free_roots=("/ux0/data/{id}/",),
    consent_roots=("/ux0/tai/", "/ur0/tai/"),
    data_areas=("/ux0/data/",),
    system_id=True,
    save_kinds=("device",),
    cheats=Cheats("psv", "/ux0/vitacheat/db/{title_id}.psv", None),
)
PS4 = Profile(
    platform="ps4",
    draft=True,
    title_id=_PS4_TITLE,
    app_ids={
        None: _re(f"{_PS4_TITLE.pattern}|{_PS4_CONTENT.pattern}"),
        "base": _PS4_TITLE,
        "update": _PS4_TITLE,
        "dlc": _PS4_CONTENT,
    },
    types=_BASE_TYPES,
    formats=("pkg",),
    homebrew_formats={"pkg": SYSTEM},
    free_roots=("/data/{id}/",),
    consent_roots=("/data/GoldHEN/",),
    data_areas=("/data/",),
    requires_min=("firmware", "goldhen"),
    system_id=True,
    save_kinds=("account",),
    cheats=Cheats(
        "json", "/data/GoldHEN/cheats/{format}/{title_id}_{build_id}.{format}", _re(r"^[0-9]{2}\.[0-9]{2}(_.+)?$")
    ),
)
ANDROID = Profile(
    platform="android",
    draft=True,
    title_id=_ANDROID,
    app_ids={None: _ANDROID},
    types=("base",),
    formats=("apk", "apks"),
    newer_base_replaces=True,
    homebrew_formats={"apk": SYSTEM, "apks": SYSTEM},
    data_areas=None,
    arches=("aarch64", "armhf", "x86", "x86_64"),
    requires_min=("sdk",),
    system_id=True,
)
LINUX = Profile(
    platform="linux",
    draft=True,
    title_id=None,
    app_ids={},
    types=None,
    formats=None,
    homebrew_formats={"zip": ARCHIVE},
    free_roots=("/{id}/",),
    consent_roots=("/",),
    data_areas=("/",),
    arches=ARCH_NAMES,
    requires_min=("glibc", "ram_mb", "screen"),
    installs_apps=False,
)

PROFILES: MappingProxyType[str, Profile] = MappingProxyType(
    {p.platform: p for p in (SWITCH, N3DS, VITA, PS4, ANDROID, LINUX)}
)
#: Platforms named by SPEC.md § 4.3 that have no profile yet (Annex A.7).
OPEN_PLATFORMS: tuple[str, ...] = ("ios", "windows", "macos", "web", "steam", "gog", "xbox")


def profile(platform: str) -> Profile | None:
    """The platform's profile, or None when it has none (a client installs nothing of it)."""
    return PROFILES.get(platform)


def is_platform(name: str) -> bool:
    """Whether `name` is a platform's name (SPEC.md § 4.3)."""
    return bool(PLATFORM.match(name))


def title_id_ok(platform: str, title_id: str) -> bool:
    """A title id of the core's form, and of the platform's profile when it has one."""
    p = profile(platform)
    return p.title_id_ok(title_id) if p is not None else bool(CORE_ID.match(title_id))


def app_id_ok(platform: str, app_id: str, app_type: str | None = None) -> bool:
    """An app id of the core's form, and of the platform's profile when it has one."""
    p = profile(platform)
    return p.app_id_ok(app_id, app_type) if p is not None else bool(CORE_ID.match(app_id))


def switch_ids(app_id: str) -> tuple[str, str]:
    """(title_id, type) of a Switch app id (Annex A.1): the base's id ends in
    000 (its lowest 13 bits zero), its update's in 800, an add-on's otherwise."""
    if not _SWITCH_ID.match(app_id):
        raise ValueError(f"{app_id!r} is not a Switch id")
    n = int(app_id, 16)
    low = n & 0x1FFF
    kind = "base" if low == 0 else "update" if low == 0x800 else "dlc"
    return f"{n & ~0x1FFF:016X}", kind


def switch_update_id(title_id: str) -> str:
    """The app id of a Switch game's update: its title id plus 800 (hex)."""
    if not _SWITCH_TITLE.match(title_id):
        raise ValueError(f"{title_id!r} is not a Switch game's title id")
    return f"{int(title_id, 16) + 0x800:016X}"


def switch_version_code(text: str) -> int:
    """A Switch title version as the system reads it, from `v196608` or `196608` (Annex A.1)."""
    m = re.fullmatch(r"v?(\d{1,10})", text.strip())
    if not m or int(m.group(1)) > 0xFFFFFFFF:
        raise ValueError(f"{text!r} is not a Switch title version")
    return int(m.group(1))


def app_ver_code(app_ver: str) -> int:
    """`APP_VER` `XX.YY` as XX*100+YY: a Vita's or a PS4's version_code (Annex A.3, A.4)."""
    m = re.fullmatch(r"(\d{2})\.(\d{2})", app_ver.strip())
    if not m:
        raise ValueError(f"{app_ver!r} is not an APP_VER (XX.YY)")
    return int(m.group(1)) * 100 + int(m.group(2))


def n3ds_version_name(version_code: int) -> str:
    """A 3DS title version's name (Annex A.2): its top 6 bits, next 6 and low 4, `2069` being `2.1.5`."""
    if not 0 <= version_code <= 0xFFFF:
        raise ValueError(f"{version_code} is not a 16-bit title version")
    return f"{version_code >> 10}.{(version_code >> 4) & 0x3F}.{version_code & 0xF}"


def cheat_path(platform: str, title_id: str, build_id: str | None = None, fmt: str | None = None) -> str:
    """Where a client writes a cheat set (Annex A). On a Switch, Atmosphère names
    the file with the first 16 digits of the build id."""
    p = profile(platform)
    if p is None or p.cheats is None:
        raise ValueError(f"no cheats on {platform}")
    if p.cheats.build_id is not None and (build_id is None or not p.cheats.build_id.match(build_id)):
        raise ValueError(f"{build_id!r} is not a {platform} build id")
    if not p.title_id_ok(title_id):
        raise ValueError(f"{title_id!r} is not a {platform} title id")
    build = (build_id or "")[:16] if platform == "switch" else (build_id or "")
    return p.cheats.path.format(title_id=title_id, build_id=build, format=fmt or p.cheats.format)
