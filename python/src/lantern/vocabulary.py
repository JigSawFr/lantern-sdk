"""The open vocabularies SPEC.md lists in its text rather than in its
schemas. A reader takes a value it does not know as the specification says
(an unknown kind is an app, an unknown `assets` is `user_owned`, an unknown
architecture is never its own); a later version may add values."""

from __future__ import annotations

import re

#: A homebrew's kinds (SPEC.md § 8.1).
KINDS: tuple[str, ...] = ("app", "game", "port", "emulator", "tool", "overlay", "sysmodule", "theme")
#: Where a port's assets come from (SPEC.md § 8.6).
ASSETS: tuple[str, ...] = ("included", "demo_included", "free_external", "user_owned")
#: The architectures a package may name (SPEC.md § 8.2).
ARCH_NAMES: tuple[str, ...] = ("aarch64", "armhf", "x86", "x86_64", "riscv64")
#: The form of an architecture's name, this version's or a later one's (SPEC.md § 8.2).
ARCH = re.compile(r"^[a-z0-9_]{1,32}$")
#: The families of the handshake's `features` (SPEC.md § 4.2).
FAMILIES: tuple[str, ...] = (
    "library",
    "titles",
    "changes",
    "sections",
    "homebrew",
    "saves",
    "cheats",
    "requests",
    "pairing",
    "signatures",
    "admin",
    "events",
    "peers",
    "sync",
    "encrypted_saves",
)
#: A platform's name (SPEC.md § 4.3).
PLATFORM = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
#: A title or an app id, the core's form (SPEC.md § 6.1).
CORE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
#: A homebrew's id (SPEC.md § 8.1).
HOMEBREW_ID = re.compile(r"^(?=.{1,128}$)[a-z][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+$")
#: A lower-case word: a filter's kind or genre, an app's type (SPEC.md § 6.1, § 8.5).
WORD = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: A cheat set's build id, the core's form (SPEC.md § 10).
BUILD_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
#: A SHA-256, lower-case hex.
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def is_platform(name: str) -> bool:
    """Whether `name` is a platform's name (SPEC.md § 4.3)."""
    return bool(PLATFORM.match(name))
