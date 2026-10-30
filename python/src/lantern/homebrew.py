"""What a client checks of a homebrew before it installs or starts it (SPEC.md
§ 8), and what a server checks before it serves one:

- path_problem() and manifest_problems(): the paths of § 8.2;
- manifest_of(), manifest_sha256() and signed_message(): a package's
  manifest, and the canonical bytes of § 8.2 and § 8.4;
- verify_signature() and key_fingerprint(): § 8.4's signature;
- install_plan(): where a manifest writes, by the profile's roots (Annex A):
  the paths written without asking, and those shown to the user first; a
  manifest with a path outside every root is refused whole;
- arch_ok() and pick_package(): the package of the device's architecture;
- port_problems() and launch_check(): a port's data (§ 8.6);
- requires_problems() and offer(): the requirements of § 8.7, and whether a
  device offers a package, warns, or refuses it.

Each takes the generated models (lantern.models).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from lantern import ed25519, limits
from lantern._generated.models import (
    GPU_NAMES,
    Homebrew,
    ManifestEntry,
    Package,
    RequiredData,
    RequiredDataGroup,
    RequiredFile,
)
from lantern.profiles import ARCHIVE, SYSTEM, profile
from lantern.vocabulary import ARCH, ARCH_NAMES, SHA256

__all__ = [
    "DOTTED_KEYS",
    "HASH_FORMS",
    "InstallPlan",
    "LaunchCheck",
    "Offer",
    "Refused",
    "arch_ok",
    "compare_dotted",
    "data_files",
    "file_hashes",
    "install_plan",
    "key_change",
    "key_fingerprint",
    "launch_check",
    "manifest_of",
    "manifest_problems",
    "manifest_sha256",
    "offer",
    "path_problem",
    "pick_package",
    "port_problems",
    "requires_problems",
    "signed_message",
    "verify_signature",
]

PURPOSE = "lantern-homebrew-1"
#: requires.min's keys that are dotted versions (SPEC.md § 8.7, Annex A).
DOTTED_KEYS: tuple[str, ...] = ("glibc", "firmware", "atmosphere", "luma", "goldhen", "sdk")
REQUIRES_KEYS: tuple[str, ...] = ("text", "min", "gpu", "homebrew")
#: The hashes a port's accepted version may give, and their length in hex.
HASH_FORMS: Mapping[str, int] = {"sha256": 64, "sha1": 40, "md5": 32}
_DOTTED = re.compile(r"^[0-9]+(\.[0-9]+){0,3}$")
_SCREEN = re.compile(r"^([1-9][0-9]{0,5})x([1-9][0-9]{0,5})$")


class Refused(Exception):
    """A homebrew a client must not install; the message says why."""


# Paths and manifests (SPEC.md § 8.2).


def path_problem(path: str) -> str | None:
    """Why `path` breaks SPEC.md § 8.2, or None."""
    if not path.startswith("/"):
        return f"{path[:80]!r} is not absolute"
    if len(path.encode()) > limits.PATH:
        return f"{path[:40]!r}…: above {limits.PATH} bytes"
    for part in path[1:].split("/"):
        if part in ("", ".", ".."):
            return f"{path[:80]!r} has an empty, . or .. part"
        if len(part.encode()) > limits.PATH_PART:
            return f"{path[:80]!r} has a part above {limits.PATH_PART} bytes"
        if any(c in '\\:"' or ord(c) < 32 or ord(c) == 127 for c in part):
            return f'{path[:80]!r} has a \\, :, " or control character'
    return None


def manifest_problems(manifest: Sequence[ManifestEntry]) -> list[str]:
    """Every way a manifest breaks SPEC.md § 8.2 ([] when it does not)."""
    out = []
    if len(manifest) > limits.MANIFEST_FILES:
        out.append(f"{len(manifest)} files, above {limits.MANIFEST_FILES}")
    seen: set[str] = set()
    for entry in manifest:
        problem = path_problem(entry.path)
        if problem:
            out.append(problem)
            continue
        folded = entry.path.casefold()
        if folded in seen:
            out.append(f"{entry.path!r} twice, when case is ignored")
        seen.add(folded)
        if entry.size < 0 or not SHA256.match(entry.sha256):
            out.append(f"{entry.path!r}: its size or sha256 is not of its form")
    return out


def manifest_of(package: Package) -> list[ManifestEntry]:
    """A package's manifest: its own, a single file's (its `path`), or none
    (the platform's installer installs it)."""
    if package.manifest is not None:
        return list(package.manifest)
    if package.path is not None:
        return [ManifestEntry(path=package.path, size=package.size, sha256=package.sha256)]
    return []


def manifest_sha256(manifest: Iterable[ManifestEntry]) -> str:
    """The SHA-256 of a manifest's canonical form (SPEC.md § 8.2): its entries
    sorted by path as UTF-8 bytes, each {"path","sha256","size"}, no space,
    characters other than ASCII as they are."""
    entries = sorted(manifest, key=lambda e: e.path.encode())
    canonical = (
        "["
        + ",".join(
            '{"path":' + json.dumps(e.path, ensure_ascii=False) + f',"sha256":"{e.sha256}","size":{e.size}}}'
            for e in entries
        )
        + "]"
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# Signatures (SPEC.md § 8.4).


def signed_message(entry: Homebrew, package: Package | None = None) -> bytes:
    """The bytes an author signs for `package` (the entry's own by default)."""
    p = package or entry.package
    return (
        f'{{"build":{entry.build},"id":"{entry.id}","manifest_sha256":"{p.manifest_sha256}",'
        f'"platform":"{entry.platform}","purpose":"{PURPOSE}","sha256":"{p.sha256}"}}'
    ).encode()


def _b64(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def verify_signature(entry: Homebrew, package: Package | None = None) -> bool | None:
    """Whether `package`'s signature (the entry's, for its own package; the
    package's, for one of `packages`) verifies; None when it is unsigned.
    A package of `packages` must be signed by the entry's key."""
    p = package or entry.package
    sig = entry.signature if p is entry.package else p.signature
    if sig is None:
        return None if entry.signature is None else False
    if entry.signature is not None and sig.public_key != entry.signature.public_key:
        return False
    public, value = _b64(sig.public_key), _b64(sig.value)
    if sig.alg != "ed25519" or public is None or value is None:
        return False
    return ed25519.verify(public, signed_message(entry, p), value)


def key_fingerprint(public_key: str) -> str:
    """A key's short fingerprint, for people (SPEC.md § 8.4, in the form of
    § 5.3): the first 16 hex digits of its SHA-256, in groups of 4."""
    raw = _b64(public_key)
    if raw is None:
        raise ValueError("not a base64 key")
    digest = hashlib.sha256(raw).hexdigest()
    return " ".join(digest[i : i + 4].upper() for i in range(0, 16, 4))


def key_change(pinned: str | None, entry: Homebrew) -> Literal["pin", "same", "changed"]:
    """SPEC.md § 8.4: "pin" on a first install (`pinned` None), "same", or
    "changed": another key, or none after one, or one after none; installed
    only when the user explicitly accepts it. `pinned` is "" for an id first
    installed unsigned."""
    offered = entry.signature.public_key if entry.signature is not None else ""
    if pinned is None:
        return "pin"
    return "same" if offered == pinned else "changed"


# Installing (SPEC.md § 8.3, Annex A).


@dataclass
class InstallPlan:
    """The paths a client writes without asking, and those it shows the user
    and writes only once they agree."""

    free: list[str] = field(default_factory=list)
    consent: list[str] = field(default_factory=list)

    @property
    def needs_consent(self) -> bool:
        return bool(self.consent)


def _under(path: str, root: str) -> bool:
    return path.startswith(root) if root.endswith("/") else path == root


def install_plan(entry: Homebrew, package: Package | None = None) -> InstallPlan:
    """Where `package` (the entry's own by default) writes, by the profile's
    roots. Refused when the platform has no profile (or none for homebrew),
    when a path breaks § 8.2, or when one lies outside every root."""
    platform = entry.platform
    prof = profile(platform)
    if prof is None or not prof.homebrew_formats:
        raise Refused(f"no profile for {platform!r} homebrew: nothing of it is installed")
    p = package or entry.package
    place = prof.homebrew_formats.get(p.format)
    if place is None:
        raise Refused(f"{p.format!r} is not a homebrew format of {platform}")
    if place == ARCHIVE and p.manifest is None:
        raise Refused("an archive without its manifest")
    if place == SYSTEM and (p.path is not None or p.manifest):
        raise Refused(f"{p.format!r} is installed by the platform's installer: no path, an empty manifest")
    if place not in (ARCHIVE, SYSTEM) and p.path is None:
        raise Refused(f"a single {p.format!r} file without its path")
    if (
        p.path is not None
        and p.manifest is not None
        and [(m.path, m.size, m.sha256) for m in p.manifest] != [(p.path, p.size, p.sha256)]
    ):
        raise Refused("a path, and a manifest that is not that one file")
    manifest = manifest_of(p)
    problems = manifest_problems(manifest)
    if problems:
        raise Refused("; ".join(problems[:3]))
    if manifest_sha256(manifest) != p.manifest_sha256:
        raise Refused("manifest_sha256 is not the digest of the manifest")
    free, consent = prof.roots(entry.id)
    plan = InstallPlan()
    for e in manifest:
        if any(_under(e.path, r) for r in free):
            plan.free.append(e.path)
        elif any(_under(e.path, r) for r in consent):
            plan.consent.append(e.path)
        else:
            raise Refused(f"{e.path!r} is outside {platform}'s roots")
    return plan


def arch_ok(package: Package, platform: str, mine: str | None = None) -> bool:
    """Without `mine`, whether a package's arch is well formed for its platform
    (none on a platform of one architecture, a list otherwise); with `mine`
    (the device's), whether it may run there: its list holds it, or there is
    none. A name a reader does not know is never its own (SPEC.md § 8.2)."""
    arch = package.arch
    if arch is None:
        return True
    prof = profile(platform)
    if (prof is not None and prof.one_arch) or not arch or not all(ARCH.match(a) for a in arch):
        return False
    return mine is None or (mine in ARCH_NAMES and mine in arch)


def pick_package(entry: Homebrew, mine: str | None) -> Package | None:
    """The package a device of architecture `mine` installs (SPEC.md § 8.2):
    one whose arch lists it, or else one without arch; None when none fits."""
    packages: list[Package] = [entry.package, *(entry.packages or [])]
    if mine is not None:
        for p in packages:
            if p.arch is not None and arch_ok(p, entry.platform, mine):
                return p
    return next((p for p in packages if p.arch is None), None)


# Ports (SPEC.md § 8.6).


def data_files(items: Iterable[RequiredData]) -> list[RequiredFile]:
    """Every file a requires_data names, those of each alternative included."""
    out: list[RequiredFile] = []
    for d in items:
        if isinstance(d, RequiredDataGroup):
            for option in d.one_of:
                out += option
        else:
            out.append(d)
    return out


def port_problems(entry: Homebrew) -> list[str]:
    """Every way a port's `port` object breaks SPEC.md § 8.6: a data_root
    outside the profile's areas or not a folder, a data path that is not
    relative to it, an alternative of fewer than two options, a data file the
    package itself serves (by its path or an accepted sha256), or an accepted
    version without its hash."""
    port = entry.port
    if port is None:
        return ["no port object"] if entry.kind == "port" else []
    out = []
    if not port.original.name:
        out.append("original has no name")
    if not port.engine.name:
        out.append("engine has no name")
    root = port.data_root
    if not (root.endswith("/") and len(root) > 1 and path_problem(root[:-1]) is None):
        return [*out, f"data_root {root[:80]!r} is not a folder's path"]
    prof = profile(entry.platform)
    areas = prof.data_areas if prof is not None else None
    if areas is not None and not any(root.startswith(a) and root != a for a in areas):
        out.append(f"data_root {root!r} is not under {', '.join(areas) or 'any area of the profile'}")
    for d in port.requires_data:
        if isinstance(d, RequiredDataGroup) and (len(d.one_of) < 2 or not all(d.one_of)):
            out.append("one_of has fewer than two alternatives, or an empty one")
    files = data_files(port.requires_data)
    if len(files) > limits.REQUIRED_DATA:
        out.append(f"more than {limits.REQUIRED_DATA} data files")
    single = [d.path for d in port.requires_data if isinstance(d, RequiredFile)]
    groups = [
        single + [f.path for f in option]
        for d in port.requires_data
        if isinstance(d, RequiredDataGroup)
        for option in d.one_of
    ]
    if any(len(set(g)) != len(g) for g in [single, *groups]):
        out.append("a data path twice")
    served: list[Package] = [entry.package, *(entry.packages or [])]
    shipped = {m.path for p in served for m in manifest_of(p)}
    hashes = {p.sha256 for p in served} | {m.sha256 for p in served for m in manifest_of(p)}
    for f in files:
        if f.path.startswith("/"):
            out.append(f"data path {f.path[:80]!r} is not relative to data_root")
            continue
        problem = path_problem(root + f.path)
        if problem:
            out.append(f"data path {f.path[:80]!r}: {problem}")
            continue
        if root + f.path in shipped:
            out.append(f"data {root + f.path!r} is in the package: Lantern never serves a port's data")
        if not f.hint:
            out.append(f"data {f.path!r}: no hint saying where the user finds it")
        if f.accept is not None and len(f.accept) > limits.ACCEPT:
            out.append(f"data {f.path!r}: more than {limits.ACCEPT} accepted versions")
        for a in f.accept or ():
            given = {k: v for k, v in (("sha256", a.sha256), ("sha1", a.sha1), ("md5", a.md5)) if v is not None}
            if not given or not all(re.fullmatch(f"[0-9a-f]{{{HASH_FORMS[k]}}}", v) for k, v in given.items()):
                out.append(f"data {f.path!r}: an accepted version without a hash of a known form")
            elif a.sha256 in hashes:
                out.append(f"data {f.path!r}: the package serves a file of an accepted hash")
    return out


def file_hashes(data: bytes) -> dict[str, str]:
    """The hashes a client compares a data file with, for launch_check()."""
    return {k: hashlib.new(k, data).hexdigest() for k in HASH_FORMS}


def _accepted(f: RequiredFile, hashes: Mapping[str, str]) -> bool:
    if not f.accept:
        return True
    for a in f.accept:
        given = {k: v for k, v in (("sha256", a.sha256), ("sha1", a.sha1), ("md5", a.md5)) if v is not None}
        if given and all(hashes.get(k) == v for k, v in given.items()):
            return True
    return False


@dataclass
class LaunchCheck:
    """What launch_check() found: the port starts only when `ok`."""

    missing: list[str] = field(default_factory=list)
    wrong: list[str] = field(default_factory=list)
    absent_optional: list[str] = field(default_factory=list)
    #: For each group none of whose alternatives is complete: every alternative's paths.
    choices: list[list[list[str]]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing and not self.wrong


def launch_check(entry: Homebrew, present: Mapping[str, Mapping[str, str]]) -> LaunchCheck:
    """What a client checks before it starts a port (SPEC.md § 8.6). `present`
    maps a path relative to data_root (exact, case included) to file_hashes()
    of the file there. For a group none of whose alternatives is complete and
    right, `missing` names the first alternative's files, and `choices` every
    alternative, so that the client can guide the user with each `hint`."""
    out = LaunchCheck()
    port = entry.port
    if port is None:
        return out

    def check(files: Iterable[RequiredFile], into: LaunchCheck) -> None:
        for f in files:
            if f.path not in present:
                (into.absent_optional if f.optional else into.missing).append(f.path)
            elif not _accepted(f, present[f.path]):
                into.wrong.append(f.path)

    for d in port.requires_data:
        if isinstance(d, RequiredDataGroup):
            tries = []
            for option in d.one_of:
                result = LaunchCheck()
                check(option, result)
                tries.append(result)
            if any(t.ok for t in tries):
                continue
            first = [f.path for f in d.one_of[0]] if d.one_of else []
            if d.optional and not any(t.wrong for t in tries):
                out.absent_optional += first
                continue
            out.missing += (tries[0].missing if tries else []) or first
            out.wrong += [w for t in tries for w in t.wrong]
            out.choices.append([[f.path for f in option] for option in d.one_of])
        else:
            check([d], out)
    return out


# Requirements (SPEC.md § 8.7).


def requires_problems(entry: Homebrew) -> list[str]:
    """Every way an entry's `requires` breaks SPEC.md § 8.7's shapes, for the
    keys this library knows (the others are a later version's or a vendor's)."""
    requires = entry.requires
    if requires is None:
        return []
    out = []
    if not requires.text:
        out.append("requires has no text")
    for k, v in (requires.min or {}).items():
        if k == "ram_mb" and not (isinstance(v, int) and not isinstance(v, bool) and v >= 1):
            out.append(f"requires.min.ram_mb {v!r} is not a positive integer")
        elif k == "screen" and not (isinstance(v, str) and _SCREEN.match(v)):
            out.append(f"requires.min.screen {v!r} is not <width>x<height>")
        elif k in DOTTED_KEYS and not (isinstance(v, str) and _DOTTED.match(v)):
            out.append(f"requires.min.{k} {v!r} is not a dotted version")
    if requires.gpu is not None and not requires.gpu:
        out.append("requires.gpu is empty")
    return out


def compare_dotted(a: str, b: str) -> int:
    """-1, 0 or 1: two dotted versions compared part by part, as numbers, a missing part being 0."""
    pa, pb = [int(p) for p in a.split(".")], [int(p) for p in b.split(".")]
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)


@dataclass
class Offer:
    """Whether a client offers a package (SPEC.md § 8.7): "offer", "warn" (with
    the conditions it cannot read, and `text` shown) or "refuse" (with the
    conditions that fail, and why)."""

    decision: Literal["offer", "warn", "refuse"]
    reasons: list[str] = field(default_factory=list)


def offer(entry: Homebrew, device: Mapping[str, object]) -> Offer:
    """Whether a client offers `entry`'s package on `device`, which says what
    the client knows of itself, each key absent when it does not know it:
    {"glibc": "2.31", "ram_mb": 1024, "screen": "1280x720",
    "gpu": ["gles2", "gles3"]}, and the profile's keys ("firmware": "18.0.0").
    A refusal wins over a warning; requires.homebrew is not a condition (the
    client installs it first)."""
    requires = entry.requires
    if requires is None:
        return Offer("offer")
    fails: list[str] = []
    unknown: list[str] = []
    for k, v in (requires.min or {}).items():
        mine = device.get(k)
        if k == "ram_mb" and isinstance(v, int) and not isinstance(v, bool):
            if not isinstance(mine, int) or isinstance(mine, bool):
                unknown.append(f"ram_mb {v} (this device's memory is unknown)")
            elif mine < v:
                fails.append(f"ram_mb: {v} MiB or more; this device has {mine}")
        elif k == "screen" and isinstance(v, str) and (want := _SCREEN.match(v)):
            have = _SCREEN.match(mine) if isinstance(mine, str) else None
            if have is None:
                unknown.append(f"screen {v} (this device's screen is unknown)")
            elif any(int(h) < int(w) for h, w in zip(have.groups(), want.groups(), strict=True)):
                fails.append(f"screen: {v} or larger; this device's is {mine}")
        elif k in DOTTED_KEYS and isinstance(v, str) and _DOTTED.match(v):
            if not (isinstance(mine, str) and _DOTTED.match(mine)):
                unknown.append(f"{k} {v} (this device's is unknown)")
            elif compare_dotted(mine, v) < 0:
                fails.append(f"{k}: {v} or later; this device has {mine}")
        else:
            unknown.append(f"min.{k} {v!r}")
    if requires.gpu is not None:
        known = [g for g in requires.gpu if g in GPU_NAMES]
        mine = device.get("gpu")
        if not isinstance(mine, (list, tuple)):
            unknown.append("gpu " + ", ".join(requires.gpu) + " (this device's graphics are unknown)")
        elif not any(g in mine for g in known):
            if known and len(known) == len(requires.gpu):
                fails.append(
                    "gpu: one of "
                    + ", ".join(requires.gpu)
                    + "; this device has "
                    + (", ".join(map(str, mine)) or "none")
                )
            else:
                unknown.append("gpu " + ", ".join(g for g in requires.gpu if g not in GPU_NAMES))
    for k in requires.extra:
        if not k.startswith("x-"):
            unknown.append(k)
    if fails:
        return Offer("refuse", fails)
    return Offer("warn", unknown) if unknown else Offer("offer")
