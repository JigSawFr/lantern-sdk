"""What a device is missing (SPEC.md § 6.3) and the homebrew it could update
(§ 8.5), computed from a listing: what a server answers, and what a client
computes itself from a static library's pages (§ 21.3, L-21.3-2), by the
same rules."""

from __future__ import annotations

from collections.abc import Collection, Iterable

from lantern._generated.models import App, Homebrew
from lantern.profiles import profile, switch_ids


def missing(
    apps: Iterable[App],
    platform: str,
    installed: list[tuple[str, int]],
    want: set[str],
    *,
    formats: Collection[str] | None = None,
    satisfies: Collection[str] | None = None,
) -> list[App]:
    """What a device of `platform` is missing (SPEC.md § 6.3), among `apps` (those of other platforms left out).

    An installed app that is one of `apps` also installs what it `includes` (L-6.3-4). `formats` and `satisfies`,
    when not None, are applied last and leave out the apps the device cannot install (L-6.3-3): None is no
    filter, an empty collection filters everything that needs one (every app has a format)."""
    apps = [a for a in apps if a.platform == platform]
    installed = list(installed)
    for app_id, version in list(installed):
        for a in apps:
            if a.app_id == app_id and a.version_code == version:
                installed += [(i.app_id, i.version_code) for i in a.includes or []]
    prof = profile(platform)
    replaces = prof.newer_base_replaces if prof is not None else False
    by_app = {a.app_id: a for a in apps}
    have: dict[str, int] = {}
    for app_id, version in installed:
        known = by_app.get(app_id)
        if known is not None:
            title, kind = known.title_id, known.type
        elif platform == "switch" and len(app_id) == 16:
            try:
                title, kind = switch_ids(app_id)
            except ValueError:
                continue
        else:
            continue  # a game this server does not know
        if kind in ("base", "update"):
            have[title] = max(have.get(title, -1), version)
    ids = {app_id for app_id, _ in installed}
    out: dict[str, App] = {}
    for title, version in have.items():
        mine = [a for a in apps if a.title_id == title]
        if replaces:
            updates = [a for a in mine if a.type == "base" and a.app_id in ids]
        else:
            updates = [a for a in mine if a.type == "update"]
        newest = max((a.version_code for a in updates), default=-1)
        if "update" in want and newest > version:
            out.update({a.id: a for a in updates if a.version_code == newest})
        if "dlc" in want:
            out.update({a.id: a for a in mine if a.type == "dlc" and a.app_id not in ids})
    if "base" in want:
        out.update({a.id: a for a in apps if a.type == "base" and a.title_id not in have})
    found = list(out.values())
    if formats is not None:
        found = [a for a in found if a.format in formats]
    if satisfies is not None:
        found = [a for a in found if set(a.requires or ()) <= set(satisfies)]
    return found


def homebrew_updates(
    entries: Iterable[Homebrew], platform: str, installed: Iterable[tuple[str, int]]
) -> list[Homebrew]:
    """The entries of `platform` newer than what is installed, (id, build) (SPEC.md § 8.5): a build above
    the highest installed of the same id."""
    builds: dict[str, int] = {}
    for homebrew_id, build in installed:
        builds[homebrew_id] = max(builds.get(homebrew_id, -1), build)
    return [e for e in entries if e.platform == platform and e.id in builds and e.build > builds[e.id]]


__all__ = ["homebrew_updates", "missing"]
