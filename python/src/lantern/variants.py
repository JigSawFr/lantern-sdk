"""Packages a device cannot use, and variants of one game (SPEC.md § 6.1,
Annex B.15).

An app lists the package `format` it is in, the `requires` tokens a device
must provide to use it (Annex A names those of each platform: on the Switch
`fs-compression`, `sigpatch`, `ncz-sparse` and `ncz-lz4`), and the versions it
`includes`. The same game may be listed in several *variants*: the same
`app_id` and `version_code`, differing in format or `requires`.

A client keeps three rules (the conformance suite cannot see them):

- **L-6.1-3, L-6.1-4**: it MUST NOT install an app of a format or with a
  `requires` token it does not know or cannot satisfy. It may list it as
  unavailable and say why. `install_decision` applies it: pass the formats
  your client reads and the tokens it knows *and* the device provides.
- **L-6.1-5**: it MUST NOT install an update that an installed app already
  `includes`, at its version or above. `included` and `install_decision` apply it.
- Which variant to install by default is the client's choice; `prefer_variant`
  is the one Annex B.15 recommends (the fewest `requires`, then the smallest
  file).

    from lantern.variants import install_decision, prefer_variant

    verdict, why = install_decision(app, {"nsp", "nsz"}, {"fs-compression"}, installed=on_device)
    if verdict == "unavailable":
        print("cannot install:", "; ".join(why))
"""

from __future__ import annotations

from collections.abc import Collection, Iterable

from lantern._generated.models import App

INSTALL = "install"
UNAVAILABLE = "unavailable"


def included(app: App, installed: Iterable[App]) -> bool:
    """Whether `app` is an update that an installed app includes at its version or above (L-6.1-5).
    `installed` are the apps (documents of § 6.1) the device has installed; only `update` apps can be included."""
    if app.type != "update":
        return False
    return any(
        i.app_id == app.app_id and i.version_code >= app.version_code for a in installed for i in a.includes or []
    )


def install_decision(
    app: App, formats: Collection[str], satisfies: Collection[str], installed: Iterable[App] = ()
) -> tuple[str, list[str]]:
    """Whether a client installs `app` (SPEC.md § 6.1): ("install", []) or ("unavailable", [reasons…]).

    `formats` are the package formats the client knows, `satisfies` the `requires` tokens it knows and the device
    provides, `installed` the apps the device has installed. A format or a token the client does not know is
    refused as one it cannot satisfy (L-6.1-3, L-6.1-4), and so is an update an installed app includes (L-6.1-5)."""
    why: list[str] = []
    if app.format not in formats:
        why.append(f"format {app.format!r}")
    why += [f"requires {t!r}" for t in app.requires or [] if t not in satisfies]
    if included(app, installed):
        why.append("already included by an installed app")
    return (UNAVAILABLE, why) if why else (INSTALL, [])


def prefer_variant(variants: Iterable[App]) -> App:
    """The variant a client installs by default among apps that share an `app_id` and a `version_code`
    (Annex B.15): the fewest `requires`, then the smallest `size`, then the smaller `id`, so that two clients agree."""
    return min(variants, key=lambda a: (len(a.requires or []), a.size, a.id))


__all__ = ["INSTALL", "UNAVAILABLE", "included", "install_decision", "prefer_variant"]
