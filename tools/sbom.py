#!/usr/bin/env python3
"""The release's SBOMs, in CycloneDX JSON (RELEASING.md).

    python3 tools/sbom.py native cpp --version 0.5.0 -o lantern-cpp.cdx.json
    python3 tools/sbom.py native c --version 0.5.0 -o lantern-c.cdx.json
    python3 tools/sbom.py normalize npm.cdx.json --name lantern-protocol --version 0.5.0 \
        --purl pkg:npm/lantern-protocol@0.5.0
    python3 tools/sbom.py validate dist/*.cdx.json

`native` writes the SBOM of the C++ library or of the C API: neither has a
package manager whose files a scanner reads, so what they are made of is
taken from cpp/THIRD_PARTY_NOTICES.md, where each vendored library is listed
with its version, origin, checksum and licence (Monocypher, inside the
library; doctest, for the tests only, so listed as excluded). The optional
TLS adapters' libraries (libcurl, mbedTLS) are the app's, not shipped: they
are left out, as the release's binaries are built without the adapters.

`normalize` makes another tool's SBOM reproducible: no random serial number,
the timestamp of SOURCE_DATE_EPOCH, the package's own name and version on
its main component (`npm sbom` names it after the folder).

Every SBOM is reproducible: its timestamp is SOURCE_DATE_EPOCH (else the
commit's time), its serial number a UUID made from its content.

Standard library only, but for `validate`, which checks each SBOM against
its CycloneDX schema with cyclonedx-python-lib (tools/release-requirements.txt).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICES = ROOT / "cpp" / "THIRD_PARTY_NOTICES.md"
REPO = "https://github.com/JigSawFr/lantern-sdk"
# A fixed namespace, so that the same content always gets the same serial number
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, REPO)


def epoch() -> int:
    if "SOURCE_DATE_EPOCH" in os.environ:
        return int(os.environ["SOURCE_DATE_EPOCH"])
    out = subprocess.run(
        ["git", "-C", str(ROOT), "log", "-1", "--format=%ct"], capture_output=True, text=True, check=False
    )
    return int(out.stdout.strip()) if out.returncode == 0 and out.stdout.strip() else 0


def timestamp() -> str:
    return datetime.datetime.fromtimestamp(epoch(), tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def vendored() -> list[dict[str, object]]:
    """The components cpp/THIRD_PARTY_NOTICES.md lists, one `## Name version (where)` section each."""
    components = []
    sections = re.split(r"^## ", NOTICES.read_text(encoding="utf-8"), flags=re.M)[1:]
    for section in sections:
        heading = section.splitlines()[0]
        match = re.match(r"(?P<name>\S+) (?P<version>\d[\w.]*) \((?P<where>[^)]*)\)", heading)
        if not match:
            raise SystemExit(f"sbom.py: {NOTICES.name}: a heading not of the form 'Name version (where)': {heading}")
        name, version = match["name"], match["version"]
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": f"vendored:{name.lower()}@{version}",
            "name": name.lower(),
            "version": version,
            # In the library, or used by its tests only
            "scope": "excluded" if "tests only" in match["where"] else "required",
            "purl": f"pkg:generic/{name.lower()}@{version}",
        }
        # "Licence: `BSD-2-Clause OR CC0-1.0`, …" or "Licence: MIT. …"
        licence = re.search(r"Licence: (?:`([^`]+)`|([A-Za-z0-9.+-]+?)\.(?:\s|$))", section)
        if licence:
            expression = (licence.group(1) or licence.group(2)).strip()
            component["licenses"] = (
                [{"expression": expression}] if " " in expression else [{"license": {"id": expression}}]
            )
        url = re.search(r"<(https://[^>]+)>", section)
        hashes = []
        for digest in re.findall(r"`([0-9a-f]{64,128})`", section):
            hashes.append({"alg": "SHA-512" if len(digest) == 128 else "SHA-256", "content": digest})
        if url:
            reference: dict[str, object] = {"type": "distribution", "url": url.group(1)}
            if hashes:
                reference["hashes"] = hashes
            component["externalReferences"] = [reference]
        component["properties"] = [{"name": "lantern:vendored-in", "value": "cpp/third_party"}]
        components.append(component)
    return components


def document(
    main: dict[str, object], components: list[dict[str, object]], dependencies: list[dict[str, object]]
) -> dict[str, object]:
    bom: dict[str, object] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp(),
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "name": "lantern-sdk tools/sbom.py"}]},
            "component": main,
        },
        "components": components,
        "dependencies": dependencies,
    }
    return with_serial(bom)


def with_serial(bom: dict[str, object]) -> dict[str, object]:
    bom.pop("serialNumber", None)
    content = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    serial = f"urn:uuid:{uuid.uuid5(NAMESPACE, content)}"
    return {
        "$schema": bom.pop("$schema", None),
        "bomFormat": bom.pop("bomFormat"),
        "specVersion": bom.pop("specVersion"),
        "serialNumber": serial,
        **bom,
    }


def library(name: str, version: str, description: str, extra: dict[str, object] | None = None) -> dict[str, object]:
    component: dict[str, object] = {
        "type": "library",
        "bom-ref": f"{name}@{version}",
        "name": name,
        "version": version,
        "description": description,
        "licenses": [{"license": {"id": "MIT"}}],
        "purl": f"pkg:github/JigSawFr/lantern-sdk@v{version}",
        "externalReferences": [{"type": "vcs", "url": f"{REPO}.git"}, {"type": "website", "url": REPO}],
    }
    component.update(extra or {})
    return component


def native(part: str, version: str) -> dict[str, object]:
    third = vendored()
    cpp = library(
        "lantern",
        version,
        "The C++23 library of the Lantern protocol (cpp/, CMake package Lantern)",
        {"properties": [{"name": "lantern:subpath", "value": "cpp"}]},
    )
    if part == "cpp":
        return document(
            cpp,
            third,
            [
                {"ref": cpp["bom-ref"], "dependsOn": [c["bom-ref"] for c in third if c["scope"] == "required"]},
            ]
            + [{"ref": c["bom-ref"]} for c in third],
        )
    c = library(
        "lantern-c",
        version,
        "The C API of the Lantern protocol over the C++ library (c/, CMake package LanternC)",
        {"properties": [{"name": "lantern:subpath", "value": "c"}]},
    )
    inner = dict(cpp, scope="required")
    return document(
        c,
        [inner, *third],
        [
            {"ref": c["bom-ref"], "dependsOn": [cpp["bom-ref"]]},
            {"ref": cpp["bom-ref"], "dependsOn": [t["bom-ref"] for t in third if t["scope"] == "required"]},
        ]
        + [{"ref": t["bom-ref"]} for t in third],
    )


def normalize(path: Path, name: str, version: str, purl: str | None) -> None:
    bom = json.loads(path.read_text(encoding="utf-8"))
    metadata = bom.setdefault("metadata", {})
    metadata["timestamp"] = timestamp()
    component = metadata.get("component")
    if isinstance(component, dict):
        component["name"] = name
        component["version"] = version
        component["bom-ref"] = component.get("bom-ref", f"{name}@{version}")
        if purl:
            component["purl"] = purl
    write(path, with_serial(bom))


def write(path: Path, bom: dict[str, object]) -> None:
    bom = {k: v for k, v in bom.items() if v is not None}
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def validate(paths: list[Path]) -> int:
    from cyclonedx.schema import SchemaVersion  # type: ignore[import-not-found,unused-ignore]
    from cyclonedx.validation.json import JsonStrictValidator  # type: ignore[import-not-found,unused-ignore]

    status = 0
    for path in paths:
        text = path.read_text(encoding="utf-8")
        version = SchemaVersion.from_version(json.loads(text)["specVersion"])
        error = JsonStrictValidator(version).validate_str(text)
        print(f"{path.name}: {'CycloneDX ' + version.to_version() if error is None else error}")
        status |= error is not None
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    n = sub.add_parser("native", help="the SBOM of the C++ library or of the C API")
    n.add_argument("part", choices=["cpp", "c"])
    n.add_argument("--version", required=True)
    n.add_argument("-o", "--output", type=Path, required=True)
    m = sub.add_parser("normalize", help="make another tool's SBOM reproducible")
    m.add_argument("path", type=Path)
    m.add_argument("--name", required=True)
    m.add_argument("--version", required=True)
    m.add_argument("--purl", help="the package URL of the main component (pkg:pypi/…, pkg:npm/…)")
    v = sub.add_parser("validate", help="check SBOMs against their CycloneDX schema")
    v.add_argument("paths", type=Path, nargs="+")
    args = parser.parse_args(argv)
    if args.command == "validate":
        return validate(args.paths)
    if args.command == "native":
        write(args.output, native(args.part, args.version))
    else:
        normalize(args.path, args.name, args.version, args.purl)
    return 0


if __name__ == "__main__":
    sys.exit(main())
