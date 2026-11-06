"""Reads a Lantern library: who serves it, its apps, what a console is missing, and one verified download.

    python examples/read_library.py https://shelf.example.org/ [platform]

The download is checked against the SHA-256 the server lists and renamed only when it matches; a `.part`
file is resumed with a Range request after a cut (SPEC.md § 6.6).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import lantern


def main(url: str, platform: str = "switch") -> None:
    with lantern.LanternClient(url, platform=platform, user_agent="ReadLibrary/1.0") as client:
        hello = client.handshake()
        print(f"{hello.name}: {', '.join(sorted(hello.features))}")

        apps = list(client.iter_apps(page_size=5))  # every page, cursor by cursor
        for app in apps:
            print(f"  {app.name} {app.version_name or app.version_code} ({app.size} bytes)")

        # What a console that holds the first app, at version 0, is missing.
        if apps:
            page = client.missing([(apps[0].app_id, 0)], want=("update", "dlc"))
            print(f"missing: {len(page.items)} on the first page")

        # The smallest non-empty file, downloaded to a temporary folder and checked on the way.
        if apps:
            smallest = min((a for a in apps if a.size), key=lambda a: a.size)
            with tempfile.TemporaryDirectory() as folder:
                saved = client.download_app(smallest, Path(folder) / f"{smallest.app_id}.pkg")
                print(
                    f"downloaded {smallest.name}: {saved.stat().st_size} bytes, sha256 {smallest.sha256[:12]}… matched"
                )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(*sys.argv[1:3])
