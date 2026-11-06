"""A static library: a library written as JSON files (GitHub Pages, a NAS, a USB stick), then read back.

    python examples/static_library.py out/        # serve out/ with any web server, or open it as a folder

SPEC.md § 21. The files are the same documents a live server sends, with their SHA-256 and a handshake at
`lantern.json`, so a client reads them with no server code behind them.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from lantern.server import MemoryLibrary
from lantern.static import StaticLibrary, export


def main(out: Path) -> None:
    library = MemoryLibrary(base="/api/lantern")
    library.add_app_file(
        data=b"a made-up game",
        platform="switch",
        title_id="0100ABCD00010000",
        app_id="0100ABCD00010000",
        type="base",
        version_code=0,
        name="Frost Garden",
        format="nsp",
        version_name="1.0.0",
    )
    summary = export(library, out, uid="3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name="Shelf on a stick")
    print(f"wrote {summary}")
    with StaticLibrary(out) as shelf:
        print(shelf.handshake().name, [app.name for app in shelf.iter_apps("switch")])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(Path(sys.argv[1]))
    else:
        with tempfile.TemporaryDirectory() as folder:
            main(Path(folder) / "shelf")
