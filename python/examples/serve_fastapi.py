"""Adds Lantern to a FastAPI app: the same one-game library as serve_flask.py.

uvicorn --factory examples.serve_fastapi:make_app --port 8080
python examples/serve_fastapi.py 8080
"""

from __future__ import annotations

import sys

from fastapi import FastAPI

from lantern.server import LanternApp, MemoryLibrary
from lantern.server.fastapi import include


def make_app() -> FastAPI:
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
    app = FastAPI()
    include(app, LanternApp(library, uid="3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name="Living room shelf"))
    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(make_app(), host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
