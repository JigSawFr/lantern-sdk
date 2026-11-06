"""Adds Lantern to a Flask app: a library of one made-up game, served anonymously.

    python examples/serve_flask.py 8080        # then: curl http://127.0.0.1:8080/.well-known/lantern

`MemoryLibrary` holds apps in memory; a real server implements `lantern.server.Library` over its own
files and database. For tokens, pairing and signed requests, pass `accounts=MemoryAccounts(...)`
(or an `authenticate` hook) to `LanternApp`.
"""

from __future__ import annotations

import sys

from flask import Flask

from lantern.server import LanternApp, MemoryLibrary
from lantern.server.flask import init_app


def make_app() -> Flask:
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
    app = Flask(__name__)
    init_app(app, LanternApp(library, uid="3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name="Living room shelf"))
    return app


if __name__ == "__main__":
    make_app().run(host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
