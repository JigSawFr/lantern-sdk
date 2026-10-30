"""A demo server built from the toolkit, over a small fictional library:
games, homebrew and cheat sets that do not exist, for the tests and the
conformance runs.

    python tests/demo.py --framework flask --port 8080      # or fastapi

It serves anonymously (the scopes library and cheats), and to a caller with
the token DEMO_TOKEN, which `authenticate` takes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import socket
import sys
import threading
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lantern import ed25519
from lantern import homebrew as hb
from lantern.models import (
    AcceptedVersion,
    Homebrew,
    Players,
    Port,
    PortEngine,
    PortOriginal,
    Rating,
    RequiredDataGroup,
    RequiredFile,
    RequiredHomebrew,
    Requires,
    Signature,
    Title,
)
from lantern.server import Account, LanternApp, MemoryLibrary, ServerRequest, make_package

UID = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f"
DEMO_TOKEN = "et_demo-0123456789abcdef0123456789abcdef"
SEED = hashlib.sha256(b"Mira's fictional signing key").digest()  # for the demo only
BASE = "/api/lantern"


def zipped(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, (2026, 10, 30, 12, 0, 0))
            info.external_attr = 0o100644 << 16
            z.writestr(info, data)
    return out.getvalue()


def sign(entry: Homebrew) -> None:
    """Sign every package of `entry` with the demo key (SPEC.md § 8.4)."""
    public = base64.b64encode(ed25519.public_key(SEED)).decode()

    def sig(package: Any) -> Signature:
        value = ed25519.sign(SEED, hb.signed_message(entry, package))
        return Signature(alg="ed25519", public_key=public, value=base64.b64encode(value).decode())

    entry.signature = sig(entry.package)
    for p in entry.packages or []:
        p.signature = sig(p)


def blob(label: str, size: int) -> bytes:
    """`size` bytes, the same each run, that are no real game's."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:size])


def build_library() -> MemoryLibrary:
    lib = MemoryLibrary(base=BASE)
    # Switch games: a base, two updates and an add-on; a second game; an Android app.
    games = [
        ("Lumen Drift", "0100AB1200010000", "0100AB1200010000", "base", 0, "1.0.0", "nsp", 5000),
        ("Lumen Drift", "0100AB1200010000", "0100AB1200010800", "update", 65536, "1.1.0", "nsz", 1200),
        ("Lumen Drift", "0100AB1200010000", "0100AB1200010800", "update", 131072, "1.2.0", "nsz", 1500),
        ("Lumen Drift: Comet Pack", "0100AB1200010000", "0100AB1200011001", "dlc", 0, None, "nsp", 600),
        ("Copper Moth", "0100CD3400020000", "0100CD3400020000", "base", 0, "1.0.0", "xci", 4000),
        ("Copper Moth", "0100CD3400020000", "0100CD3400020800", "update", 196608, "1.3.0", "nsp", 900),
        ("Quiet Tide", "0100EF5600030000", "0100EF5600030000", "base", 0, "1.0.0", "nsp", 0),
    ]
    for i, (name, title_id, app_id, kind, version, version_name, fmt, size) in enumerate(games):
        lib.add_app_file(
            data=blob(f"{app_id}v{version}", size),
            platform="switch",
            title_id=title_id,
            app_id=app_id,
            type=kind,
            version_code=version,
            version_name=version_name,
            name=name,
            format=fmt,
            added=f"2026-10-{10 + i:02d}T12:00:00Z",
        )
    lib.add_app_file(
        data=blob("lumen-android", 2048),
        platform="android",
        title_id="org.example.lumendrift",
        app_id="org.example.lumendrift",
        type="base",
        version_code=12,
        version_name="1.2.0",
        name="Lumen Drift",
        format="apk",
        added="2026-10-20T12:00:00Z",
    )
    lib.add_title(
        Title(
            platform="switch",
            title_id="0100AB1200010000",
            name="Lumen Drift",
            language="en",
            publisher="Northwind Toys",
            developer="Northwind Toys",
            release="2025-11-02",
            genres=["adventure", "puzzle"],
            tags=["co-op", "space"],
            players=Players(min=1, max=2, online=False),
            ratings=[Rating(system="PEGI", rating="7")],
            languages=["en", "fr"],
            summary="Guide a drifting lantern between quiet planets.",
        )
    )
    lib.add_title(
        Title(
            platform="switch",
            title_id="0100CD3400020000",
            name="Copper Moth",
            release="2026-02-14",
            genres=["platformer"],
            summary="A moth of copper looks for the moon.",
        )
    )
    lib.add_title(
        Title(
            platform="switch",
            title_id="0100EF5600030000",
            name="Quiet Tide",
            release="2024-06-30",
            genres=["simulation"],
        )
    )
    lib.add_title(
        Title(
            platform="android",
            title_id="org.example.lumendrift",
            name="Lumen Drift",
            release="2026-03-01",
            genres=["adventure"],
        )
    )
    add_homebrew(lib)
    lib.add_cheat(
        platform="switch",
        title_id="0100AB1200010000",
        build_id="AB12CD34EF560789",
        source="Community list",
        note="Endless lamp oil",
        text="[Endless lamp oil]\n04000000 0011A0B0 00000063\n",
    )
    lib.add_cheat(
        platform="switch",
        title_id="0100AB1200010000",
        build_id="AB12CD34EF560789",
        source="Mira",
        text="[Slow comets]\n04000000 0011A0C8 00000001\n",
    )
    lib.add_cheat(
        platform="switch",
        title_id="0100CD3400020000",
        build_id="0123456789ABCDEF",
        source="Community list",
        text="[Moon jump]\n04000000 00ABC010 0000FFFF\n",
    )
    return lib


def add_homebrew(lib: MemoryLibrary) -> None:
    # A signed archive, with a manifest under the Switch's free roots.
    star = "org.example.starjar"
    data = zipped(
        {f"switch/{star}/starjar.nro": blob("starjar.nro", 700), f"config/{star}/settings.ini": b"[jar]\nstars=12\n"}
    )
    package, file = make_package(data, "zip", platform="switch", homebrew_id=star)
    entry = Homebrew(
        id=star,
        platform="switch",
        kind="tool",
        name="Star Jar",
        author="Mira",
        version="1.2.0",
        build=10200,
        license="MIT",
        summary="Keep the stars you saw tonight.",
        genres=["education"],
        tags=["notes"],
        requires=Requires(text="Atmosphère 1.7 or later", min={"atmosphere": "1.7.0"}),
        updated="2026-10-29T08:00:00Z",
        package=package,
    )
    sign(entry)
    lib.add_homebrew(entry, {package.file: file})
    # The same id built for the 3DS: a single .3dsx.
    package, file = make_package(blob("starjar.3dsx", 300), "3dsx", platform="3ds", homebrew_id=star)
    lib.add_homebrew(
        Homebrew(
            id=star,
            platform="3ds",
            kind="tool",
            name="Star Jar",
            author="Mira",
            version="1.1.0",
            build=10100,
            package=package,
        ),
        {package.file: file},
    )
    # A single .nro, a game.
    clock = "org.example.mothclock"
    package, file = make_package(blob("mothclock.nro", 400), "nro", platform="switch", homebrew_id=clock)
    lib.add_homebrew(
        Homebrew(
            id=clock,
            platform="switch",
            kind="game",
            name="Moth Clock",
            author="Oren",
            version="0.4.0",
            build=400,
            genres=["puzzle"],
            package=package,
        ),
        {package.file: file},
    )
    # An overlay: a root that needs consent, and a loader it needs.
    glow = "org.example.glowmeter"
    package, file = make_package(
        blob("glow.ovl", 256), "ovl", platform="switch", homebrew_id=glow, file_name="glowmeter.ovl"
    )
    lib.add_homebrew(
        Homebrew(
            id=glow,
            platform="switch",
            kind="overlay",
            name="Glow Meter",
            author="Oren",
            version="1.0.0",
            build=100,
            requires=Requires(
                text="An overlay loader", homebrew=[RequiredHomebrew(id="org.example.overlay-loader", min_build=1)]
            ),
            package=package,
        ),
        {package.file: file},
    )
    # A port: the user brings the original game's data.
    port_id = "org.example.tidewalk-port"
    data = zipped(
        {
            f"switch/{port_id}/tidewalk.nro": blob("tidewalk.nro", 500),
            f"switch/{port_id}/readme.txt": b"Bring tide.pak from your own copy.\n",
        }
    )
    package, file = make_package(data, "zip", platform="switch", homebrew_id=port_id)
    pak = blob("tide.pak 1.0", 512)
    lib.add_homebrew(
        Homebrew(
            id=port_id,
            platform="switch",
            kind="port",
            name="Tidewalk Port",
            author="Oren",
            version="0.3.0",
            build=300,
            genres=["adventure"],
            license="GPL-2.0-or-later",
            package=package,
            port=Port(
                original=PortOriginal(name="Tidewalk", year=1999, developer="Northwind Toys"),
                engine=PortEngine(name="Shoreline", version="0.3.0"),
                data_root="/switch/tidewalk/",
                assets="user_owned",
                requires_data=[
                    RequiredFile(
                        path="data/tide.pak",
                        size=len(pak),
                        accept=[AcceptedVersion(label="1.0", sha256=hashlib.sha256(pak).hexdigest())],
                        hint="tide.pak, in the folder where Tidewalk is installed.",
                    ),
                    RequiredDataGroup(
                        one_of=[
                            [RequiredFile(path="music/full.pak", hint="From the soundtrack.")],
                            [RequiredFile(path="music/demo.pak", hint="From the free demo.")],
                        ],
                        optional=True,
                    ),
                ],
            ),
        ),
        {package.file: file},
    )
    # A Linux port, a package per architecture, signed.
    harbor = "org.example.harborglow"
    files = {}
    packages = []
    for arch in (["aarch64", "armhf"], ["x86_64"]):
        data = zipped(
            {
                "Harbor Glow.sh": b"#!/bin/sh\nexec ./org.example.harborglow/harbor\n",
                f"{harbor}/harbor.{arch[0]}": blob(f"harbor.{arch[0]}", 300),
            }
        )
        p, f = make_package(data, "zip", platform="linux", homebrew_id=harbor, arch=arch)
        packages.append(p)
        files[p.file] = f
    entry = Homebrew(
        id=harbor,
        platform="linux",
        kind="port",
        name="Harbor Glow",
        author="Mira",
        version="2.0.0",
        build=20000,
        genres=["simulation"],
        requires=Requires(text="glibc 2.30, OpenGL ES 2, 512 MiB", min={"glibc": "2.30", "ram_mb": 512}, gpu=["gles2"]),
        package=packages[0],
        packages=packages[1:],
        port=Port(
            original=PortOriginal(name="Harbor Glow"),
            engine=PortEngine(name="Beacon"),
            data_root=f"/{harbor}/data/",
            assets="user_owned",
            requires_data=[RequiredFile(path="HARBOR.PAK", hint="From your own copy.")],
        ),
    )
    sign(entry)
    lib.add_homebrew(entry, files)
    # An Android app, installed by the system.
    remote = "org.example.mothremote"
    package, file = make_package(
        blob("remote.apk", 300), "apk", platform="android", homebrew_id=remote, arch=["aarch64", "armhf"]
    )
    lib.add_homebrew(
        Homebrew(
            id=remote,
            platform="android",
            kind="tool",
            name="Moth Remote",
            author="Oren",
            version="3.0",
            build=30,
            system_id=remote,
            package=package,
        ),
        {package.file: file},
    )


def authenticate(request: ServerRequest) -> Account | None:
    header = request.header("Authorization") or ""
    if header == f"Bearer {DEMO_TOKEN}":
        return Account(scopes=frozenset({"library", "cheats"}), name="mira")
    return None


def make_lantern(library: MemoryLibrary | None = None, **options: Any) -> LanternApp:
    return LanternApp(
        library or build_library(),
        uid=UID,
        name="Demo shelf",
        base=BASE,
        software=("lantern-protocol demo", "0.1"),
        authenticate=authenticate,
        **options,
    )


def flask_app(lantern: LanternApp) -> Any:
    import flask

    from lantern.server.flask import init_app

    app = flask.Flask("lantern_demo")
    init_app(app, lantern)
    return app


def fastapi_app(lantern: LanternApp) -> Any:
    import fastapi

    from lantern.server.fastapi import include

    app = fastapi.FastAPI()
    include(app, lantern)
    return app


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@contextmanager
def serve(framework: str, lantern: LanternApp | None = None, port: int = 0) -> Iterator[str]:
    """The demo served on loopback, by `framework` (flask or fastapi), in a thread; its URL."""
    lantern = lantern or make_lantern()
    port = port or free_port()
    if framework == "flask":
        from werkzeug.serving import make_server

        server = make_server("127.0.0.1", port, flask_app(lantern), threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{port}/"
        finally:
            server.shutdown()
            thread.join(5)
    elif framework == "fastapi":
        import uvicorn

        config = uvicorn.Config(fastapi_app(lantern), host="127.0.0.1", port=port, log_level="warning", lifespan="off")
        userver = uvicorn.Server(config)
        thread = threading.Thread(target=userver.run, daemon=True)
        thread.start()
        for _ in range(200):
            if userver.started:
                break
            time.sleep(0.025)
        try:
            yield f"http://127.0.0.1:{port}/"
        finally:
            userver.should_exit = True
            thread.join(5)
    else:
        raise ValueError(framework)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--framework", choices=("flask", "fastapi"), default="flask")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    with serve(args.framework, port=args.port) as url:
        print(f"demo: {url} ({args.framework}); token {DEMO_TOKEN}", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
