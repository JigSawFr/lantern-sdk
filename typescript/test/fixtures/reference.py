#!/usr/bin/env python3
"""The specification's reference server (spec/server), started for the
TypeScript library's integration tests over its fictional library
(spec/tests/library.py), as python/tests/test_reference_v04.py starts it.

    python3 test/fixtures/reference.py [--tls] [--public] [--bound-only]

It prints one JSON line once it listens, then serves until it is stopped
(SIGTERM, or its standard input closed):

    {"url", "spki", "admin_token", "admin_seed", "token", "switch", "served",
     "served_homebrew", "frostline", "paperlamp", "harbor", "port"}

- private (the default): accounts lea (every scope but admin) and ada
  (every scope); `admin_token` is ada's, bound to the device key whose
  32-byte seed is `admin_seed` (base64); pairing polls every second;
- `--public`: anyone reads the library; `token` is a bearer-only token of
  lea's (library, cheats);
- `--tls`: a self-signed certificate (the `cryptography` package), whose
  key's fingerprint is `spki`.

Every name, key and game in it is fictional.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve()
REPOSITORY = HERE.parents[3]
SPEC = REPOSITORY / "spec"
sys.path.insert(0, str(SPEC))
sys.path.insert(0, str(SPEC / "tests"))
sys.path.insert(0, str(REPOSITORY / "python" / "tools"))
sys.path.insert(0, str(REPOSITORY / "python" / "src"))

import library as fiction  # noqa: E402  (spec/tests/library.py)
from server import lantern_server as ls  # noqa: E402

ls.log = lambda msg: None
ADMIN_SEED = hashlib.sha256(b"Ada's fictional phone key").digest()
EVERY = ["library", "saves", "cheats", "cheats.write", "requests", "admin"]
LEA = ["library", "saves", "cheats", "cheats.write", "requests"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--public", action="store_true")
    parser.add_argument("--bound-only", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="lantern-reference-") as folder:
        root = Path(folder)
        library_root = fiction.make(root / "library")
        password = ls.hash_password("frost-lantern", 1000)
        users = root / "users.json"
        accounts = (
            [{"name": "lea", "password": password, "scopes": ["library", "cheats"], "state": "active"}]
            if args.public
            else [
                {"name": "lea", "password": password, "scopes": LEA, "state": "active"},
                {"name": "ada", "password": password, "scopes": EVERY, "state": "active"},
            ]
        )
        users.write_text(json.dumps({"schema": 1, "public": args.public, "users": accounts}), encoding="utf-8")
        context = spki = None
        if args.tls:
            from hostile_server import make_certificate, server_context, spki_of

            cert, key = make_certificate("Reference shelf")
            context, spki = server_context(cert, key), spki_of(cert)
        lib = ls.Library(library_root, root / "state.json")
        server = ls.LanternServer(
            ("127.0.0.1", 0),
            lib,
            ls.Accounts(users),
            rescan=0,
            quiet=True,
            tls=context,
            spki=spki,
            bound_only=args.bound_only,
        )
        server.pairing.interval = 1
        scheme = "https" if args.tls else "http"
        info = {
            "url": f"{scheme}://127.0.0.1:{server.server_address[1]}/",
            "spki": spki,
            "switch": fiction.SWITCH,
            "served": fiction.SERVED,
            "served_homebrew": fiction.SERVED_HOMEBREW,
            "frostline": fiction.FROSTLINE,
            "paperlamp": fiction.PAPERLAMP,
            "harbor": fiction.HARBOR,
            "port": fiction.PORT,
        }
        if args.public:
            info["token"] = server.tokens.issue("lea", "Lea's test device", ["library", "cheats"])
        else:
            from lantern.ed25519 import public_key  # python/src: the device key of the admin's phone

            info["admin_token"] = server.tokens.issue("ada", "Ada's phone", EVERY, key=public_key(ADMIN_SEED))
            info["admin_seed"] = base64.b64encode(ADMIN_SEED).decode()
            info["old_token"] = server.tokens.issue("lea", "An old console", ["library"])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(json.dumps(info), flush=True)
        try:
            sys.stdin.read()  # until the test closes it, or stops the process
        except KeyboardInterrupt:
            pass
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
