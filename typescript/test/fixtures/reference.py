#!/usr/bin/env python3
"""The specification's reference server (spec/server), started for the
TypeScript library's integration tests over its fictional library
(spec/tests/library.py), as python/tests/test_reference_v04.py starts it.

    python3 test/fixtures/reference.py [--tls] [--public] [--bound-only] [--v05]

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
  key's fingerprint is `spki`;
- `--v05` (private): what draft 0.5 adds. lea also holds sync.read and
  sync.write, and `lea_token` is hers, bound to the key whose seed is
  `lea_seed`; events beat every 5 seconds; `export` is the library written
  as a static library (spec/server/static.py), and `peer` the address of a
  reference peer (spec/server/peer.py) that holds the library's files and
  takes this server's grants.

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
SYNC = ["sync.read", "sync.write"]
LEA_SEED = hashlib.sha256(b"Lea's fictional console key").digest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--public", action="store_true")
    parser.add_argument("--bound-only", action="store_true")
    parser.add_argument("--v05", action="store_true")
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
                {"name": "lea", "password": password, "scopes": LEA + (SYNC if args.v05 else []), "state": "active"},
                {"name": "ada", "password": password, "scopes": EVERY + (SYNC if args.v05 else []), "state": "active"},
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
            **({"heartbeat": 5} if args.v05 else {}),
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
            if args.v05:
                info["lea_token"] = server.tokens.issue("lea", "Lea's console", LEA + SYNC, key=public_key(LEA_SEED))
                info["lea_seed"] = base64.b64encode(LEA_SEED).decode()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        peer = None
        if args.v05 and not args.public:
            from server import peer as reference_peer
            from server import static

            info["export"] = str(root / "static")
            static.export(ls, lib, root / "static", page_size=4, name="Reference shelf, static")
            uid, key, wanted = reference_peer.server_files(info["url"], info["admin_token"], ADMIN_SEED, None)
            held = reference_peer.held_files(library_root, wanted)
            peer = reference_peer.Peer(("127.0.0.1", 0), held, {uid: key}, slots=2, name="Lea's Switch")
            threading.Thread(target=peer.serve_forever, daemon=True).start()
            info["peer"] = f"http://127.0.0.1:{peer.server_address[1]}{reference_peer.BASE}"
            info["peer_uid"] = peer.uid
            info["library_root"] = str(library_root)
        print(json.dumps(info), flush=True)
        try:
            sys.stdin.read()  # until the test closes it, or stops the process
        except KeyboardInterrupt:
            pass
        if peer is not None:
            peer.shutdown()
            peer.server_close()
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
