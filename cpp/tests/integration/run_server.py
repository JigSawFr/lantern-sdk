#!/usr/bin/env python3
"""Runs the C++ integration tests against the specification's reference
server, on loopback.

    python3 run_server.py --spec SPEC -- TEST_BINARY [doctest options]

It builds the specification's fictional library (spec/tests/library.py:
Frostline Tales, Moss and Ember, Lea, Noor and Ines…) in a temporary
folder, then starts two reference servers on it (python3 -m server):

- a public one, which answers without a token;
- a private one, paired as a console would (spec/tools/pair_for_ci.py),
  whose token holds every scope.

The test binary reads LANTERN_TEST_PUBLIC, LANTERN_TEST_PRIVATE and
LANTERN_TEST_TOKEN. Both servers are stopped at the end, whatever happens.
Standard library only.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(origin, process, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            sys.exit(f"run_server: the server stopped (exit {process.returncode})")
        try:
            with urllib.request.urlopen(origin + "/.well-known/lantern", timeout=2) as answer:
                if answer.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.2)
    sys.exit("run_server: the server did not answer in time")


def stop(pid):
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--" not in argv:
        sys.exit("usage: run_server.py --spec SPEC -- TEST_BINARY [options]")
    split = argv.index("--")
    p = argparse.ArgumentParser(description="Integration tests against the reference server.")
    p.add_argument("--spec", required=True, help="the specification's folder (the submodule spec/)")
    args = p.parse_args(argv[:split])
    command = argv[split + 1:]
    spec = Path(args.spec).resolve()
    python = sys.executable

    with tempfile.TemporaryDirectory(prefix="lantern-cpp-") as tmp:
        tmp = Path(tmp)
        library = tmp / "library"
        subprocess.run([python, str(spec / "tests" / "library.py"), str(library)], check=True, cwd=spec,
                       stdout=subprocess.DEVNULL)

        public_port = free_port()
        public = subprocess.Popen(
            [python, "-m", "server", "--library", str(library), "--port", str(public_port), "--quiet",
             "--state", str(tmp / "public-state.json"), "--saves", str(tmp / "public-saves")],
            cwd=spec, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=(tmp / "public.log").open("ab"), start_new_session=True)
        private_dir = tmp / "private"
        private_pid = None
        try:
            wait_for(f"http://127.0.0.1:{public_port}", public)
            private_port = free_port()
            paired = subprocess.run(
                [python, str(spec / "tools" / "pair_for_ci.py"), "--library", str(library), "--workdir",
                 str(private_dir), "--port", str(private_port)],
                cwd=spec, capture_output=True, text=True, timeout=120)
            if (private_dir / "server.pid").exists():
                private_pid = int((private_dir / "server.pid").read_text().strip())
            if paired.returncode != 0:
                sys.stderr.write(paired.stderr)
                return paired.returncode
            env = dict(os.environ)
            env["LANTERN_TEST_PUBLIC"] = f"http://127.0.0.1:{public_port}"
            env["LANTERN_TEST_PRIVATE"] = f"http://127.0.0.1:{private_port}"
            env["LANTERN_TEST_TOKEN"] = paired.stdout.strip()
            return subprocess.run(command, env=env).returncode
        finally:
            stop(public.pid)
            if private_pid is not None:
                stop(private_pid)
            for log in (tmp / "public.log", private_dir / "server.log"):
                if log.exists() and log.stat().st_size:
                    sys.stderr.write(f"--- {log.name}\n{log.read_text(errors='replace')[-4000:]}\n")


if __name__ == "__main__":
    sys.exit(main())
