#!/usr/bin/env python3
"""Runs the C++ integration tests against the specification's reference
server, on loopback.

    python3 run_server.py --spec SPEC [--tls] [--hostile-server SCRIPT] -- TEST_BINARY [doctest options]

It builds the specification's fictional library (spec/tests/library.py:
Frostline Tales, Moss and Ember, Lea, Noor and Ines…) in a temporary
folder, then starts reference servers on it (python3 -m server):

- a public one, which answers without a token, and LAN discovery on a UDP
  port of its own (SPEC.md § 4.1);
- a private one, paired as a console would (spec/tools/pair_for_ci.py),
  whose token holds every scope and is bound to a device key (§ 5.4);
- with --tls, a public one over HTTPS, with a self-signed certificate made
  for the run (openssl), for the TLS adapters' pinning (§ 5.3);
- with --hostile-server SCRIPT (or LANTERN_HOSTILE_SERVER), a deliberately
  malicious test server, started as `python3 SCRIPT --port N`: the tests
  of a client against it run only then.

The test binary reads LANTERN_TEST_PUBLIC, LANTERN_TEST_PRIVATE,
LANTERN_TEST_TOKEN, LANTERN_TEST_KEY (the device key's seed, base64),
LANTERN_TEST_DISCOVERY_PORT, and with --tls LANTERN_TEST_TLS,
LANTERN_TEST_TLS_SPKI (the SHA-256 of the certificate's SPKI, hex) and
LANTERN_TEST_TLS_CERT (its PEM file), and LANTERN_TEST_HOSTILE. Every
server is stopped at the end, whatever happens. Standard library only, and
openssl for --tls.
"""
import argparse
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(origin, process, seconds=30, context=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            sys.exit(f"run_server: the server stopped (exit {process.returncode})")
        try:
            with urllib.request.urlopen(origin + "/.well-known/lantern", timeout=2, context=context) as answer:
                if answer.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.2)
    sys.exit("run_server: the server did not answer in time")


def wait_for_port(port, process, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            sys.exit(f"run_server: the hostile server stopped (exit {process.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    sys.exit("run_server: the hostile server did not listen in time")


def self_signed(folder):
    """A certificate for 127.0.0.1, made for this run: (cert, key)."""
    cert, key = folder / "tls-cert.pem", folder / "tls-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=Lantern test",
                    "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


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
    p.add_argument("--tls", action="store_true", help="also a public server over HTTPS, self-signed")
    p.add_argument("--hostile-server", default=os.environ.get("LANTERN_HOSTILE_SERVER"),
                   help="a malicious test server's script, started as python3 SCRIPT --port N")
    args = p.parse_args(argv[:split])
    command = argv[split + 1:]
    spec = Path(args.spec).resolve()
    python = sys.executable

    with tempfile.TemporaryDirectory(prefix="lantern-cpp-") as tmp:
        tmp = Path(tmp)
        library = tmp / "library"
        subprocess.run([python, str(spec / "tests" / "library.py"), str(library)], check=True, cwd=spec,
                       stdout=subprocess.DEVNULL)

        public_port, discovery_port = free_port(), free_port(socket.SOCK_DGRAM)
        public = subprocess.Popen(
            [python, "-m", "server", "--library", str(library), "--port", str(public_port), "--quiet",
             "--state", str(tmp / "public-state.json"), "--saves", str(tmp / "public-saves"),
             "--discovery", "--discovery-port", str(discovery_port)],
            cwd=spec, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=(tmp / "public.log").open("ab"), start_new_session=True)
        others = []     # (process, log) of the other servers this script starts
        private_dir = tmp / "private"
        private_pid = None
        env = dict(os.environ)
        try:
            wait_for(f"http://127.0.0.1:{public_port}", public)
            if args.tls:
                cert, key = self_signed(tmp)
                tls_port = free_port()
                log = tmp / "tls.log"
                tls = subprocess.Popen(
                    [python, "-m", "server", "--library", str(library), "--port", str(tls_port), "--quiet",
                     "--state", str(tmp / "tls-state.json"), "--saves", str(tmp / "tls-saves"),
                     "--tls-cert", str(cert), "--tls-key", str(key)],
                    cwd=spec, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log.open("ab"),
                    start_new_session=True)
                others.append((tls, log))
                unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                unverified.check_hostname, unverified.verify_mode = False, ssl.CERT_NONE
                wait_for(f"https://127.0.0.1:{tls_port}", tls, context=unverified)
                sys.path.insert(0, str(spec))
                from server import lantern_server
                env["LANTERN_TEST_TLS"] = f"https://127.0.0.1:{tls_port}"
                env["LANTERN_TEST_TLS_SPKI"] = lantern_server.spki_sha256(cert.read_text(encoding="ascii"))
                env["LANTERN_TEST_TLS_CERT"] = str(cert)
            if args.hostile_server:
                hostile_port = free_port()
                log = tmp / "hostile.log"
                hostile = subprocess.Popen([python, args.hostile_server, "--port", str(hostile_port)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=log.open("ab"), start_new_session=True)
                others.append((hostile, log))
                wait_for_port(hostile_port, hostile)
                env["LANTERN_TEST_HOSTILE"] = f"http://127.0.0.1:{hostile_port}"
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
            env["LANTERN_TEST_PUBLIC"] = f"http://127.0.0.1:{public_port}"
            env["LANTERN_TEST_PRIVATE"] = f"http://127.0.0.1:{private_port}"
            env["LANTERN_TEST_TOKEN"] = paired.stdout.strip()
            env["LANTERN_TEST_KEY"] = (private_dir / "device.key").read_text(encoding="ascii").strip()
            env["LANTERN_TEST_DISCOVERY_PORT"] = str(discovery_port)
            return subprocess.run(command, env=env).returncode
        finally:
            stop(public.pid)
            if private_pid is not None:
                stop(private_pid)
            for process, _ in others:
                stop(process.pid)
            for log in (tmp / "public.log", private_dir / "server.log", *(log for _, log in others)):
                if log.exists() and log.stat().st_size:
                    sys.stderr.write(f"--- {log.name}\n{log.read_text(errors='replace')[-4000:]}\n")


if __name__ == "__main__":
    sys.exit(main())
