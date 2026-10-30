"""The specification's conformance suite (spec/conformance/run.py) against
the demo server built from the toolkit (tests/demo.py), served by Flask and
by FastAPI, anonymously and with a token. Families the toolkit does not
offer (sections, saves, requests) are declared 0: the suite checks that
their routes are refused, and skips the rest of them. The demo pairs
devices, checks signed requests and answers the administration API: with
its token, bound to its key, it reaches the levels LEVELS says."""

from __future__ import annotations

import importlib.util
import io
import re
from pathlib import Path
from types import ModuleType

import pytest

from conftest import SPEC
from demo import DEMO_KEY, DEMO_TOKEN, demo_accounts, make_lantern, serve
from lantern.server.http import content_coding

pytestmark = pytest.mark.conformance

# The read-side checks of the families the toolkit offers: each must pass, not be skipped.
REQUIRED = [
    "handshake.well-known",
    "handshake.v1",
    "handshake.anonymous",
    "handshake.platforms",
    "auth.unknown-token",
    "auth.unknown-handshake",
    "auth.basic-refused",
    "apps.first-page",
    "apps.pages.name",
    "apps.pages.added",
    "apps.pages.release",
    "apps.sha256",
    "apps.platforms",
    "apps.page-size",
    "apps.bad-cursor",
    "apps.filters",
    "apps.etag",
    "platforms.filter",
    "platforms.query",
    "platforms.unknown",
    "platforms.bad-name",
    "platforms.vary",
    "missing.no-platform",
    "missing.installed",
    "missing.up-to-date",
    "missing.base",
    "missing.malformed",
    "files.whole",
    "files.ranges",
    "files.unsatisfiable",
    "files.unknown",
    "changes.token",
    "changes.bad-token",
    "titles.known",
    "titles.unknown",
    "titles.bulk",
    "titles.bulk-limit",
    "titles.changes",
    "titles.bad-token",
    "homebrew.pages",
    "homebrew.entries",
    "homebrew.manifests",
    "homebrew.kinds",
    "homebrew.filters",
    "homebrew.requires",
    "homebrew.ports",
    "homebrew.packages",
    "homebrew.signatures",
    "homebrew.updates",
    "homebrew.updates-platform",
    "homebrew.unknown",
    "cheats.sets",
    "cheats.text",
    "cheats.unknown",
    "cheats.write",
    "schema.refused.library",
    "schema.refused.homebrew",
    "errors.unknown-route",
    "errors.problem",
    "errors.never-200",
    "errors.www-authenticate",
    "auth.no-basic",
    "documents.schema",
    "documents.type",
    "documents.limits",
    *[
        f"features.{f}"
        for f in ("library", "titles", "changes", "sections", "homebrew", "saves", "cheats", "requests", "pairing")
    ],
]
# Pairing, offered to every caller.
REQUIRED += [
    "handshake.auth",
    "pairing.offered",
    "pairing.code",
    "pairing.verify-complete",
    "pairing.waiting",
    "pairing.slow-down",
    "pairing.unknown",
    "pairing.key",
    "admin.refused",
    "language.problem",
    "compression.files",
    "documents.date",
    "features.admin",
]
# With the demo's token, bound to its key, and every scope the demo serves.
WITH_TOKEN = [
    "handshake.account",
    "features.anonymous",
    "caching.private",
    "signatures.unsigned",
    "signatures.invalid",
    "signatures.stale",
    "signatures.replayed",
    "signatures.digest",
    "signatures.accept-signature",
    "admin.users",
    "admin.pairings",
    "admin.rating-cap",
    "admin.refuse",
    "admin.devices",
    "admin.invitations",
    "compression.etag",
]
#: The levels the demo reaches with its token (SPEC.md § 17).
LEVELS = "Lantern Core +titles +homebrew +cheats +admin"


def suite() -> ModuleType:
    jsonschema = pytest.importorskip("jsonschema")
    assert jsonschema
    spec = importlib.util.spec_from_file_location("lantern_conformance", SPEC / "conformance" / "run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("framework", ["flask", "fastapi"])
@pytest.mark.parametrize("token", [False, True], ids=["anonymous", "token"])
def test_the_suite_passes(framework: str, token: bool, tmp_path: Path) -> None:
    pytest.importorskip(framework)
    if framework == "fastapi":
        pytest.importorskip("uvicorn")
    run = suite()
    out = io.StringIO()
    key = tmp_path / "demo.key"
    key.write_text(DEMO_KEY.seed_b64(), encoding="ascii")
    with serve(framework, make_lantern(accounts=demo_accounts())) as url:
        code = run.main([url, *(["--token", DEMO_TOKEN, "--key", str(key)] if token else [])], out=out)
    report = out.getvalue()
    status = {m.group(2): m.group(1) for m in re.finditer(r"^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)", report, re.M)}
    failed = [line for line in report.splitlines() if line.startswith("FAIL")]
    assert code == 0 and not failed, report
    for check in REQUIRED + (WITH_TOKEN if token else []):
        assert status.get(check) == "PASS", f"{check}: {status.get(check)}\n{report}"
    warnings = [cid for cid, s in status.items() if s == "WARN"]
    # Plain HTTP on loopback; and gzip without zstd, before Python 3.14 (the standard library has no zstd or br).
    expected = ["transport.https"] + ([] if zstd_available() else ["compression.json"])
    assert warnings == expected, report
    if token:
        assert f"Levels reached (SPEC.md § 17, draft 0.4): {LEVELS}" in report, report


def zstd_available() -> bool:
    return content_coding("zstd") == "zstd"
