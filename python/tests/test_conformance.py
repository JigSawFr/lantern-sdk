"""The specification's conformance suite (spec/conformance/run.py) against
the demo server built from the toolkit (tests/demo.py), served by Flask and
by FastAPI, anonymously and with a token. Families the toolkit does not
offer yet (sections, saves, requests, pairing) are declared 0: the suite
checks that their routes are refused, and skips the rest of them."""

from __future__ import annotations

import importlib.util
import io
import re
from types import ModuleType

import pytest

from conftest import SPEC
from demo import DEMO_TOKEN, serve

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
WITH_TOKEN = ["handshake.account", "features.anonymous", "caching.private"]


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
def test_the_suite_passes(framework: str, token: bool) -> None:
    pytest.importorskip(framework)
    if framework == "fastapi":
        pytest.importorskip("uvicorn")
    run = suite()
    out = io.StringIO()
    with serve(framework) as url:
        code = run.main([url, *(["--token", DEMO_TOKEN] if token else [])], out=out)
    report = out.getvalue()
    status = {m.group(2): m.group(1) for m in re.finditer(r"^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)", report, re.M)}
    failed = [line for line in report.splitlines() if line.startswith("FAIL")]
    assert code == 0 and not failed, report
    for check in REQUIRED + (WITH_TOKEN if token else []):
        assert status.get(check) == "PASS", f"{check}: {status.get(check)}\n{report}"
    warnings = [cid for cid, s in status.items() if s == "WARN"]
    assert warnings == ["transport.https"], report  # plain HTTP on loopback: the only warning
