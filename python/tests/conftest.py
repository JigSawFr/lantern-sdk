"""Shared fixtures: the specification's folder (the submodule), its examples
and its refused examples."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
SPEC = HERE.parents[1] / "spec"
EXAMPLES = SPEC / "examples" / "v1"
sys.path.insert(0, str(HERE))
logging.getLogger("werkzeug").setLevel(logging.ERROR)


def examples() -> list[Path]:
    return sorted(EXAMPLES.glob("*.json"))


def refused() -> list[Path]:
    return sorted((EXAMPLES / "invalid").glob("*.json"))


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def example() -> Any:
    def read(name: str) -> Any:
        return load(EXAMPLES / f"{name}.json")

    return read
