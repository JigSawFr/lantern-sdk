"""sdk.json (tools/site_data.py): its shape, and that the sources it is read from are the ones that exist."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import site_data  # noqa: E402

DOC = json.loads(site_data.render())
ID = {"cpp", "c", "python", "typescript", "go", "rust"}


class Shape(unittest.TestCase):
    def test_schema_and_versions(self) -> None:
        self.assertEqual(DOC["schema"], 1)
        self.assertRegex(DOC["sdk"]["version"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(DOC["sdk"]["spec_draft"], r"^\d+\.\d+$")
        self.assertIsNone(DOC["sdk"]["release"])  # nothing is published yet

    def test_every_language_is_listed_once(self) -> None:
        self.assertEqual([lang["id"] for lang in DOC["languages"]], ["cpp", "c", "python", "typescript", "go", "rust"])
        for lang in DOC["languages"]:
            self.assertIn(lang["status"], {"complete", "building", "planned"})
            self.assertEqual(lang["readme"] is None, lang["status"] == "planned")

    def test_families_cover_the_columns(self) -> None:
        self.assertTrue(DOC["families"])
        for row in DOC["families"]:
            self.assertEqual(set(row["support"]), ID)
            for cell in row["support"].values():
                self.assertLessEqual({cell["client"], cell["server"]}, {"yes", "partial", "no"})

    def test_levels_start_at_core(self) -> None:
        for level in DOC["levels"].values():
            self.assertTrue(level.startswith("Lantern Core"))

    def test_calls_have_a_place_wherever_they_have_a_name(self) -> None:
        for call in DOC["calls"]:
            named = {lang for lang, name in call["calls"].items() if name}
            self.assertEqual(set(call["where"]), named, call["id"])
            for path in call["where"].values():
                self.assertTrue((site_data.ROOT / path).is_file(), path)

    def test_every_example_has_a_title_and_its_source(self) -> None:
        self.assertGreaterEqual({e["language"] for e in DOC["examples"]}, {"cpp", "c", "python", "typescript"})
        for example in DOC["examples"]:
            self.assertTrue(example["title"], example["path"])
            self.assertEqual((site_data.ROOT / example["path"]).read_text(encoding="utf-8"), example["source"])


class Drift(unittest.TestCase):
    def test_a_call_that_does_not_exist_is_refused(self) -> None:
        real = site_data.text
        try:
            site_data.text = lambda path: (  # type: ignore[assignment]
                json.dumps({"gestures": [{"id": "x", "spec": "1", "calls": {"python": "no_such_call_anywhere"}}]})
                if path == "tools/sdk-calls.json"
                else real(path)
            )
            with self.assertRaises(SystemExit):
                site_data.calls()
        finally:
            site_data.text = real

    def test_the_committed_file_is_current(self) -> None:
        self.assertEqual(site_data.OUT.read_text(encoding="utf-8"), site_data.render())


if __name__ == "__main__":
    unittest.main()
