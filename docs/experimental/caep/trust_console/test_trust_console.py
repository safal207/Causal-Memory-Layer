from __future__ import annotations

import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class TrustConsoleStaticTests(unittest.TestCase):
    """Lock the dependency-free Trust Console product contract."""

    def test_expected_files_and_ui_contract(self) -> None:
        html = (HERE / "index.html").read_text(encoding="utf-8")
        css = (HERE / "styles.css").read_text(encoding="utf-8")
        app = (HERE / "app.js").read_text(encoding="utf-8")

        for asset in ("styles.css", "app.js"):
            self.assertIn(asset, html)
        for element_id in (
            "fileInput",
            "pasteButton",
            "loadDemoButton",
            "recordTabs",
            "integrityBadge",
            "causalTimeline",
            "downloadButton",
        ):
            self.assertIn(f'id="{element_id}"', html)
        self.assertIn("@media print", css)
        self.assertIn("crypto.subtle", app)
        self.assertIn("canonicalRecord", app)
        self.assertIn("normalizeInput", app)
        self.assertIn("caep.diverged.example.json", app)
        self.assertIn("caep.recovered.example.json", app)
        self.assertNotRegex(html + css + app, r"https?://")

    def test_javascript_uses_strict_mode_and_has_no_module_dependency(self) -> None:
        app = (HERE / "app.js").read_text(encoding="utf-8")
        self.assertTrue(app.startswith('"use strict";'))
        self.assertNotIn(" import ", app)
        self.assertNotIn("require(", app)
        self.assertIsNotNone(re.search(r"function\s+loadValue\(", app))


if __name__ == "__main__":
    unittest.main()
