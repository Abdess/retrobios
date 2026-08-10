"""Tests for rendered-site metadata and link validation."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts"))

from validate_site import validate_site  # noqa: E402


def _page(title: str, description: str, body: str = "") -> str:
    structured = json.dumps(
        {"@context": "https://schema.org", "@type": "TechArticle"}
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <title>{title}</title>
  <meta name="description" content="{description}">
  <link rel="canonical" href="https://example.test/retrobios/">
  <script type="application/ld+json">{structured}</script>
</head>
<body><main><h1 id="top">{title}</h1>{body}</main></body>
</html>
"""


class RenderedSiteValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.root = Path(self.temp.name)
        self.site = self.root / "site"
        self.site.mkdir()
        self.config = self.root / "mkdocs.yml"
        self.config.write_text(
            "site_url: https://example.test/retrobios/\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_valid_page_and_base_path_link_pass(self):
        asset = self.site / "assets" / "file.json"
        asset.parent.mkdir()
        asset.write_text("{}\n", encoding="utf-8")
        (self.site / "index.html").write_text(
            _page(
                "Home",
                "Unique home description.",
                '<a href="/retrobios/#top">Top</a>'
                '<a href="/retrobios/assets/file.json">Data</a>'
                '<img src="assets/logo.png" alt="Logo">',
            ),
            encoding="utf-8",
        )
        (self.site / "assets" / "logo.png").write_bytes(b"png")
        self.assertEqual(validate_site(self.site, self.config), [])

    def test_broken_fragment_and_missing_alt_fail(self):
        (self.site / "index.html").write_text(
            _page(
                "Home",
                "Unique home description.",
                '<a href="#absent">Missing</a><img src="missing.png">',
            ),
            encoding="utf-8",
        )
        issues = validate_site(self.site, self.config)
        self.assertTrue(any("missing fragment" in issue for issue in issues))
        self.assertTrue(any("images missing alt" in issue for issue in issues))
        self.assertTrue(any("broken local link" in issue for issue in issues))

    def test_duplicate_search_metadata_fails(self):
        (self.site / "index.html").write_text(
            _page("Repeated", "Repeated description."), encoding="utf-8"
        )
        child = self.site / "child"
        child.mkdir()
        (child / "index.html").write_text(
            _page("Repeated", "Repeated description."), encoding="utf-8"
        )
        issues = validate_site(self.site, self.config)
        self.assertTrue(any("duplicate title" in issue for issue in issues))
        self.assertTrue(any("duplicate description" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
