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


class ProsePlaceholders(unittest.TestCase):
    """A path written with angle brackets reaches the reader as written."""

    def test_a_placeholder_is_text_not_a_tag(self):
        from siterender import _admonition_body, _escape_tags

        self.assertEqual(
            _escape_tags("gameProfiles/<title id>.ini under <system_dir>/Cemu"),
            "gameProfiles/&lt;title id>.ini under &lt;system_dir>/Cemu",
        )
        self.assertIn("&lt;title id>", _admonition_body("read <title id>.ini"))

    def test_code_spans_and_links_are_left_alone(self):
        from siterender import _escape_tags

        self.assertEqual(_escape_tags("`<system_dir>/x`"), "`<system_dir>/x`")
        self.assertEqual(_escape_tags("see <https://example.org/a>"), "see <https://example.org/a>")
        self.assertEqual(_escape_tags("size < 4096"), "size &lt; 4096")


class WikiSourceHeadings(unittest.TestCase):
    def test_no_prose_line_starts_with_a_hash(self):
        """Python-Markdown reads `#79).` at the start of a line as a heading:
        it asks for no space after the hash. A wrapped issue reference gave
        the release page a second H1 and failed the site build."""
        offenders = []
        for page in sorted((ROOT / "wiki").glob("*.md")):
            fenced = False
            for number, line in enumerate(
                page.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if line.lstrip().startswith("```"):
                    fenced = not fenced
                elif not fenced and line.startswith("#") and not line.startswith(
                    ("# ", "## ", "### ", "#### ", "##### ", "###### ")
                ):
                    offenders.append(f"{page.name}:{number}")
        self.assertEqual(offenders, [])


class PlatformDetails(unittest.TestCase):
    def test_lists_and_flags_read_as_prose(self):
        import generate_site

        lines = generate_site._render_platform_details(
            {"platform_details": {"megacd": {
                "extensions_tried": [".bin", ".zip"],
                "hle_available": False,
                "root": "<system_dir>/x",
            }}}
        )
        self.assertIn("    - extensions_tried: .bin, .zip", lines)
        self.assertIn("    - hle_available: no", lines)
        self.assertIn("    - root: &lt;system_dir>/x", lines)


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
