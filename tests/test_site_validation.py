"""Tests for rendered-site metadata and link validation."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import os
import re
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
                if line.lstrip().startswith(("```", "~~~")):
                    fenced = not fenced
                elif not fenced and line.startswith("#") and not line.startswith(
                    ("# ", "## ", "### ", "#### ", "##### ", "###### ")
                ):
                    offenders.append(f"{page.name}:{number}")
                elif not fenced and line[:1].isspace() and line.lstrip().startswith("#"):
                    # Inside a list item or an admonition an indented hash is
                    # a heading too. Code that needs one goes in a fence.
                    offenders.append(f"{page.name}:{number}")
        self.assertEqual(offenders, [])

    def test_an_indented_hash_renders_as_a_heading(self):
        """What the check above guards: a wrapped `#79)` inside a list item."""
        try:
            import markdown
        except ImportError:
            self.skipTest("rendering needs markdown")
        html = markdown.markdown(
            "1. First paragraph.\n\n    Second paragraph (see issue\n    #79). More."
        )
        self.assertIn("<h1", html)


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
        # The path the site is served under.
        self.config = "/retrobios/"

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

    def test_a_redirect_is_judged_by_its_target(self):
        """A moved page's old address holds only a meta refresh. It has no
        title or landmark to check, but a target that is gone is reported."""
        (self.site / "index.html").write_text(
            _page("Home", "Unique home description."), encoding="utf-8"
        )
        for name, target in (("old", "/retrobios/"), ("lost", "/retrobios/gone/")):
            folder = self.site / name
            folder.mkdir()
            (folder / "index.html").write_text(
                f'<!doctype html><title>Redirecting to: {target}</title>'
                f'<meta http-equiv="refresh" content="0;url={target}">'
                f'<a href="{target}">Redirecting</a>',
                encoding="utf-8",
            )
        issues = validate_site(self.site, self.config)
        self.assertFalse([i for i in issues if "old/" in i], issues)
        self.assertTrue(any("lost/" in i and "broken local link" in i for i in issues), issues)

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



class TheSiteStaysWithinItsBudgets(unittest.TestCase):
    """The 10.5 MB page and the 21 MB search index passed every check:
    validate_site now holds the gains, each limit with its reason."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.site = Path(self.temp.name) / "site"
        self.site.mkdir()
        self.config = "/retrobios/"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _issues(self, body: str) -> list[str]:
        (self.site / "index.html").write_text(_page("Home", "Home page.", body), encoding="utf-8")
        return validate_site(self.site, self.config)

    def test_a_clean_page_passes(self):
        (self.site / "javascripts").mkdir()
        (self.site / "javascripts" / "site.js").write_text("", encoding="utf-8")
        self.assertEqual(self._issues(
            "<h2 id='a'>A</h2><h3 id='b'>B</h3><h2 id='c'>C</h2>"
            "<table><thead><tr><th>Detail</th><th>Value</th></tr></thead></table>"
            '<script src="javascripts/site.js"></script>'), [])

    def test_a_page_over_its_size(self):
        import validate_site as module

        issues = self._issues("<p>" + "x" * module.MAX_PAGE_BYTES + "</p>")
        self.assertTrue(any("over the" in issue and "HTML" in issue for issue in issues), issues)

    def test_a_skipped_heading_level(self):
        issues = self._issues("<h2 id='a'>A</h2><h4 id='b'>B</h4>")
        self.assertTrue(any("h2 to h4" in issue for issue in issues), issues)

    def test_an_empty_table_header(self):
        issues = self._issues("<table><thead><tr><th> </th><th></th></tr></thead></table>")
        self.assertTrue(any("2 table header cell(s) without text" in issue for issue in issues))

    def test_a_script_or_a_diagram_from_another_host(self):
        issues = self._issues(
            '<script src="https://unpkg.com/mermaid@11/dist/mermaid.min.js"></script>'
            '<pre class="mermaid">graph LR</pre>')
        self.assertTrue(any("scripts loaded from another host" in issue for issue in issues))
        self.assertTrue(any("drawn by a script at runtime" in issue for issue in issues))

    def test_a_search_index_over_its_budget(self):
        import validate_site as module

        index = self.site / "pagefind" / "index"
        index.mkdir(parents=True)
        (index / "en_big.pf_index").write_bytes(b"x" * (module.MAX_PAGEFIND_CHUNK_BYTES + 1))
        (self.site / "pagefind" / "pagefind.en_x.pf_meta").write_bytes(
            b"x" * (module.MAX_PAGEFIND_META_BYTES + 1))
        issues = self._issues("")
        self.assertTrue(any("en_big.pf_index" in issue for issue in issues), issues)
        self.assertTrue(any(".pf_meta" in issue for issue in issues), issues)


class UnrenderedMarkdown(unittest.TestCase):
    """The clownmdemu analysis block reached readers as "- **bios_hle:**
    True": a list indented one level too deep, read as code."""

    setUp = RenderedSiteValidation.setUp
    tearDown = RenderedSiteValidation.tearDown

    def test_asterisks_in_prose_fail_and_in_code_pass(self):
        (self.site / "index.html").write_text(
            _page("Home", "Unique home description.", "<p>- **bios_hle:** True</p>"),
            encoding="utf-8",
        )
        issues = validate_site(self.site, self.config)
        self.assertTrue(any("markdown left unrendered" in issue for issue in issues))
        (self.site / "index.html").write_text(
            _page("Home", "Unique home description.",
                  "<pre><code>a = 2 ** 8</code></pre><code>**/*.py</code>"),
            encoding="utf-8",
        )
        self.assertEqual(validate_site(self.site, self.config), [])


class EveryTestDependencyIsInstalledInCi(unittest.TestCase):
    """The markdown rendering test skipped on every CI run: the test job
    installed pyyaml and jsonschema only. A test that skips where it is
    meant to run guards nothing."""

    PACKAGES = {"yaml": "pyyaml", "jsonschema": "jsonschema", "markdown": "markdown"}

    def test_the_test_job_installs_what_the_tests_import(self):
        import ast

        root = Path(__file__).resolve().parents[1]
        local = (
            {p.stem for p in (root / "scripts").rglob("*.py")}
            | {p.name for p in (root / "scripts").iterdir() if p.is_dir()}
            | {p.stem for p in (root / "tests").glob("*.py")}
            | {p.name for p in (root / "tests").iterdir() if p.is_dir()}
            | {"scripts", "tests", "install"}
        )
        imported: set[str] = set()
        for path in (root / "tests").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module.split(".")[0])
        third_party = {
            m for m in imported if m not in sys.stdlib_module_names and m not in local
        }
        workflow = (root / ".github" / "workflows" / "validate.yml").read_text()
        job = workflow[workflow.index("run-tests:"):]
        # The suite runs on the default python: a line that installs into
        # another interpreter (python3.9 -m pip) does not count.
        install_line = next(
            line for line in job.splitlines() if "run: pip install" in line
        )
        missing = sorted(
            m for m in third_party if self.PACKAGES.get(m, m) not in install_line
        )
        self.assertEqual(missing, [])

    def test_a_contributor_installs_what_ci_installs(self):
        # The contributing page installed pyyaml and jsonschema only, so the
        # markdown test skipped on a contributor's machine and ran in CI.
        from generate_readme import generate_contributing

        command = next(
            line for line in generate_contributing().splitlines() if "pip install" in line
        )
        guide = (Path(__file__).resolve().parents[1] / "wiki" / "testing-guide.md").read_text(
            encoding="utf-8"
        )
        for package in self.PACKAGES.values():
            with self.subTest(package=package):
                self.assertIn(package, command)
                self.assertIn(package, guide)



class TheTestingGuideNamesEveryModule(unittest.TestCase):
    """The guide described 18 modules of 144, and a contributor touching
    slots.py or the downloader found no module named for it."""

    def test_every_module_is_in_the_table(self):
        root = Path(__file__).resolve().parents[1]
        guide = (root / "wiki" / "testing-guide.md").read_text(encoding="utf-8")
        missing = sorted(
            path.stem for path in (root / "tests").glob("test_*.py")
            if f"`{path.stem}`" not in guide
        )
        self.assertEqual(missing, [])



class TheSitemapIsAnnouncedWhereCrawlersLook(unittest.TestCase):
    """robots.txt was published as /retrobios/robots.txt, which no crawler
    reads (RFC 9309 reads the host root): the sitemap it announced was
    never found that way."""

    def test_the_head_names_it_and_no_robots_is_written(self):
        # Starlight links the sitemap from every page's head when the site
        # has an address, and the config keeps sitemap.xml at its old path.
        root = Path(__file__).resolve().parents[1]
        config = (root / "website" / "astro.config.mjs").read_text()
        self.assertIn("site: SITE", config)
        self.assertIn("sitemap.xml", config)
        from tests.sitepages import generator_sources

        for path in generator_sources():
            source = path.read_text(encoding="utf-8")
            with self.subTest(module=path.name):
                self.assertNotIn('"robots.txt"),\n        "User-agent', source)
                self.assertNotIn("Sitemap: https://", source)



class TheHomeTitleSaysWhatTheSiteIs(unittest.TestCase):
    def test_not_the_site_name_twice(self):
        from generate_site import SITE_NAME, _browser_title

        title = _browser_title(Path("index.md"), SITE_NAME)
        self.assertNotEqual(title, SITE_NAME)
        self.assertIn("BIOS", title)



class PlatformPagesPrintTheDeclaredCrc32(unittest.TestCase):
    """System.dat pins aes.zip by crc32 91e93107. The RetroArch page printed
    only its sha1 and md5, so the crc a clrmamepro user pastes found nothing."""

    def test_the_rendered_page(self):
        from tests import sitepages  # noqa: PLC0415

        sitepages.require()
        # The page and the systems moved to pages of their own.
        text = "".join(
            path.read_text(encoding="utf-8") for path in sitepages.pages()
            if sitepages.name(path) == "platforms/retroarch.md"
            or sitepages.name(path).startswith("platforms/retroarch-"))
        self.assertIn('CRC32: <code class="rb-hash">91e93107</code>', text)


class PlainHouseStyle(unittest.TestCase):
    """The stylesheet stays a plain documentation theme.

    Gradient banners, coloured side stripes on cards, lifting hover cards,
    pill badges and small-caps table headers had piled up into the look of
    a generated landing page. Each pattern below brought one of them back.
    """

    PATTERNS = {
        "gradient": re.compile(r"gradient\("),
        "side stripe": re.compile(r"border-(?:left|inline-start)\s*:\s*\d+px"),
        "lifting card": re.compile(r"translateY\("),
        # "box-shadow: none" removes one of Starlight's shadows.
        "drop shadow": re.compile(r"box-shadow\s*:(?!\s*none\s*[;}])"),
        "small caps header": re.compile(r"text-transform\s*:\s*uppercase"),
        "pill": re.compile(r"border-radius\s*:\s*(?:[5-9]|\d{2,})px|50%"),
        "box-drawing rule": re.compile("[\u2500-\u257f]"),
    }

    def test_the_stylesheet_has_none_of_the_patterns(self):
        css = (ROOT / "website" / "src" / "styles" / "retrobios.css").read_text(encoding="utf-8")
        for label, pattern in self.PATTERNS.items():
            with self.subTest(pattern=label):
                self.assertIsNone(pattern.search(css), label)

    def test_headings_do_not_repeat_the_site_name(self):
        # The header bar already names the site, and the browser title gets
        # it from the theme: "# DuckStation - RetroBIOS" said it twice.
        from tests.sitepages import generator_sources

        for path in generator_sources():
            with self.subTest(module=path.name):
                self.assertNotRegex(path.read_text(encoding="utf-8"),
                                    r'"# [^"]* - (?:\{SITE_NAME\}|RetroBIOS)')
        for page in sorted((ROOT / "wiki").glob("*.md")):
            first = page.read_text(encoding="utf-8").splitlines()[0]
            with self.subTest(page=page.name):
                self.assertFalse(first.endswith(" - RetroBIOS"), first)
