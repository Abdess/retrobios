"""Search.

The search gate listed the queries that missed and no workflow ran it: its
browser runner could not even start from the repository root. Console and
error words had no field to reach their page ("wonderswan color", "bios not
found"), parts of a split page carried the console page's weight and came
first for "which mame version", and 707 pages gave search engines one of
five template sentences of level 3 words as their description. These tests
read the generator, the gate, the workflow and, where it is built, the site.
"""

from __future__ import annotations

import ast
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import sitestarlight  # noqa: E402
import validate_site  # noqa: E402

TOOLS = REPO_ROOT / "website" / "tools"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy-site.yml"
DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"
DIST = REPO_ROOT / "website" / "dist"


def _front(text: str) -> dict:
    return yaml.safe_load(text.split("---\n")[1])


def _gate_queries() -> dict:
    tree = ast.parse((TOOLS / "search_gate.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "QUERIES":
            return ast.literal_eval(node.value)
    raise AssertionError("no QUERIES in search_gate.py")


def _finalize(rel: str, body: str, authored: dict) -> dict:
    _target, text = sitestarlight.finalize_page(
        rel, body, level="", weight=None, browser_title="T", description="d",
        structured={}, terms={}, authored=authored)
    return {"front": _front(text), "text": text}


class TheGateRunsAndBlocks(unittest.TestCase):
    def test_the_deploy_runs_the_gate_before_the_upload(self) -> None:
        steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["build"]["steps"]
        runs = [str(step.get("run", "")) for step in steps]
        uses = [str(step.get("uses", "")) for step in steps]
        gate = next(i for i, run in enumerate(runs)
                    if "website/tools/search_gate.py --site-dir website/dist" in run)
        build = next(i for i, run in enumerate(runs) if "npm run build --prefix website" in run)
        upload = next(i for i, use in enumerate(uses) if "upload-pages-artifact" in use)
        self.assertLess(build, gate)
        self.assertLess(gate, upload)
        # The driver is pinned to a version and kept out of the lockfile.
        self.assertRegex(runs[gate], r"npm install --no-save --prefix website playwright-core@\d+\.\d+\.\d+")

    def test_no_third_party_action_and_every_action_pinned(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for repo, ref in re.findall(r"uses:\s*([\w.-]+/[\w.-]+)@(\S+)", text):
            with self.subTest(action=repo):
                self.assertTrue(repo.startswith("actions/"))
                self.assertRegex(ref, r"^[0-9a-f]{40}$")

    def test_the_runner_resolves_from_website_and_says_what_is_missing(self) -> None:
        source = (TOOLS / "measure.mjs").read_text(encoding="utf-8")
        self.assertIn("await import('playwright-core')", source)
        self.assertIn("npm install --no-save --prefix website playwright-core", source)
        self.assertNotRegex(source, r"^import \{ chromium \}", "a static import fails before any message")

    def test_the_gate_serves_a_build_dir_and_fails_on_a_miss(self) -> None:
        source = (TOOLS / "search_gate.py").read_text(encoding="utf-8")
        self.assertIn("--site-dir", source)
        self.assertIn("serve.mjs", source)
        self.assertIn("return 0 if answered == len(QUERIES)", source)

    def test_the_plans_queries_are_gated(self) -> None:
        queries = _gate_queries()
        expected = {
            "playstation bios": ("systems/sony-playstation/", 1),
            "please insert playstation cd-rom": ("wiki/troubleshooting/", 3),
            "bios not found": ("wiki/troubleshooting/", 3),
            "check my dump": ("files/", 1),
            "md5 check": ("files/", 1),
            "manifest": ("data/", 3),
            "events": ("wiki/installer/", 3),
            "exit code": ("wiki/installer/", 3),
            "rate limit": ("data/", 3),
            "ios": ("wiki/faq/", 3),
            "dc bios missing": ("emulators/flycast/", 3),
            "neogeo.zip": ("systems/snk/", 1),
            "scph5501": ("systems/sony-playstation/", 3),
        }
        for query, (page, rank) in expected.items():
            with self.subTest(query=query):
                pages, gated = queries[query]
                self.assertTrue(any(page.startswith(prefix) for prefix in pages))
                self.assertLessEqual(gated, rank)

    def test_the_home_has_a_weight_budget(self) -> None:
        source = (TOOLS / "search_gate.py").read_text(encoding="utf-8")
        self.assertIn("HOME_BUDGET_KB = 80", source)


class FieldsFromFrontMatter(unittest.TestCase):
    def test_consoles_and_terms_become_search_fields(self) -> None:
        text = _finalize("systems/snk.md", "# SNK\n\nBody.\n", {
            "consoles": ["Neo Geo", "Neo Geo Pocket Color"],
            "terms": "bios not found, bios missing",
        })["text"]
        self.assertIn('data-pagefind-meta="consoles:Neo Geo Neo Geo Pocket Color"', text)
        self.assertIn('data-pagefind-meta="terms:bios not found bios missing Neo Geo BIOS '
                      'Neo Geo Pocket Color BIOS"', text)
        # A field value is an attribute: none of it reaches an excerpt.
        self.assertNotRegex(text, r">[^<]*bios missing[^<]*<")

    def test_no_search_word_is_typed_in_the_module(self) -> None:
        source = (REPO_ROOT / "scripts" / "sitestarlight.py").read_text(encoding="utf-8")
        for words in ("bios not found", "mame version", "WonderSwan"):
            self.assertNotIn(words, source)

    def test_a_page_without_fields_gets_none(self) -> None:
        text = _finalize("wiki/legal.md", "# Legal\n\nBody.\n", {})["text"]
        self.assertNotIn("consoles:", text)
        self.assertNotIn("terms:", text)


class FindOrCheckAFile(unittest.TestCase):
    """"check my dump" and "md5 check" found emulator pages first."""

    def test_the_page_weighs_two(self) -> None:
        rel = Path("files/index.md")
        self.assertEqual(gs.search_weight(rel, gs.page_level(rel)), 2)

    def test_its_terms_become_a_field(self) -> None:
        text = _finalize("files/index.md", "# Find or check a file\n\nBody.\n",
                         {"terms": "check dump, md5 check"})["text"]
        self.assertIn('data-pagefind-meta="terms:check dump md5 check"', text)

    def test_the_sidebar_names_it_as_its_title(self) -> None:
        source = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertIn('{"Find or check a file": "files/index.md"}', source)
        self.assertNotIn('{"Find a file": "files/index.md"}', source)


class PartPages(unittest.TestCase):
    def test_part_weight(self) -> None:
        self.assertEqual(gs.SEARCH_WEIGHT["part"], 0.5)
        self.assertEqual(gs.search_weight(Path("systems/arcade-mame-5.md"), "part"), 0.5)

    def test_a_part_keeps_its_own_weight_and_neighbours(self) -> None:
        """The MAME card parts write prev, next and searchWeight: the build
        kept only parent and wrote prev: false, next: false."""
        page = (
            "---\n"
            "parent:\n  label: MAME\n  link: mame.md\n"
            "prev:\n  label: MAME files, part 2 of 8\n  link: mame-files-2.md\n"
            "next:\n  label: MAME files, part 4 of 8\n  link: mame-files-4.md\n"
            f"searchWeight: {gs.search_weight(Path('emulators/mame-files-3.md'), 'part')}\n"
            "---\n\n# MAME files, part 3 of 8\n\nPart of [MAME](mame.md). "
            "This part holds 196 entries, `a.zip` to `b.zip`.\n"
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            path = Path(tmp) / "emulators" / "mame-files-3.md"
            path.parent.mkdir()
            path.write_text(page, encoding="utf-8")
            gs.PART_PAGES.add("emulators/mame-files-3.md")
            self.addCleanup(gs.PART_PAGES.discard, "emulators/mame-files-3.md")
            gs.decorate_markdown_pages(Path(tmp))
            front = _front(path.read_text(encoding="utf-8"))
        self.assertEqual(front["searchWeight"], 0.5)
        self.assertEqual(front["prev"], {"label": "MAME files, part 2 of 8",
                                         "link": "/retrobios/emulators/mame-files-2/"})
        self.assertEqual(front["next"]["link"], "/retrobios/emulators/mame-files-4/")
        self.assertEqual(front["parent"]["link"], "/retrobios/emulators/mame/")
        self.assertIn("This part holds 196 entries, a.zip to b.zip", front["description"])

    def test_built_mame_parts_state_their_neighbours(self) -> None:
        part = DOCS / "emulators" / "mame-files-3.md"
        if not part.is_file():
            self.skipTest("site pages not generated")
        front = _front(part.read_text(encoding="utf-8"))
        if "searchWeight" not in front and front.get("prev") is False:
            self.skipTest("the emulator pages package is not merged")
        self.assertEqual(front["searchWeight"], 0.5)
        self.assertTrue(str(front["prev"]["link"]).startswith("/retrobios/emulators/"))


class Descriptions(unittest.TestCase):
    def test_titles_say_bios_files(self) -> None:
        saved = dict(gs.PAGE_DATA)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved)))
        gs.PAGE_DATA["emulators/duckstation.md"] = {"hasPart": [{"name": "scph5501.bin"}]}
        self.assertEqual(gs._browser_title(Path("emulators/duckstation.md"), "DuckStation"),
                         "DuckStation BIOS files")
        self.assertEqual(gs._browser_title(Path("systems/sega.md"), "Sega"), "Sega BIOS files")
        self.assertEqual(gs._browser_title(Path("systems/sega-dreamcast.md"), "Sega: Dreamcast"),
                         "Dreamcast BIOS files (Sega)")

    def test_an_emulator_page_is_described_by_its_intro(self) -> None:
        saved = dict(gs.PAGE_DATA)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved)))
        gs.PAGE_DATA["emulators/duckstation.md"] = {"hasPart": [{"name": "scph5501.bin"}]}
        body = ("# DuckStation\n\nDuckStation emulates Sony PlayStation. It picks the BIOS for "
                "your game's region.\n\n<details>\n\nThe installer finds your platform.\n")
        text = gs._page_description(body, Path("emulators/duckstation.md"), "DuckStation")
        self.assertTrue(text.startswith("DuckStation emulates Sony PlayStation."))
        self.assertNotIn("source-pinned", text)

    def test_a_console_page_is_described_by_its_start_line(self) -> None:
        body = "# Sega: Dreamcast\n\nPart of Sega.\n\n**Start with**: `dc_boot.bin`, `dc_flash.bin`.\n"
        text = gs._page_description(body, Path("systems/sega-dreamcast.md"), "Sega: Dreamcast")
        self.assertEqual(text, "Dreamcast BIOS files (Sega). Start with dc_boot.bin, dc_flash.bin.")

    def test_the_faq_is_described_by_its_questions(self) -> None:
        body = ("# Common questions\n\n## Do I need BIOS files?\n\nYes.\n\n## Which one?\n\n"
                "Run the command with --dry-run.\n\n## Zip or not?\n\nZip.\n")
        text = gs._page_description(body, Path("wiki/faq.md"), "Common questions")
        self.assertTrue(text.startswith("Common questions: Do I need BIOS files?"))

    def test_a_written_description_wins(self) -> None:
        source = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertIn('authored.get("description") or _page_description(', source)

    def test_the_check_counts_templates(self) -> None:
        pages = {}
        for n in range(12):
            page = validate_site.Page(Path(f"/s/p{n}/index.html"))
            page.h1 = f"Core {n}"
            page.title = f"Core {n} BIOS files - RetroBIOS"
            page.descriptions = [f"Core {n}: emulator firmware profile with paths."]
            pages[page.path] = page
        issues = validate_site._check_description_templates(pages, Path("/s"))
        self.assertEqual(len(issues), 1)
        self.assertIn("12 pages share", issues[0])
        for page in list(pages.values())[:2]:
            page.descriptions = [f"{page.h1} emulates a console of its own {page.h1[-1]}x."]
        self.assertEqual(validate_site._check_description_templates(pages, Path("/s")), [])

    def test_built_descriptions_are_not_templates(self) -> None:
        if not (DIST / "index.html").is_file():
            self.skipTest("site not built")
        pages = {path.resolve(): validate_site._parse_page(path) for path in DIST.rglob("*.html")}
        content = {path: page for path, page in pages.items() if not page.redirect}
        self.assertEqual(validate_site._check_description_templates(content, DIST.resolve()), [])


if __name__ == "__main__":
    unittest.main()
