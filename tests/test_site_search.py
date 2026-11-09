"""Search, sidebar and head.

The search gate listed the queries that missed and no workflow ran it: its
browser runner could not even start from the repository root. Console and
error words had no field to reach their page ("wonderswan color", "bios not
found"), parts of a split page carried the console page's weight and came
first for "which mame version", and 707 pages gave search engines one of
five template sentences of level 3 words as their description. These tests
read the generator, the gate, the workflow and, where it is built, the site.

The get/ download pages sat in no tab, and the theme then numbered the tabs
0 to 4. "snes bios" found NES.emu and never the SNES page, which answers
"No file needed" and so never says BIOS where the search reads. An emulator
crumb ran through its letter group ("Emulators / D"). The home page's
structured data named the page and called it part of itself, and an
emulator's source repository published a commit id as its version beside a
placeholder description. These tests read the generator and, where it is
built, the site.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import re
import sys
import tempfile
import unittest
from pathlib import Path
import yaml
import json
from html.parser import HTMLParser

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import sitestarlight  # noqa: E402
import validate_site  # noqa: E402
import generate_site  # noqa: E402
from common import list_registered_platforms, load_emulator_profiles  # noqa: E402
from tests.test_site_nav import ANCHORS, _nav, _present  # noqa: E402


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
                "the game's region.\n\n<details>\n\nThe installer finds the platform.\n")
        text = gs._page_description(body, Path("emulators/duckstation.md"), "DuckStation")
        self.assertTrue(text.startswith("DuckStation emulates Sony PlayStation."))
        self.assertNotIn("source-pinned", text)

    def test_a_page_whose_files_come_with_the_app_promises_none(self) -> None:
        """DaedalusX64's three files come with the app. The result read
        "DaedalusX64 BIOS files" over "DaedalusX64 emulates Nintendo 64."."""
        saved, shipped = dict(gs.PAGE_DATA), set(gs.NOTHING_TO_FETCH)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved),
                                 gs.NOTHING_TO_FETCH.clear(), gs.NOTHING_TO_FETCH.update(shipped)))
        with open(REPO_ROOT / "emulators" / "daedalusx64.yml", encoding="utf-8") as handle:
            gs.record_emulator_page("daedalusx64", yaml.safe_load(handle))
        key = Path("emulators/daedalusx64.md")
        self.assertEqual(gs._browser_title(key, "DaedalusX64"), "DaedalusX64 emulator")
        body = "# DaedalusX64\n\nDaedalusX64 emulates Nintendo 64.\n"
        self.assertEqual(gs._page_description(body, key, "DaedalusX64"),
                         "DaedalusX64 emulates Nintendo 64. Every file it reads comes with the app.")

    def test_an_emulator_snippet_names_the_files_searched_for(self) -> None:
        """"gba_bios.bin" and "dreamcast bios" landed on pages described as
        "It reads 4 files, none of them required": fewer than 1 in 70 clicked."""
        saved, snippets = dict(gs.PAGE_DATA), dict(gs.EMULATOR_SNIPPETS)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved),
                                 gs.EMULATOR_SNIPPETS.clear(),
                                 gs.EMULATOR_SNIPPETS.update(snippets)))
        with open(REPO_ROOT / "emulators" / "flycast.yml", encoding="utf-8") as handle:
            gs.record_emulator_page("flycast", yaml.safe_load(handle))
        key = Path("emulators/flycast.md")
        body = ("# Flycast\n\nFlycast emulates Sega Dreamcast. It reads 10 files, 4 of them "
                "required: without a required file it does not start games.\n")
        text = gs._page_description(body, key, "Flycast")
        self.assertTrue(text.startswith("Sega Dreamcast BIOS for Flycast: dc_boot.bin, "), text)
        self.assertLessEqual(len(text), 155)
        self.assertFalse(text.endswith("..."), text)

    def test_a_switch_emulator_reads_keys(self) -> None:
        self.assertEqual(gs._snippet_noun(["prod.keys", "dev.keys", "title.keys", "key_retail.bin"], 4, 4), "keys")
        self.assertEqual(gs._snippet_noun(["prod.keys", "title.keys", "<firmware>.zip", "a.txt"], 3, 4),
                         "keys and firmware")
        self.assertEqual(gs._snippet_noun(["gba_bios.bin", "gb_bios.bin"], 2, 2), "BIOS")
        self.assertEqual(gs._snippet_noun(["oot.z64", "oot-mq.z64", "font.bin"], 1, 3), "files")

    def test_an_any_name_snippet_says_what_to_do(self) -> None:
        saved = dict(gs.PAGE_DATA)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved)))
        gs.PAGE_DATA["emulators/aethersx2.md"] = {"hasPart": [{"name": "ps2.bin"}]}
        body = ("# AetherSX2\n\nAetherSX2 needs one Sony PlayStation 2 BIOS file, any region."
                "\n\n1. Download [`ps2.bin`](../x/).\n2. Put it in this folder:\n")
        self.assertEqual(
            gs._page_description(body, Path("emulators/aethersx2.md"), "AetherSX2"),
            "AetherSX2 needs one Sony PlayStation 2 BIOS file, any region. Download one "
            "from this page and put it in the folder it shows. Any file name works.")

    def test_an_initial_does_not_end_the_sentence(self) -> None:
        """hcl's description was "Hydra Castle Labyrinth: open-source port of E."."""
        body = ("# Hydra Castle Labyrinth\n\n<details>\n<summary>Technical notes</summary>\n\n"
                "Open-source port of E. Hashimoto's 2008 freeware Metroidvania. It reads "
                "its data folder.\n\n</details>\n")
        text = gs._emulator_description(body, "emulators/hcl.md", "Hydra Castle Labyrinth", "")
        self.assertTrue(text.startswith("Hydra Castle Labyrinth: open-source port of E. "
                                        "Hashimoto's 2008 freeware Metroidvania."), text)
        self.assertNotIn("It reads", text)

    def test_a_platform_page_says_what_it_gives(self) -> None:
        """All 18 ended on the label of a link a snippet cannot follow,
        "ROCKNIX website.", and never named the BIOS files or their folder."""
        body = ("# ROCKNIX\n\nA system for handhelds. [ROCKNIX website](https://rocknix.org).\n\n"
                "## On the device { #install }\n")
        self.assertEqual(
            gs._page_description(body, Path("platforms/rocknix.md"), "ROCKNIX"),
            "The BIOS files for ROCKNIX, the folder they go in and the command that installs "
            "them. A system for handhelds.")

    def test_a_console_page_is_described_by_its_start_line(self) -> None:
        body = "# Sega: Dreamcast\n\nPart of Sega.\n\n**Start with**: `dc_boot.bin`, `dc_flash.bin`.\n"
        text = gs._page_description(body, Path("systems/sega-dreamcast.md"), "Sega: Dreamcast")
        self.assertEqual(text, "Dreamcast BIOS files (Sega). Start with dc_boot.bin, dc_flash.bin.")

    def test_the_faq_is_described_by_its_questions(self) -> None:
        body = ("# Common questions\n\n## Are BIOS files needed?\n\nYes.\n\n## Which one?\n\n"
                "Run the command with --dry-run.\n\n## Zip or not?\n\nZip.\n")
        text = gs._page_description(body, Path("wiki/faq.md"), "Common questions")
        self.assertTrue(text.startswith("Common questions: Are BIOS files needed?"))

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


QUERIES = _gate_queries()
ROUTE = REPO_ROOT / "website" / "src" / "routeData.ts"
PLATFORMS = str(REPO_ROOT / "platforms")


def _sidebar_with_get_pages() -> tuple[dict, list[str]]:
    nav = _nav()
    names = list_registered_platforms(PLATFORMS)
    get_pages = ["get/index.md", *(f"get/{name}.md" for name in names)]
    return sitestarlight.sidebar(nav, _present(nav) | set(get_pages), ANCHORS), get_pages


class GetPagesSitInYourSetup(unittest.TestCase):
    """3.1: a folder the navigation lists nothing of takes the tab of the
    pages of the same name, and nothing is excluded from every tab."""

    def test_every_get_page_joins_your_setup(self):
        side, get_pages = _sidebar_with_get_pages()
        self.assertEqual(side["options"]["exclude"], [])
        setup = set(side["options"]["topics"].get("setups", []))
        for rel in get_pages:
            with self.subTest(page=rel):
                self.assertIn("/" + sitestarlight._sidebar_link(rel).strip("/"), setup)

    def test_a_get_page_is_dated_by_its_release(self):
        """The sitemap gave no date to the pages that change only with a release."""
        saved = dict(gs.PAGE_DATA)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved)))
        record = json.loads((REPO_ROOT / "release.json").read_text(encoding="utf-8"))
        tag = re.fullmatch(r"v(\d{4})\.(\d{2})\.(\d{2})", record["tag"])
        gs.generate_get_page("retroarch")
        self.assertEqual(gs.PAGE_DATA["get/retroarch.md"], {"dateModified": "-".join(tag.groups())})

    def test_no_page_is_left_out_of_every_tab(self):
        nav = _nav()
        present = _present(nav) | {"orphans/alone.md"}
        side = sitestarlight.sidebar(nav, present, ANCHORS)
        self.assertEqual(side["options"]["exclude"], [])
        placed = {path for paths in side["options"]["topics"].values() for path in paths}
        self.assertIn("/orphans/alone", placed)


class ConsoleWordsReachTheConsole(unittest.TestCase):
    """3.2: "<name> BIOS" for each console the page names, from its own
    `consoles` field, never a word typed in the generator."""

    def test_each_console_with_bios(self):
        self.assertEqual(sitestarlight.console_words(["SNES", "Super Famicom"]),
                         ["SNES BIOS", "Super Famicom BIOS"])

    def test_the_terms_field_carries_them(self):
        _target, text = sitestarlight.finalize_page(
            "systems/nintendo-snes.md", "# SNES\n\nNo file needed.\n", level="0",
            weight=None, browser_title="SNES", description="d",
            structured={"@type": "TechArticle"}, terms={},
            authored={"consoles": ["SNES"]})
        self.assertIn('data-pagefind-meta="consoles:SNES"', text)
        self.assertIn('data-pagefind-meta="terms:SNES BIOS"', text)

    def test_no_search_word_is_typed_in_the_generator(self):
        tree = ast.parse((REPO_ROOT / "scripts" / "sitestarlight.py").read_text(encoding="utf-8"))
        docstrings = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Expr)}
        strings = {node.value.casefold() for node in ast.walk(tree)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)
                   and id(node) not in docstrings}
        typed = {text for text in strings for query in QUERIES
                 if re.search(rf"(?<!\w){re.escape(query)}(?!\w)", text)}
        self.assertEqual(typed, set())


class ANameAnotherPageCovers(unittest.TestCase):
    """3.2: the PlayStation 2 page holds every word of "playstation bios".
    A console whose words another page's consoles also hold is written once
    more, in `exact`, on its own page, and file names reach the search as
    their parts: "ds" found twelve dsi_* names on the DSi page."""

    PAGES = {
        "systems/sony-playstation": ["PlayStation"],
        "systems/sony-playstation-2": ["PlayStation 2"],
        "systems/sony": ["PlayStation 3", "PlayStation Portable"],
        "systems/nintendo-nintendo-ds": ["Nintendo DS"],
        "systems/nintendo-nintendo-dsi": ["Nintendo DSi"],
        "systems/nintendo": ["Famicom Disk System", "Nintendo 64", "Super Famicom Box"],
        "systems/arcade-nintendo-super-system": ["Nintendo Super System"],
        "systems/sega-saturn": ["Saturn"],
    }

    def words(self) -> dict[str, set[str]]:
        return {page: sitestarlight.page_console_words({"consoles": names}, "")
                for page, names in self.PAGES.items()}

    def test_names_another_page_covers(self):
        covered = {page: sitestarlight.covered_names(names, page, self.words())
                   for page, names in self.PAGES.items()}
        self.assertEqual(covered, {
            "systems/sony-playstation": ["PlayStation"],
            "systems/sony-playstation-2": [],
            # Every word of PlayStation 3 is on the PlayStation 2 page, but
            # not "3" itself: no page covers it.
            "systems/sony": [],
            "systems/nintendo-nintendo-ds": ["Nintendo DS"],
            "systems/nintendo-nintendo-dsi": [],
            "systems/nintendo": [],
            # Nintendo, Super and System, each in another name.
            "systems/arcade-nintendo-super-system": ["Nintendo Super System"],
            "systems/sega-saturn": [],
        })

    def test_words_of_a_decorated_page(self):
        text = '<span data-pagefind-meta="consoles:Nintendo DS" hidden></span>'
        self.assertEqual(sitestarlight.page_console_words({}, text), {"nintendo", "ds"})
        self.assertEqual(sitestarlight.page_console_words({}, "No field."), set())

    def test_the_exact_field_is_written_on_the_covered_page_only(self):
        words = self.words()

        def text(page: str) -> str:
            return sitestarlight.finalize_page(
                f"{page}.md", "# T\n\nBody.\n", level="0", weight=None,
                browser_title="T", description="d", structured={"@type": "TechArticle"},
                terms={}, authored={"consoles": self.PAGES[page]}, words_by_page=words)[1]

        self.assertIn('data-pagefind-meta="exact:PlayStation"', text("systems/sony-playstation"))
        for page in ("systems/sony-playstation-2", "systems/sega-saturn"):
            with self.subTest(page=page):
                self.assertNotIn('data-pagefind-meta="exact:', text(page))

    def test_the_field_is_weighted_and_never_shown(self):
        config = (REPO_ROOT / "website" / "astro.config.mjs").read_text(encoding="utf-8")
        weights = re.search(r"metaWeights: \{([^}]*)\}", config)[1]
        fields = dict(re.findall(r"(\w+): ([\d.]+)", weights))
        self.assertIn("exact", fields)
        # Below the console field, so the longer name keeps its own query.
        self.assertLess(float(fields["exact"]), float(fields["consoles"]))
        site = (REPO_ROOT / "website" / "src" / "scripts" / "site.ts").read_text(encoding="utf-8")
        self.assertRegex(site, r"UNSHOWN_FIELDS = new Set\(\[[^\]]*'exact'")

    def test_file_names_as_parts(self):
        body = "".join(f'<h3 class="rb-file-title"><code>{name}</code></h3>'
                       for name in ("dsi_bios7.bin", "DSi_Nand_USA.bin", "NDS_Bios7.bin"))
        meta = sitestarlight.file_names_meta(body)
        self.assertIn('data-pagefind-meta="files:DSi Nand USA bin NDS Bios7"', meta)
        # A letter of any script is a letter.
        self.assertIn("ファミコン", sitestarlight.file_names_meta(
            '<h3 class="rb-file-title"><code>ファミコン_bios.rom</code></h3>'))


class GateQueries(unittest.TestCase):
    """3.2, 3.3 and 3.6: the queries the gate runs, the pages that answer
    them and the rank they must reach."""

    EXPECTED = {
        "snes bios": (("systems/nintendo-snes/",), 1),
        "nes bios": (("systems/nintendo-nes/",), 1),
        "gamecube bios": (("systems/nintendo-gamecube/",), 1),
        "game boy bios": (("systems/nintendo-game-boy/",), 1),
        "3ds bios": (("systems/nintendo-3ds/",), 1),
        "playstation bios": (("systems/sony-playstation/",), 1),
        "playstation 2 bios": (("systems/sony-playstation-2/",), 1),
        "playstation 3 bios": (("systems/sony-playstation-3/",), 2),
        "ps3 bios": (("systems/sony-playstation-3/",), 1),
        "game boy advance bios": (("systems/nintendo/",), 1),
        "game boy color bios": (("systems/nintendo/",), 1),
        "nintendo ds bios": (("systems/nintendo-nintendo-ds/",), 1),
        "nintendo dsi bios": (("systems/nintendo-nintendo-dsi/",), 1),
        "wii bios": (("systems/nintendo/",), 1),
        "wii u bios": (("systems/nintendo-wii-u/",), 1),
        "saturn bios": (("systems/sega-saturn/",), 1),
        "check my bios folder": (("wiki/troubleshooting/",), 3),
        "is my bios correct": (("files/",), 3),
        "schema": (("data/",), 3),
        "json schema": (("data/",), 3),
        "license": (("data/", "wiki/legal/"), 3),
        "check bios folder script": (("data/",), 3),
        "ios": (("which-pack/", "wiki/faq/"), 3),
    }

    def test_the_gate_runs_each_query(self):
        for query, expected in self.EXPECTED.items():
            with self.subTest(query=query):
                self.assertEqual(QUERIES.get(query), expected)

    def test_each_console_query_names_a_generated_console_page(self):
        docs = REPO_ROOT / "website" / "src" / "content" / "docs"
        if not docs.is_dir():
            self.skipTest("site not generated")
        for query, (pages, _rank) in self.EXPECTED.items():
            if not query.endswith(" bios"):
                continue
            stem = pages[0].strip("/")
            with self.subTest(query=query):
                self.assertTrue(any((docs / f"{stem}{ext}").is_file() for ext in (".md", ".mdx")),
                                stem)


class LetterGroupsAreNoCrumb(unittest.TestCase):
    """3.4: a group of names by their first letter is a way through a
    list, not a place."""

    def test_by_initial(self):
        names = [{"label": "Dolphin", "link": "/d"}, {"label": "DuckStation", "link": "/e"}]
        self.assertTrue(sitestarlight.by_initial("D", names))
        self.assertFalse(sitestarlight.by_initial("E", names))
        digits = [{"label": "2600.emu", "link": "/a"}, {"label": "81", "link": "/b"}]
        self.assertTrue(sitestarlight.by_initial("0 to 9", digits))
        self.assertFalse(sitestarlight.by_initial("Sony", names))
        self.assertFalse(sitestarlight.by_initial("D", [{"label": "D", "items": names}]))

    def test_emulator_letter_groups_are_marked(self):
        side = sitestarlight.sidebar(_nav(), _present(_nav()), ANCHORS)
        letters = {key: value for key, value in side["groups"].items()
                   if key.startswith("Explore/Emulators/")}
        self.assertTrue(letters)
        for key, group in letters.items():
            with self.subTest(group=key):
                self.assertIs(group["crumb"], False)
        self.assertIs(side["groups"]["Explore/Emulators"]["crumb"], True)
        self.assertIs(side["groups"]["Explore/Systems"]["crumb"], True)

    def test_the_route_middleware_skips_them(self):
        self.assertIn("group?.crumb === false", ROUTE.read_text(encoding="utf-8"))


class StructuredData(unittest.TestCase):
    """3.5: the home page is the site, and a source repository states the
    release, never a commit id, and no placeholder description."""

    def test_versions_name_releases_only(self):
        release = generate_site.release_versions
        self.assertEqual(release({"core_version": "v0.1-12070"}), {"": "v0.1-12070"})
        self.assertEqual(release({"core_version": "1.5.85"}), {"": "1.5.85"})
        self.assertEqual(release({"core_version": "8dc77b0"}), {})
        self.assertEqual(release({"core_version": "0.8.139-2-g25e1ee2fd5"}), {})
        self.assertEqual(release({"core_version": "libretro branch"}), {})
        self.assertEqual(release({"core_version": "edge"}), {})
        self.assertEqual(release({}), {})
        self.assertEqual(release({"core_version": {"standalone": "v1.1", "libretro": "4122fed"}}),
                         {"standalone": "v1.1"})
        # A pin of digits only, in the version: supermodel3.
        self.assertEqual(release({"core_version": "0.3a-1481545-mm DirtBagXon (Sinden)",
                                  "upstream_commit": "14815455dc28fca2c8662fb1ed99d447ecf8f364"}),
                         {})
        # A dated release whose digits start no pin stays.
        self.assertEqual(release({"core_version": "20200712", "source_commit": "a1626f4e"}),
                         {"": "20200712"})

    def test_the_pin_is_never_a_version(self):
        data = generate_site.emulator_structured_data({
            "emulator": "Redream", "source": "https://github.com/x/redream",
            "source_commit": "0123abcd",
        })
        self.assertEqual(data["about"], {"@type": "SoftwareSourceCode", "name": "Redream",
                                         "codeRepository": "https://github.com/x/redream"})


class _Head(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ld: list[dict] = []
        self.sidebar: list[str] = []
        self.tabs_current = 0
        self._ld: list[str] | None = None
        self._label: list[str] | None = None
        self._tabs = False
        # A summary in the page body (a file row) is no sidebar group.
        self._main = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "script" and a.get("type") == "application/ld+json":
            self._ld = []
        if tag == "summary" and self._main:
            self._label = []
        if tag == "nav" and a.get("aria-label") == "Main":
            self._main = True
        if tag == "nav" and a.get("aria-label") == "Sections":
            self._tabs = True
        elif self._tabs and tag == "a" and a.get("aria-current"):
            self.tabs_current += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "nav":
            self._tabs = False
            self._main = False
        if tag == "script" and self._ld is not None:
            self.ld.append(json.loads("".join(self._ld)))
            self._ld = None
        if tag == "summary" and self._label is not None:
            self.sidebar.append(" ".join("".join(self._label).split()))
            self._label = None

    def handle_data(self, data: str) -> None:
        for buffer in (self._ld, self._label):
            if buffer is not None:
                buffer.append(data)


def _head(path: Path) -> _Head:
    page = _Head()
    page.feed(path.read_text(encoding="utf-8"))
    return page


@unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
class BuiltSearchSidebarAndHead(unittest.TestCase):
    def test_no_sidebar_group_is_named_by_a_number(self):
        for path in sorted(DIST.rglob("*.html")):
            labels = _head(path).sidebar
            with self.subTest(page=str(path.relative_to(DIST))):
                self.assertFalse([label for label in labels if re.fullmatch(r"\d+", label)])

    def test_every_get_page_has_one_current_tab(self):
        pages = sorted((DIST / "get").rglob("index.html"))
        self.assertTrue(pages)
        for path in [*pages, DIST / "404.html", DIST / "index.html"]:
            with self.subTest(page=str(path.relative_to(DIST))):
                self.assertEqual(_head(path).tabs_current, 1)

    def test_the_home_page_is_the_site(self):
        ld = _head(DIST / "index.html").ld
        self.assertEqual(len(ld), 1)
        self.assertEqual(ld[0]["@type"], "WebSite")
        self.assertEqual(ld[0]["name"], "RetroBIOS")
        self.assertNotIn("isPartOf", ld[0])

    def test_no_source_repository_states_a_commit_or_a_description(self):
        pins = {str(value).casefold()[:7]
                for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values()
                for field in ("source_commit", "upstream_commit")
                for value in (profile[field].values() if isinstance(profile.get(field), dict)
                              else [profile.get(field)])
                if value}
        self.assertTrue(pins)
        seen = 0
        for path in sorted((DIST / "emulators").rglob("index.html")):
            for data in _head(path).ld:
                about = data.get("about") or []
                for entry in about if isinstance(about, list) else [about]:
                    seen += 1
                    with self.subTest(page=str(path.relative_to(DIST)), repo=entry.get("codeRepository")):
                        self.assertNotIn("description", entry)
                        runs = re.findall(r"[0-9a-f]{7,40}", str(entry.get("version", "")).casefold())
                        self.assertFalse([run for run in runs if run[:7] in pins])
                        self.assertFalse(generate_site._COMMIT_ID.search(str(entry.get("version", ""))))
        self.assertTrue(seen)


if __name__ == "__main__":
    unittest.main()
