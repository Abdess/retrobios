"""The site reads as a funnel, from someone who knows nothing to a contributor.

Five tabs in reading order, every registered platform reachable from the
device picker, a level on every page, and no page for beginners sending its
reader two levels deeper without saying so.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
from tests import sitepages  # noqa: E402
from common import list_registered_platforms, load_platform_config, load_platform_registry  # noqa: E402
from siteguides import DEVICE_GROUPS, GROUP_ANCHORS, GUIDES  # noqa: E402

DOCS = sitepages.CONTENT
ORDER = list(generate_site.LEVELS)
# Pages link to site addresses once written for the site.
LINK = re.compile(r"\[[^\]]*\]\((/retrobios/[^)\s#?]*)(?:[#?][^)]*)?\)")
FENCED = re.compile(r"^\s*```.*?^\s*```", re.S | re.M)


def _registered() -> list[str]:
    return list_registered_platforms(str(REPO_ROOT / "platforms"), include_archived=True)


def _which_pack() -> str:
    with contextlib.chdir(REPO_ROOT):
        return generate_site.generate_which_pack()


def _docs_pages() -> list[Path]:
    return [p for p in sitepages.pages() if p.name not in ("404.md",)]


def _level(page: Path) -> str:
    return str(generate_site._front_matter(page.read_text(encoding="utf-8")).get("level") or "")


class FiveTabs(unittest.TestCase):
    """Twelve tabs put the walkthrough at position eleven, under "Wiki"."""

    def test_the_tabs_in_reading_order(self):
        nav = generate_site.generate_nav({}, {}, {}, {})
        self.assertEqual(
            [next(iter(tab)) for tab in nav],
            ["Start here", "Your setup", "Explore", "Reference", "Contribute"],
        )

    def test_each_tab_opens_on_an_index_or_a_first_page(self):
        nav = generate_site.generate_nav({}, {}, {}, {})
        tabs = {next(iter(tab)): next(iter(tab.values())) for tab in nav}
        self.assertEqual(tabs["Start here"][0], "index.md")
        self.assertEqual(tabs["Your setup"][0], "platforms/index.md")
        self.assertEqual(tabs["Reference"][0], "wiki/index.md")
        self.assertEqual(tabs["Contribute"][0], "contributing.md")

    def test_the_breadcrumbs_are_on(self):
        title = (REPO_ROOT / "website" / "src" / "components" / "PageTitle.astro").read_text(encoding="utf-8")
        route = (REPO_ROOT / "website" / "src" / "routeData.ts").read_text(encoding="utf-8")
        self.assertIn('aria-label="Breadcrumb"', title)
        self.assertIn("rbBreadcrumbs", route)


class EveryPlatformOnThePicker(unittest.TestCase):
    """KNULLI, MinUI, AmberELEC, EmuELEC, NextUI and MyMinUI were on no table
    of the download page: a hand-written list leaves out what it forgets."""

    def test_every_platform_has_a_group_and_a_guide(self):
        registry = load_platform_registry(str(REPO_ROOT / "platforms"))
        for key in _registered():
            with self.subTest(platform=key):
                self.assertIn(registry[key].get("device_group"), DEVICE_GROUPS)
                self.assertIn(key, GUIDES)

    def test_every_group_has_an_anchor(self):
        self.assertEqual(set(GROUP_ANCHORS), set(DEVICE_GROUPS))

    def test_every_platform_has_a_row(self):
        page = _which_pack()
        for key in _registered():
            name = load_platform_config(key, str(REPO_ROOT / "platforms"))["platform"]
            with self.subTest(platform=key):
                self.assertIn(f"| [{name}](platforms/{key}.md) |", page)

    def test_every_wiki_page_is_in_the_navigation(self):
        """A wiki page is published as soon as it exists, but a page left out
        of the nav is reachable only by a link and MkDocs says so at info
        level."""
        def targets(entries) -> list[str]:
            found = []
            for entry in entries:
                if isinstance(entry, str):
                    found.append(entry)
                else:
                    for value in entry.values():
                        found += targets(value) if isinstance(value, list) else [value]
            return found

        nav = " ".join(targets(generate_site.generate_nav({}, {}, {}, {})))
        kept_out: set[str] = set()
        wiki = Path(__file__).resolve().parents[1] / "wiki"
        missing = sorted(
            p.name for p in wiki.glob("*.md")
            if p.name not in kept_out and f"wiki/{p.name}" not in nav
        )
        self.assertEqual(missing, [])

    def test_every_platform_is_in_the_navigation_of_its_group(self):
        registry = load_platform_registry(str(REPO_ROOT / "platforms"))
        coverages = {
            key: {"platform": load_platform_config(key, str(REPO_ROOT / "platforms"))["platform"]}
            for key in _registered()
        }
        nav = generate_site.generate_nav(coverages, {}, {}, registry)
        setup = next(tab["Your setup"] for tab in nav if "Your setup" in tab)
        groups = {next(iter(item)): next(iter(item.values()))
                  for item in setup if isinstance(item, dict)}
        for key in coverages:
            label = DEVICE_GROUPS[registry[key]["device_group"]][0]
            with self.subTest(platform=key):
                self.assertIn({coverages[key]["platform"]: f"platforms/{key}.md"}, groups[label])

    def test_handheld_systems_that_run_retroarch_are_named(self):
        """muOS, ArkOS and the rest are detected as RetroArch by the
        installer and were named on no page a user reads."""
        from siteguides import HANDHELD_GUIDE

        page = generate_site.generate_handheld_guide(HANDHELD_GUIDE)
        self.assertIn("| muOS |", page)
        self.assertIn("`MUOS/bios` on the card", page)
        self.assertNotIn("| TrimUI |", page)


class SampleCoresLeaveTheNavigation(unittest.TestCase):
    """13 libretro sample cores (testsw, testgl_ff...) sat in the emulators
    navigation among the cores people look up."""

    def test_a_core_with_no_system_and_no_file_is_left_out(self):
        profiles = {
            "testsw": {"emulator": "testsw", "type": "libretro", "systems": []},
            "duckstation": {"emulator": "DuckStation", "type": "standalone",
                            "systems": ["sony-playstation"], "files": [{"name": "a.bin"}]},
            "zx": {"emulator": "zx81", "type": "libretro", "systems": ["sinclair-zx81"]},
        }
        nav = generate_site._emulator_nav(profiles)
        self.assertEqual(nav[0], "emulators/index.md")
        groups = {next(iter(group)): next(iter(group.values())) for group in nav[1:]}
        self.assertEqual(groups, {
            "D": [{"DuckStation": "emulators/duckstation.md"}],
            "Z": [{"zx81": "emulators/zx.md"}],
        })


class EveryPageHasALevel(unittest.TestCase):
    def test_wiki_sources_declare_one(self):
        for page in sorted((REPO_ROOT / "wiki").glob("*.md")):
            level = generate_site._front_matter(page.read_text(encoding="utf-8")).get("level")
            with self.subTest(page=page.name):
                self.assertIn(level, generate_site.LEVELS)

    def test_every_generated_page_has_one_and_its_label(self):
        for page in _docs_pages():
            text = page.read_text(encoding="utf-8")
            level = _level(page)
            with self.subTest(page=str(page.relative_to(DOCS))):
                self.assertIn(level, generate_site.LEVELS)
                self.assertIn(f"\nlevel: {level}\n", text)
        # The label above each title comes from the page's level.
        component = (REPO_ROOT / "website" / "src" / "components" / "PageTitle.astro").read_text()
        for level, label in generate_site.LEVELS.items():
            with self.subTest(level=level):
                self.assertIn(f"{level}: '{label}'", component)

    def test_the_decoration_keeps_an_authored_level(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            page = Path(tmp) / "wiki" / "faq.md"
            page.parent.mkdir()
            page.write_text("---\nlevel: start\n---\n\n# FAQ\n\nQuestions people ask first.\n")
            generate_site.decorate_markdown_pages(Path(tmp))
            generate_site.decorate_markdown_pages(Path(tmp))
            text = page.read_text()
        self.assertEqual(text.count("level: start"), 1)
        self.assertIn("searchWeight: 10\n", text)
        self.assertIn("title: FAQ\n", text)


class DeepLinksCarryALabel(unittest.TestCase):
    """A beginner page sent its reader to Tools and Architecture as the next
    step. A link from a start or setup page to a page two levels deeper or
    more says what it leads to, with that page's level label before it on
    its line, or in the heading of its section ("## Reference: ...").

    A link right after the question it answers ("Have a file? [Check it]")
    says it too: there a label read as a broken crumb beside the Reference
    tab."""

    # Answers a start page sends its reader to on purpose: the arcade
    # version table opens on one plain sentence, and "Reference:" before
    # its link read as a broken crumb.
    ANSWERS = ("/retrobios/wiki/technical-faq/#which-mame-version-do-the-arcade-bios-sets-match",)

    def test_start_and_setup_pages(self):
        import sitestarlight  # noqa: PLC0415

        pages = _docs_pages()
        levels = {page: _level(page) for page in pages}
        by_url = {sitestarlight.page_url(sitepages.name(page)): page for page in pages}
        offenders = []
        for page, level in levels.items():
            if level not in ("start", "setup"):
                continue
            text = FENCED.sub("", page.read_text(encoding="utf-8"))
            # The headings the line sits under, by depth: a system's h3 sits
            # in the "## Reference: every file by system" section.
            headings: dict[int, str] = {}
            for line in text.splitlines():
                level_match = re.match(r"(#{1,3}) ", line)
                if level_match:
                    depth = len(level_match[1])
                    headings = {d: h for d, h in headings.items() if d < depth}
                    headings[depth] = line.lstrip("#").strip()
                for match in LINK.finditer(line):
                    target = by_url.get(match.group(1))
                    if target not in levels:
                        continue
                    deeper = levels[target]
                    if ORDER.index(deeper) - ORDER.index(level) < 2:
                        continue
                    if any(f"]({answer})" in match.group(0) for answer in self.ANSWERS):
                        continue
                    label = f"{generate_site.LEVELS[deeper]}:"
                    if line[: match.start()].rstrip().endswith("?"):
                        continue
                    if label not in line[: match.start()] and not any(
                            heading.startswith(label) for heading in headings.values()):
                        offenders.append(f"{page.relative_to(DOCS)}: {match.group(0)}")
        self.assertEqual(offenders, [], "\n".join(offenders[:30]))


class GuidePagesEndOnANextStep(unittest.TestCase):
    def test_home_picker_and_platform_page(self):
        # The home page has none: its hero buttons are the next step.
        for page in ("which-pack.md", "platforms/batocera.md",
                     "wiki/first-install.md", "wiki/troubleshooting.md",
                     "wiki/what-are-bios-files.md", "wiki/faq.md"):
            if page.startswith(("index", "which", "platforms")):
                sitepages.require()
                path = sitepages.page(page)
            else:
                path = REPO_ROOT / page
            with self.subTest(page=page):
                text = path.read_text(encoding="utf-8")
                if page.startswith("wiki/"):
                    # A plain list: an aside drew a coloured stripe and an icon.
                    self.assertIn("\n## Next steps\n", text)
                    self.assertNotIn(":::tip[Next]", text)
                else:
                    self.assertTrue(":::tip[Next]" in text or "## Next steps" in text
                                    or "## What comes next" in text)

    def test_the_platform_page_opens_on_its_guide(self):
        """The folder came after four counters and a metadata table, and was
        the pack-relative `bios/` where Batocera reads /userdata/bios/."""
        sitepages.require()
        text = sitepages.page("platforms/batocera.md").read_text(encoding="utf-8")
        # Batocera runs on its own device: the computer route comes first.
        order = [text.index(h) for h in (
            "## Where the files go", "## From your computer", "## On the device",
            "## How to check", "## Reference: every file by system",
        )]
        self.assertEqual(order, sorted(order))
        self.assertLess(text.index("`/userdata/bios/`"), text.index("rb-stat-value"))


if __name__ == "__main__":
    unittest.main()
