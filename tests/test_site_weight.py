"""Pages a phone can open: split pages, light navigation, short tables of contents.

systems/game-engines/ was one 10.5 MB page, emulators/mame/ 3 MB, and each
of 600 emulator pages carried 65 KB of navigation. A large page is now a
summary with pages of its own, and every address cited before the split
still lands: a console's heading stays on the summary, a card's sha1 anchor
is looked up by content, an emulator card's anchor sits on its row.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitestarlight  # noqa: E402
import siterender  # noqa: E402
import sitemarkup as markup  # noqa: E402
from cross_reference import FileConsumers  # noqa: E402


def _file(name: str, index: int, console: str, maker: str = "Maker") -> dict:
    sha1 = f"{index:012x}" + "0" * 28
    return {"name": name, "sha1": sha1, "md5": f"{index:032x}", "size": 10,
            "path": f"bios/{maker}/{console}/{name}"}


class ASystemPageOverItsBudgetIsSplit(unittest.TestCase):
    def setUp(self) -> None:
        siterender.reset_console_pages()
        self.addCleanup(siterender.reset_console_pages)
        self.consoles = {
            "Big": [_file(f"big{i:03d}.bin", i, "Big") for i in range(60)],
            "Small": [_file("small.bin", 900, "Small")],
        }

    def _pages(self, budget: int) -> dict:
        return generate_site.system_pages(
            "Maker", self.consoles, FileConsumers({"files": {}}), budget=budget)

    def test_a_page_within_its_budget_stays_whole(self):
        pages = self._pages(10_000_000)
        self.assertEqual(list(pages), ["maker"])
        self.assertIn("## Big", pages["maker"][0])

    def test_the_largest_section_moves_and_is_cut_in_parts(self):
        pages = self._pages(20_000)
        summary = pages["maker"][0]
        # Both headings stay on the summary: systems/maker/#big still lands.
        self.assertIn("## Big", summary)
        self.assertIn("## Small", summary)
        # The small section keeps its cards in place.
        self.assertIn('id="sha1-' + f"{900:012x}", summary)
        parts = [stem for stem in pages if stem.startswith("maker-big")]
        self.assertGreater(len(parts), 1)
        self.assertEqual(parts[0], "maker-big")
        for stem in parts:
            self.assertIn(f"]({stem}.md)", summary)
            self.assertLessEqual(len(pages[stem][0]), 20_000 + 5_000)
            self.assertIn("## Files", pages[stem][0])
        # Each card is on exactly one part, and the links follow it.
        held = [f["sha1"] for stem in parts for f in pages[stem][1]["Big"]]
        self.assertEqual(sorted(held), sorted(f["sha1"] for f in self.consoles["Big"]))
        last = self.consoles["Big"][-1]
        self.assertEqual(siterender.card_page(last["path"], last["sha1"]), parts[-1])
        small = self.consoles["Small"][0]
        self.assertEqual(siterender.card_page(small["path"], small["sha1"]), "maker")
        self.assertEqual(siterender.console_href("maker", "Big"), "systems/maker.md#big")

    def test_a_console_on_one_page_is_linked_directly(self):
        self.consoles["Big"] = self.consoles["Big"][:12]
        # The budget is measured in the Markdown it was set on.
        with markup.using("mkdocs"):
            whole = self._pages(10**9)["maker"][0]
        pages = self._pages(len(whole) - 1)
        self.assertIn("maker-big", pages)
        self.assertNotIn("maker-big-2", pages)
        self.assertEqual(siterender.console_href("maker", "Big", "../"),
                         "../systems/maker-big.md")


class AnEmulatorWithTooManyCardsIsSplit(unittest.TestCase):
    def test_parts_are_balanced_and_rows_keep_the_anchors(self):
        files = [{"name": f"set{i:04d}.zip", "required": i % 2 == 0, "category": "bios_zip"}
                 for i in range(generate_site.EMULATOR_CARDS_PER_PAGE * 2 + 1)]
        parts = generate_site.emulator_parts("big", files)
        self.assertEqual([stem for stem, _ in parts], ["big-files-1", "big-files-2", "big-files-3"])
        sizes = [len(entries) for _, entries in parts]
        self.assertLessEqual(max(sizes) - min(sizes), 1)
        self.assertEqual(generate_site.emulator_parts("small", files[:3]), [])

        pages = generate_site.emulator_pages(
            "big", {"emulator": "Big", "type": "standalone", "files": files}, {"files": {}})
        self.assertEqual(sorted(pages), ["big", "big-files-1", "big-files-2", "big-files-3"])
        main = pages["big"]
        anchors = generate_site.emulator_file_anchors(files)
        for anchor in anchors:
            self.assertIn(f'<a id="{anchor}" href=', main)
        self.assertIn('class="rb-card-index"', main)
        self.assertNotIn("rb-file-title", main)
        self.assertIn(f'id="{anchors[0]}" class="rb-file-title"', pages["big-files-1"])

    def test_cards_are_linked_on_the_page_that_holds_them(self):
        files = [{"name": f"set{i:04d}.zip"} for i in range(generate_site.EMULATOR_CARDS_PER_PAGE + 1)]
        generate_site.plan_emulator_pages({"big": {"files": files}})
        anchors = generate_site.emulator_file_anchors(files)
        self.assertEqual(siterender.emulator_card_page("big", anchors[-1]), "big-files-2")
        self.assertEqual(siterender.emulator_card_page("other", "file-x"), "other")


class APlatformSystemOverItsBudgetMoves(unittest.TestCase):
    def test_the_heading_stays_and_the_list_moves(self):
        files = [{"name": f"f{i:04d}.zip", "status": "ok"} for i in range(40)]
        config = {("arcade", f["name"]): [{"name": f["name"], "md5": "a" * 32}] for f in files}
        moved: dict[str, str] = {}
        budget = generate_site.PLATFORM_SECTION_BUDGET
        generate_site.PLATFORM_SECTION_BUDGET = 5
        try:
            lines = generate_site._render_platform_systems(
                {"arcade": files}, config, {}, ("deck", "Deck"), moved)
        finally:
            generate_site.PLATFORM_SECTION_BUDGET = budget
        text = "\n".join(lines)
        self.assertIn("{ #arcade }", text)
        self.assertIn("](deck-arcade.md)", text)
        self.assertNotIn("f0001.zip", text)
        self.assertIn("f0001.zip", moved["deck-arcade"])
        self.assertIn("[Deck page](deck.md#arcade)", moved["deck-arcade"])


class TheNavigationOpensOneInitial(unittest.TestCase):
    def test_one_group_per_initial_one_level_deep(self):
        profiles = {
            key: {"emulator": name, "systems": ["s"]}
            for key, name in (("a1", "Alpha"), ("b1", "Beta"), ("b2", "bravo"), ("z", "Zed"),
                              ("n", "2ship"))
        }
        nav = generate_site._emulator_nav(profiles)
        self.assertEqual(nav[1:], [
            {"0 to 9": [{"2ship": "emulators/n.md"}]},
            {"A": [{"Alpha": "emulators/a1.md"}]},
            {"B": [{"Beta": "emulators/b1.md"}, {"bravo": "emulators/b2.md"}]},
            {"Z": [{"Zed": "emulators/z.md"}]},
        ])


class TheTableOfContentsOfACardPageStopsAtLevelTwo(unittest.TestCase):
    @staticmethod
    @staticmethod
    def _contents(rel: str, sections: int):
        import yaml  # noqa: PLC0415

        body = "# T\n\n" + "".join(f"## S{i}\n\n### card\n\n" for i in range(sections))
        _target, text = sitestarlight.finalize_page(
            rel, body, level="", weight=None, browser_title="T", description="d",
            structured={}, terms={})
        return yaml.safe_load(text.split("---\n")[1]).get("tableOfContents", "default")

    def test_cards_leave_the_toc_and_wiki_pages_keep_level_three(self):
        level_two = {"minHeadingLevel": 2, "maxHeadingLevel": 2}
        for rel, sections, expected in (
            ("systems/sony.md", 3, level_two), ("platforms/retroarch.md", 5, level_two),
            ("emulators/mame.md", 3, level_two), ("wiki/faq.md", 3, "default"),
            # One or two headings over hundreds of cards: no table at all,
            # whose script watched every block of the page.
            ("emulators/mame-files-2.md", 1, False), ("systems/arcade-arcade.md", 2, False),
        ):
            with self.subTest(rel=rel):
                self.assertEqual(self._contents(rel, sections), expected)


if __name__ == "__main__":
    unittest.main()
