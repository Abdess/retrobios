"""System pages and file cards.

The Game Boy, NES and SNES sections said "Start with" a file one core of
sixteen requires, under a home page saying they need none. The romset line
said no MAME release matched sets MAME loads. The Neo Geo opened on files
ares alone reads, and RetroArch had no install line. The Arcade page was
sorted by storage folder: NAOMI, PGM and ZN-1 had no section, and their
names were plain on every emulator page. Cards named emulators by id, part
pages had no parent and no name, and four paragraphs came before the first
console.
"""

from __future__ import annotations

import json
import re
import sys
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
from sitestarlight import toc_slug  # noqa: E402

DIST = REPO_ROOT / "website" / "dist"
CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"


def _unlinked(text: str) -> str:
    """A start line's wording: each file it names links to its card."""
    return re.sub(r"\[(`[^`]*`)\]\([^)]*\)", r"\1", text)


def _file(name: str, char: str, path: str = "") -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 4096,
            "path": path or f"bios/Nintendo/Game Boy/{name}"}


def _consumers(readers: dict[str, list[tuple[str, dict]]],
               systems: dict[str, dict[str, set[str]]] | None = None) -> types.SimpleNamespace:
    """Consumers where each sha1 is read by the given (emulator, entry)."""
    files_of: dict[str, list] = {}
    entries: dict[str, dict[str, int]] = {}
    emulators: dict[str, set[str]] = {}
    for sha1, read_by in readers.items():
        for emulator, entry in read_by:
            files_of.setdefault(emulator, []).append(entry)
            entries.setdefault(sha1, {})[emulator] = len(files_of[emulator]) - 1
            emulators.setdefault(sha1, set()).add(emulator)
    return types.SimpleNamespace(
        platforms={}, emulators=emulators, emulator_entries=entries,
        emulator_files=files_of, installed={}, platform_systems=systems or {},
        platform_destinations={}, _db={"files": {}},
    )


def _page(path: Path) -> str:
    if not path.is_file():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not built")
    return path.read_text(encoding="utf-8")


def _opening(html: str, anchor: str) -> str:
    """The text of the first paragraph under a heading."""
    start = html.index("<p>", html.index(f'id="{anchor}"'))
    return re.sub(r"<[^>]+>", "", html[start:html.index("</p>", start)]).strip()


class AFileFewRequireIsNoStartFile(unittest.TestCase):
    """6.1: one requiring emulator decided the line for the console."""

    def test_one_of_four_says_no_file_needed_and_names_it(self) -> None:
        boot = _file("dmg_boot.bin", "1")
        optional = {"required": False, "system": "nintendo-gb"}
        consumers = _consumers({"1" * 40: [
            ("emux_gb", {"name": "dmg_boot.bin", "required": True}),
            ("gambatte", optional), ("mgba", optional), ("sameboy", optional)]})
        line = _unlinked(gs._start_with([boot], consumers)[0])
        self.assertTrue(line.startswith("**No file needed** with "), line)
        self.assertRegex(line, r"Only \S.* requires `dmg_boot.bin`\.$")

    def test_most_requiring_keeps_the_start_line(self) -> None:
        bios = _file("scph5501.bin", "2")
        required = {"name": "scph5501.bin", "required": True}
        consumers = _consumers({"2" * 40: [
            ("a", required), ("b", required), ("c", {"required": False, "hle_fallback": True})]})
        self.assertEqual(_unlinked(gs._start_with([bios], consumers)[0]), "**Start with**: `scph5501.bin`.")

    def test_an_entry_read_for_a_system_with_no_section_is_dropped(self) -> None:
        sample = _file("ym2608_adpcm_rom.bin", "3", "bios/Nintendo/NES/ym2608_adpcm_rom.bin")
        consumers = _consumers({"3" * 40: [
            ("fbneo", {"name": "ym2608_adpcm_rom.bin", "required": True,
                       "system": "no-such-system-anywhere"})]})
        self.assertEqual(gs._start_with([sample], consumers, section=("Nintendo", "NES")), [])

    def test_the_home_usually_not_consoles_open_on_no_file_needed(self) -> None:
        home = _page(DIST / "index.html")
        match = re.search(r"<strong>Usually not</strong> for ([^<.]+)", home)
        self.assertIsNotNone(match, "the home page no longer says Usually not")
        names = re.split(r", | and ", match[1])
        sections = {"NES": ("nintendo", "nes"), "Super Nintendo": ("nintendo", "snes"),
                    "Mega Drive": ("sega", "mega-drive"), "Game Boy": ("nintendo", "game-boy"),
                    "Game Boy Advance": ("nintendo", "game-boy-advance")}
        for name in names:
            self.assertIn(name, sections, f"map {name!r} to its section")
            page, anchor = sections[name]
            html = _page(DIST / "systems" / page / "index.html")
            self.assertTrue(_opening(html, anchor).startswith("No file needed"), name)


class TheRomsetLineMatchesByCrc(unittest.TestCase):
    """6.2: a set with an extra BIOS revision read "No match"."""

    def test_the_main_neogeo_set_names_every_mame_release(self) -> None:
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        main = next((f for sha1, f in db["files"].items() if sha1.startswith("447e2375")), None)
        if main is None or not (REPO_ROOT / main["path"]).is_file():
            self.skipTest("the main neogeo.zip is not in this checkout")
        line = gs._romset_line(main)
        self.assertIn("Holds every ROM of MAME 0.190 to 0.289", line)
        self.assertNotIn("No match", line)


class TheNeoGeoOpensOnItsSet(unittest.TestCase):
    """6.3: the set 26 emulators read leads, RetroArch gets its command."""

    def test_the_lead_names_the_exceptions(self) -> None:
        neogeo = _file("neogeo.zip", "4", "bios/SNK/Neo Geo/neogeo.zip")
        epo = _file("neo-epo.sp1", "5", "bios/SNK/Neo Geo/neo-epo.sp1")
        mvs = {"name": "neogeo.zip", "required": True, "system": "snk-neogeo-mvs"}
        consumers = _consumers({
            "4" * 40: [(f"mame{n}", mvs) for n in range(4)],
            "5" * 40: [("ares", {"name": "neo-epo.sp1", "required": True,
                                 "system": "snk-neogeo"})],
        })
        lines = [_unlinked(line) for line in gs._start_with([neogeo, epo], consumers, section=("SNK", "Neo Geo"))]
        self.assertTrue(lines[0].startswith("**Start with** `neogeo.zip`. Keep it zipped. "))
        self.assertIn("ares reads `neo-epo.sp1` instead.", lines)
        cards = gs._console_cards("SNK", [epo, neogeo], consumers, set(),
                                  start=gs._start_order([neogeo, epo], consumers,
                                                        ("SNK", "Neo Geo")))
        self.assertIn("neogeo.zip", cards[0][1][2])

    def test_a_setup_filing_the_set_elsewhere_gets_its_command(self) -> None:
        consumers = _consumers({}, systems={"a" * 40: {"retroarch": {"arcade"}}})
        pairs = gs._install_pairs([("batocera", "snk-neogeo")], "a" * 40, consumers)
        self.assertIn(("retroarch", "arcade"), pairs)
        block = "\n".join(gs._console_install_block("Neo Geo", pairs))
        self.assertIn("<li>RetroArch: <code", block)
        self.assertIn("--platform retroarch --system arcade</code>", block)

    def test_the_built_section(self) -> None:
        html = _page(DIST / "systems" / "snk" / "index.html")
        section = html[html.index('id="neo-geo"'):]
        self.assertTrue(_opening(html, "neo-geo").startswith("Start with neogeo.zip"))
        self.assertIn("--platform retroarch --system arcade", re.sub(r"<[^>]+>", "", section))


BOARDS = ("Sega NAOMI", "Sammy Atomiswave", "Capcom ZN-1", "IGS PolyGame Master",
          "Nintendo PlayChoice-10", "SNK Hyper Neo Geo 64")


class EachArcadeBoardHasASection(unittest.TestCase):
    """6.4: the Arcade page was cut by storage folder."""

    def test_each_board_heads_its_page(self) -> None:
        # The page's title names the board, no h2 says it again.
        for name in BOARDS:
            slug = toc_slug(name)
            html = _page(DIST / "systems" / f"arcade-{slug}" / "index.html")
            self.assertRegex(html, rf"<h1[^>]*>Arcade: {re.escape(name)}</h1>", name)
            self.assertNotRegex(html, rf"<h2[^>]*>{re.escape(name)}<", name)

    def test_every_board_on_an_emulator_systems_row_is_a_link(self) -> None:
        if not (DIST / "emulators").is_dir():
            self.skipTest("site not built")
        plain = []
        for page in sorted((DIST / "emulators").glob("*/index.html")):
            row = re.search(r"<td>Systems</td>\s*<td>(.*?)</td>", page.read_text(encoding="utf-8"),
                            re.S)
            if not row:
                continue
            text = re.sub(r"<a [^>]*>.*?</a>", "", row[1])
            plain += [(page.parent.name, name) for name in BOARDS if name in text]
        self.assertEqual(plain, [])

    def test_the_arcade_page_lists_the_boards_first(self) -> None:
        md = _page(CONTENT / "systems" / "arcade.md")
        headings = re.findall(r"^## (.+?) \{", md, re.M)
        self.assertIn("Sega NAOMI", headings)
        self.assertLess(headings.index("Sega NAOMI"), headings.index(gs.OTHER_ARCADE_LABEL))


class CardsNameEmulatorsByName(unittest.TestCase):
    """6.6: 19,499 card links read the profile id."""

    def test_the_display_name_is_the_link_text(self) -> None:
        sha1 = "6" * 40
        consumers = _consumers({sha1: [("melonds_ds", {"name": "bios7.bin"})]})
        link = gs._emulator_links(sha1, consumers)[0]
        self.assertTrue(link.startswith("[melonDS DS]("), link)

    def test_no_built_card_link_reads_an_id(self) -> None:
        if not (DIST / "systems").is_dir():
            self.skipTest("site not built")
        profiles = gs._profiles_on_disk()
        bad = set()
        for page in (DIST / "systems").glob("*/index.html"):
            for emulator, text in re.findall(
                    r'<a href="/retrobios/emulators/([^/"#]+)/[^"]*">([^<]+)</a>',
                    page.read_text(encoding="utf-8")):
                display = str((profiles.get(emulator) or {}).get("emulator") or emulator)
                if text == emulator and display != emulator:
                    bad.add(emulator)
        self.assertEqual(sorted(bad), [])


class PartPagesKnowWhereTheyAre(unittest.TestCase):
    def tearDown(self) -> None:
        # system_pages records where consoles went, for every later page.
        gs.reset_console_pages()

    """6.7: 128 system pages had no parent, parts were "part 3 of 5"."""

    def test_every_part_has_a_parent_and_a_name(self) -> None:
        if not (CONTENT / "systems").is_dir():
            self.skipTest("pages not generated")
        orphans, numbered = [], []
        for page in sorted((CONTENT / "systems").glob("*.md*")):
            text = page.read_text(encoding="utf-8")
            # A part is titled "<maker>: <console>" or "<name> files a to b".
            title = re.search(r"^title: (.*)$", text, re.M)
            part = title and (": " in title[1] or re.search(r" files .+ to ", title[1]))
            if part and "\nparent:" not in text.split("\n---\n", 1)[0]:
                orphans.append(page.name)
            if re.search(r"^title: .*part \d+ of \d+", text, re.M | re.I):
                numbered.append(page.name)
        self.assertEqual(orphans, [])
        self.assertEqual(numbered, [])

    def test_parts_are_even_and_linked_to_their_neighbours(self) -> None:
        files = [_file(f"rom{i:02}.bin", "0123456789"[i], f"bios/Sony/PlayStation 2/rom{i:02}.bin")
                 for i in range(10)]
        consumers = _consumers({})
        with gs.markup.using("mkdocs"):
            one = sum(len(line) + 1 for line in gs._system_file_card(files[0], consumers))
        pages = gs.system_pages("Sony", {"PlayStation 2": files}, consumers, budget=one * 7)
        parts = [stem for stem in pages if stem != "sony"]
        self.assertEqual(len(parts), 2)
        counts = [pages[stem][0].count('class="rb-sys-file"') for stem in parts]
        self.assertEqual(counts, [5, 5])
        first = pages[parts[0]][0]
        self.assertIn("parent:\n  label: \"Sony\"\n  link: \"/systems/sony/\"", first)
        self.assertIn(f"next:\n  label: \"PlayStation 2 files rom05.bin to rom09.bin\"\n"
                      f"  link: \"/systems/{parts[1]}/\"", first)
        self.assertIn("# PlayStation 2 files rom00.bin to rom04.bin", first)
        self.assertIn(f"searchWeight: {gs._part_weight()}", first)


def _consoles(page: str) -> list[str]:
    """The consoles: front matter of a generated page."""
    front = page.split("\n---\n", 1)[0] if page.startswith("---\n") else ""
    block = re.search(r"^consoles:\n((?:  - .*\n?)+)", front + "\n", re.M)
    return [json.loads(line[4:]) for line in block[1].splitlines()] if block else []


class ConsolesFieldNamesMachinesOnce(unittest.TestCase):
    def tearDown(self) -> None:
        # system_pages records where consoles went, for every later page.
        gs.reset_console_pages()

    """The consoles search field: only machine sections, and a console
    with a page of its own is that page's, or "dolphin" found Other and
    "playstation bios" found Sony before the PlayStation page."""

    def test_no_emulator_folder_is_a_console(self) -> None:
        for maker in ("Other", "Game Engines"):
            page = gs.system_pages(maker, {"dolphin": [_file("a.bin", "a")]}, _consumers({}))
            self.assertEqual(_consoles(page[gs._slug(maker)][0]), [], maker)

    def test_a_console_with_its_own_page_is_left_to_it(self) -> None:
        big = [_file(f"r{i:02}.bin", "0123456789"[i], f"bios/Sega/Saturn/r{i:02}.bin")
               for i in range(10)]
        small = [_file("pico.bin", "p", "bios/Sega/Pico/pico.bin")]
        consumers = _consumers({})
        with gs.markup.using("mkdocs"):
            one = sum(len(line) + 1 for line in gs._system_file_card(big[0], consumers))
        # Sega splits by size. Every Sony console has a page whatever its size.
        pages = gs.system_pages("Sega", {"Saturn": big, "Pico": small},
                                consumers, budget=one * 12)
        self.assertIn("sega-saturn", pages)
        self.assertEqual(_consoles(pages["sega"][0]), ["Pico"])
        self.assertEqual(_consoles(pages["sega-saturn"][0]), ["Saturn"])
        self.addCleanup(gs.reset_console_pages)
        sony = gs.system_pages("Sony", {"PlayStation": big, "PocketStation": small},
                               consumers, budget=one * 12)
        self.assertEqual(_consoles(sony["sony"][0]), [])
        self.assertEqual(_consoles(sony["sony-pocketstation"][0]), ["PocketStation"])


class OneLineBeforeTheFirstConsole(unittest.TestCase):
    """6.8: four paragraphs, word for word on every maker's page."""

    def test_the_intro_is_one_line_and_the_legend_closed(self) -> None:
        page = gs.generate_system_page("SNK", {"Neo Geo": [_file("a.bin", "a")]}, _consumers({}))
        body = page.split("# SNK\n", 1)[1]
        before = body[:body.index("## Neo Geo")]
        self.assertTrue(before.lstrip().startswith(
            "Every BIOS file for SNK machines, one card per file.\n"))
        legend = before[before.index("<section data-pagefind-ignore>"):]
        self.assertIn("<summary>How to read a card</summary>", legend)
        self.assertNotIn(" open>", legend)
        self.assertNotIn("JSON", before)
        self.assertIn("as JSON](../api/v1/systems/snk.json)", page.split("## Next steps")[1])


class SetupsGroupedByPlace(unittest.TestCase):
    """6.9: each setup repeated the name it gives the file."""

    def test_one_line_per_place(self) -> None:
        places = [("Batocera", "b.md", ["scph5501.bin"]), ("KNULLI", "k.md", ["scph5501.bin"]),
                  ("RetroDECK", "r.md", ["bios/scph5501.bin"]), ("EmuDeck", "e.md", [])]
        self.assertEqual(gs._places_lines(places), [
            "<code>scph5501.bin</code>: [Batocera](b.md), [KNULLI](k.md)",
            "<code>bios/scph5501.bin</code>: [RetroDECK](r.md)",
            "[EmuDeck](e.md)",
        ])


if __name__ == "__main__":
    unittest.main()
