"""System pages and file cards (round 2, package 6).

The Sony page opened on LibPS.exe, its card titles read "scph5501.bin
permalink" in the site search, the two setup lines of a card were defined
only in a code comment, and the systems index named no console.
"""

from __future__ import annotations

import re
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import siterender  # noqa: E402
from cross_reference import FileConsumers  # noqa: E402

DIST = REPO_ROOT / "website" / "dist"


def _file(name: str, char: str, path: str = "") -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 524288,
            "path": path or f"bios/Sony/PlayStation/{name}"}


def _consumers(readers: dict[str, list[dict]], platforms: dict[str, set[str]] | None = None
               ) -> types.SimpleNamespace:
    """Consumers where each sha1 is read by the given profile entries, one
    emulator per entry."""
    files_of: dict[str, list] = {}
    entries: dict[str, dict[str, int]] = {}
    emulators: dict[str, set[str]] = {}
    for sha1, read_by in readers.items():
        for number, entry in enumerate(read_by):
            emulator = f"emu{number}-{sha1[:4]}"
            files_of[emulator] = [entry]
            entries.setdefault(sha1, {})[emulator] = 0
            emulators.setdefault(sha1, set()).add(emulator)
    return types.SimpleNamespace(
        platforms=platforms or {}, emulators=emulators, emulator_entries=entries,
        emulator_files=files_of, installed={}, platform_systems={},
        platform_destinations={},
    )


class TheConsoleBiosComesFirst(unittest.TestCase):
    """Cards were sorted by byte order: capitals first, so LibPS.exe and
    PSX_DTLH2000.bin opened the PlayStation section and scph5501.bin was
    28th."""

    def setUp(self):
        self.files = [
            _file("LibPS.exe", "1"), _file("PSX_DTLH2000.bin", "2"),
            _file("dtlh1100.bin", "3"), _file("scph5501.bin", "4"),
            _file("scph5500.bin", "5"), _file("scph1001.bin", "6"),
            _file("openbios.bin", "7"),
        ]
        self.consumers = _consumers({
            "4" * 40: [{"name": "scph5501.bin", "required": True, "priority": 2,
                        "region": ["north-america"]}],
            "5" * 40: [{"name": "scph5500.bin", "required": True, "priority": 5,
                        "region": ["japan"]}],
            "6" * 40: [{"name": "scph1001.bin", "required": False, "priority": 1}],
            "2" * 40: [{"name": "PSX_DTLH2000.bin", "required": False}],
        }, platforms={"6" * 40: {"a", "b"}, "3" * 40: {"a", "b", "c"}})

    def names(self) -> list[str]:
        cards = gs._console_cards("Sony", self.files, self.consumers, set())
        return [re.search(r"<code>(.*?)</code>", card[2])[1] for _v, card, _s in cards]

    def test_required_then_priority_then_setups_then_name(self):
        self.assertEqual(self.names(), [
            "scph5501.bin", "scph5500.bin",  # required, by priority
            "scph1001.bin",                 # optional with a priority
            "dtlh1100.bin",                 # listed by three setups
            "LibPS.exe", "openbios.bin", "PSX_DTLH2000.bin",  # by name, any case
        ])

    def test_a_console_cut_in_parts_goes_by_name(self):
        cards = gs._console_cards("Sony", self.files, self.consumers, set(), by_name=True)
        names = [re.search(r"<code>(.*?)</code>", card[2])[1] for _v, card, _s in cards]
        self.assertEqual(names, sorted(names, key=str.casefold))

    def required_only(self) -> types.SimpleNamespace:
        """The BIOS readers alone: an emulator reading only an optional
        file runs without the BIOS, and two of four would say so."""
        return _consumers({
            "4" * 40: [{"name": "scph5501.bin", "required": True, "priority": 2,
                        "region": ["north-america"]}],
            "5" * 40: [{"name": "scph5500.bin", "required": True, "priority": 5,
                        "region": ["japan"]}],
        })

    def test_the_section_opens_on_the_bios_by_region(self):
        lines = gs._start_with(self.files, self.required_only())
        self.assertEqual(lines[0], "**Start with** the BIOS for the region of your games:")
        self.assertIn("- **North America**: [`scph5501.bin`](#sha1-444444444444)", lines)
        self.assertIn("- **Japan**: [`scph5500.bin`](#sha1-555555555555)", lines)
        self.assertLess(lines.index("- **North America**: [`scph5501.bin`](#sha1-444444444444)"),
                        lines.index("- **Japan**: [`scph5500.bin`](#sha1-555555555555)"))

    def test_regions_needing_the_same_file_share_a_line(self):
        consumers = _consumers({"4" * 40: [
            {"required": True, "region": ["north-america", "latin-america", "brazil"]}]})
        lines = gs._start_with([_file("scph5501.bin", "4")], consumers)
        # Brazil says nothing Latin America does not.
        self.assertIn("- **North America, Latin America**: [`scph5501.bin`](#sha1-444444444444)", lines)

    def test_a_long_list_names_the_first_and_counts_the_rest(self):
        files = [_file(f"rom{i}.bin", "abcdefgh"[i]) for i in range(8)]
        # One emulator requires all eight: files each required by another
        # emulator are other names for one slot (round 5, 6.2).
        consumers = _consumers({f["sha1"]: [{"required": True}] for f in files})
        consumers.emulator_files = {"emu": [{"required": True}] * len(files)}
        consumers.emulator_entries = {f["sha1"]: {"emu": i} for i, f in enumerate(files)}
        self.assertEqual(gs._start_with(files, consumers)[0],
                         "**Start with**: [`rom0.bin`](#sha1-aaaaaaaaaaaa), [`rom1.bin`](#sha1-bbbbbbbbbbbb), "
                         "[`rom2.bin`](#sha1-cccccccccccc) and 5 more files. "
                         "They come first below.")

    def test_no_required_file_no_line(self):
        self.assertEqual(gs._start_with([_file("a.bin", "a")], _consumers({})), [])

    def test_the_page_carries_the_line_under_the_console(self):
        # Sega keeps its consoles as sections. Sony gives each a page.
        page = gs.generate_system_page("Sega", {"Saturn": self.files}, self.required_only())
        heading = page.index("## Saturn")
        self.assertLess(heading, page.index("**Start with**"))
        self.assertLess(page.index("**Start with**"), page.index('class="rb-sys-file"'))


class ThePermalinkIsAnIcon(unittest.TestCase):
    """The word "permalink" was link text inside every card title: the
    search showed "scph5501.bin permalink" and screen readers read it."""

    def test_no_word_and_out_of_the_search(self):
        lines = gs._system_file_card(_file("scph5501.bin", "4"), FileConsumers({"files": {}}))
        title = lines[2]
        link = re.search(r'<a class="rb-permalink"[^>]*>(.*?)</a>', title)
        self.assertNotIn("permalink", re.sub(r"<[^>]+>", "", title))
        self.assertIn('aria-label="Permanent link to scph5501.bin"', link[0])
        self.assertIn("data-pagefind-ignore", link[0])
        self.assertIn('<use href="#rb-link-icon"/>', link[1])

    def test_the_page_draws_the_icon_once(self):
        page = gs.generate_system_page(
            "Sega", {"Saturn": [_file("a.bin", "a"), _file("b.bin", "b")]},
            FileConsumers({"files": {}}))
        self.assertEqual(page.count('<symbol id="rb-link-icon"'), 1)
        self.assertEqual(page.count('href="#rb-link-icon"'), 2)


class TheCardLinesSayWhatTheyMean(unittest.TestCase):
    """"Platforms:" and "Also installed by:" listed different setups, as
    lower-case ids, and only a code comment told them apart."""

    def setUp(self):
        sha1 = "4" * 40
        self.consumers = types.SimpleNamespace(
            platforms={sha1: {"batocera"}}, emulators={},
            platform_systems={sha1: {"batocera": {"sony-playstation"}}},
            platform_destinations={sha1: {"batocera": {"scph5501.bin"}}},
            installed={sha1: {"retrobat": {"bios/scph5501.bin"}}},
        )
        self.lines = gs._system_file_card(_file("scph5501.bin", "4"), self.consumers)

    def test_labels_and_display_names(self):
        text = "\n".join(self.lines)
        # Grouped by where the setups put the file (round 4, 6.9).
        self.assertIn("<dt>On the setup's list</dt><dd><code>scph5501.bin</code>: <a href=\"../"
                      "platforms/batocera.md#sony-playstation\">Batocera</a></dd>", text)
        self.assertIn("<dt>Packed for its emulators by</dt><dd><code>bios/scph5501.bin</code>: "
                      "<a href=\"../platforms/retrobat.md\">RetroBat</a></dd>", text)
        self.assertNotIn("Platforms:", text)
        self.assertNotIn("Also installed by", text)

    def test_the_facts_are_out_of_the_search(self):
        # The setup list made every card's excerpt a run of names and
        # paths (round 4, V6): the card's title is what the search reads.
        # The facts shown open are one list, the others one fold, both
        # out of the search.
        shown = self.lines[:next(i for i, line in enumerate(self.lines) if line.startswith("<details"))]
        lists = [line for line in shown if line.startswith("<dl")]
        self.assertEqual(lists, ['<dl class="rb-facts" data-pagefind-ignore>'])
        folds = [line for line in self.lines if line.startswith("<details")]
        self.assertEqual(len(folds), 1)
        self.assertEqual(folds, ["<details data-pagefind-ignore>"])

    def test_the_page_defines_both_lines(self):
        page = gs.generate_system_page("Sega", {"Saturn": [_file("scph5501.bin", "4")]},
                                       self.consumers)
        key = page.index("**On the setup's list** names")
        self.assertLess(key, page.index('class="rb-sys-file"'))
        self.assertIn("**Packed for its emulators by** names", page)

    def test_a_file_nothing_reads_says_so(self):
        title = gs._system_file_card(_file("GameIndex.yaml", "9"), FileConsumers({"files": {}}))[2]
        self.assertIn(">No reader</span>", title)
        self.assertNotIn("No reader", self.lines[2])


class FileFactsAreAGrid(unittest.TestCase):
    """Each card was two bullet lists of code chips."""

    def test_one_value_cell_per_label_and_plain_hashes(self):
        entry = {**_file("scph5501.bin", "4"), "crc32": "8d8cb7e4",
                 "provenance": {"redump": {"name": "ps-30a.bin"},
                                "tosec": {"name": "SCPH-5501 (1996).bin"}}}
        lines = gs._system_file_card(entry, FileConsumers({"files": {}}))
        text = "\n".join(lines)
        # One value cell after each label, in the open list and in the fold.
        facts = re.findall(r"<dt>[^<]*</dt><dd[^>]*>.*?</dd>", text)
        self.assertTrue(facts)
        self.assertEqual(len(facts), text.count("<dt>"))
        self.assertEqual(text.count("<dt>"), len(re.findall(r"<dd[ >]", text)))
        # The hash is the cell's text, styled by the cell: no element around it.
        self.assertIn('<dt>SHA1</dt><dd class="rb-hash">' + "4" * 40 + "</dd>", text)
        self.assertNotIn("<code class=\"rb-hash\">", text)
        self.assertNotIn('<span class="rb-hash">', text)
        catalogued = next(fact for fact in facts if fact.startswith("<dt>Catalogued"))
        self.assertIn("<br>", catalogued)
        self.assertNotRegex(text, r"(?m)^- ")

    def test_collection_path_keeps_its_chip(self):
        text = "\n".join(gs._system_file_card(_file("a.bin", "a"), FileConsumers({"files": {}})))
        self.assertIn("<dt>Collection path</dt><dd><code>bios/Sony/PlayStation/a.bin</code>", text)


class ConsoleHeadingsStartWithTheName(unittest.TestCase):
    """The icon and a space came before the name: "Section titled
    “ PlayStation”" on five of seven Sony headings. Round 3 removed the
    icon altogether."""

    def test_no_icon_even_when_one_exists(self):
        icon = siterender._icon_name("Sony", "PlayStation")
        with mock.patch.dict(siterender._icon_available, {icon: True}):
            self.assertEqual(gs._console_heading("Sony", "PlayStation"),
                             "## PlayStation { #playstation }")

    def test_no_icon_no_image(self):
        icon = siterender._icon_name("Nobody", "Nothing")
        with mock.patch.dict(siterender._icon_available, {icon: False}):
            self.assertEqual(gs._console_heading("Nobody", "Nothing"), "## Nothing { #nothing }")


class TheSystemsIndexListsConsoles(unittest.TestCase):
    """The index listed 74 manufacturers and no console: PlayStation had to
    be known to be under Sony."""

    def test_one_row_per_console_by_its_name(self):
        gs.reset_console_pages()
        self.addCleanup(gs.reset_console_pages)
        groups = {
            "Sony": {"PlayStation": [_file("a.bin", "a")], "PlayStation 2": [_file("b.bin", "b")]},
            "Other": {"ScummVM": [_file("c.bin", "c")]},
            "Game Engines": {"TheXTech": [_file("d.png", "d")]},
        }
        page = gs.generate_systems_index(groups)
        self.assertIn("| [Sony PlayStation](sony.md#playstation) | 1 | [Sony](sony.md) |", page)
        self.assertIn("| [Sony PlayStation 2](sony.md#playstation-2) | 1 | [Sony](sony.md) |",
                      page)
        # A program's folder under Other is named alone, in its own table.
        consoles = page.split("## Emulator folders")[0]
        self.assertNotIn("ScummVM", consoles)
        self.assertIn("| [ScummVM](../emulators/scummvm.md) | [1 file](other.md#scummvm) |",
                      page.split("## Emulator folders")[1])
        self.assertNotIn("TheXTech", consoles)
        self.assertIn("| [TheXTech](game-engines.md#thextech)", page)

    def test_rows_go_by_name_not_by_maker(self):
        groups = {"Sega": {"Saturn": [_file("a.bin", "a")]},
                  "Atari": {"Lynx": [_file("b.bin", "b")]}}
        page = gs.generate_systems_index(groups)
        self.assertLess(page.index("Atari Lynx"), page.index("Sega Saturn"))


class FindAFileSaysWhatAHashIs(unittest.TestCase):

    def test_the_sentence_above_the_box(self):
        page = gs.generate_files_page()
        intro = page.split('<form class="rb-file-lookup"')[0]
        self.assertIn("A hash is a fingerprint of a file's contents", intro)
        self.assertIn("(../wiki/glossary.md)", intro)
        self.assertNotIn("**permalink**", page)


@unittest.skipUnless((DIST / "systems" / "sony" / "index.html").is_file(), "site not built")
class TheBuiltSonyPage(unittest.TestCase):

    def setUp(self):
        self.text = (DIST / "systems" / "sony" / "index.html").read_text(encoding="utf-8")

    def test_no_card_title_says_permalink(self):
        # Every Sony console has a page of its own: the cards are there.
        own = (DIST / "systems" / "sony-playstation" / "index.html").read_text(encoding="utf-8")
        titles = re.findall(r'<h3[^>]*class="rb-file-title".*?</h3>', own, re.S)
        self.assertTrue(titles)
        for title in titles:
            self.assertNotIn("permalink", re.sub(r"<[^>]+>", "", title))

    def test_playstation_opens_on_a_bios_it_needs(self):
        section = self.text.split('id="playstation"', 1)[1].split("<h2", 1)[0]
        # The opening line follows the profiles: "Start with" when most
        # emulators require the BIOS, "No file needed with ... Only ...
        # require" when most run without it. Either way it names a BIOS and
        # links it, before the first card.
        opening = section.split('class="rb-sys-file"', 1)[0]
        self.assertRegex(opening, r'<a href="[^"]+"><code[^>]*>scph\d+\.bin</code></a>')
        # PlayStation has a page of its own, and its files open there.
        own = (DIST / "systems" / "sony-playstation" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="/retrobios/systems/sony-playstation/"', section)
        first = re.search(r'class="rb-file-title"[^>]*><code[^>]*>(.*?)</code>', own)[1]
        self.assertNotIn(first, {"LibPS.exe", "PSX_DTLH2000.bin"})
        self.assertRegex(first, r"^scph\d+")

    def test_headings_have_no_leading_space(self):
        self.assertNotRegex(self.text, r'<h2 id="playstation[^"]*"><img[^>]*>\s')


if __name__ == "__main__":
    unittest.main()
