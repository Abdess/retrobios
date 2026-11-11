"""System pages, boards and file cards.

The Sony page opened on LibPS.exe, its card titles read "scph5501.bin
permalink" in the site search, the two setup lines of a card were defined
only in a code comment, and the systems index named no console.

The DS section opened on five DSi files, the Game Boy Advance line printed
BizHawk's file name where eight setups write another, the Neo Geo section
opened on a file one emulator reads, no arcade card said which release its
set matches, console headings carried an icon on 15 % of them, arcade boards
sat under "Consoles and computers", and every system page shared one card.

The Game Boy, NES and SNES sections said "Start with" a file one core of
sixteen requires, under a home page saying they need none. The romset line
said no MAME release matched sets MAME loads. The Neo Geo opened on files
ares alone reads, and RetroArch had no install line. The Arcade page was
sorted by storage folder: NAOMI, PGM and ZN-1 had no section, and their
names were plain on every emulator page. Cards named emulators by id, part
pages had no parent and no name, and four paragraphs came before the first
console.

NAOMI opened on hod2bios.zip, a set 13 of the 19 emulators listing it read
for one game. Lines read other names for one file as files to get: "Start
with: fdsbios.zip, disksys.rom". Twelve neogeo.zip were on five pages, the
SNK ones closed under Variants. The Atom, two MZ computers, a sound chip and
a toy had board pages, and the NAOMI and Atomiswave sets under the
Dreamcast folder stayed off their boards' pages. ScummVM's files were on
three pages, one section named ".variants". Board pages said their name
three times before the first file.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import types
import unittest
from pathlib import Path
from unittest import mock
import zipfile
import json

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import siterender  # noqa: E402
from cross_reference import FileConsumers  # noqa: E402
import make_og_cards  # noqa: E402
from sitestarlight import toc_slug  # noqa: E402


DIST = REPO_ROOT / "website" / "dist"


def _sony_file(name: str, char: str, path: str = "") -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 524288,
            "path": path or f"bios/Sony/PlayStation/{name}"}


def _one_reader_each(readers: dict[str, list[dict]], platforms: dict[str, set[str]] | None = None
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
            _sony_file("LibPS.exe", "1"), _sony_file("PSX_DTLH2000.bin", "2"),
            _sony_file("dtlh1100.bin", "3"), _sony_file("scph5501.bin", "4"),
            _sony_file("scph5500.bin", "5"), _sony_file("scph1001.bin", "6"),
            _sony_file("openbios.bin", "7"),
        ]
        self.consumers = _one_reader_each({
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
        return _one_reader_each({
            "4" * 40: [{"name": "scph5501.bin", "required": True, "priority": 2,
                        "region": ["north-america"]}],
            "5" * 40: [{"name": "scph5500.bin", "required": True, "priority": 5,
                        "region": ["japan"]}],
        })

    def test_the_section_opens_on_the_bios_by_region(self):
        lines = gs._start_with(self.files, self.required_only())
        self.assertEqual(lines[0], "**Start with** the BIOS for the region of the games:")
        self.assertIn("- **North America**: [`scph5501.bin`](#sha1-444444444444)", lines)
        self.assertIn("- **Japan**: [`scph5500.bin`](#sha1-555555555555)", lines)
        self.assertLess(lines.index("- **North America**: [`scph5501.bin`](#sha1-444444444444)"),
                        lines.index("- **Japan**: [`scph5500.bin`](#sha1-555555555555)"))

    def test_regions_needing_the_same_file_share_a_line(self):
        consumers = _one_reader_each({"4" * 40: [
            {"required": True, "region": ["north-america", "latin-america", "brazil"]}]})
        lines = gs._start_with([_sony_file("scph5501.bin", "4")], consumers)
        # Brazil says nothing Latin America does not.
        self.assertIn("- **North America, Latin America**: [`scph5501.bin`](#sha1-444444444444)", lines)

    def test_a_long_list_names_the_first_and_counts_the_rest(self):
        files = [_sony_file(f"rom{i}.bin", "abcdefgh"[i]) for i in range(8)]
        # One emulator requires all eight: files each required by another
        # emulator are other names for one slot.
        consumers = _one_reader_each({f["sha1"]: [{"required": True}] for f in files})
        consumers.emulator_files = {"emu": [{"required": True}] * len(files)}
        consumers.emulator_entries = {f["sha1"]: {"emu": i} for i, f in enumerate(files)}
        self.assertEqual(gs._start_with(files, consumers)[0],
                         "**Start with**: [`rom0.bin`](#sha1-aaaaaaaaaaaa), [`rom1.bin`](#sha1-bbbbbbbbbbbb), "
                         "[`rom2.bin`](#sha1-cccccccccccc) and 5 more files. "
                         "They come first below.")

    def test_no_required_file_no_line(self):
        self.assertEqual(gs._start_with([_sony_file("a.bin", "a")], _one_reader_each({})), [])

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
        lines = gs._system_file_card(_sony_file("scph5501.bin", "4"), FileConsumers({"files": {}}))
        title = lines[2]
        link = re.search(r'<a class="rb-permalink"[^>]*>(.*?)</a>', title)
        self.assertNotIn("permalink", re.sub(r"<[^>]+>", "", title))
        self.assertIn('aria-label="Permanent link to scph5501.bin"', link[0])
        self.assertIn("data-pagefind-ignore", link[0])
        self.assertIn('<use href="#rb-link-icon"/>', link[1])

    def test_the_page_draws_the_icon_once(self):
        page = gs.generate_system_page(
            "Sega", {"Saturn": [_sony_file("a.bin", "a"), _sony_file("b.bin", "b")]},
            FileConsumers({"files": {}}))
        self.assertEqual(page.count('<symbol id="rb-link-icon"'), 1)
        self.assertEqual(page.count('href="#rb-link-icon"'), 2)


class TheCardGivesTheSizeInBytes(unittest.TestCase):
    """The badge rounded to 0.1 KB and no line of a system card gave the
    bytes an emulator compares."""

    def test_the_badge_is_exact(self):
        for size, shown in ((524288, "512 KB"), (44348015, "44,348,015 B"),
                            (2 * 1024 * 1024, "2 MB"), (2304, "2,304 B"), (10, "10 B")):
            with self.subTest(size=size):
                card = {**_sony_file("scph5501.bin", "4"), "size": size}
                title = gs._system_file_card(card, FileConsumers({"files": {}}))[2]
                self.assertIn(f'<span class="rb-badge rb-badge-muted">{shown}</span>', title)


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
        self.lines = gs._system_file_card(_sony_file("scph5501.bin", "4"), self.consumers)

    def test_labels_and_display_names(self):
        text = "\n".join(self.lines)
        # Grouped by where the setups put the file.
        self.assertIn("<dt>On the setup's list</dt><dd><code>scph5501.bin</code>: <a href=\"../"
                      "platforms/batocera.md#sony-playstation\">Batocera</a></dd>", text)
        self.assertIn("<dt>Packed for its emulators by</dt><dd><code>bios/scph5501.bin</code>: "
                      "<a href=\"../platforms/retrobat.md\">RetroBat</a></dd>", text)
        self.assertNotIn("Platforms:", text)
        self.assertNotIn("Also installed by", text)

    def test_the_facts_are_out_of_the_search(self):
        # The setup list made every card's excerpt a run of names and
        # paths: the card's title is what the search reads.
        # The facts shown open are one list, the others one fold, both
        # out of the search.
        shown = self.lines[:next(i for i, line in enumerate(self.lines) if line.startswith("<details"))]
        lists = [line for line in shown if line.startswith("<dl")]
        self.assertEqual(lists, ['<dl class="rb-facts" data-pagefind-ignore>'])
        folds = [line for line in self.lines if line.startswith("<details")]
        self.assertEqual(len(folds), 1)
        self.assertEqual(folds, ["<details data-pagefind-ignore>"])

    def test_the_page_defines_both_lines(self):
        page = gs.generate_system_page("Sega", {"Saturn": [_sony_file("scph5501.bin", "4")]},
                                       self.consumers)
        key = page.index("**On the setup's list** names")
        self.assertLess(key, page.index('class="rb-sys-file"'))
        self.assertIn("**Packed for its emulators by** names", page)

    def test_a_file_nothing_reads_says_so(self):
        title = gs._system_file_card(_sony_file("GameIndex.yaml", "9"), FileConsumers({"files": {}}))[2]
        self.assertIn(">No reader</span>", title)
        self.assertNotIn("No reader", self.lines[2])


class FileFactsAreAGrid(unittest.TestCase):
    """Each card was two bullet lists of code chips."""

    def test_one_value_cell_per_label_and_plain_hashes(self):
        entry = {**_sony_file("scph5501.bin", "4"), "crc32": "8d8cb7e4",
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
        text = "\n".join(gs._system_file_card(_sony_file("a.bin", "a"), FileConsumers({"files": {}})))
        self.assertIn("<dt>Collection path</dt><dd><code>bios/Sony/PlayStation/a.bin</code>", text)


class ConsoleHeadingsStartWithTheName(unittest.TestCase):
    """The icon and a space came before the name: "Section titled
    “ PlayStation”" on five of seven Sony headings. The icon is gone
    altogether."""

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
            "Sony": {"PlayStation": [_sony_file("a.bin", "a")], "PlayStation 2": [_sony_file("b.bin", "b")]},
            "Other": {"ScummVM": [_sony_file("c.bin", "c")]},
            "Game Engines": {"TheXTech": [_sony_file("d.png", "d")]},
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
        groups = {"Sega": {"Saturn": [_sony_file("a.bin", "a")]},
                  "Atari": {"Lynx": [_sony_file("b.bin", "b")]}}
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


TMP = REPO_ROOT / "tmp"


def _file_at(name: str, char: str, path: str) -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 4096, "path": path}


def _consumers_with_db(
    readers: dict[str, list[tuple[str, dict]]],
    db_files: list[dict] = (),
    destinations: dict[str, dict[str, set[str]]] | None = None,
) -> types.SimpleNamespace:
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
        emulator_files=files_of, installed={}, platform_systems={},
        platform_destinations=destinations or {},
        _db={"files": {f["sha1"]: f for f in db_files}},
    )


DS = ("Nintendo", "Nintendo DS")


class TheSectionStartsWithItsOwnConsole(unittest.TestCase):
    """A file filed with the DS but read for the DSi is the DSi's."""

    def setUp(self) -> None:
        folder = "bios/Nintendo/Nintendo DS"
        self.files = [_file_at("NDS_Bios7.bin", "7", f"{folder}/NDS_Bios7.bin"),
                      _file_at("NDS_Bios9.bin", "9", f"{folder}/NDS_Bios9.bin"),
                      _file_at("dsi_bios7.bin", "d", f"{folder}/dsi_bios7.bin")]
        hle = {"required": False, "hle_fallback": True, "system": "nintendo-ds"}
        self.consumers = _consumers_with_db({
            "7" * 40: [("emu-a", {**hle, "name": "bios7.bin"}),
                       ("emu-b", {**hle, "name": "bios7.bin"})],
            "9" * 40: [("emu-a", {**hle, "name": "bios9.bin"})],
            "d" * 40: [("emu-a", {"name": "dsi_bios7.bin", "required": True,
                                  "system": "nintendo-dsi"})],
        })

    def test_no_dsi_file_on_the_ds_line(self) -> None:
        text = "\n".join(gs._start_with(self.files, self.consumers, section=DS))
        self.assertNotIn("dsi", text)

    def test_a_console_its_emulators_run_without_says_so(self) -> None:
        self.assertEqual(gs._start_with(self.files, self.consumers, section=DS), [
            "**No file needed** with emu-a or emu-b. For full accuracy: "
            "[`bios7.bin`](#sha1-777777777777), [`bios9.bin`](#sha1-999999999999).", ""])

    def test_the_dsi_section_names_its_file(self) -> None:
        lines = gs._start_with(self.files, self.consumers, section=("Nintendo", "Nintendo DSi"))
        self.assertEqual(lines, ["**Start with**: [`dsi_bios7.bin`](#sha1-dddddddddddd).", ""])

    def test_more_than_three_emulators_are_counted(self) -> None:
        hle = {"required": False, "hle_fallback": True, "system": "nintendo-ds"}
        consumers = _consumers_with_db({"7" * 40: [(f"emu-{n}", hle) for n in "abcd"]})
        self.assertEqual(gs._start_with(self.files[:1], consumers, section=DS)[0],
                         "**No file needed**: none of its 4 emulators requires one. "
                         "For full accuracy: [`NDS_Bios7.bin`](#sha1-777777777777).")

    def test_a_shipped_file_is_no_start(self) -> None:
        consumers = _consumers_with_db({"7" * 40: [("emu-a", {"required": True, "bundled": True,
                                                      "system": "nintendo-ds"})]})
        self.assertEqual(gs._start_with(self.files[:1], consumers, section=DS), [])


class TheNameSetupsWrite(unittest.TestCase):
    def test_most_setups_win_over_the_collection_name(self) -> None:
        f = _file_at("GBA_bios.rom", "a", "bios/Nintendo/Game Boy Advance/GBA_bios.rom")
        consumers = _consumers_with_db(
            {"a" * 40: [("emu-a", {"name": "GBA_bios.rom", "required": True,
                                   "system": "nintendo-gba"})]},
            destinations={"a" * 40: {"p1": {"gba_bios.bin"}, "p2": {"bios/gba_bios.bin"},
                                     "p3": {"GBA_bios.rom"}}})
        self.assertEqual(gs._start_with([f], consumers, section=("Nintendo", "Game Boy Advance")),
                         ["**Start with**: [`gba_bios.bin`](#sha1-aaaaaaaaaaaa).", ""])

    def test_no_setup_then_the_emulators_name(self) -> None:
        f = _file_at("x.rom", "b", "bios/Nintendo/Game Boy Advance/x.rom")
        consumers = _consumers_with_db({"b" * 40: [("emu-a", {"name": "gba_bios.bin", "required": True})]})
        self.assertEqual(gs._setup_name(f, consumers, [("emu-a", {"name": "gba_bios.bin"})]),
                         "gba_bios.bin")


class ArcadeSetsAreNamedWhereverFiled(unittest.TestCase):
    """The Neo Geo BIOS is under Arcade: the Neo Geo section named
    aes.zip, read by one emulator, and never neogeo.zip."""

    def setUp(self) -> None:
        self.aes = _file_at("aes.zip", "1", "bios/SNK/Neo Geo/aes.zip")
        neogeo = _file_at("neogeo.zip", "2", "bios/Arcade/Arcade/neogeo.zip")
        mega_cd = _file_at("bios_CD_U.bin", "3", "bios/Sega/Mega CD/bios_CD_U.bin")
        shader = _file_at("tfx.glsl", "4", "bios/Other/emu/tfx.glsl")
        mvs = {"required": True, "system": "snk-neogeo-mvs"}
        self.consumers = _consumers_with_db({
            "1" * 40: [("geolith", {"name": "aes.zip", "required": True,
                                    "system": "snk-neogeo-aes"})],
            "2" * 40: [(f"mame{n}", {**mvs, "name": "neogeo.zip"}) for n in range(3)],
            "3" * 40: [("bizhawk", {"name": "bios_CD_U.bin", "required": True,
                                    "system": "snk-neogeo-mvs"})],
            "4" * 40: [("emu", {"name": "tfx.glsl", "required": True,
                                "system": "snk-neogeo-mvs"})],
        }, db_files=[self.aes, neogeo, mega_cd, shader])

    def test_the_file_most_emulators_read_leads_and_the_arcade_set_is_linked(self) -> None:
        lines = gs._start_with([self.aes], self.consumers, section=("SNK", "Neo Geo"))
        link = f"[`neogeo.zip`](/retrobios/files/?sha1={'2' * 40})"
        self.assertEqual(lines[0], f"**Start with** {link}. Keep it zipped. "
                                   "mame0, mame1 and mame2 read it.")
        self.assertIn("Geolith reads [`aes.zip`](#sha1-111111111111) instead.", lines)

    def test_another_consoles_file_or_an_emulators_folder_is_left_out(self) -> None:
        text = "\n".join(gs._start_with([self.aes], self.consumers, section=("SNK", "Neo Geo")))
        self.assertNotIn("bios_CD_U.bin", text)
        self.assertNotIn("tfx.glsl", text)

    def test_the_card_read_by_most_emulators_comes_first(self) -> None:
        one = _file_at("aes.zip", "1", "bios/SNK/Neo Geo/aes.zip")
        many = _file_at("sp-s3.sp1", "5", "bios/SNK/Neo Geo/sp-s3.sp1")
        consumers = _consumers_with_db({
            "1" * 40: [("geolith", {"required": True})],
            "5" * 40: [(f"emu{n}", {"required": True}) for n in range(3)],
        })
        cards = gs._console_cards("SNK", [one, many], consumers, set())
        self.assertIn("sp-s3.sp1", cards[0][1][2])

    def test_a_long_list_names_the_first_files(self) -> None:
        files = [_file_at(f"rom{i}.bin", "abcdefgh"[i], f"bios/SNK/Neo Geo/rom{i}.bin")
                 for i in range(8)]
        consumers = _consumers_with_db({f["sha1"]: [("emu", {"required": True})] for f in files})
        self.assertEqual(gs._start_with(files, consumers, first_below=False)[0],
                         "**Start with**: [`rom0.bin`](#sha1-aaaaaaaaaaaa), [`rom1.bin`](#sha1-bbbbbbbbbbbb), "
                         "[`rom2.bin`](#sha1-cccccccccccc) and 5 more files.")


class CardsSayWhichReleaseTheSetMatches(unittest.TestCase):
    def setUp(self) -> None:
        TMP.mkdir(exist_ok=True)
        self.path = TMP / "r3_systems_set.zip"
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("sp-s2.sp1", b"bios")
        crc = f"{zipfile.ZipFile(self.path).infolist()[0].CRC:08x}"
        self.releases = {"set.zip": [
            ((("sp-s2.sp1", crc),), "mame", [(0, "0.190"), (1, "0.195"), (4, "0.220")]),
            ((("sp-s2.sp1", crc),), "fbneo", [(2, "1.0.0.03"), (7, "1.0.0.03")]),
            ((("other.bin", "00000000"),), "mame", [(9, "0.289")]),
        ]}

    def tearDown(self) -> None:
        self.path.unlink(missing_ok=True)

    def card(self) -> str:
        f = {"name": "set.zip", "sha1": "e" * 40, "md5": "e" * 32, "size": 4,
             "path": str(self.path)}
        with mock.patch.object(gs, "_romset_releases", return_value=self.releases):
            return "\n".join(gs._system_file_card(f, _consumers_with_db({})))

    def test_the_matching_releases_as_runs(self) -> None:
        self.assertIn("<dt>Romset</dt><dd>Same contents as MAME 0.190 to 0.195, 0.220 and "
                      "FBNeo 1.0.0.03</dd>", self.card())

    def test_no_match_counts_what_is_missing(self) -> None:
        self.releases["set.zip"] = self.releases["set.zip"][2:]
        self.assertIn("<dd>No match: missing 1 ROM of MAME 0.289</dd>", self.card())

    def test_no_recipe_no_line(self) -> None:
        self.releases = {}
        self.assertNotIn("Romset", self.card())

    def test_the_snapshots_cover_mame_and_fbneo(self) -> None:
        coverage = gs._romset_coverage()
        self.assertRegex(coverage, r"^MAME 0\.\d+ to 0\.\d+ or FBNeo [\d.]+$")

    def test_a_page_of_sets_links_the_version_answer(self) -> None:
        f = {"name": "set.zip", "sha1": "e" * 40, "path": "bios/SNK/Neo Geo/set.zip"}
        with mock.patch.object(gs, "_romset_releases", return_value=self.releases):
            page = gs.generate_system_page("SNK", {"Neo Geo": [f]}, _consumers_with_db({}))
        self.assertIn("MAME and FBNeo sets must match the emulator's version. [Which version "
                      f"each core reads]({gs.ROMSET_FAQ}).", page)
        anchor = gs.ROMSET_FAQ.split("#")[1]
        faq = (REPO_ROOT / "wiki" / "technical-faq.md").read_text(encoding="utf-8")
        self.assertIn("## Which MAME version do the arcade BIOS sets match?", faq)
        self.assertEqual(anchor, "which-mame-version-do-the-arcade-bios-sets-match")


class ArcadeIsItsOwnGroup(unittest.TestCase):
    def test_arcade_rows_under_arcade(self) -> None:
        f = {"name": "a.bin", "sha1": "a" * 40, "path": "bios/x/a.bin"}
        index = gs.generate_systems_index({"Arcade": {"MAME": [f]}, "Sony": {"PlayStation": [f]}})
        arcade = index.index("## Arcade")
        self.assertLess(index.index("## Consoles and computers"), arcade)
        self.assertGreater(index.index("[MAME]"), arcade)
        self.assertLess(index.index("[Sony PlayStation]"), arcade)


class EachManufacturerHasItsCard(unittest.TestCase):
    def test_a_tagline_holds_three_lines_and_counts_the_rest(self) -> None:
        names = [f"Console number {n}" for n in range(40)]
        text = make_og_cards.consoles_tagline(names)
        self.assertRegex(text, r" and \d+ more$")
        lines = make_og_cards.wrap(text, make_og_cards.TAGLINE_WIDTH, make_og_cards.TAGLINE_SIZE)
        self.assertLessEqual(len(lines), make_og_cards.TAGLINE_LINES)
        self.assertEqual(make_og_cards.consoles_tagline(["Saturn", "Dreamcast"]),
                         "BIOS files for Dreamcast and Saturn")

    def test_every_manufacturer_page_has_a_committed_card(self) -> None:
        cards = make_og_cards.system_cards()
        missing = [key for key in cards
                   if not (REPO_ROOT / "docs_assets" / "og" / f"{key}.png").is_file()]
        self.assertEqual(missing, [], "run python scripts/make_og_cards.py --only systems")
        # A card left behind by a page that went: oric.png outlived its page.
        committed = (REPO_ROOT / "docs_assets" / "og" / "systems").glob("*.png")
        stale = sorted(f"systems/{path.stem}" for path in committed
                       if f"systems/{path.stem}" not in cards)
        self.assertEqual(stale, [])


@unittest.skipUnless((DIST / "systems" / "nintendo" / "index.html").is_file(), "site not built")
class TheBuiltSystemPages(unittest.TestCase):
    def test_no_console_heading_carries_an_icon(self) -> None:
        with_icon = [path.relative_to(DIST).as_posix() for path in DIST.glob("systems/**/index.html")
                     if re.search(r"<h2[^>]*>(?:(?!</h2>).)*<img", path.read_text(encoding="utf-8"), re.S)]
        self.assertEqual(with_icon, [])

    def test_the_ds_section_names_no_dsi_file(self) -> None:
        page = (DIST / "systems" / "nintendo" / "index.html").read_text(encoding="utf-8")
        start = page.index('id="nintendo-ds"')
        section = page[start:page.index('id="nintendo-dsi"')]
        # The section may have moved to a page of its own: no card follows.
        opening = section.split('class="rb-sys-file"')[0]
        self.assertRegex(opening, r"No file needed|Start with")
        self.assertNotRegex(opening.casefold(), r"dsi_|bios7i|bios9i")

    def test_the_gba_line_prints_the_setups_name(self) -> None:
        page = (DIST / "systems" / "nintendo" / "index.html").read_text(encoding="utf-8")
        section = page[page.index('id="game-boy-advance"'):page.index('id="game-boy-color"')]
        self.assertRegex(section[:section.index("class=\"rb-sys-file\"")], r"<code[^>]*>gba_bios.bin</code>")

    def test_the_neo_geo_section_opens_on_the_neo_geo_bios(self) -> None:
        page = (DIST / "systems" / "snk" / "index.html").read_text(encoding="utf-8")
        section = page[page.index('id="neo-geo"'):]
        opening = section[:section.index('class="rb-sys-file"')]
        self.assertRegex(opening, r"<code[^>]*>neogeo.zip</code>")
        self.assertIn("Which version each core reads", page)

    def test_the_nintendo_summary_holds_its_budget(self) -> None:
        size = (DIST / "systems" / "nintendo" / "index.html").stat().st_size
        self.assertLess(size, 540_000)


class InstallBoxesCountTowardTheSummary(unittest.TestCase):
    """Ten install boxes were 295 KB of the 583 KB Nintendo page: the
    weights that keep a section on its maker's summary counted cards only,
    and the page passed its 600 KB budget once the DS files were refiled."""

    def setUp(self) -> None:
        import siterender

        siterender.reset_console_pages()
        self.addCleanup(siterender.reset_console_pages)
        self.consoles = {
            name: [_file_at(f"{name}{i}.bin", "0123456789"[index * 3 + i],
                         f"bios/Maker/{name}/{name}{i}.bin") for i in range(3)]
            for index, name in enumerate(("Boxed", "Heavy", "Light"))
        }

    def pages(self, box: int) -> dict:
        def install(console: str, _declared: list) -> list[str]:
            return ["x" * box] if console == "Boxed" else []

        with mock.patch.object(gs, "_console_install_block", side_effect=install), \
                mock.patch.object(gs, "SYSTEM_SUMMARY_HTML", 50_000):
            return gs.system_pages("Maker", self.consoles, _consumers_with_db({}), budget=30_000)

    def test_a_section_with_a_heavy_install_box_moves(self) -> None:
        pages = self.pages(20_000)
        self.assertIn("maker-boxed", pages)
        self.assertNotIn("maker-light", pages)

    def test_a_light_install_box_stays(self) -> None:
        self.assertEqual(list(self.pages(10)), ["maker"])


CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"


def _unlinked(text: str) -> str:
    """A start line's wording: each file it names links to its card."""
    return re.sub(r"\[(`[^`]*`)\]\([^)]*\)", r"\1", text)


def _game_boy_file(name: str, char: str, path: str = "") -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 4096,
            "path": path or f"bios/Nintendo/Game Boy/{name}"}


def _consumers_by_system(readers: dict[str, list[tuple[str, dict]]],
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


def _built_page(path: Path) -> str:
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
        boot = _game_boy_file("dmg_boot.bin", "1")
        optional = {"required": False, "system": "nintendo-gb"}
        consumers = _consumers_by_system({"1" * 40: [
            ("emux_gb", {"name": "dmg_boot.bin", "required": True}),
            ("gambatte", optional), ("mgba", optional), ("sameboy", optional)]})
        line = _unlinked(gs._start_with([boot], consumers)[0])
        self.assertTrue(line.startswith("**No file needed** with "), line)
        self.assertRegex(line, r"Only \S.* requires `dmg_boot.bin`\.$")

    def test_most_requiring_keeps_the_start_line(self) -> None:
        bios = _game_boy_file("scph5501.bin", "2")
        required = {"name": "scph5501.bin", "required": True}
        consumers = _consumers_by_system({"2" * 40: [
            ("a", required), ("b", required), ("c", {"required": False, "hle_fallback": True})]})
        self.assertEqual(_unlinked(gs._start_with([bios], consumers)[0]), "**Start with**: `scph5501.bin`.")

    def test_an_entry_read_for_a_system_with_no_section_is_dropped(self) -> None:
        sample = _game_boy_file("ym2608_adpcm_rom.bin", "3", "bios/Nintendo/NES/ym2608_adpcm_rom.bin")
        consumers = _consumers_by_system({"3" * 40: [
            ("fbneo", {"name": "ym2608_adpcm_rom.bin", "required": True,
                       "system": "no-such-system-anywhere"})]})
        self.assertEqual(gs._start_with([sample], consumers, section=("Nintendo", "NES")), [])

    def test_the_home_usually_not_consoles_open_on_no_file_needed(self) -> None:
        home = _built_page(DIST / "index.html")
        match = re.search(r"<strong>Usually not</strong> for ([^<.]+)", home)
        self.assertIsNotNone(match, "the home page no longer says Usually not")
        names = re.split(r", | and ", match[1])
        sections = {"NES": ("nintendo", "nes"), "Super Nintendo": ("nintendo", "snes"),
                    "Mega Drive": ("sega", "mega-drive"), "Game Boy": ("nintendo", "game-boy"),
                    "Game Boy Advance": ("nintendo", "game-boy-advance")}
        for name in names:
            self.assertIn(name, sections, f"map {name!r} to its section")
            page, anchor = sections[name]
            html = _built_page(DIST / "systems" / page / "index.html")
            self.assertTrue(_opening(html, anchor).startswith("No file needed"), name)


class TheRomsetLineMatchesByCrc(unittest.TestCase):
    """6.2: a set with an extra BIOS revision read "No match"."""

    def test_the_main_neogeo_set_names_every_mame_release(self) -> None:
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        main = next((f for sha1, f in db["files"].items() if sha1.startswith("447e2375")), None)
        if main is None or not (REPO_ROOT / main["path"]).is_file():
            self.skipTest("the main neogeo.zip is not in this checkout")
        line = gs._romset_line(main)
        self.assertIn("Holds every ROM of MAME 0.177 to 0.289", line)
        self.assertNotIn("No match", line)


class TheNeoGeoOpensOnItsSet(unittest.TestCase):
    """6.3: the set 26 emulators read leads, RetroArch gets its command."""

    def test_the_lead_names_the_exceptions(self) -> None:
        neogeo = _game_boy_file("neogeo.zip", "4", "bios/SNK/Neo Geo/neogeo.zip")
        epo = _game_boy_file("neo-epo.sp1", "5", "bios/SNK/Neo Geo/neo-epo.sp1")
        mvs = {"name": "neogeo.zip", "required": True, "system": "snk-neogeo-mvs"}
        consumers = _consumers_by_system({
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
        consumers = _consumers_by_system({}, systems={"a" * 40: {"retroarch": {"arcade"}}})
        pairs = gs._install_pairs([("batocera", "snk-neogeo")], "a" * 40, consumers)
        self.assertIn(("retroarch", "arcade"), pairs)
        block = "\n".join(gs._console_install_block("Neo Geo", pairs))
        self.assertIn("<li>RetroArch: <code", block)
        self.assertIn("--platform retroarch --system arcade</code>", block)

    def test_the_built_section(self) -> None:
        html = _built_page(DIST / "systems" / "snk" / "index.html")
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
            html = _built_page(DIST / "systems" / f"arcade-{slug}" / "index.html")
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
        md = _built_page(CONTENT / "systems" / "arcade.md")
        headings = re.findall(r"^## (.+?) \{", md, re.M)
        self.assertIn("Sega NAOMI", headings)
        self.assertLess(headings.index("Sega NAOMI"), headings.index(gs.OTHER_ARCADE_LABEL))


class CardsNameEmulatorsByName(unittest.TestCase):
    """6.6: 19,499 card links read the profile id."""

    def test_the_display_name_is_the_link_text(self) -> None:
        sha1 = "6" * 40
        consumers = _consumers_by_system({sha1: [("melonds_ds", {"name": "bios7.bin"})]})
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
        files = [_game_boy_file(f"rom{i:02}.bin", "0123456789"[i], f"bios/Sony/PlayStation 2/rom{i:02}.bin")
                 for i in range(10)]
        consumers = _consumers_by_system({})
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
            page = gs.system_pages(maker, {"dolphin": [_game_boy_file("a.bin", "a")]}, _consumers_by_system({}))
            self.assertEqual(_consoles(page[gs._slug(maker)][0]), [], maker)

    def test_a_console_with_its_own_page_is_left_to_it(self) -> None:
        big = [_game_boy_file(f"r{i:02}.bin", "0123456789"[i], f"bios/Sega/Saturn/r{i:02}.bin")
               for i in range(10)]
        small = [_game_boy_file("pico.bin", "p", "bios/Sega/Pico/pico.bin")]
        consumers = _consumers_by_system({})
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
        page = gs.generate_system_page("SNK", {"Neo Geo": [_game_boy_file("a.bin", "a")]}, _consumers_by_system({}))
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


SYSTEMS = CONTENT / "systems"


def _naomi_file(name: str, char: str, path: str = "") -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 4096,
            "path": path or f"bios/Sega/NAOMI/{name}"}


def _consumers(reads: dict[str, list[tuple[str, dict]]]) -> types.SimpleNamespace:
    """Consumers where each sha1 is read by (emulator, entry) pairs, an
    emulator's entries kept in one list as a profile keeps them."""
    files_of: dict[str, list] = {}
    entries: dict[str, dict[str, int]] = {}
    emulators: dict[str, set[str]] = {}
    for sha1, read_by in reads.items():
        for emulator, entry in read_by:
            files_of.setdefault(emulator, []).append(entry)
            entries.setdefault(sha1, {})[emulator] = len(files_of[emulator]) - 1
            emulators.setdefault(sha1, set()).add(emulator)
    return types.SimpleNamespace(
        platforms={}, emulators=emulators, emulator_entries=entries,
        emulator_files=files_of, installed={}, platform_systems={},
        platform_destinations={}, _db={"files": {}},
    )


def _pages(pattern: str) -> list[Path]:
    """The generated pages a stem pattern names: a page with tabs is MDX.
    Reading .md alone skipped eleven tests in silence once the SNK, Sega
    and Nintendo pages had tabs."""
    return sorted(SYSTEMS.glob(f"{pattern}.md")) + sorted(SYSTEMS.glob(f"{pattern}.mdx"))


def _system_page(stem: str) -> str:
    found = _pages(stem)
    if not found:
        raise unittest.SkipTest(f"systems/{stem}.md not generated")
    return _unlinked(found[0].read_text(encoding="utf-8"))


def _start_line(text: str) -> str:
    match = re.search(r"^\*\*(Start with|No file needed)\*\*.*$", text, re.M)
    return match[0] if match else ""


def _database() -> dict:
    path = REPO_ROOT / "database.json"
    if not path.is_file():
        raise unittest.SkipTest("database.json is not built")
    return json.loads(path.read_text(encoding="utf-8"))


class AStartFileIsNoOnesExtra(unittest.TestCase):
    """6.1: a file most of whose readers take beside another one is no
    start file, whoever requires it."""

    def test_the_board_opens_on_its_bios_alone(self) -> None:
        naomi, hod2 = _naomi_file("naomi.zip", "1"), _naomi_file("hod2bios.zip", "2")
        both = [(f"flycast{n}", {"name": "hod2bios.zip", "required": True}) for n in range(2)]
        extra = [(f"mame{n}", {"name": "hod2bios.zip", "required": False}) for n in range(3)]
        consumers = _consumers({
            "1" * 40: [(e, {"name": "naomi.zip", "required": True}) for e, _ in both + extra],
            "2" * 40: both + extra,
        })
        self.assertEqual([_unlinked(line) for line in gs._start_with([naomi, hod2], consumers)],
                         ["**Start with**: `naomi.zip`.", ""])

    def test_the_naomi_page_opens_on_naomi_zip(self) -> None:
        self.assertEqual(_start_line(_system_page("arcade-sega-naomi")), "**Start with**: `naomi.zip`.")

    def test_a_file_several_require_beside_the_lead_stays(self) -> None:
        bios7, bios9 = _naomi_file("bios7.bin", "3"), _naomi_file("bios9.bin", "4")
        consumers = _consumers({
            "3" * 40: [(e, {"name": "bios7.bin", "required": True}) for e in ("a", "b")],
            "4" * 40: [(e, {"name": "bios9.bin", "required": True}) for e in ("a", "b")],
        })
        self.assertEqual(_unlinked(gs._start_with([bios7, bios9], consumers)[0]),
                         "**Start with**: `bios7.bin`, `bios9.bin`.")

    def test_some_files_each_is_not_every_file_for_one(self) -> None:
        """The SNES said bsnes and four more require 22 files."""
        files = [_naomi_file(f"chip{n}.rom", str(n)) for n in range(1, 4)]
        reads = {f["sha1"]: [(f"free{k}", {"name": f["name"], "required": False,
                                           "hle_fallback": True}) for k in range(5)]
                 for f in files}
        reads["1" * 40].append(("bsnes", {"name": "chip1.rom", "required": True}))
        reads["2" * 40].append(("jgenesis", {"name": "chip2.rom", "required": True}))
        reads["3" * 40].append(("jgenesis", {"name": "chip3.rom", "required": True}))
        line = gs._start_with(files, _consumers(reads))[0]
        self.assertIn("require some of these files: ", line)


class OtherNamesForOneSlotReadAsAlternatives(unittest.TestCase):
    """6.2: "Start with: fdsbios.zip, disksys.rom" read as two files."""

    def test_the_other_name_is_read_instead(self) -> None:
        disk, fds = _naomi_file("disksys.rom", "5"), _naomi_file("fdsbios.zip", "6")
        consumers = _consumers({
            "5" * 40: [(e, {"name": "disksys.rom", "required": True})
                       for e in ("mesen", "nestopia", "fceumm")],
            "6" * 40: [("fbneo", {"name": "fdsbios.zip", "required": True})],
        })
        self.assertEqual(_unlinked(gs._start_with([disk, fds], consumers)[0]),
                         "**Start with**: `disksys.rom`. FinalBurn Neo reads `fdsbios.zip` instead.")

    def test_a_card_read_under_another_name_says_both(self) -> None:
        disk, card = _naomi_file("disksys.rom", "5"), _naomi_file("long name (1986).bin", "7")
        consumers = _consumers({
            "5" * 40: [(e, {"name": "disksys.rom", "required": True}) for e in ("a", "b")],
            "7" * 40: [("c", {"name": "short.rom", "required": True})],
        })
        self.assertIn("reads `long name (1986).bin` (as `short.rom`) instead.",
                      _unlinked(gs._start_with([disk, card], consumers)[0]))

    def test_a_regional_line_names_one_file_per_reader(self) -> None:
        mega_cd = _system_page("sega").split("{ #mega-cd }", 1)[1].split("\n## ", 1)[0]
        regions = [line for line in mega_cd.splitlines() if line.startswith("- **")]
        self.assertTrue(regions)
        for line in regions:
            lead = line.split(". ", 1)[0]
            self.assertEqual(len(re.findall(r"`[^`]+`", lead)), 1, line)

    def test_the_fds_line(self) -> None:
        fds = _system_page("nintendo").split("{ #famicom-disk-system }", 1)[1]
        self.assertRegex(_start_line(fds), r"^\*\*Start with\*\*: `disksys.rom`\. FinalBurn Neo "
                                           r"reads \[?`fdsbios.zip`.* instead\.$")


class TheNeoGeoSetsSitWithTheNeoGeo(unittest.TestCase):
    """6.3: every neogeo.zip has its card on SNK's pages, side by side and
    open, and ares is among the readers of the set."""

    def test_every_neogeo_zip_is_on_snk(self) -> None:
        db = _database()
        sha1s = [sha1 for sha1, f in db["files"].items() if f["name"] == "neogeo.zip"]
        held = "".join(path.read_text(encoding="utf-8") for path in _pages("snk*"))
        if not held:
            self.skipTest("SNK pages not generated")
        self.assertEqual([s for s in sha1s if f'id="sha1-{s[:12]}"' not in held], [])
        others = "".join(path.read_text(encoding="utf-8")
                         for path in _pages("arcade*"))
        self.assertEqual([s for s in sha1s if f'id="sha1-{s[:12]}"' in others], [])

    def test_the_sets_are_open_and_together(self) -> None:
        section = _system_page("snk").split("{ #neo-geo }", 1)[1].split("\n## ", 1)[0]
        titles = re.findall(r'class="rb-file-title"[^>]*><code>([^<]+)</code>', section)
        sets = [n for n, name in enumerate(titles) if name == "neogeo.zip"]
        self.assertGreater(len(sets), 1)
        self.assertEqual(sets, list(range(len(sets))))
        variants = section.split("Variants (", 1)[1] if "Variants (" in section else ""
        self.assertNotIn("<code>neogeo.zip</code>", variants)

    def test_ares_is_told_the_card_it_reads(self) -> None:
        # ares reads neogeo.zip for an MVS game (desktop-ui/emulator/arcade.cpp:456-464):
        # the lead names it among its readers, with no sentence of its own.
        start = _system_page("snk").split("{ #neo-geo }", 1)[1]
        self.assertRegex(_start_line(start), r"^\*\*Start with\*\* `neogeo.zip`\..* ares and .* read it\.$")
        self.assertNotIn("ares reads", start.split("\n## ", 1)[0])


class ABoardIsAnArcadeMachine(unittest.TestCase):
    """6.4: computers, a sound chip and a toy had board pages."""

    def test_no_board_has_a_parent_outside_arcade(self) -> None:
        wrong = sorted(board for board in siterender.arcade_boards()
                       if board in siterender.SYSTEM_PARENTS)
        self.assertEqual(wrong, [])

    def test_no_board_page_for_a_machine_filed_elsewhere(self) -> None:
        if not SYSTEMS.is_dir():
            self.skipTest("pages not generated")
        for stem in ("arcade-acorn-atom", "arcade-sharp-mz-2000", "arcade-sharp-mz-2500",
                     "arcade-yamaha-ym2608", "arcade-miuchiz"):
            self.assertEqual(_pages(stem), [], stem)

    def test_the_computers_sets_are_on_their_makers_page(self) -> None:
        acorn = _system_page("acorn")
        self.assertIn("{ #atom }", acorn)
        self.assertIn("<code>atom_gdos.zip</code>", acorn)
        cards = re.findall(r'class="rb-file-title"[^>]*><code>([^<]+)</code>', _system_page("sharp"))
        self.assertEqual(cards.count("mz2000.zip"), 2)


class TheDreamcastBoardsAreFiledByBoard(unittest.TestCase):
    """6.5: the NAOMI and Atomiswave sets under the Dreamcast folder."""

    def test_the_board_sets_left_the_dreamcast(self) -> None:
        sega = _system_page("sega")
        dreamcast = sega.split("{ #dreamcast }", 1)[1].split("\n## ", 1)[0]
        for name in ("naomi.zip", "awbios.zip", "naomi2.zip"):
            self.assertNotIn(f"<code>{name}</code>", dreamcast)
        self.assertIn("(/retrobios/systems/arcade-sega-naomi/)", dreamcast)
        self.assertIn("(/retrobios/systems/arcade-sammy-atomiswave/)", dreamcast)

    def test_every_naomi_set_is_on_its_board(self) -> None:
        db = _database()
        page = _system_page("arcade-sega-naomi")
        missing = [sha1 for sha1, f in db["files"].items()
                   if f["name"] == "naomi.zip" and f'id="sha1-{sha1[:12]}"' not in page]
        self.assertEqual(missing, [])

    def test_the_dreamcast_arcade_id_leads_to_naomi(self) -> None:
        siterender.reset_console_pages()
        for board in siterender.arcade_boards():
            siterender.record_board_section(board)
        try:
            self.assertEqual(siterender.system_section("sega-dreamcast-arcade"),
                             ("arcade", "Sega NAOMI"))
        finally:
            siterender.reset_console_pages()


class EnginesGoByEngine(unittest.TestCase):
    """6.6: no section named after a folder of variants or a file."""

    def test_no_section_or_row_is_a_folder_or_a_file(self) -> None:
        db = _database()
        names = set(db["indexes"]["by_name"])
        index = _system_page("index")
        rows = re.findall(r"^\| \[([^\]]+)\]\(", index, re.M)
        headings = [h.strip() for path in _pages("*")
                    for h in re.findall(r"^## ([^{\n]+)", path.read_text(encoding="utf-8"), re.M)]
        wrong = sorted({n for n in rows + headings if n.startswith(".") or n in names})
        self.assertEqual(wrong, [])

    def test_scummvm_has_one_page(self) -> None:
        self.assertEqual(_pages("other-scummvm"), [])
        self.assertIn("## ScummVM {", _system_page("scummvm"))
        self.assertNotIn("](/retrobios/systems/other/#scummvm)", _system_page("index"))

    def test_a_folder_named_by_a_profile_key_reads_the_engine(self) -> None:
        index = _system_page("index")
        self.assertIn("| [EasyRPG Player](/retrobios/systems/rpg-maker/#easyrpg) |", index)
        self.assertIn("| [SDLPAL](", index)

    def test_moved_pages_redirect(self) -> None:
        if not SYSTEMS.is_dir():
            self.skipTest("pages not generated")
        for old, target in gs.SYSTEM_PAGES_MOVED.items():
            new = target.partition("#")[0]
            written = [path for path in (CONTENT / old, (CONTENT / old).with_suffix(".mdx"))
                       if path.exists()]
            # A maker's page split by console again (Sega past its budget)
            # writes the old address as one of its parts: the redirect then
            # stands aside, and the page names the one it moved to as parent.
            for path in written:
                parent = re.search(r"^parent:\n  label: .*\n  link: (\S+)$",
                                   path.read_text(encoding="utf-8"), re.M)
                self.assertIsNotNone(parent, old)
                self.assertEqual(parent.group(1), "/" + new.removesuffix(".md") + "/", old)
            # A page with tabs is written as MDX.
            self.assertTrue((CONTENT / new).exists() or (CONTENT / new).with_suffix(".mdx").exists(), new)
        redirects = CONTENT.parents[1] / "generated" / "redirects.json"
        if redirects.is_file():
            table = json.loads(redirects.read_text(encoding="utf-8"))
            self.assertEqual(table.get("/systems/other-scummvm/"), "/systems/scummvm/")
            self.assertEqual(table.get("/systems/oric/"), "/systems/tangerine/#oric")


class OneLabelOnceOnABoardPage(unittest.TestCase):
    """6.7, 6.8, 6.9, 6.10: the words a board or part page repeats."""

    def test_a_label_naming_files_installs_these_files(self) -> None:
        block = "\n".join(gs._console_install_block("Other arcade files", [("mame", "arcade")]))
        self.assertIn("<summary>Install these files</summary>", block)
        block = "\n".join(gs._console_install_block("Sega NAOMI", [("mame", "arcade")]))
        self.assertIn("<summary>Install the files of Sega NAOMI</summary>", block)

    def test_a_board_page_has_no_heading_of_its_name(self) -> None:
        page = _system_page("arcade-sega-naomi")
        self.assertNotRegex(page, r"^## Sega NAOMI", )
        self.assertNotIn("](/retrobios/systems/arcade-sega-naomi/#sega-naomi)",
                         _system_page("index"))

    def test_no_part_says_where_it_sits(self) -> None:
        if not SYSTEMS.is_dir():
            self.skipTest("pages not generated")
        said = sorted(p.name for p in _pages("*")
                      if "\nPart of [" in p.read_text(encoding="utf-8"))
        self.assertEqual(said, [])

    def test_a_part_goes_by_the_emulators_name(self) -> None:
        titles = [re.search(r"^title: (.*)$", p.read_text(encoding="utf-8"), re.M)[1].strip("'")
                  for p in _pages("other-mame*")]
        if not titles:
            self.skipTest("pages not generated")
        self.assertEqual([t for t in titles if not t.startswith(("MAME files", "Other: MAME"))],
                         [])


class EachFileDownloadsFromItsCard(unittest.TestCase):
    """The Apple II page named eight start files and gave no visible way to
    get one: the download was a "(download)" after the collection path,
    fourth of a card's facts."""

    def test_the_card_title_holds_the_download(self) -> None:
        from cross_reference import FileConsumers  # noqa: PLC0415

        f = _naomi_file("apple2-asoft-auto.rom", "3", "bios/Apple/Apple II/apple2-asoft-auto.rom")
        title = next(line for line in gs._system_file_card(f, FileConsumers({"files": {}}))
                     if "rb-file-title" in line)
        self.assertIn('class="rb-download" href="https://raw.githubusercontent.com/Abdess/'
                      'retrobios/main/bios/Apple/Apple%20II/apple2-asoft-auto.rom"', title)
        self.assertIn('aria-label="Download apple2-asoft-auto.rom"', title)
        facts = "\n".join(gs._system_file_card(f, FileConsumers({"files": {}})))
        self.assertNotIn("(download)", facts)

    def test_a_start_name_leads_to_its_card(self) -> None:
        line = gs._link_held_names("- **Apple II**: `a.rom`, `b.rom`.",
                                   {"a.rom": "a" * 40, "b.rom": "b" * 40}, {"a" * 40})
        self.assertEqual(line, "- **Apple II**: [`a.rom`](#sha1-aaaaaaaaaaaa), `b.rom`.")

    def test_a_card_on_another_part_is_reached_by_its_permalink(self) -> None:
        full = next(iter(json.loads((REPO_ROOT / "database.json").read_text())["files"]))
        here = f'[`x.rom`](#sha1-{full[:12]})'
        away = gs._cards_elsewhere(here)
        self.assertEqual(away, f"[`x.rom`](/retrobios/files/?sha1={full})")
        held = here + f'\n<h3 id="sha1-{full[:12]}" class="rb-file-title">'
        self.assertEqual(gs._cards_elsewhere(held), held)

    def test_every_start_name_on_the_built_apple_page_links(self) -> None:
        page = next(SYSTEMS.glob("apple.md*"), None)
        if page is None:
            self.skipTest("site not generated")
        section = page.read_text(encoding="utf-8").split("## Apple II {", 1)[1]
        start = section.split("<section", 1)[0]
        line = next(row for row in start.splitlines() if row.startswith("- **Apple II**: "))
        # The files to start with come before the first sentence ("MAME MESS
        # reads ... instead"), which names what other emulators read.
        named = line.removeprefix("- **Apple II**: ").split(". ", 1)[0].rstrip(".")
        names = [part.strip() for part in named.split(", ")]
        self.assertTrue(names)
        for name in names:
            self.assertRegex(name, r"^\[`[^`]+`\]\(#sha1-[0-9a-f]{12}\)$")


if __name__ == "__main__":
    unittest.main()
