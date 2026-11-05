"""System pages and boards.

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

import json
import re
import sys
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import siterender  # noqa: E402

CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"
SYSTEMS = CONTENT / "systems"


def _file(name: str, char: str, path: str = "") -> dict:
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


def _unlinked(text: str) -> str:
    """The wording of a start line: each file it names links to its card,
    which EachFileDownloadsFromItsCard holds."""
    return re.sub(r"\[(`[^`]*`)\]\([^)]*\)", r"\1", text)


def _page(stem: str) -> str:
    path = SYSTEMS / f"{stem}.md"
    if not path.is_file():
        raise unittest.SkipTest(f"systems/{stem}.md not generated")
    return _unlinked(path.read_text(encoding="utf-8"))


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
        naomi, hod2 = _file("naomi.zip", "1"), _file("hod2bios.zip", "2")
        both = [(f"flycast{n}", {"name": "hod2bios.zip", "required": True}) for n in range(2)]
        extra = [(f"mame{n}", {"name": "hod2bios.zip", "required": False}) for n in range(3)]
        consumers = _consumers({
            "1" * 40: [(e, {"name": "naomi.zip", "required": True}) for e, _ in both + extra],
            "2" * 40: both + extra,
        })
        self.assertEqual([_unlinked(line) for line in gs._start_with([naomi, hod2], consumers)],
                         ["**Start with**: `naomi.zip`.", ""])

    def test_the_naomi_page_opens_on_naomi_zip(self) -> None:
        self.assertEqual(_start_line(_page("arcade-sega-naomi")), "**Start with**: `naomi.zip`.")

    def test_a_file_several_require_beside_the_lead_stays(self) -> None:
        bios7, bios9 = _file("bios7.bin", "3"), _file("bios9.bin", "4")
        consumers = _consumers({
            "3" * 40: [(e, {"name": "bios7.bin", "required": True}) for e in ("a", "b")],
            "4" * 40: [(e, {"name": "bios9.bin", "required": True}) for e in ("a", "b")],
        })
        self.assertEqual(_unlinked(gs._start_with([bios7, bios9], consumers)[0]),
                         "**Start with**: `bios7.bin`, `bios9.bin`.")

    def test_some_files_each_is_not_every_file_for_one(self) -> None:
        """The SNES said bsnes and four more require 22 files."""
        files = [_file(f"chip{n}.rom", str(n)) for n in range(1, 4)]
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
        disk, fds = _file("disksys.rom", "5"), _file("fdsbios.zip", "6")
        consumers = _consumers({
            "5" * 40: [(e, {"name": "disksys.rom", "required": True})
                       for e in ("mesen", "nestopia", "fceumm")],
            "6" * 40: [("fbneo", {"name": "fdsbios.zip", "required": True})],
        })
        self.assertEqual(_unlinked(gs._start_with([disk, fds], consumers)[0]),
                         "**Start with**: `disksys.rom`. FinalBurn Neo reads `fdsbios.zip` instead.")

    def test_a_card_read_under_another_name_says_both(self) -> None:
        disk, card = _file("disksys.rom", "5"), _file("long name (1986).bin", "7")
        consumers = _consumers({
            "5" * 40: [(e, {"name": "disksys.rom", "required": True}) for e in ("a", "b")],
            "7" * 40: [("c", {"name": "short.rom", "required": True})],
        })
        self.assertIn("reads `long name (1986).bin` (as `short.rom`) instead.",
                      _unlinked(gs._start_with([disk, card], consumers)[0]))

    def test_a_regional_line_names_one_file_per_reader(self) -> None:
        mega_cd = _page("sega").split("{ #mega-cd }", 1)[1].split("\n## ", 1)[0]
        regions = [line for line in mega_cd.splitlines() if line.startswith("- **")]
        self.assertTrue(regions)
        for line in regions:
            lead = line.split(". ", 1)[0]
            self.assertEqual(len(re.findall(r"`[^`]+`", lead)), 1, line)

    def test_the_fds_line(self) -> None:
        fds = _page("nintendo").split("{ #famicom-disk-system }", 1)[1]
        self.assertRegex(_start_line(fds), r"^\*\*Start with\*\*: `disksys.rom`\. FinalBurn Neo "
                                           r"reads \[?`fdsbios.zip`.* instead\.$")


class TheNeoGeoSetsSitWithTheNeoGeo(unittest.TestCase):
    """6.3: every neogeo.zip has its card on SNK's pages, side by side and
    open, and the ares sentence names the card."""

    def test_every_neogeo_zip_is_on_snk(self) -> None:
        db = _database()
        sha1s = [sha1 for sha1, f in db["files"].items() if f["name"] == "neogeo.zip"]
        held = "".join(path.read_text(encoding="utf-8") for path in SYSTEMS.glob("snk*.md"))
        if not held:
            self.skipTest("SNK pages not generated")
        self.assertEqual([s for s in sha1s if f'id="sha1-{s[:12]}"' not in held], [])
        others = "".join(path.read_text(encoding="utf-8")
                         for path in SYSTEMS.glob("arcade*.md"))
        self.assertEqual([s for s in sha1s if f'id="sha1-{s[:12]}"' in others], [])

    def test_the_sets_are_open_and_together(self) -> None:
        section = _page("snk").split("{ #neo-geo }", 1)[1].split("\n## ", 1)[0]
        titles = re.findall(r'class="rb-file-title"[^>]*><code>([^<]+)</code>', section)
        sets = [n for n, name in enumerate(titles) if name == "neogeo.zip"]
        self.assertGreater(len(sets), 1)
        self.assertEqual(sets, list(range(len(sets))))
        variants = section.split("Variants (", 1)[1] if "Variants (" in section else ""
        self.assertNotIn("<code>neogeo.zip</code>", variants)

    def test_ares_is_told_the_card_it_reads(self) -> None:
        self.assertIn("ares reads `neo-epo.bin` and `sp-45.sp1` instead.", _page("snk"))


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
            self.assertFalse((SYSTEMS / f"{stem}.md").exists(), stem)

    def test_the_computers_sets_are_on_their_makers_page(self) -> None:
        acorn = _page("acorn")
        self.assertIn("{ #atom }", acorn)
        self.assertIn("<code>atom_gdos.zip</code>", acorn)
        cards = re.findall(r'class="rb-file-title"[^>]*><code>([^<]+)</code>', _page("sharp"))
        self.assertEqual(cards.count("mz2000.zip"), 2)


class TheDreamcastBoardsAreFiledByBoard(unittest.TestCase):
    """6.5: the NAOMI and Atomiswave sets under the Dreamcast folder."""

    def test_the_board_sets_left_the_dreamcast(self) -> None:
        sega = _page("sega")
        dreamcast = sega.split("{ #dreamcast }", 1)[1].split("\n## ", 1)[0]
        for name in ("naomi.zip", "awbios.zip", "naomi2.zip"):
            self.assertNotIn(f"<code>{name}</code>", dreamcast)
        self.assertIn("(/retrobios/systems/arcade-sega-naomi/)", dreamcast)
        self.assertIn("(/retrobios/systems/arcade-sammy-atomiswave/)", dreamcast)

    def test_every_naomi_set_is_on_its_board(self) -> None:
        db = _database()
        page = _page("arcade-sega-naomi")
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
        index = _page("index")
        rows = re.findall(r"^\| \[([^\]]+)\]\(", index, re.M)
        headings = [h.strip() for path in SYSTEMS.glob("*.md")
                    for h in re.findall(r"^## ([^{\n]+)", path.read_text(encoding="utf-8"), re.M)]
        wrong = sorted({n for n in rows + headings if n.startswith(".") or n in names})
        self.assertEqual(wrong, [])

    def test_scummvm_has_one_page(self) -> None:
        self.assertFalse((SYSTEMS / "other-scummvm.md").exists())
        self.assertIn("## ScummVM {", _page("scummvm"))
        self.assertNotIn("](/retrobios/systems/other/#scummvm)", _page("index"))

    def test_a_folder_named_by_a_profile_key_reads_the_engine(self) -> None:
        index = _page("index")
        self.assertIn("| [EasyRPG Player](/retrobios/systems/rpg-maker/#easyrpg) |", index)
        self.assertIn("| [SDLPAL](", index)

    def test_moved_pages_redirect(self) -> None:
        if not SYSTEMS.is_dir():
            self.skipTest("pages not generated")
        for old, new in gs.SYSTEM_PAGES_MOVED.items():
            self.assertFalse((CONTENT / old).exists() or (CONTENT / old).with_suffix(".mdx").exists(), old)
            # A page with tabs is written as MDX.
            self.assertTrue((CONTENT / new).exists() or (CONTENT / new).with_suffix(".mdx").exists(), new)
        redirects = CONTENT.parents[1] / "generated" / "redirects.json"
        if redirects.is_file():
            table = json.loads(redirects.read_text(encoding="utf-8"))
            self.assertEqual(table.get("/systems/other-scummvm/"), "/systems/scummvm/")


class OneLabelOnceOnABoardPage(unittest.TestCase):
    """6.7, 6.8, 6.9, 6.10: the words a board or part page repeats."""

    def test_a_label_naming_files_installs_these_files(self) -> None:
        block = "\n".join(gs._console_install_block("Other arcade files", [("mame", "arcade")]))
        self.assertIn("<summary>Install these files</summary>", block)
        block = "\n".join(gs._console_install_block("Sega NAOMI", [("mame", "arcade")]))
        self.assertIn("<summary>Install the files of Sega NAOMI</summary>", block)

    def test_a_board_page_has_no_heading_of_its_name(self) -> None:
        page = _page("arcade-sega-naomi")
        self.assertNotRegex(page, r"^## Sega NAOMI", )
        self.assertNotIn("](/retrobios/systems/arcade-sega-naomi/#sega-naomi)",
                         _page("index"))

    def test_no_part_says_where_it_sits(self) -> None:
        if not SYSTEMS.is_dir():
            self.skipTest("pages not generated")
        said = sorted(p.name for p in SYSTEMS.glob("*.md")
                      if "\nPart of [" in p.read_text(encoding="utf-8"))
        self.assertEqual(said, [])

    def test_a_part_goes_by_the_emulators_name(self) -> None:
        titles = [re.search(r"^title: (.*)$", p.read_text(encoding="utf-8"), re.M)[1].strip("'")
                  for p in SYSTEMS.glob("other-mame*.md")]
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

        f = _file("apple2-asoft-auto.rom", "3", "bios/Apple/Apple II/apple2-asoft-auto.rom")
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
        self.assertIn("[`apple2-asoft-auto.rom`](#sha1-33a24f5489ba)", start)


if __name__ == "__main__":
    unittest.main()
