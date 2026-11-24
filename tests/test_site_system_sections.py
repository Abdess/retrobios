"""Every system id with a section leads to it.

260 of 636 system ids linked: a variant (WonderSwan Color, Neo Geo MVS)
never matched a heading, twin folders (DS and Nintendo DS) made the exact
name ambiguous, and every Arcade heading was refused. siterender now reads
a reviewed SYSTEM_PARENTS table after the id's own section, accepts an
Arcade heading that reads the name exactly, and leads an arcade board
(NAOMI, ZN-1, PGM) to its own section. An id counts as holding files
through a set archive (``category: bios_zip``) its profile declares for it,
not only through a file's own hash. An id whose files the collection holds
and that stays plain is named below, with the reason.
Reads the repository: skips when the database is absent.
"""

from __future__ import annotations

import tests
from tests.sources import script_source

import json
import os
import unittest
from collections.abc import Iterable
from pathlib import Path

from sitegen import render as siterender
from sitegen import runlinks
from sitegen import runsections
from model import siteinputs, systemnames

REPO_ROOT = Path(__file__).resolve().parents[1]

# Ids whose files the collection holds and that lead to no section.
UNLINKED: dict[str, str] = {
    # Files only under a program's folder (Other/<emulator>, Arcade/<core>,
    # Game Engines/<engine>, a top named after the program), a folder of
    # several systems' files or not reviewed as the system's own. The
    # heading names the program, not the system.
    "capcom-cps3": "Arcade > FBNeo",
    "commanderx16": "Other > x16emu",
    "dark-forces-ii": "Game Engines > OpenJKDF2",
    "fpinball": "Other > future-pinball-fploader",
    "fruitmachine": "Other > mfme",
    "mysteries-of-the-sith": "Game Engines > OpenJKDF2",
    "namco-nb1": "Arcade > FBNeo",
    "omicron": "Other > omicron",
    "rpgmaker": "RPG Maker > easyrpg",
    "sdlpal": "the SDLPAL section under its own top, named after the program",
    "sega-system16b": "Arcade > FBNeo, and isgsm.zip is also the ISG Selection Master's",
    "smbx": "Game Engines > TheXTech",
    "thomson-mo6": "Other > Clock Signal",
    "vgmplay": "qsound.zip, ym2413.zip, ym2608.zip: sound chips, no board",
    # Files filed with another machine: a link would name the wrong one.
    "commodore-c64-supercpu": "VICE's tree under the C128",
    "spectravideo": "the SVI ROMs are filed with the MSX",
    "taito-type-x": "mame2010 files taitogn.zip, the G-NET BIOS, under this id",
    "vvvvvv": "SDL's controller database",
    # Files of distinct machines or games, one section each.
    "catacomb-adventure": "three games, three sections",
    "sinclair-zx80-81": "ZX 80 and ZX 81 sections",
}


def _accepts(fe: dict, local: str | None, status: str) -> bool:
    """A resolution that proves the entry's content or its full path."""
    from resolve.localfile import resolution_is_hash_exact

    if not local:
        return False
    if resolution_is_hash_exact(status) or status == "path_exact":
        return True
    path = fe.get("path")
    return bool(path) and local.endswith("/" + str(path))


def _archives_held(fe: dict, db: dict) -> set[str]:
    """The copies of a set archive (``category: bios_zip``) the collection
    holds: by its name, kept when it holds one CRC32 its ``contents:``
    lists. MAME hashes the members, never the archive, so the entry has no
    hash of its own and a name match is the only way to it."""
    from core.ziptools import zip_member_crcs

    crcs = {str(m["crc32"]).lower() for m in fe.get("contents") or []
            if isinstance(m, dict) and m.get("crc32")}
    names = {str(fe.get("name", ""))} | {str(a) for a in fe.get("aliases") or []}
    held: set[str] = set()
    for name in names:
        for sha1 in db["indexes"]["by_name"].get(name.rsplit("/", 1)[-1], []):
            members = zip_member_crcs(str(REPO_ROOT / db["files"][sha1]["path"]))
            if not crcs or not members or members & crcs:
                held.add(sha1)
    return held


def _entries_by_system(platforms: list[dict], profiles: dict) -> dict[str, list[dict]]:
    entries: dict[str, list[dict]] = {}
    for config in platforms:
        for sys_id, system in config.get("systems", {}).items():
            entries.setdefault(sys_id, []).extend(system.get("files") or [])
    for profile in profiles.values():
        systems = [str(s) for s in profile.get("systems") or []]
        for fe in profile.get("files") or []:
            if not isinstance(fe, dict):
                continue
            owners = {str(fe["system"])} if fe.get("system") else set()
            owners.update(str(s) for s in fe.get("systems") or [])
            if not owners and len(systems) == 1:
                owners = set(systems)
            for owner in owners:
                entries.setdefault(owner, []).append(fe)
    return entries


def _held_sections(
    ids: Iterable[str], entries: dict[str, list[dict]], board_sections: dict, db: dict
) -> dict[str, set[tuple[str, str]]]:
    """Id -> the (manufacturer, console) sections holding its files."""
    from resolve.localfile import resolve_local_file

    # Where each content has a card.
    places: dict[str, set[tuple[str, str, str]]] = {}
    for mfr, consoles in board_sections.items():
        for console, files in consoles.items():
            for f in files:
                places.setdefault(f["sha1"], set()).add((mfr, console, f["name"]))
    by_path = {entry.get("path"): sha1 for sha1, entry in db["files"].items()}
    held: dict[str, set[tuple[str, str]]] = {}
    for sys_id in ids:
        sections: set[tuple[str, str]] = set()
        for fe in entries.get(sys_id, []):
            if fe.get("category") == "bios_zip":
                for sha1 in _archives_held(fe, db):
                    sections.update((m, c) for m, c, _ in places.get(sha1, set()))
                continue
            local, status = resolve_local_file(fe, db)
            if not _accepts(fe, local, status):
                continue
            sha1 = by_path.get(local)
            if sha1 is not None:
                sections.update((m, c) for m, c, _ in places.get(sha1, set()))
        if sections:
            held[sys_id] = sections
    return held


@unittest.skipUnless((REPO_ROOT / "database.json").exists(), "database.json is not built")
class SystemLinks(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            from model.registry import list_registered_platforms
            from model.profiles import load_emulator_profiles
            from model.platforms import load_platform_config
            from model.collection import group_by_manufacturer
            from sitegen.systempages import arcade_board_sections

            with open("database.json", encoding="utf-8") as handle:
                db = json.load(handle)
            grouping = group_by_manufacturer(db)
            cls.manufacturers = grouping.sections
            profiles = load_emulator_profiles("emulators", skip_aliases=False)
            runsections.install_grouping(
                grouping, systemnames.program_names(profiles))
            # The system pages give every arcade board a section of its own
            # and record it. The built pages are checked by
            # test_site_built_gate.
            runlinks.reset_console_pages()
            # The sections as the system pages hold them: each board, the
            # sets a reviewed machine owns under that machine.
            cls.sections = arcade_board_sections(cls.manufacturers)
            platforms = [
                load_platform_config(name, "platforms")
                for name in list_registered_platforms("platforms")
            ]
            cls.ids = siterender.system_ids(profiles, platforms)
            cls.coverages = {name: {"config": config} for name, config in
                             zip(list_registered_platforms("platforms"), platforms)}

            entries = _entries_by_system(platforms, profiles)
            cls.held: dict[str, set[tuple[str, str]]] = _held_sections(
                cls.ids, entries, cls.sections, db)
        finally:
            os.chdir(previous)

    @classmethod
    def tearDownClass(cls) -> None:
        runlinks.reset_console_pages()

    def test_every_id_with_files_links(self) -> None:
        linked, total = runlinks.link_coverage(self.ids)
        with_files = set(self.held)
        print(f"\n  {linked} of {total} system ids linked, "
              f"{len(with_files - set(UNLINKED))} of {len(with_files)} with files, "
              f"{len(self.ids - with_files)} with no file")
        plain = sorted(
            sys_id for sys_id in with_files - set(UNLINKED)
            if runlinks.system_section(sys_id) is None
        )
        self.assertEqual(plain, [], "link these or name them in UNLINKED with the reason")

    def test_install_commands_sit_where_the_system_links(self) -> None:
        """The commands were placed by the folder votes of sitegen.places
        and the links by system_section: Game Boy Color's commands sat under
        Game Boy, Super A'Can's under Arcade, while their links led to their
        own sections."""
        from sitegen.cards import system_install_choices
        from sitegen.install import manifest_systems

        placed = {
            (platform, sys_id): (slug, console)
            for slug, consoles in system_install_choices(self.coverages).items()
            for console, pairs in consoles.items()
            for platform, sys_id in pairs
        }
        wrong = sorted(
            (pair, place, runlinks.system_section(pair[1]))
            for pair, place in placed.items()
            if runlinks.system_section(pair[1]) != place
        )
        self.assertEqual(wrong, [])
        unplaced = sorted(
            (name, sys_id)
            for name, cov in self.coverages.items()
            for sys_id in set(cov["config"].get("systems") or {}) & manifest_systems(name)
            if runlinks.system_section(sys_id) and (name, sys_id) not in placed
        )
        self.assertEqual(unplaced, [])

    def test_unlinked_list_is_current(self) -> None:
        stale = sorted(
            sys_id for sys_id in UNLINKED
            if sys_id not in self.held or runlinks.system_section(sys_id) is not None
        )
        self.assertEqual(stale, [])

    def test_a_matching_heading_is_linked(self) -> None:
        """An id whose name reads one heading, outside Other, leads there."""
        by_heading: dict[str, set[tuple[str, str]]] = {}
        labels = runsections.section_labels()
        for mfr, consoles in self.manufacturers.items():
            for console in consoles:
                for name in {systemnames.heading_name(mfr, console, labels), console}:
                    by_heading.setdefault(name.casefold(), set()).add((mfr, console))
        missed = []
        for sys_id in sorted(self.ids):
            places = by_heading.get(runsections.system_name(sys_id).casefold(), set())
            if len(places) != 1:
                continue
            mfr, console = next(iter(places))
            if mfr == "Other" or (
                mfr == "Arcade" and console.casefold() in runsections.current().sections.programs
            ):
                continue
            if runlinks.system_section(sys_id) is None:
                missed.append(sys_id)
        self.assertEqual(missed, [])

    def test_parents_are_sections(self) -> None:
        sections = {
            (mfr, console)
            for mfr, consoles in self.sections.items() for console in consoles
        }
        self.assertEqual(
            sorted(k for k, v in systemnames.SYSTEM_PARENTS.items() if v not in sections), [])

    def test_parents_hold_the_files(self) -> None:
        """A parent holds a file of the id, or of an id of the same name.
        An entry its own section shadows is never read and is not judged."""
        by_name: dict[str, set[tuple[str, str]]] = {}
        for sys_id, sections in self.held.items():
            by_name.setdefault(runsections.system_name(sys_id), set()).update(sections)
        wrong = []
        for sys_id, parent in sorted(systemnames.SYSTEM_PARENTS.items()):
            if runsections.own_section(sys_id) is not None:
                continue
            held = by_name.get(runsections.system_name(sys_id))
            if held is not None and parent not in held:
                wrong.append((sys_id, parent))
        self.assertEqual(wrong, [])

    def test_variants_lead_to_their_family(self) -> None:
        expect = {
            "wonderswan-color": ("bandai", "WonderSwan"),
            "bandai-wswanc": ("bandai", "WonderSwan"),
            "ngpc": ("snk", "Neo Geo Pocket"),
            "snk-neogeo-mvs": ("snk", "Neo Geo"),
            "snk-neogeo-aes": ("snk", "Neo Geo"),
            "nintendo-ds": ("nintendo", "Nintendo DS"),
            "nintendo-64dd": ("nintendo", "Nintendo 64DD"),
            "zx-spectrum-128": ("sinclair", "ZX Spectrum"),
            "pc-engine-ld": ("pioneer", "LaserActive"),
        }
        for sys_id, section in expect.items():
            with self.subTest(sys_id=sys_id):
                self.assertEqual(runlinks.system_section(sys_id), section)

    def test_arcade_heading_by_exact_name(self) -> None:
        self.assertEqual(
            runlinks.system_section("namco-system246"), ("arcade", "Namco System 246"))
        # A board leads to its own section, never a folder of copies a core
        # loads (Arcade > FBNeo).
        self.assertEqual(runlinks.system_section("sega-naomi"), ("arcade", "Sega NAOMI"))
        self.assertEqual(
            runlinks.system_section("igs-pgm"), ("arcade", "IGS PolyGame Master"))

    def test_folder_votes_stay_out(self) -> None:
        """A copy filed with another machine names no section: the Arcadia
        stays plain, NAOMI 2 goes to its board, never to the Dreamcast."""
        self.assertIsNone(runlinks.system_section("emerson-arcadia-2001"))
        self.assertEqual(runlinks.system_section("naomi2"), ("arcade", "Sega NAOMI 2"))
        for sys_id in ("emerson-arcadia-2001", "naomi2"):
            with self.subTest(sys_id=sys_id):
                self.assertNotIn(sys_id, systemnames.SYSTEM_PARENTS)

    def test_emulator_rows_link_the_variant(self) -> None:
        from sitegen.emulatorcards import named_system_link

        self.assertEqual(
            named_system_link("wonderswan-color", "../"),
            "[Bandai WonderSwan Color](../systems/bandai.md#wonderswan)")


class SearchAliases(unittest.TestCase):

    def test_platform_names(self) -> None:
        self.assertIn("psx", runlinks.system_search_aliases("sony-playstation"))
        self.assertIn("dc", runlinks.system_search_aliases("sega-dreamcast"))
        self.assertIn("gba", runlinks.system_search_aliases("nintendo-gba"))

    def test_one_typed_word_per_name(self) -> None:
        runlinks.system_search_aliases("sony-playstation")
        for sys_id, names in runlinks._search_aliases[str(siteinputs.current().platforms)].items():
            with self.subTest(sys_id=sys_id):
                self.assertNotIn(sys_id, names)
                self.assertEqual(len({n.casefold() for n in names}), len(names))
                for name in names:
                    self.assertNotRegex(name, r"[\s,]")

    def test_unknown_id(self) -> None:
        self.assertEqual(runlinks.system_search_aliases("no-such-system"), [])

    def test_page_aliases_follow_the_run(self) -> None:
        """Built once and never dropped, a second run's pages carried the
        first run's names, and a console split after the first call kept
        its names on the manufacturer's page."""
        self.addCleanup(runlinks.use, runlinks.current())
        runlinks.use(runlinks.LinkTables())
        runlinks.set_system_page_map({"sony-playstation": ("sony", "PlayStation")})
        self.assertIn("psx", runlinks.page_aliases("systems/sony.md"))
        runlinks.record_console_pages("sony", "PlayStation", ["sony-playstation"], [[]])
        self.assertEqual(runlinks.page_aliases("systems/sony.md"), [])
        self.assertIn("psx", runlinks.page_aliases("systems/sony-playstation.md"))
        runlinks.use(runlinks.LinkTables())
        runlinks.set_system_page_map({"nintendo-gba": ("nintendo", "Game Boy Advance")})
        self.assertEqual(runlinks.page_aliases("systems/sony.md"), [])
        self.assertEqual(runlinks.page_aliases("systems/sony-playstation.md"), [])
        self.assertIn("gba", runlinks.page_aliases("systems/nintendo.md"))


class BuildCount(unittest.TestCase):

    def test_generator_prints_the_count(self) -> None:
        source = script_source("generate_site.py")
        self.assertIn("link_coverage(", source)
        self.assertIn("system ids linked", source)


class AnEntryListingSystemsIsFiledUnderEach(unittest.TestCase):
    """MAME declares a device set under `systems:`, the machines of several
    systems loading it. The site read only `system:`, so ym2608.zip was filed
    under neither Arcade nor NEC PC-88, and kept on pages it does not serve."""

    def test_the_site_reads_the_common_rule(self):
        from sitegen import consolecards
        from model.profiles import entry_system_ids

        entry = {"name": "ym2608.zip", "systems": ["arcade", "pc80"]}
        self.assertEqual(consolecards.entry_systems("mame", entry), ["arcade", "pc80"])
        self.assertEqual(
            consolecards.entry_systems("mame", entry), entry_system_ids(entry, {"systems": []})
        )
        self.assertEqual(consolecards.entry_systems("mame", {"name": "a", "system": "pc80"}), ["pc80"])


if __name__ == "__main__":
    unittest.main()
