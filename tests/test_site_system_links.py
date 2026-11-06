"""A system is placed by the folder its files live in, and a link to it
goes to the section named after it.

The site mapped each system by the bare name of its first file, the last
console written winning: MiSTer's boot.rom sits under a dozen consoles, so
wonderswan and tiger-game-com linked to VideoBrain, ngpc and tandy-coco to
TI-99. A link then followed that folder, not the name it printed:
emerson-arcadia-2001 led to the Saturn and sega-naomi to the Dreamcast.
Reads the repository: skips when the database is absent.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402


class LinksFollowContent(unittest.TestCase):
    def test_an_ambiguous_name_places_nothing(self):
        names = {"boot.rom": {("VideoBrain", "VideoBrain"), ("Bandai", "WonderSwan")}}
        files = [{"name": "boot.rom", "sha1": "0" * 40}]
        self.assertIsNone(gs._system_folder(files, {"files": {}, "indexes": {}}, names))
        names["only.rom"] = {("Bandai", "WonderSwan")}
        files.append({"name": "only.rom"})
        self.assertEqual(
            gs._system_folder(files, {"files": {}, "indexes": {}}, names),
            ("Bandai", "WonderSwan"),
        )

    def test_mister_systems(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        from common import load_database, load_platform_config

        db = load_database("database.json")
        config = load_platform_config("misterfpga")
        names: dict = {}
        for mfr, consoles in gs._group_by_manufacturer(db).items():
            for console, entries in consoles.items():
                for entry in entries:
                    names.setdefault(entry["name"], set()).add((mfr, console))
        expected = {"wonderswan": "WonderSwan", "ngpc": "Neo Geo Pocket"}
        for sys_id, console in expected.items():
            system = config["systems"].get(sys_id)
            if system is None:
                continue
            with self.subTest(system=sys_id):
                place = gs._system_folder(system.get("files", []), db, names)
                self.assertEqual(place and place[1], console)


class OtherSpellingsOfOneSystem(unittest.TestCase):
    """Platforms and profiles spell systems their own way: the RetroArch page
    listed no emulator for sega-mega-drive although genesis_plus_gx declares
    sega-megadrive, and 2,057 of 4,215 emulator system lines had no link."""

    def test_a_platform_system_finds_its_emulators(self):
        index = gs._build_emulator_file_index({
            "genesis_plus_gx": {"systems": ["sega-megadrive"]},
            "np2kai": {"systems": ["pc-98"]},
        })
        self.assertEqual(gs._system_emulators("sega-mega-drive", index), ["genesis_plus_gx"])
        self.assertEqual(gs._system_emulators("nintendo-snes", index), [])

    def _install(self, mapping: dict) -> None:
        import siterender

        saved = dict(siterender._system_page_map)
        self.addCleanup(siterender.set_system_page_map, saved)
        siterender.set_system_page_map(mapping)

    def test_a_profile_spelling_finds_the_platform_page(self):
        import siterender

        self._install({"sega-mega-drive": ("sega", "Mega Drive")})
        self.assertEqual(siterender._page_by_norm("sega-megadrive"), ("sega", "Mega Drive"))
        self._install({"sega-mega-drive": ("sega", "Mega Drive"),
                       "megadrive": ("other", "Elsewhere")})
        self.assertIsNone(siterender._page_by_norm("sega-megadrive"))

    def test_a_table_of_the_same_size_replaces_the_other_spellings(self):
        """The index of other spellings was kept while the table kept its
        length, so a second table of one entry linked to the first one's page."""
        import siterender

        self._install({"sega-mega-drive": ("sega", "Mega Drive")})
        self.assertEqual(siterender._page_by_norm("sega-megadrive"), ("sega", "Mega Drive"))
        self._install({"sega-mega-drive": ("other", "Elsewhere")})
        self.assertEqual(siterender._page_by_norm("sega-megadrive"), ("other", "Elsewhere"))

    def test_a_system_only_profiles_name_is_placed_by_their_files(self):
        manufacturers = {"Commodore": {"PET": [{"name": "basic4.bin"}]}}
        profiles = {"vice_xpet": {"systems": ["commodore-pet"],
                                  "files": [{"name": "basic4.bin"}]}}
        pages = gs._system_pages_from_data(
            manufacturers, {}, {"files": {}, "indexes": {}}, profiles)
        self.assertEqual(pages["commodore-pet"], ("commodore", "PET"))


class ACopyIsOnItsOwnFoldersPage(unittest.TestCase):
    """The database keeps one path per content: the Channel F BIOS was on the
    Arcade page only, and Fairchild had no system page at all."""

    def test_every_folder_holding_a_copy_lists_it(self):
        import tempfile

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            for rel in ("Arcade/FBNeo/sl31253.rom", "Fairchild/Channel F/sl31253.bin"):
                (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / rel).write_bytes(b"x")
            db = {
                "bios_dir": tmp,
                "files": {"s": {"path": "bios/Arcade/FBNeo/sl31253.rom", "sha1": "s",
                                "name": "sl31253.rom"}},
                "indexes": {"by_path_suffix": {
                    "Arcade/FBNeo/sl31253.rom": ["s"], "FBNeo/sl31253.rom": ["s"],
                    "Fairchild/Channel F/sl31253.bin": ["s"], "Channel F/sl31253.bin": ["s"],
                }},
            }
            groups = gs._group_by_manufacturer(db)
        self.assertEqual(sorted(groups), ["Arcade", "Fairchild"])
        self.assertEqual(list(groups["Fairchild"]), ["Channel F"])
        # The copy is listed twice and counted once.
        self.assertRegex(gs.generate_systems_index(groups), r"2 consoles, 1 files? ")


class AnIdNamesOneCardPerPage(unittest.TestCase):
    """A copy filed under two consoles of one maker was listed twice with
    the same id, and the deployed site refused 20 pages."""

    def test_the_second_card_has_no_id(self):
        from cross_reference import FileConsumers

        entry = {"name": "a.bin", "sha1": "a" * 40, "md5": "b" * 32, "size": 3,
                 "path": "bios/Nintendo/DS/a.bin"}
        page = gs.generate_system_page(
            "Nintendo", {"DS": [entry], "DSi": [entry]}, FileConsumers({"files": {}}))
        self.assertEqual(page.count('id="sha1-aaaaaaaaaaaa" class="rb-file-title"'), 1)
        self.assertEqual(page.count("rb-sys-file"), 2)


class ACopyFiledByEmulatorDoesNotMoveAMachine(unittest.TestCase):
    """The database keeps one path per content, and the system links followed
    it: nintendo-nes and nintendo-fds led to Arcade > FBNeo, where
    disksys.rom is kept as fdsbios.nes, sega-mastersystem and
    sinclair-zx-spectrum to Other > zesarux."""

    def _db(self, tmp: str) -> dict:
        for rel in ("Arcade/FBNeo/fdsbios.nes", "Nintendo/Famicom Disk System/disksys.rom",
                    "Nintendo/NES/other.rom"):
            (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / rel).write_bytes(b"x")
        return {
            "bios_dir": tmp,
            "files": {
                "d" * 40: {"path": "bios/Arcade/FBNeo/fdsbios.nes", "sha1": "d" * 40,
                           "name": "fdsbios.nes"},
                "e" * 40: {"path": "bios/Nintendo/NES/other.rom", "sha1": "e" * 40,
                           "name": "other.rom"},
            },
            "indexes": {
                "by_sha1": {}, "by_md5": {}, "by_name": {},
                "by_path_suffix": {
                    "Arcade/FBNeo/fdsbios.nes": ["d" * 40],
                    "Nintendo/Famicom Disk System/disksys.rom": ["d" * 40],
                    "Nintendo/NES/other.rom": ["e" * 40],
                },
            },
        }

    def test_the_copy_under_the_declared_name_places_the_system(self):
        import tempfile

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            db = self._db(tmp)
            files = [{"name": "disksys.rom", "sha1": "d" * 40}]
            self.assertEqual(
                gs._system_folder(files, db, {}, "nintendo-fds"),
                ("Nintendo", "Famicom Disk System"),
            )
            # A file named otherwise still finds the maker's copy before the
            # emulator's folder.
            files = [{"name": "FDS_disksys-nintendo.rom", "sha1": "d" * 40}]
            self.assertEqual(
                gs._system_folder(files, db, {}, "fds"),
                ("Nintendo", "Famicom Disk System"),
            )

    def test_an_id_that_spells_a_folder_links_to_it(self):
        import tempfile

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            db = self._db(tmp)
            manufacturers = gs._group_by_manufacturer(db)
            config = {"systems": {"nintendo-nes": {"files": [
                {"name": "FDS_disksys-nintendo.rom", "sha1": "d" * 40}]}}}
            pages = gs._system_pages_from_data(
                manufacturers, {"p": {"config": config}}, db)
        self.assertEqual(pages["nintendo-nes"], ("nintendo", "NES"))

    def test_repository_systems(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        from common import load_database, load_emulator_profiles

        db = load_database("database.json")
        manufacturers = gs._group_by_manufacturer(db)
        pages = gs._system_pages_from_data(
            manufacturers, {}, db, load_emulator_profiles("emulators", skip_aliases=False))
        expected = {
            "nintendo-nes": ("nintendo", "NES"),
            "nintendo-fds": ("nintendo", "Famicom Disk System"),
            "sega-mastersystem": ("sega", "Master System"),
            "sinclair-zx-spectrum": ("sinclair", "ZX Spectrum"),
            "commodore-vic20": ("commodore", "VIC-20"),
        }
        for sys_id, page in expected.items():
            with self.subTest(system=sys_id):
                self.assertEqual(pages.get(sys_id), page)


class SystemEmulatorsWhenNoIdMatches(unittest.TestCase):
    """RetroArch files NAOMI and Atomiswave as sega-dreamcast-arcade and the
    Enterprise as enterprise-64-128, ids no profile uses: the emulator cell
    of both rows was empty on every platform page."""

    def setUp(self):
        self.index = gs._build_emulator_file_index({
            "flycast": {"systems": ["sega-naomi"], "files": [{"name": "airlbios.zip"}]},
            "fbneo": {"systems": ["arcade"], "files": [
                {"name": "boot.bin", "archive": "bubsys.zip"}]},
            "genesis": {"systems": ["sega-mega-drive"], "files": [{"name": "bios_MD.bin"}]},
        })

    def test_a_file_the_system_lists_names_its_emulator(self):
        self.assertEqual(
            gs._system_emulators("sega-dreamcast-arcade", self.index, [{"name": "airlbios.zip"}]),
            ["flycast"],
        )

    def test_an_archive_member_is_not_a_file_by_that_name(self):
        self.assertEqual(
            gs._system_emulators("sega-dreamcast", self.index, [{"name": "boot.bin"}]), []
        )

    def test_an_id_match_is_kept_alone(self):
        self.assertEqual(
            gs._system_emulators("sega-megadrive", self.index, [{"name": "airlbios.zip"}]),
            ["genesis"],
        )


DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"


@unittest.skipUnless((REPO_ROOT / "database.json").is_file()
                     and (DOCS / "systems" / "sony.md").is_file(), "site not generated")
class EverySystemLinkLandsOnItsSection(unittest.TestCase):
    """Every system id of every platform and profile, linked as the pages
    link it, against the generated pages: the anchor exists on its target
    page, and the heading there is the one system_name() reads."""

    @classmethod
    def setUpClass(cls):
        import re

        import siterender
        import sitestarlight
        from common import (
            list_registered_platforms, load_database, load_emulator_profiles, load_platform_config,
        )

        db = load_database(str(REPO_ROOT / "database.json"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        siterender.set_console_sections(gs._group_by_manufacturer(db), siterender.program_names(profiles))
        platforms = REPO_ROOT / "platforms"
        ids = {str(sid) for profile in profiles.values() for sid in profile.get("systems") or []}
        for name in list_registered_platforms(str(platforms)):
            ids |= {str(sid) for sid in load_platform_config(name, str(platforms)).get("systems") or {}}
        cls.ids = sorted(ids)
        cls.siterender = siterender
        heading = re.compile(r"^##\s+(?:<img [^>]*>)?(?P<text>.+?)\s*\{\s*#(?P<id>[^\s}]+)[^}]*\}\s*$", re.M)
        cls.headings: dict[str, dict[str, str]] = {}
        for page in (DOCS / "systems").glob("*.md*"):
            text = page.read_text(encoding="utf-8")
            cls.headings[page.name.rsplit(".", 1)[0]] = {
                m["id"]: m["text"] for m in heading.finditer(text)}
            cls.headings[page.name.rsplit(".", 1)[0]].update(
                dict.fromkeys(sitestarlight.heading_ids(text) - cls.headings[page.name.rsplit(".", 1)[0]].keys(), ""))

    def test_every_anchor_exists_and_names_the_system(self):
        import re
        import urllib.parse

        linked = 0
        for sys_id in self.ids:
            link = self.siterender._system_link(sys_id)
            match = re.fullmatch(r"\[[^\]]*\]\(systems/(?P<page>[^)#]+)\.md(?:#(?P<anchor>[^)]+))?\)", link)
            if not match:
                self.assertEqual(link, sys_id)
                continue
            linked += 1
            page = urllib.parse.unquote(match["page"])
            with self.subTest(system=sys_id, link=link):
                self.assertIn(page, self.headings)
                if match["anchor"]:
                    self.assertIn(match["anchor"], self.headings[page])
                    slug, console = self.siterender.system_section(sys_id)
                    # The Arcade folder of sets no board claims is headed by
                    # what it holds, its id staying the folder's.
                    if slug == "arcade":
                        console = gs._section_label("Arcade", console)
                    self.assertEqual(self.headings[page][match["anchor"]], console)
        self.assertGreater(linked, 200)

    def test_a_system_without_a_section_of_its_name_is_not_sent_elsewhere(self):
        for sys_id in ("emerson-arcadia-2001", "sega-naomi"):
            with self.subTest(system=sys_id):
                link = self.siterender._system_link(sys_id)
                self.assertNotIn("#saturn", link)
                self.assertNotIn("#dreamcast", link)


if __name__ == "__main__":
    unittest.main()
