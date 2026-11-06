"""One display name per system id.

An emulator page listed the folders a system's files were voted onto:
nintendo-gba read "Nintendo Game Boy", camplynx "Arcade", and MAME
"emulated FBNeo". siterender.system_name names a system from the console
section that is its own, then from SYSTEM_NAMES, and raises otherwise.
database.json carries no system id: its files reach a page through their
console folders, so the ids to name are the platforms' and the profiles'.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import siterender  # noqa: E402
from common import (  # noqa: E402
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
)
from generate_site import _group_by_manufacturer  # noqa: E402


def _profile_system_ids(profiles: dict[str, dict]) -> set[str]:
    ids: set[str] = set()
    for profile in profiles.values():
        ids.update(str(sys_id) for sys_id in profile.get("systems") or [])
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("system"):
                ids.add(str(entry["system"]))
            ids.update(str(sys_id) for sys_id in entry.get("systems") or [])
    return ids


class SystemNames(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        with open(REPO_ROOT / "database.json", encoding="utf-8") as handle:
            db = json.load(handle)
        cls.manufacturers = _group_by_manufacturer(db)
        cls.profiles = load_emulator_profiles(
            str(REPO_ROOT / "emulators"), skip_aliases=False)
        siterender.set_console_sections(
            cls.manufacturers, siterender.program_names(cls.profiles))
        platforms_dir = str(REPO_ROOT / "platforms")
        cls.platform_ids = {
            sys_id
            for name in list_registered_platforms(platforms_dir)
            for sys_id in load_platform_config(name, platforms_dir).get("systems", {})
        }
        cls.profile_ids = _profile_system_ids(cls.profiles)

    def _all_ids(self) -> set[str]:
        return self.platform_ids | self.profile_ids

    def test_every_system_id_has_a_name(self) -> None:
        unnamed = []
        for sys_id in sorted(self._all_ids()):
            try:
                name = siterender.system_name(sys_id)
            except KeyError:
                unnamed.append(sys_id)
                continue
            self.assertTrue(name.strip(), sys_id)
        self.assertEqual(unnamed, [], "add these to siterender.SYSTEM_NAMES")

    def test_no_name_is_a_manufacturer_page_or_an_emulator(self) -> None:
        taken = {name.casefold() for name in self.manufacturers}
        taken |= {name.casefold() for name in siterender.program_names(self.profiles)}
        clashes = sorted(
            (sys_id, siterender.system_name(sys_id))
            for sys_id in self._all_ids()
            if siterender.system_name(sys_id).casefold() in taken
        )
        self.assertEqual(clashes, [])

    def test_table_entries_are_reached(self) -> None:
        """A table entry an own section shadows is never read, and an entry
        no platform or profile names is a leftover."""
        shadowed = sorted(
            sys_id for sys_id in siterender.SYSTEM_NAMES
            if siterender._own_section(sys_id) is not None
        )
        self.assertEqual(shadowed, [])
        unused = sorted(set(siterender.SYSTEM_NAMES) - self._all_ids())
        self.assertEqual(unused, [])

    def test_names_that_read_a_folder_vote(self) -> None:
        self.assertEqual(siterender.system_name("nintendo-gba"), "Nintendo Game Boy Advance")
        self.assertEqual(siterender.system_name("camplynx"), "Camputers Lynx")
        self.assertEqual(siterender.system_name("atari-lynx"), "Atari Lynx")
        self.assertEqual(siterender.system_name("arcade"), "Arcade games")
        self.assertEqual(siterender.system_name("sega-naomi"), "Sega NAOMI")

    def test_own_section_names_from_its_heading(self) -> None:
        self.assertEqual(siterender.system_name("nintendo-snes"), "Nintendo SNES")
        self.assertEqual(siterender.system_name("sony-playstation"), "Sony PlayStation")

    def test_an_unknown_id_raises(self) -> None:
        with self.assertRaises(KeyError):
            siterender.system_name("no-such-system-anywhere")

    def test_mame_names_systems_not_emulators(self) -> None:
        names = {siterender.system_name(s) for s in self.profiles["mame"].get("systems") or []}
        self.assertNotIn("FBNeo", names)
        self.assertNotIn("Arcade", names)
        self.assertFalse(names & siterender.program_names(self.profiles))


class SectionsComeBeforeThePlan(unittest.TestCase):
    """plan_emulator_pages names systems. Run before set_console_sections,
    it made siterender read ./database.json and ./emulators whatever --db
    and --emulators-dir gave, so the parts were cut on another collection."""

    def test_generate_installs_the_sections_before_planning(self):
        import ast
        import inspect

        import generate_site

        tree = ast.parse(inspect.getsource(generate_site._generate))
        lines = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                lines.setdefault(node.func.id, node.lineno)
        self.assertLess(lines["set_console_sections"], lines["plan_emulator_pages"])


if __name__ == "__main__":
    unittest.main()
