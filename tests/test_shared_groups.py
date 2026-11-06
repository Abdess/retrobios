"""_shared.yml is curation of the code, not of System.dat.

The np2kai group declared itf.rom required, a file the core never opens
(bios.c:579 sits behind the #else of BIOS_SIMULATE, always defined), and
bios.rom, sound.rom and the rhythm WAVs required where the code falls back.
System.dat masked the group: a rescrape dropping itf.rom would have brought
it back as a required file of RetroArch, Lakka and RetroPie.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import load_emulator_profiles  # noqa: E402
from safeparse import yaml_load  # noqa: E402


class SharedGroupsFollowTheProfiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(REPO_ROOT / "platforms" / "_shared.yml", encoding="utf-8") as f:
            cls.groups = (yaml_load(f) or {}).get("shared_groups", {})
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.by_destination: dict[str, list[dict]] = {}
        for profile in profiles.values():
            for entry in profile.get("files") or []:
                destination = entry.get("path") or entry.get("name")
                if not destination:
                    continue
                # quasi88 reads N88EXT0.ROM before n88_0.rom: an alias in
                # the entry's directory is the same declaration.
                folder = destination.rpartition("/")[0]
                for name in [destination] + [
                    f"{folder}/{alias}" if folder else str(alias)
                    for alias in entry.get("aliases") or []
                ]:
                    cls.by_destination.setdefault(name.casefold(), []).append(entry)

    def _declarations(self, entry: dict) -> list[dict]:
        names = [entry.get("destination") or entry["name"]]
        return [d for n in names for d in self.by_destination.get(n.casefold(), [])]

    def test_every_entry_is_a_file_a_profile_declares(self):
        phantoms = [
            f"{group}: {entry['name']}"
            for group, entries in self.groups.items()
            for entry in entries
            if not self._declarations(entry)
        ]
        self.assertEqual(phantoms, [])

    def test_required_follows_the_code(self):
        disagreements = []
        for group, entries in self.groups.items():
            for entry in entries:
                declared = self._declarations(entry)
                if not declared:
                    continue
                required = any(d.get("required") for d in declared)
                if bool(entry.get("required", True)) != required:
                    disagreements.append(f"{group}: {entry['name']}")
        self.assertEqual(disagreements, [])


if __name__ == "__main__":
    unittest.main()
