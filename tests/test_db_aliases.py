"""A profile's aliases attach to the file its name designates, or to none.

generate_db matched an alias-carrying entry by name through a dict that
kept the last file of that name. quasi88's disk.rom aliases (N88SUB.ROM,
n88sub.rom) went to a Tandy CoCo disk.rom, and a name lookup for the PC-88
disk ROM then served the CoCo one.
"""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class _NoCoreInfo:
    def fetch_requirements(self):
        return []


class AliasesNeedAnUnambiguousName(unittest.TestCase):
    def _aliases(self, files: dict) -> dict:
        import generate_db

        stub = types.ModuleType("scraper.coreinfo_scraper")
        stub.Scraper = _NoCoreInfo
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/x.yml").write_text(
                    'files:\n  - name: "disk.rom"\n    aliases: ["n88sub.rom"]\n'
                )
                with mock.patch.dict(sys.modules, {"scraper.coreinfo_scraper": stub}):
                    return generate_db._collect_all_aliases(files)
            finally:
                os.chdir(previous)

    @staticmethod
    def _file(name: str, path: str, md5: str) -> dict:
        return {"name": name, "path": path, "md5": md5}

    def test_homonyms_take_no_alias(self):
        files = {
            "a": self._file("disk.rom", "bios/NEC/PC-98/disk.rom", "m1"),
            "b": self._file("disk.rom", "bios/Tandy/CoCo/disk.rom", "m2"),
        }
        aliases = self._aliases(files)
        named = {a["name"] for entries in aliases.values() for a in entries}
        self.assertNotIn("n88sub.rom", named)

    def test_a_unique_name_still_carries_its_aliases(self):
        files = {"a": self._file("disk.rom", "bios/NEC/PC-88/disk.rom", "m1")}
        aliases = self._aliases(files)
        self.assertEqual([a["name"] for a in aliases.get("a", [])], ["n88sub.rom"])


class NoNetworkInTheBuild(unittest.TestCase):
    def test_generate_db_reads_no_remote_source(self):
        """core-info was fetched on every run, offline ones included."""
        source = (REPO_ROOT / "scripts" / "generate_db.py").read_text(encoding="utf-8")
        self.assertNotIn("coreinfo_scraper", source)
        self.assertNotIn("urllib.request", source)

    def test_hash_proven_entry_registers_its_own_name(self):
        import generate_db

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/g.yml").write_text(
                    'files:\n  - name: "writer.rom"\n    sha1: "s1"\n'
                )
                aliases = generate_db._collect_all_aliases(
                    {"s1": {"name": "WRITER.ROM", "path": "bios/WRITER.ROM", "md5": "m"}}
                )
            finally:
                os.chdir(previous)
        self.assertEqual([a["name"] for a in aliases.get("s1", [])], ["writer.rom"])

class AcceptedRevisionLists(unittest.TestCase):
    def test_a_list_of_sha1_names_every_held_revision(self):
        """A profile accepting several revisions writes sha1 as a list."""
        import generate_db

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/m.yml").write_text(
                    'files:\n  - name: "MT32_CONTROL.ROM"\n'
                    '    sha1: ["s1", "s2", "absent"]\n'
                )
                aliases = generate_db._collect_all_aliases({
                    "s1": {"name": "ctrl_1_04.rom", "path": "a", "md5": "m1"},
                    "s2": {"name": "ctrl_1_05.rom", "path": "b", "md5": "m2"},
                })
            finally:
                os.chdir(previous)
        for sha in ("s1", "s2"):
            self.assertEqual([a["name"] for a in aliases.get(sha, [])], ["MT32_CONTROL.ROM"])

if __name__ == "__main__":
    unittest.main()
