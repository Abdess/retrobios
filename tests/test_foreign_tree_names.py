"""The name step does not settle on another emulator's copy.

xm6typeg asked for SCSIINROM.DAT: only XM6 Utility's synthesized image
matched the casing, under bios/Other/xm6pro68k/, and the X68000 dump stored
as scsiinrom.dat was never a candidate. blueMSX asked for RS232.ROM: its own
8 KB copy was msx-emu's, set aside as foreign, and the 16 KB file left was
served while data/bluemsx held the 8 KB one.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import resolve_local_file  # noqa: E402


class ForeignTreeNames(unittest.TestCase):
    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        # The collection's paths are relative to the repository root.
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.root)
        self.db = {"files": {}, "indexes": {
            "by_md5": {}, "by_name": {}, "by_crc32": {}, "by_path_suffix": {},
        }}

    def _hold(self, rel: str, data: bytes) -> str:
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        name = rel.rsplit("/", 1)[-1]
        if "/.variants/" in rel:
            name = name.rsplit(".", 1)[0]
        self.db["files"][sha1] = {
            "path": rel, "name": name, "size": len(data),
            "md5": hashlib.md5(data).hexdigest(), "crc32": "",
        }
        self.db["indexes"]["by_name"].setdefault(name, []).append(sha1)
        return rel

    def test_a_casing_only_another_tree_holds(self):
        self._hold("bios/Other/xm6pro68k/.variants/SCSIINROM.DAT.47404fbb", b"X" * 64)
        own = self._hold("bios/Sharp/X68000/scsiinrom.dat", b"D" * 64)
        entry = {"name": "SCSIINROM.DAT", "source_emulator": "xm6typeg"}
        self.assertEqual(resolve_local_file(entry, self.db)[0], own)

    def test_a_set_aside_copy_sends_the_name_to_the_data_directory(self):
        self._hold("bios/Microsoft/MSX/RS232.ROM", b"L" * 128)
        self._hold("bios/Other/msx-emu/Machines/Shared Roms/RS232.ROM", b"S" * 64)
        cache = self.root / "data" / "bluemsx"
        (cache / "Machines" / "Shared Roms").mkdir(parents=True)
        (cache / "Machines" / "Shared Roms" / "RS232.ROM").write_bytes(b"S" * 64)
        entry = {
            "name": "RS232.ROM", "path": "Machines/Shared Roms/RS232.ROM",
            "size": 64, "source_emulator": "bluemsx",
        }
        path, status = resolve_local_file(
            entry, self.db,
            data_dir_registry={"bluemsx": {"local_cache": str(cache)}},
        )
        self.assertEqual(status, "data_dir")
        self.assertEqual(Path(path).stat().st_size, 64)

    def test_a_casing_only_another_tree_holds_reads_the_data_directory(self):
        """MSX2P.rom: only msx-emu's tree had the exact casing, and widening
        to every casing served Microsoft/MSX/MSX2P.ROM, another dump, while
        data/bluemsx held the one blueMSX ships."""
        self._hold("bios/Other/msx-emu/Machines/Shared Roms/MSX2P.rom", b"B" * 64)
        self._hold("bios/Microsoft/MSX/MSX2P.ROM", b"O" * 64)
        cache = self.root / "data" / "bluemsx"
        (cache / "Machines" / "Shared Roms").mkdir(parents=True)
        (cache / "Machines" / "Shared Roms" / "MSX2P.rom").write_bytes(b"B" * 64)
        entry = {
            "name": "MSX2P.rom", "path": "Machines/Shared Roms/MSX2P.rom",
            "source_emulator": "bluemsx",
        }
        path, status = resolve_local_file(
            entry, self.db,
            data_dir_registry={"bluemsx": {"local_cache": str(cache)}},
        )
        self.assertEqual(status, "data_dir")
        self.assertEqual(Path(path).read_bytes(), b"B" * 64)

    def _bluemsx_cache(self, rel: str, data: bytes) -> dict:
        cache = self.root / "data" / "bluemsx"
        (cache / rel).parent.mkdir(parents=True, exist_ok=True)
        (cache / rel).write_bytes(data)
        return {"bluemsx": {"local_cache": str(cache)}}

    def test_a_platform_declaration_reads_the_data_directory_at_its_path(self):
        """AmberELEC declares every blueMSX machine's config.ini with no hash.
        The name step met msx-emu's ColecoVision config.ini first and wrote it
        into each machine folder, while data/bluemsx held the machine's own
        at that very path."""
        self._hold("bios/Other/msx-emu/Machines/COL - ColecoVision/config.ini", b"C" * 64)
        registry = self._bluemsx_cache("Machines/MSX - Arabic/config.ini", b"A" * 64)
        entry = {
            "name": "config.ini",
            "destination": "bios/Machines/MSX - Arabic/config.ini",
        }
        path, status = resolve_local_file(entry, self.db, data_dir_registry=registry)
        self.assertEqual(status, "path_exact")
        self.assertEqual(Path(path).read_bytes(), b"A" * 64)

    def test_a_platform_rs232_rom_reads_the_data_directory_at_its_path(self):
        self._hold("bios/Microsoft/MSX/RS232.ROM", b"L" * 128)
        registry = self._bluemsx_cache("Machines/Shared Roms/RS232.ROM", b"S" * 64)
        entry = {
            "name": "RS232.ROM",
            "destination": "bios/Machines/Shared Roms/RS232.ROM",
        }
        path, _status = resolve_local_file(entry, self.db, data_dir_registry=registry)
        self.assertEqual(Path(path).read_bytes(), b"S" * 64)

    def test_a_profile_dump_outranks_the_free_copy_of_its_tree(self):
        """Dolphin's dsp_coef.bin: the dump in bios/ wins over the free
        replacement Sys/GC bundles at the same path."""
        own = self._hold("bios/Nintendo/GameCube/.variants/dsp_coef.bin.c116d867", b"R" * 64)
        cache = self.root / "data" / "dolphin-sys"
        (cache / "GC").mkdir(parents=True)
        (cache / "GC" / "dsp_coef.bin").write_bytes(b"F" * 64)
        entry = {
            "name": "dsp_coef.bin", "destination": "GC/dsp_coef.bin",
            "source_profile": "dolphin",
        }
        path, _status = resolve_local_file(
            entry, self.db, dest_hint="GC/dsp_coef.bin",
            data_dir_registry={"dolphin-sys": {"local_cache": str(cache)}},
        )
        self.assertEqual(path, own)

    def test_another_casing_in_another_tree_is_not_the_file(self):
        """reminiscence's music module reunion took skyline's
        zoneinfo/Indian/Reunion, a time-zone file, on the casefold step."""
        self._hold("bios/Other/skyline/tzdata/zoneinfo/Indian/Reunion", b"T" * 64)
        entry = {
            "name": "reunion", "aliases": ["mod.flashback-reunion"],
            "category": "game_data", "source_profile": "reminiscence",
        }
        self.assertEqual(resolve_local_file(entry, self.db), (None, "not_found"))


class RetailDashboardTree(unittest.TestCase):
    """x1-box asked for C/xbox.xtf: the only copy at that tail sat in hakuX's
    tree and was set aside, and the name step served Xenia's Xbox 360 font.
    The retail dashboard both emulators import lives with the console."""

    def test_partition_c_resolves_by_path_for_both_importers(self):
        import yaml

        from common import load_database

        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json absent")
        db = load_database(str(db_path))
        for profile in ("x1-box", "hakux"):
            document = yaml.safe_load(
                (REPO_ROOT / "emulators" / f"{profile}.yml").read_text()
            )
            for entry in document["files"]:
                dest = str(entry.get("path") or "")
                if not dest.startswith("C/"):
                    continue
                with self.subTest(profile=profile, dest=dest):
                    asked = {**entry, "source_profile": profile}
                    cwd = os.getcwd()
                    os.chdir(REPO_ROOT)
                    try:
                        path, status = resolve_local_file(asked, db, dest_hint=dest)
                    finally:
                        os.chdir(cwd)
                    self.assertEqual(status, "path_exact", path)


class TheGapReportAsksAsTheEmulator(unittest.TestCase):
    """dosbox-x's et4000.bin, no hash: pcem's et4000.BIN was its only
    casing. The resolver, asked as dosbox-x, refuses it and the pack and the
    installer leave the file out, while the gap report, verify's core files
    and the manifest's held flag counted it available."""

    _hold = ForeignTreeNames._hold

    def setUp(self):
        ForeignTreeNames.setUp(self)
        self._hold("bios/Other/pcem/roms/et4000.BIN", b"E" * 64)
        self.entry = {"name": "et4000.bin", "required": True}

    def _source(self, owner: str) -> str | None:
        from cross_reference import entry_source

        by_name = self.db["indexes"]["by_name"]
        index = {
            "by_name": by_name, "by_name_lower": {k.lower(): k for k in by_name},
            "by_path_suffix": {}, "by_md5": {}, "by_sha256": {}, "by_crc32": {},
            "db_files": self.db["files"], "data_names": None,
        }
        return entry_source({**self.entry, "source_profile": owner}, index)

    def test_another_tree_casing_is_not_held(self):
        self.assertIsNone(self._source("dosbox-x"))
        entry = {**self.entry, "source_profile": "dosbox-x"}
        self.assertEqual(resolve_local_file(entry, self.db), (None, "not_found"))

    def test_the_tree_owner_holds_it(self):
        self.assertEqual(self._source("pcem"), "bios")

    def test_core_files_follow_the_resolver(self):
        from verify import find_undeclared_files

        profiles = {"dosbox-x": {
            "emulator": "DOSBox-X", "type": "libretro", "systems": ["dos"],
            "files": [self.entry],
        }}
        config = {"platform": "P", "verification_mode": "md5", "cores": ["dosbox-x"],
                  "systems": {"dos": {"files": []}}}
        (found,) = [
            u for u in find_undeclared_files(config, "emulators", self.db, profiles)
            if u["name"] == "et4000.bin"
        ]
        self.assertFalse(found["in_repo"])


if __name__ == "__main__":
    unittest.main()
