"""The name step does not settle on another emulator's copy.

xm6typeg asked for SCSIINROM.DAT: only XM6 Utility's synthesized image
matched the casing, under bios/Other/xm6pro68k/, and the X68000 dump stored
as scsiinrom.dat was never a candidate. blueMSX asked for RS232.ROM: its own
8 KB copy was msx-emu's, set aside as foreign, and the 16 KB file left was
served while data/bluemsx held the 8 KB one.
"""

from __future__ import annotations

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

    def test_another_casing_in_another_tree_is_not_the_file(self):
        """reminiscence's music module reunion took skyline's
        zoneinfo/Indian/Reunion, a time-zone file, on the casefold step."""
        self._hold("bios/Other/skyline/tzdata/zoneinfo/Indian/Reunion", b"T" * 64)
        entry = {
            "name": "reunion", "aliases": ["mod.flashback-reunion"],
            "category": "game_data", "source_profile": "reminiscence",
        }
        self.assertEqual(resolve_local_file(entry, self.db), (None, "not_found"))


if __name__ == "__main__":
    unittest.main()
