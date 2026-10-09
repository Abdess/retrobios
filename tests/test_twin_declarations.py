"""A destination two systems declare with two hashes ships one file.

RetroDECK declares bios/disk.rom for pc88 (the N88SUB ROM) and for coco (the
CoCo disk ROM), and bios/cdibios.zip for two components with two md5. The
pack holds one file per path; verify resolved each declaration to its own
file and counted both OK, so three green tools described a pack whose
frontend hashes bios/disk.rom for xroar and finds the PC-88 ROM.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
from verify import verify_platform  # noqa: E402


class TwinDeclarations(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        files, self.md5 = {}, {}
        for rel, payload in (
            ("bios/NEC/PC-98/N88SUB.ROM", b"pc88 disk rom"),
            ("bios/Tandy/CoCo/disk.rom", b"coco disk rom"),
        ):
            path = Path(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            self.md5[rel] = hashlib.md5(payload).hexdigest()
            files[sha1] = {
                "path": rel, "name": path.name, "size": len(payload), "sha1": sha1,
                "md5": self.md5[rel], "sha256": hashlib.sha256(payload).hexdigest(),
                "crc32": "00000001",
            }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        self.emulators = Path(self._tmp.name) / "emulators"
        self.emulators.mkdir()
        common._emulator_profiles_cache.clear()

    def tearDown(self):
        common._emulator_profiles_cache.clear()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_the_losing_declaration_is_scored_against_the_shipped_file(self):
        config = {
            "platform": "Twins",
            "verification_mode": "md5",
            "base_destination": "bios",
            "cores": [],
            "systems": {
                "pc88": {"files": [{"name": "N88SUB.ROM", "destination": "disk.rom",
                                    "md5": self.md5["bios/NEC/PC-98/N88SUB.ROM"]}]},
                "coco": {"files": [{"name": "disk.rom", "destination": "disk.rom",
                                    "md5": self.md5["bios/Tandy/CoCo/disk.rom"]}]},
            },
        }
        report = verify_platform(
            config, self.db, str(self.emulators), {}, supplemental_names=set()
        )
        by_system = {d["system"]: d for d in report["details"] if d["name"] in ("N88SUB.ROM", "disk.rom")}
        statuses = sorted(d["status"] for d in by_system.values())
        self.assertEqual(statuses.count("ok"), 1, by_system)
        loser = next(d for d in by_system.values() if d["status"] != "ok")
        self.assertIn("is not met at the path", loser.get("discrepancy", ""))
        # The path counts once, for the file it ships; the loser is a detail.
        self.assertEqual(report["status_counts"], {"ok": 1})


if __name__ == "__main__":
    unittest.main()
