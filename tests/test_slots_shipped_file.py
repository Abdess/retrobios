"""Slot arbitration models the file the pack ships at a destination.

slots.py chose the platform's file by a rule of its own and folded case on
every platform. The builder keeps case on Linux frontends and picks, among
declarations sharing a destination, the archive most zipped_file members
accept, then the md5_exact one. RetroDECK's MSX ``DISK.ROM`` was reported as
colliding with ``disk.rom``, which ships beside it, and Batocera's
``adam_fdc.zip`` was taken for the one-member MAME set.
Reads the repository: skips when the database or the files are absent.
"""

from __future__ import annotations

import tests

import copy
import hashlib
import os
import unittest
from pathlib import Path

from model.database import load_database
from model.platforms import load_platform_config
from packs import slots
from resolve import collisions

REPO_ROOT = Path(__file__).resolve().parents[1]

MAME_ADAM = "bios/Arcade/MAME/adam_fdc.zip"
MSX_DISK = "bios/Microsoft/MSX/DISK.ROM"
COCO_DISK = "bios/Tandy/CoCo/disk.rom"


def _needs(*paths: str) -> None:
    missing = [p for p in ("database.json", *paths) if not (REPO_ROOT / p).exists()]
    if missing:
        raise unittest.SkipTest(f"repository data absent: {missing}")


class SlotsReadTheShippedFile(unittest.TestCase):
    def setUp(self):
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)

    def test_case_kept_where_the_filesystem_keeps_it(self):
        """RetroDECK runs on Linux: the MSX DISK.ROM and the CoCo disk.rom
        are two files. Its own manifests declare DISK.ROM for MSX and PC-88
        too, a collision of the same name, which stays. Only the folded
        pairing with disk.rom must not."""
        _needs(MSX_DISK, COCO_DISK)
        db = load_database("database.json")
        config = load_platform_config("retrodeck")
        self.assertFalse(config.get("case_insensitive_fs"))

        def paired(cfg: dict) -> bool:
            return any({MSX_DISK, COCO_DISK} <= set(collision.resolved)
                       for collision in collisions.find_collisions(cfg, db))

        self.assertFalse(paired(config))
        folded = copy.deepcopy(config)
        folded["case_insensitive_fs"] = True
        self.assertTrue(paired(folded))

    def test_profile_judged_against_the_builders_archive(self):
        _needs(MAME_ADAM)
        db = load_database("database.json")
        config = load_platform_config("batocera")
        # The declaration the one-member MAME set answers comes first: the
        # YAML's order must not decide which archive is believed to ship,
        # the builder takes the one most members accept.
        files = config["systems"]["adam"]["files"]
        files.sort(key=lambda fe: not str(fe.get("zipped_file", "")).startswith("adam disk"))
        md5 = hashlib.md5((REPO_ROOT / MAME_ADAM).read_bytes()).hexdigest()
        profiles = {
            "probe": {
                "emulator": "probe",
                "type": "libretro",
                "files": [
                    {"name": "adam_fdc.zip", "md5": md5, "system": "coleco-adam"}
                ],
            }
        }
        conflicts = slots.find_conflicts(
            config, profiles, db, config.get("base_destination", "")
        )
        shipped = {c.destination: c.platform_claim.local_path for c in conflicts}
        self.assertIn("bios/adam_fdc.zip", shipped)
        self.assertNotEqual(shipped["bios/adam_fdc.zip"], MAME_ADAM)


if __name__ == "__main__":
    unittest.main()
