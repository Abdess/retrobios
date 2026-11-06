"""A dump the frontend refuses does not hold a regional slot.

platform_region_groups counted a declaration as held as soon as a file
answered it, hash_mismatch included. On a md5 platform the builder leaves
that file out as unsafe, so a US file with the wrong md5 displaced a correct
Japanese one, and the system shipped no BIOS at all.
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

from packextras import _ships  # noqa: E402


class ARefusedDumpHoldsNothing(unittest.TestCase):
    def test_held_follows_the_frontend(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        Path("bios").mkdir()
        data = b"US BIOS, ANOTHER REVISION"
        Path("bios/us.bin").write_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        db = {
            "files": {sha1: {"path": "bios/us.bin", "name": "us.bin", "size": len(data),
                             "md5": hashlib.md5(data).hexdigest(), "crc32": ""}},
            "indexes": {"by_md5": {}, "by_name": {"us.bin": [sha1]}, "by_crc32": {},
                        "by_path_suffix": {}},
        }
        entry = {"name": "us.bin", "md5": "0" * 32}
        def ships(config: dict, fe: dict) -> bool:
            return _ships(config, fe, db, None, None, None)

        self.assertFalse(ships({"verification_mode": "md5"}, entry))
        self.assertTrue(ships({"verification_mode": "existence"}, entry))
        self.assertTrue(ships({"verification_mode": "md5"}, {"name": "us.bin"}))


class ADataDirectoryCopyIsHeld(unittest.TestCase):
    """The region pass resolves with the builder's inputs.

    Without the data directories, AmberELEC's config.ini (served from the
    bluemsx tree) and dolphin-mmjr2's nwc24msg.cfg (served from the Dolphin
    Sys tree) read as missing while both packs held them.
    """

    @classmethod
    def setUpClass(cls):
        if not (REPO_ROOT / "data" / "bluemsx").is_dir() or not (
            REPO_ROOT / "data" / "dolphin-sys"
        ).is_dir():
            raise unittest.SkipTest("data/ not refreshed")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            from common import load_data_dir_registry, load_database
            from common import load_emulator_profiles, load_platform_config
            cls.db = load_database("database.json")
            cls.registry = load_data_dir_registry("platforms")
            cls.profiles = load_emulator_profiles("emulators")
            cls.amberelec = load_platform_config("amberelec", "platforms")
        finally:
            os.chdir(previous)

    def setUp(self):
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)

    def test_platform_declaration_from_a_data_tree(self):
        entry = next(
            fe for fe in self.amberelec["systems"]["coleco-colecovision"]["files"]
            if fe["destination"].endswith("Dina/config.ini")
        )
        self.assertTrue(
            _ships(self.amberelec, entry, self.db, {}, self.registry, None)
        )

    def test_emulator_entry_from_a_data_tree(self):
        from packextras import _emulator_ships
        from validation import _build_validation_index

        profile = self.profiles["dolphin-mmjr2"]
        entry = next(
            fe for fe in profile["files"] if fe.get("name") == "nwc24msg.cfg"
        )
        index = _build_validation_index({"dolphin-mmjr2": profile})
        self.assertTrue(_emulator_ships(
            entry, "dolphin-mmjr2", profile, self.db, index, {}, self.registry,
        ))


if __name__ == "__main__":
    unittest.main()
