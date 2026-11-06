"""A platform that inherits another one.

The child was merged over the parent's cached config: its overrides rewrote
the parent's systems for the rest of the run, and the parent's registry
fields hid the child's own, so RetroPie loaded as active with RetroArch's
scraper and install block.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402


class AChildLeavesItsParentAlone(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._shared_yml_cache.clear)
        files = {
            "parent.yml": {"platform": "Parent", "verification_mode": "existence",
                           "systems": {"sys-a": {"files": [{"name": "a.bin"}]}}},
            "child.yml": {"platform": "Child", "inherits": "parent", "overrides": {
                "systems": {"sys-a": {"files": [{"name": "child.bin"}]},
                            "sys-new": {"files": [{"name": "new.bin"}]}}}},
            "_registry.yml": {"platforms": {
                "parent": {"device_group": "computer", "scraper": "parent",
                           "hash_type": "md5", "cores": "all_libretro"},
                "child": {"device_group": "gaming-os", "scraper": "child"},
            }},
        }
        for name, data in files.items():
            (self.dir / name).write_text(yaml.safe_dump(data))

    def load(self, name):
        return common.load_platform_config(name, str(self.dir))

    def test_the_parent_keeps_its_systems(self):
        self.load("parent")
        self.load("child")
        parent = self.load("parent")
        self.assertEqual(list(parent["systems"]), ["sys-a"])
        self.assertEqual(
            parent["systems"]["sys-a"]["files"],
            [{"name": "a.bin", "platform_system": "sys-a"}],
        )

    def test_the_child_reads_its_own_registry_entry_first(self):
        self.load("parent")
        child = self.load("child")
        self.assertEqual((child["device_group"], child["scraper"]), ("gaming-os", "child"))
        # What it does not say comes from its parent's entry.
        self.assertEqual((child["hash_type"], child["cores"]), ("md5", "all_libretro"))
        self.assertEqual(
            child["systems"]["sys-a"]["files"],
            [{"name": "child.bin", "platform_system": "sys-a"}],
        )



class ALinuxPlatformKeepsBothCases(unittest.TestCase):
    """Lakka and RetroPie inherited RetroArch's case folding although both
    run on Linux: np2kai opens 2608_bd.wav and MesenCE bios.col with that
    exact case, and only System.dat's 2608_BD.WAV and BIOS.col shipped."""

    def setUp(self):
        self.addCleanup(common._platform_config_cache.clear)
        common._platform_config_cache.clear()

    def test_the_linux_platforms_do_not_fold(self):
        platforms = str(REPO_ROOT / "platforms")
        self.assertTrue(common.load_platform_config("retroarch", platforms)["case_insensitive_fs"])
        for name in ("lakka", "retropie"):
            with self.subTest(platform=name):
                config = common.load_platform_config(name, platforms)
                self.assertFalse(config["case_insensitive_fs"])
                dests = {
                    f.get("destination", f.get("name"))
                    for system in config["systems"].values() for f in system["files"]
                }
                self.assertTrue({"np2kai/2608_BD.WAV", "np2kai/2608_bd.wav"} <= dests)

    def test_lakka_does_not_share_retroarchs_pack(self):
        groups = common.group_identical_platforms(
            ["retroarch", "lakka"], str(REPO_ROOT / "platforms")
        )
        self.assertEqual(sorted(g for g, _rep in groups), [["lakka"], ["retroarch"]])


if __name__ == "__main__":
    unittest.main()
