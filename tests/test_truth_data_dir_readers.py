"""A core that reads a file through its data directory is one of its readers.

LRPS2 reads pcsx2/resources/GameIndex.yaml from the tree its data directory
reference names and declares no file entry for it. The truth entry other
cores build for that path named armsx2 and yaps2 alone, so the export paired
RetroArch's System.dat line, which describes LRPS2's copy, with armsx2's
revision, and hash_conflict did not see LRPS2's value.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "exporter"))

from exporter.baseline import checked_hashes  # noqa: E402
from truth import generate_platform_truth  # noqa: E402

GAME_INDEX = "pcsx2/resources/GameIndex.yaml"
DECLARED = b"the revision armsx2 declares"
TREE_COPY = b"the revision the tree holds"


def _profile(name: str, **fields) -> dict:
    return {"emulator": name, "type": "libretro", "systems": ["sony-playstation-2"], **fields}


class DataDirectoryReaders(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        for tree, content in (("lrps2", TREE_COPY), ("resources", TREE_COPY)):
            relative = GAME_INDEX if tree == "lrps2" else "GameIndex.yaml"
            copy = root / tree / relative
            copy.parent.mkdir(parents=True)
            copy.write_bytes(content)
        self.registry = {
            "lrps2": {"local_cache": str(root / "lrps2")},
            "resources": {"local_cache": str(root / "resources")},
        }
        self.profiles = {
            "armsx2": _profile("armsx2", files=[{
                "name": "GameIndex.yaml", "path": GAME_INDEX, "system": "sony-playstation-2",
                "sha1": hashlib.sha1(DECLARED).hexdigest(),
            }]),
            "lrps2": _profile("lrps2", data_directories=[
                {"ref": "lrps2", "destination": ""},
            ], files=[{"name": "<bios>.bin", "path": "pcsx2/bios/<bios>.bin"}]),
            # Names what it reads in the tree, patches.zip alone: the tree
            # adds no reader of GameIndex.yaml (pcee2 compiles it in).
            "listed": _profile("listed", data_directories=[
                {"ref": "resources", "destination": "pcsx2/resources"},
            ], files=[{"name": "patches.zip", "path": "pcsx2/resources/patches.zip"}]),
        }
        self.config = {"cores": ["armsx2", "lrps2", "listed"],
                       "systems": {"sony-playstation-2": {"files": []}}}

    def _entry(self, registry: dict) -> dict:
        model = generate_platform_truth(
            "plat", self.config, {}, self.profiles, data_registry=registry,
        )
        return next(
            f for f in model["systems"]["sony-playstation-2"]["files"]
            if f["name"] == "GameIndex.yaml"
        )

    def test_the_reader_counts_and_its_copy_conflicts(self):
        entry = self._entry(self.registry)
        self.assertEqual(entry["_cores"], ["armsx2", "lrps2"])
        self.assertIn("sha1", entry["hash_conflict"])
        # The kept value describes one revision among those the cores read:
        # it pairs a line, it never corrects one.
        self.assertNotIn("sha1", checked_hashes(entry))

    def test_without_the_cache_nothing_is_folded(self):
        entry = self._entry({})
        self.assertEqual(entry["_cores"], ["armsx2"])
        self.assertNotIn("hash_conflict", entry)

    def test_the_same_copy_adds_a_reader_and_no_conflict(self):
        tree_copy = Path(self.registry["lrps2"]["local_cache"]) / GAME_INDEX
        tree_copy.write_bytes(DECLARED)
        entry = self._entry(self.registry)
        self.assertEqual(entry["_cores"], ["armsx2", "lrps2"])
        self.assertNotIn("hash_conflict", entry)


if __name__ == "__main__":
    os.environ.setdefault("RETROBIOS_OFFLINE", "1")
    unittest.main()
