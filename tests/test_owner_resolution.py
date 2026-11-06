"""Every reader of a profile entry names its owner, as the builder does.

The resolver prefers the owning profile's copy when a name has several. The
builder passes `source_profile`. The site's consumer index, the slot claims
and the agnostic scan did not, and resolved 95 entries to other files: the
site credited aethersx2's game_controller_db.txt to armsx2 and left the copy
armsx2's pack ships without a reader, and MAME's neogeo.zip without MAME.
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

import cross_reference  # noqa: E402
import slots  # noqa: E402
from common import (  # noqa: E402
    build_zip_contents_index,
    load_database,
    load_emulator_profiles,
)


class ReadersNameTheOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise AssertionError("database.json is committed and missing")
        cls.db = load_database(str(db_path))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.sha1_by_path = {r["path"]: s for s, r in cls.db["files"].items()}

    def test_the_site_credits_the_copy_the_pack_ships(self):
        consumers = cross_reference.FileConsumers(
            self.db, build_zip_contents_index(self.db)
        )
        consumers.add_emulators(self.profiles)
        sha1 = self.sha1_by_path.get("bios/Arcade/MAME/neogeo.zip")
        self.assertIsNotNone(sha1, "MAME's neogeo.zip is not collected")
        self.assertIn("mame", consumers.emulators.get(sha1, set()))

    def test_slot_claims_resolve_the_owners_tree(self):
        claims = slots.profile_claims({"pcem": self.profiles["pcem"]}, self.db)
        held = {
            claim.destination.rsplit("/", 1)[-1]: claim.local_path for claim in claims
        }
        # pcem declares ide_xt.bin and the collection holds it: an unclaimed
        # file here is a claiming defect, not missing data.
        self.assertTrue(
            any(e.get("path", "").endswith("/ide_xt.bin")
                for e in self.db["files"].values()),
            "ide_xt.bin is not collected",
        )
        local = held.get("ide_xt.bin")
        self.assertIsNotNone(local, "pcem's ide_xt.bin is not claimed")
        self.assertTrue(local.startswith("bios/Other/pcem/"), local)


class EachForkReadsItsOwnCopy(unittest.TestCase):
    """Two emulators ship a file under one name in their own trees. Without
    the owner, the site credited aethersx2's game_controller_db.txt to
    armsx2 and left the copy armsx2's pack ships without a reader."""

    NAME = "game_controller_db.txt"

    def setUp(self):
        self._previous = os.getcwd()
        self._tree = tempfile.TemporaryDirectory()
        root = Path(self._tree.name)
        files: dict[str, dict] = {}
        self.sha1_of: dict[str, str] = {}
        for owner in ("aethersx2", "armsx2"):
            rel = f"bios/Other/{owner}/{self.NAME}"
            payload = f"{owner} mappings".encode()
            (root / rel).parent.mkdir(parents=True)
            (root / rel).write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {
                "name": self.NAME, "sha1": sha1, "path": rel,
                "md5": hashlib.md5(payload).hexdigest(), "size": len(payload),
            }
            self.sha1_of[owner] = sha1
        self.db = {"files": files, "indexes": {
            "by_name": {self.NAME: sorted(files)},
            "by_md5": {}, "by_path_suffix": {},
        }}
        os.chdir(root)

    def tearDown(self):
        os.chdir(self._previous)
        self._tree.cleanup()

    def test_the_site_credits_each_owner_with_its_copy(self):
        consumers = cross_reference.FileConsumers(self.db, data_dir_registry={})
        consumers.add_emulators({
            owner: {"type": "standalone", "files": [{"name": self.NAME}]}
            for owner in self.sha1_of
        })
        for owner, sha1 in self.sha1_of.items():
            with self.subTest(owner=owner):
                self.assertEqual(consumers.emulators.get(sha1), {owner})


if __name__ == "__main__":
    unittest.main()
