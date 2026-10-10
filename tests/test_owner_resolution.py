"""Every reader of a profile entry names its owner, as the builder does.

The resolver prefers the owning profile's copy when a name has several. The
builder passes `source_profile`; the site's consumer index, the slot claims
and the agnostic scan did not, and resolved 95 entries to other files: the
site credited aethersx2's game_controller_db.txt to armsx2 and left the copy
armsx2's pack ships without a reader, and MAME's neogeo.zip without MAME.
"""

from __future__ import annotations

import sys
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
            raise unittest.SkipTest("database.json is not built")
        cls.db = load_database(str(db_path))
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        cls.sha1_by_path = {r["path"]: s for s, r in cls.db["files"].items()}

    def test_the_site_credits_the_copy_the_pack_ships(self):
        consumers = cross_reference.FileConsumers(
            self.db, build_zip_contents_index(self.db)
        )
        consumers.add_emulators(self.profiles)
        for path, owner in (
            ("bios/Other/armsx2/game_controller_db.txt", "armsx2"),
            ("bios/Arcade/MAME/neogeo.zip", "mame"),
        ):
            with self.subTest(path=path):
                sha1 = self.sha1_by_path.get(path)
                if sha1 is None:
                    self.skipTest(f"{path} is not collected")
                self.assertIn(owner, consumers.emulators.get(sha1, set()))

    def test_slot_claims_resolve_the_owners_tree(self):
        claims = slots.profile_claims({"pcem": self.profiles["pcem"]}, self.db)
        held = {
            claim.destination.rsplit("/", 1)[-1]: claim.local_path for claim in claims
        }
        local = held.get("ide_xt.bin")
        if local is None:
            self.skipTest("ide_xt.bin is not claimed")
        self.assertTrue(local.startswith("bios/Other/pcem/"), local)


if __name__ == "__main__":
    unittest.main()
