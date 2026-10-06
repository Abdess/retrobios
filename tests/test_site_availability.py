"""An emulator page never shows an unsourceable entry as held.

The page resolved each entry by name without the `unsourceable:` check
cross_reference runs first: ioquake3's pak0.pk3 wore a green "in repo"
badge, served by the pak0.pk3 of another game, and 52 such entries read as
held across the site while the gaps page listed them as known absences.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from generate_site import _availability_check, _file_badges

SHA1 = "a" * 40
DB = {
    "files": {SHA1: {"name": "pak0.pk3", "sha1": SHA1, "path": "bios/x/pak0.pk3"}},
    "indexes": {"by_name": {"pak0.pk3": [SHA1]}},
}


class UnsourceableIsNotHeld(unittest.TestCase):
    def test_a_homonym_does_not_stand_in(self):
        available = _availability_check(DB, set())
        self.assertTrue(available({"name": "pak0.pk3"}))
        self.assertFalse(available({"name": "pak0.pk3", "unsourceable": "retail data"}))

    def test_the_badge_says_why(self):
        entry = {"name": "pak0.pk3", "unsourceable": "retail data"}
        badges = " ".join(_file_badges(entry, False))
        self.assertIn("unsourceable", badges)
        self.assertNotIn(">missing<", badges)
        self.assertNotIn("in repo", badges)

    def test_no_profile_entry_is_shown_held(self):
        from common import load_database

        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        available = _availability_check(load_database(str(db_path)), set())
        shown_held = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            shown_held.extend(
                f"{path.stem}: {entry['name']}"
                for entry in document.get("files") or []
                if isinstance(entry, dict) and entry.get("unsourceable")
                and available(entry)
            )
        self.assertEqual(shown_held, [])


if __name__ == "__main__":
    unittest.main()
