"""The command line report judges "undeclared" on the flat declared set.

Per normalized system id, bk and elektronika-bk never met, nor nintendo-sgb
and nintendo-super-game-boy: 646 entries whose exact name a platform
declares were counted undeclared, while verify and the site read one flat
set, enriched with every spelling the database knows.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import load_database, load_emulator_profiles  # noqa: E402
from cross_reference import (  # noqa: E402
    _build_supplemental_index,
    cross_reference,
    declared_names,
    load_platform_files,
)


class FlatDeclaredSet(unittest.TestCase):
    def test_a_name_declared_under_another_system_id_is_not_a_gap(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("no database.json")
        db = load_database(str(REPO_ROOT / "database.json"))
        platforms = str(REPO_ROOT / "platforms")
        profiles = {k: v for k, v in load_emulator_profiles(str(REPO_ROOT / "emulators")).items() if k == "bk"}
        if not profiles:
            self.skipTest("no bk profile")
        declared, data_dirs = load_platform_files(platforms, ["batocera"])
        names = _build_supplemental_index()
        per_system = cross_reference(profiles, declared, db, data_dirs, names)
        flat = cross_reference(
            profiles, declared, db, data_dirs, names,
            all_declared=declared_names(platforms, ["batocera"], db),
        )
        gaps = {g["name"] for g in flat["bk"]["gap_details"]}
        self.assertNotIn("MONIT10.ROM", gaps)
        self.assertLess(flat["bk"]["gaps"], per_system["bk"]["gaps"])


if __name__ == "__main__":
    unittest.main()
