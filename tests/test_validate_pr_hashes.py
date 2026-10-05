"""validate_pr knows every revision a platform accepts.

It read the platform YAMLs raw: a Recalbox md5 field "a,b,c" stayed one
value, so a pull request adding the seventh falcon.img Recalbox lists was
answered "hash differs, may be a variant". Inheritance and shared groups
were lost the same way.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class EveryAcceptedRevisionIsKnown(unittest.TestCase):
    def test_multi_hash_members_are_known(self):
        import validate_pr

        known = validate_pr.load_platform_hashes(str(REPO_ROOT / "platforms"))
        raw = yaml.safe_load((REPO_ROOT / "platforms" / "recalbox.yml").read_text())
        listed = [
            value.strip().lower()
            for system in raw["systems"].values()
            for entry in system.get("files", [])
            if "," in str(entry.get("md5", ""))
            for value in str(entry["md5"]).split(",")
        ]
        self.assertTrue(listed)
        self.assertEqual([v for v in listed if v not in known["md5"]], [])


if __name__ == "__main__":
    unittest.main()
