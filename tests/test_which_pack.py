"""The "which pack" table sends each platform to the pack built for it.

RetroPie's row linked the RetroArch pack, although a RetroPie pack is
published and carries 3916 files the RetroArch one does not.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class WhichPackRows(unittest.TestCase):
    def test_platform_rows_name_their_own_pack(self):
        from common import (
            group_identical_platforms,
            list_registered_platforms,
            load_platform_config,
        )

        platforms_dir = str(REPO_ROOT / "platforms")
        registered = list_registered_platforms(platforms_dir, include_archived=True)
        display = {
            p: load_platform_config(p, platforms_dir).get("platform", p)
            for p in registered
        }
        packs_of: dict[str, set[str]] = {}
        for group, _rep in group_identical_platforms(registered, platforms_dir):
            names = {display[p] for p in group}
            for p in group:
                packs_of[display[p]] = names
        source = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        row = re.compile(r"^\| \[([^\]]+)\]\([^)]*\) \|[^|]*\| \[([^\]]+)\]\(\{rel\}\)", re.M)
        checked = 0
        for setup, pack in row.findall(source):
            if setup not in packs_of:
                continue
            checked += 1
            with self.subTest(setup=setup):
                self.assertIn(pack, packs_of[setup])
        self.assertGreater(checked, 5)


if __name__ == "__main__":
    unittest.main()
