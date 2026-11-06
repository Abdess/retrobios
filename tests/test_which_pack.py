"""The Get your files page sends each platform to the pack built for it.

RetroPie's row linked the RetroArch pack, although a RetroPie pack is
published and carries 3916 files the RetroArch one does not.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class WhichPackRows(unittest.TestCase):
    """Every row of the Get your files page links only its own pack.

    The rows were written by hand and the RetroPie one sent readers to the
    RetroArch pack. They are now built from each platform's registry key, and
    this reads the rendered page to keep it so. The per-platform folder notes
    that getting-started.md carried moved to each platform page, built by the
    same key.
    """

    def test_platform_rows_name_their_own_pack(self):
        """A row links its own get/ page, never another setup's and never a
        release asset: the asset URL dies with its tag."""
        import generate_site  # noqa: PLC0415
        import release_record  # noqa: PLC0415

        record = release_record.load_advertised()
        page = generate_site.generate_which_pack()
        row = re.compile(r"^\| \[[^\]]+\]\(platforms/([a-z0-9]+)\.md\) \|(.*)$", re.M)
        get = re.compile(r'href="get/([a-z0-9]+)\.md"')
        checked = 0
        for key, rest in row.findall(page):
            linked = set(get.findall(rest))
            pack = release_record.pack_for(key, record)
            with self.subTest(platform=key):
                self.assertNotIn("/releases/download/", rest)
                self.assertLessEqual(linked, {key})
                if pack:
                    checked += 1
                    self.assertEqual(linked, {key})
                elif not generate_site.has_release_pack(key):
                    self.assertIn(f"No ZIP. [Use the command](platforms/{key}.md#install).", rest)
        self.assertGreater(checked, 3)
