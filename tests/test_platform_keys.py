"""Code reads platform entries by the keys the platform YAMLs write.

expand_platform_declared_names skipped archive members through
`fe.get("zippedFile")`, the upstream Batocera spelling. The YAMLs write
`zipped_file`, so a member's md5 was taken for a loose file and its name
counted as declared: 76 Batocera entries added names such as boot0.rom.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# Where the camelCase key is the upstream format itself: scrapers read it,
# the Batocera exporter writes it back.
UPSTREAM_FORMAT = {"scraper", "exporter"}


class ZippedFileKey(unittest.TestCase):
    def test_no_entry_is_read_by_the_upstream_spelling(self):
        pattern = re.compile(r"""\.get\(\s*["']zippedFile["']|\[\s*["']zippedFile["']\s*\]""")
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            if UPSTREAM_FORMAT & set(path.relative_to(REPO_ROOT / "scripts").parts[:-1]):
                continue
            with self.subTest(module=str(path.relative_to(REPO_ROOT))):
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")))

    def test_member_md5_declares_no_loose_name(self):
        from common import expand_platform_declared_names

        config = {"systems": {"s": {"files": [
            {"name": "casloopy.zip", "md5": "m1", "zipped_file": "hd6437021.lsi302"},
        ]}}}
        db = {"files": {"x": {"name": "boot0.rom"}}, "indexes": {"by_md5": {"m1": "x"}}}
        self.assertEqual(expand_platform_declared_names(config, db), {"casloopy.zip"})


if __name__ == "__main__":
    unittest.main()
