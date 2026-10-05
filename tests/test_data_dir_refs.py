"""Every data_directories ref names a registered data directory.

yaps2 referenced yaps2-resources, absent from _data_dirs.yml: the pack and
verify only said "not cached" and refresh_data_dirs had nothing to fetch.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class DataDirRefsAreRegistered(unittest.TestCase):
    def test_no_unknown_ref(self):
        try:
            import validate_schemas
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")
        self.assertEqual(validate_schemas._unknown_data_dir_refs(), [])


if __name__ == "__main__":
    unittest.main()
