"""--required-only reaches archives in emulator packs.

geolith declares neocd.zip and irrmaze.zip optional, members included, and
its _Required pack held them anyway: the archive loop never read `required`.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class RequiredOnlyArchives(unittest.TestCase):
    def test_optional_archives_stay_out(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json not built")
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            result = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--emulator", "geolith",
                 "--required-only", "--offline", "--output-dir", tmp],
                capture_output=True, text=True, cwd=REPO_ROOT, timeout=600,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pack = next(Path(tmp).glob("*.zip"))
            names = set(zipfile.ZipFile(pack).namelist())
        self.assertNotIn("neocd.zip", names)
        self.assertNotIn("irrmaze.zip", names)
        self.assertIn("neogeo.zip", names)


if __name__ == "__main__":
    unittest.main()
