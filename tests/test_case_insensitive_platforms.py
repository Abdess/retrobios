"""A platform the installer targets on Windows or macOS packs case-insensitively.

RetroBat shipped quasi88/N88.ROM (the md5 it pins) beside quasi88/n88.rom;
extracted on NTFS the second overwrote the first and RetroBat's own check
went red. The flag lived in retrobat.yml and vanished at the next scrape.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from common import load_platform_config  # noqa: E402


class CaseInsensitiveWhereTheFilesystemIs(unittest.TestCase):
    def test_windows_and_macos_platforms_carry_the_flag(self):
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        for name, data in registry["platforms"].items():
            systems = {str(d.get("os")) for d in (data.get("install") or {}).get("detect", [])}
            if systems & {"windows", "darwin"}:
                with self.subTest(platform=name):
                    config = load_platform_config(name, str(REPO_ROOT / "platforms"))
                    self.assertTrue(config.get("case_insensitive_fs"))


if __name__ == "__main__":
    unittest.main()
