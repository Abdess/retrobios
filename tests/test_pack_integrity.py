#!/usr/bin/env python3
"""End-to-end pack integrity test.

Thin unittest wrapper around generate_pack.py --verify-packs.
Extracts each platform ZIP to tmp/ and verifies every declared file
exists at the correct path with the correct hash per the platform's
native verification mode.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
DIST_DIR = os.path.join(REPO_ROOT, "dist")
PLATFORMS_DIR = os.path.join(REPO_ROOT, "platforms")


def _platform_has_pack(platform_name: str) -> bool:
    """Check if a pack ZIP exists for the platform."""
    if not os.path.isdir(DIST_DIR):
        return False
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    from common import load_platform_config
    config = load_platform_config(platform_name, PLATFORMS_DIR)
    display = config.get("platform", platform_name).replace(" ", "_")
    return any(
        f.endswith("_BIOS_Pack.zip") and display in f
        for f in os.listdir(DIST_DIR)
    )


class PackIntegrityTest(unittest.TestCase):
    """Verify each platform pack via generate_pack.py --verify-packs."""

    def _verify_platform(self, platform_name: str) -> None:
        if not _platform_has_pack(platform_name):
            self.skipTest(f"no pack found for {platform_name}")
        result = subprocess.run(
            [sys.executable, "scripts/generate_pack.py",
             "--platform", platform_name,
             "--verify-packs", "--output-dir", "dist/"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        if result.returncode != 0:
            self.fail(
                f"{platform_name} pack integrity failed:\n"
                f"{result.stdout}\n{result.stderr}"
            )

    def test_retroarch(self):
        self._verify_platform("retroarch")

    def test_batocera(self):
        self._verify_platform("batocera")

    def test_bizhawk(self):
        self._verify_platform("bizhawk")

    def test_emudeck(self):
        self._verify_platform("emudeck")

    def test_recalbox(self):
        self._verify_platform("recalbox")

    def test_retrobat(self):
        self._verify_platform("retrobat")

    def test_retrodeck(self):
        self._verify_platform("retrodeck")

    def test_romm(self):
        self._verify_platform("romm")


if __name__ == "__main__":
    unittest.main()
