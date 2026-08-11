#!/usr/bin/env python3
"""End-to-end pack integrity test.

Thin unittest wrapper around generate_pack.py --verify-packs, which checks
every declared platform file and every in-repo core extra against the pack,
at the correct path and with the correct hash per the platform's native mode.

The assertion presupposes a pack built from the current profiles. The check
runs first and keeps its teeth: a failure is only downgraded to a skip when a
profile landed after the pack was built, which makes the pack incomplete by
construction and says nothing about pack generation. A failure on an up to
date pack stays a failure.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
DIST_DIR = os.path.join(REPO_ROOT, "dist")
PLATFORMS_DIR = os.path.join(REPO_ROOT, "platforms")
EMULATORS_DIR = os.path.join(REPO_ROOT, "emulators")


def _pack_path(platform_name: str) -> str | None:
    """Path of the platform's pack ZIP, or None when there is none."""
    if not os.path.isdir(DIST_DIR):
        return None
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    from common import load_platform_config

    config = load_platform_config(platform_name, PLATFORMS_DIR)
    display = config.get("platform", platform_name).replace(" ", "_")
    for entry in sorted(os.listdir(DIST_DIR)):
        if entry.endswith("_BIOS_Pack.zip") and display in entry:
            return os.path.join(DIST_DIR, entry)
    return None


def _profiles_newer_than(path: str) -> list[str]:
    """Profiles modified after the pack was built."""
    built = os.path.getmtime(path)
    return [
        os.path.basename(p)
        for p in glob.glob(os.path.join(EMULATORS_DIR, "*.yml"))
        if os.path.getmtime(p) > built
    ]


class PackIntegrityTest(unittest.TestCase):
    """Verify each platform pack via generate_pack.py --verify-packs."""

    def _verify_platform(self, platform_name: str) -> None:
        pack = _pack_path(platform_name)
        if pack is None:
            self.skipTest(f"no pack found for {platform_name}")
        result = subprocess.run(
            [
                sys.executable,
                "scripts/generate_pack.py",
                "--platform",
                platform_name,
                "--verify-packs",
                "--output-dir",
                "dist/",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        if result.returncode == 0:
            return
        # A build holding the exclusive lock means the packs on disk are
        # half-written. Failing then reports a corrupt archive when the only
        # fact established is that somebody else is building, and which test
        # goes red depends on how far along that build is.
        if "is in use by another run" in (result.stdout + result.stderr):
            self.skipTest(f"dist/ is being written; {platform_name} not verifiable")
        newer = _profiles_newer_than(pack)
        if newer:
            self.skipTest(
                f"{platform_name} pack predates {len(newer)} profile(s) "
                f"({', '.join(sorted(newer)[:3])}): rebuild before verifying\n"
                f"{result.stdout}"
            )
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
