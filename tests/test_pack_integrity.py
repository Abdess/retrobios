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
    """Path of the platform's full pack, by the exact name the builder writes."""
    if not os.path.isdir(DIST_DIR):
        return None
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    from generate_pack import _expected_pack_names

    names = _expected_pack_names([platform_name], PLATFORMS_DIR, [], None)
    for entry in sorted(names[platform_name]):
        path = os.path.join(DIST_DIR, entry)
        if os.path.isfile(path):
            return path
    return None


def _registered_platforms() -> list[str]:
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    from common import list_registered_platforms

    return list_registered_platforms(PLATFORMS_DIR, include_archived=True)


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

    def test_every_registered_platform(self):
        """Every platform the registry knows, not a list written by hand.

        Eight names were written out and ROCKNIX and MiSTer FPGA, both
        released, were never checked.
        """
        for platform_name in _registered_platforms():
            with self.subTest(platform=platform_name):
                self._verify_platform(platform_name)


if __name__ == "__main__":
    unittest.main()
