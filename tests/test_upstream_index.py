"""One reverse index from upstream core names to profiles.

Five copies broke ties differently. The target branch of
resolve_platform_cores kept the last profile claiming a name, so the
buildbot's `pcsx2` (the LRPS2 core) mapped to the standalone pcsx2 profile
and a RetroArch target pack lost LRPS2's files.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    preferred_profile,
    resolve_platform_cores,
    upstream_profile_index,
)

PROFILES = {
    "lrps2": {"type": "libretro", "cores": ["lrps2", "pcsx2"]},
    "pcsx2": {"type": "standalone", "cores": ["pcsx2"]},
}


class OneIndex(unittest.TestCase):
    def test_target_keeps_every_claimant(self):
        config = {"cores": "all_libretro"}
        self.assertEqual(
            resolve_platform_cores(config, PROFILES, target_cores={"pcsx2"}), {"lrps2"}
        )

    def test_platform_list_prefers_the_key(self):
        config = {"cores": ["pcsx2"]}
        self.assertEqual(resolve_platform_cores(config, PROFILES), {"pcsx2"})
        self.assertEqual(preferred_profile(upstream_profile_index(PROFILES), "pcsx2"), "pcsx2")

    def test_no_hand_made_index(self):
        pattern = re.compile(r"(upstream_to_profile|core_to_profile)\[[^\]]+\]\s*=")
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            with self.subTest(module=path.name):
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
