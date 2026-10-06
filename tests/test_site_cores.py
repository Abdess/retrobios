"""The site counts a platform's cores the way the builder resolves them.

The cross-reference page re-implemented the resolution and dropped the
libretro set a cores: list naming retroarch pulls in: RetroDECK read 20 cores
where its pack is built from 321.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
from common import (  # noqa: E402
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    resolve_platform_cores,
)


class SiteCoreCounts(unittest.TestCase):
    def test_each_platform_count_is_the_resolved_set(self):
        platforms = str(REPO_ROOT / "platforms")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        unique = {k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")}
        coverages = {}
        for name in list_registered_platforms(platforms, include_archived=True):
            config = load_platform_config(name, platforms)
            coverages[name] = {"platform": config.get("platform", name), "config": config}
        page = generate_site.generate_cross_reference(coverages, profiles)
        shown = {
            m.group(1): int(m.group(2))
            for m in re.finditer(r'\?\?\? abstract "([^"]+)"\n\n.*\n\n {4}\*\*(\d+) cores', page)
        }
        for name, cov in coverages.items():
            with self.subTest(platform=name):
                expected = len(resolve_platform_cores(cov["config"], unique))
                self.assertEqual(shown[cov["platform"]], expected)


if __name__ == "__main__":
    unittest.main()
