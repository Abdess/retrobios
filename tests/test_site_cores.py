"""The site counts a platform's cores the way the builder resolves them.

The cross-reference page re-implemented the resolution and dropped the
libretro set a cores: list naming retroarch pulls in: RetroDECK read 20 cores
where its pack is built from 321.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

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
        unique = {k: v for k, v in profiles.items() if v.get("type") != "alias" and v.get("role") != "test"}
        coverages = {}
        for name in list_registered_platforms(platforms):
            config = load_platform_config(name, platforms)
            coverages[name] = {"platform": config.get("platform", name), "config": config}
        moved: dict[str, str] = {}
        page = generate_site.generate_cross_reference(coverages, profiles, moved)
        shown = {
            m.group(1): int(m.group(2))
            for m in re.finditer(r"^\| \[([^\]]+)\]\(platforms/[^)]+\) \| (\d+)", page, re.M)
        }
        for name, cov in coverages.items():
            with self.subTest(page=name):
                if generate_site._own_list_only(cov["config"]):
                    # cores: [] (MiSTer, BizHawk): no core table, the overview
                    # row points at the platform's own list instead.
                    self.assertNotIn(f"cross-reference-{name}", moved)
                    self.assertEqual(shown[cov["platform"]], 0)
                    continue
                rows = [line for line in moved[f"cross-reference-{name}"].splitlines()
                        if line.startswith("| [")]
                self.assertEqual(len(rows), shown[cov["platform"]])
        for name, cov in coverages.items():
            with self.subTest(platform=name):
                expected = len(resolve_platform_cores(cov["config"], unique))
                self.assertEqual(shown[cov["platform"]], expected)


class AllLibretroLabel(unittest.TestCase):
    """RetroPie and RetroDECK pull in every libretro core by naming retroarch
    in a list, and the label read "(all libretro)" for RetroArch and Lakka
    only, the two whose cores: is the string."""

    PROFILES = {
        "a": {"type": "libretro"},
        "b": {"type": "standalone + libretro"},
        "sa": {"type": "standalone"},
    }

    def test_a_list_naming_retroarch_is_labelled(self):
        note = generate_site._core_scope_note(
            {"cores": ["retroarch", "sa"]}, self.PROFILES)
        self.assertEqual(note, " (all libretro, plus 1 other core)")

    def test_the_string_form_is_labelled(self):
        note = generate_site._core_scope_note({"cores": "all_libretro"}, self.PROFILES)
        self.assertEqual(note, " (all libretro)")

    def test_a_selection_is_not(self):
        self.assertEqual(
            generate_site._core_scope_note({"cores": ["a", "sa"]}, self.PROFILES), "")


if __name__ == "__main__":
    unittest.main()
