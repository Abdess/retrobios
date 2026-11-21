"""One reverse index from upstream core names to profiles.

Five copies broke ties differently. The target branch of
resolve_platform_cores kept the last profile claiming a name, so the
buildbot's `pcsx2` (the LRPS2 core) mapped to the standalone pcsx2 profile
and a RetroArch target pack lost LRPS2's files.
"""

from __future__ import annotations

import tests

import re
import unittest
from pathlib import Path

from model.profiles import (
    core_key_index, platform_builds, platform_core_profiles, preferred_profile,
    upstream_profile_index,
)
from resolve.cores import resolve_platform_cores

REPO_ROOT = Path(__file__).resolve().parents[1]

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


# The claimants of three names Recalbox and RetroPie write, as the profiles
# declared them when both exporters kept one by load order.
CONTESTED = {
    "lrps2": {"type": "libretro", "cores": ["lrps2", "pcsx2"]},
    "lrps2-416291a": {"type": "libretro", "cores": ["pcsx2"], "built_by": ["batocera"]},
    "pcsx2-libretro-408e3b2": {"type": "libretro", "cores": ["pcsx2"], "built_by": ["recalbox"]},
    "pcsx2": {"type": "standalone", "cores": ["pcsx2"]},
    "amiberry": {"type": "standalone + libretro", "cores": ["amiberry", "AMIBERRY"]},
    "amiberry-5.6.5": {"type": "standalone", "cores": ["amiberry"], "built_by": ["rocknix"]},
    "amiberry-5.7.2": {"type": "standalone", "cores": ["amiberry"], "built_by": ["retropie"]},
    "amiberry-6.3.3": {"type": "standalone", "cores": ["amiberry"], "built_by": ["retropie"]},
    "amiberry-8.2.2": {"type": "standalone + libretro", "cores": ["amiberry"],
                       "built_by": ["recalbox"]},
    "vice": {"type": "libretro", "cores": ["vice_x64", "vice_x64sc"]},
    "vice_x64": {"type": "libretro", "cores": ["vice_x64", "x64"]},
}


class PlatformCoreProfiles(unittest.TestCase):
    """A core name in a platform's own list means the build that platform
    ships, whatever order the profiles load in."""

    def designated(self, name: str, platform: str, mode: str | None) -> set[str]:
        index = core_key_index(CONTESTED, include_aliases=True)
        return platform_core_profiles(index, CONTESTED, name, platform, mode)

    def test_the_platforms_own_build_answers(self):
        self.assertEqual(self.designated("pcsx2", "recalbox", "libretro"),
                         {"pcsx2-libretro-408e3b2"})
        self.assertEqual(self.designated("pcsx2", "batocera", "libretro"), {"lrps2-416291a"})
        self.assertEqual(self.designated("AMIBERRY", "recalbox", "libretro"), {"amiberry-8.2.2"})

    def test_the_mode_named_narrows_the_claimants(self):
        self.assertEqual(self.designated("pcsx2", "recalbox", "standalone"), {"pcsx2"})

    def test_every_own_build_of_a_name_answers(self):
        self.assertEqual(self.designated("amiberry", "retropie", "standalone"),
                         {"amiberry-5.7.2", "amiberry-6.3.3"})

    def test_another_platforms_build_never_answers(self):
        self.assertEqual(self.designated("amiberry", "lakka", "standalone"), {"amiberry"})
        self.assertEqual(self.designated("pcsx2", "lakka", "libretro"), {"lrps2"})

    def test_the_profile_keyed_by_the_name_comes_first(self):
        self.assertEqual(self.designated("vice-x64", "recalbox", "libretro"), {"vice_x64"})
        self.assertEqual(self.designated("vice_x64sc", "recalbox", "libretro"), {"vice"})

    def test_no_mode_reads_both_builds(self):
        self.assertEqual(self.designated("pcsx2", "lakka", None), {"pcsx2"})

    def test_platform_builds_keeps_unbuilt_claimants(self):
        self.assertEqual(
            platform_builds({"lrps2", "lrps2-416291a"}, CONTESTED, "recalbox"), {"lrps2"}
        )


if __name__ == "__main__":
    unittest.main()
