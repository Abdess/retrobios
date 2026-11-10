"""Batocera runs every emulator its ES lists, not only each system's default.

The platform scraper read configgen-defaults.yml alone, one core per system,
so DOSBox Staging, melonDS DS and nine other cores Batocera builds and lets a
user pick stayed outside the pack. The target scraper read es_systems.yml but
dropped a standalone emulator's own name, keeping only the machines listed
under it: amiberry, fsuae and vice were never in a target list.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

ES_SYSTEMS = """\
dos:
  emulators:
    libretro:
      dosbox_pure: { requireAnyOf: [BR2_PACKAGE_LIBRETRO_DOSBOX_PURE] }
      dosbox_staging: { requireAnyOf: [BR2_PACKAGE_LIBRETRO_DOSBOX_STAGING] }
    dosbox:
      dosbox: { requireAnyOf: [BR2_PACKAGE_DOSBOX] }
amiga500:
  emulators:
    amiberry:
      A500: { requireAnyOf: [BR2_PACKAGE_AMIBERRY] }
      archs_include: [x86_64]
"""


class ThePlatformListsEveryOfferedCore(unittest.TestCase):
    def test_libretro_cores_and_standalone_emulators(self):
        from scripts.scraper.batocera_scraper import es_systems_emulators

        cores, standalone = es_systems_emulators(ES_SYSTEMS)
        self.assertEqual(
            cores, {"dosbox_pure", "dosbox_staging", "dosbox", "amiberry", "A500"}
        )
        self.assertEqual(standalone, {"dosbox", "amiberry", "A500"})

    def test_the_overrides_drop_the_machine_selectors(self):
        from scripts.scraper.batocera_scraper import _not_cores

        self.assertIn("A500", _not_cores())

    def test_the_registry_leaves_the_list_to_the_scraper(self):
        import yaml

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        self.assertNotIn("cores", registry["platforms"]["batocera"])
        platform = yaml.safe_load((REPO_ROOT / "platforms" / "batocera.yml").read_text())
        self.assertIn("dosbox_staging", platform["cores"])


class TheTargetsNameTheStandaloneEmulator(unittest.TestCase):
    def test_the_group_name_is_a_core(self):
        from scripts.scraper.targets.batocera_targets_scraper import _parse_es_systems

        mapping = _parse_es_systems(ES_SYSTEMS)
        self.assertEqual(mapping["BR2_PACKAGE_AMIBERRY"], ["amiberry", "A500"])
        self.assertEqual(mapping["BR2_PACKAGE_LIBRETRO_DOSBOX_STAGING"], ["dosbox_staging"])



class AnEmulatorLaunchedBothWaysGetsBothLayouts(unittest.TestCase):
    """es_systems.yml offers libretro:dolphin and standalone dolphin for
    GameCube. Filed as standalone only, the pack gave libretro Dolphin no
    dolphin-emu/Sys/GC/ files: no IPL, no DSP ROM."""

    def test_the_scraper_names_dual_mode_emulators(self):
        from scripts.scraper.batocera_scraper import es_systems_emulators, es_systems_libretro

        text = ES_SYSTEMS + (
            "gamecube:\n  emulators:\n    libretro:\n      dolphin: { requireAnyOf: [X] }\n"
            "    dolphin:\n      dolphin: { requireAnyOf: [Y] }\n"
        )
        _cores, standalone = es_systems_emulators(text)
        self.assertEqual(standalone & es_systems_libretro(text), {"dolphin"})

    def test_the_layouts_are_both(self):
        from common import DUAL_MODE_PREFIX, platform_layouts

        profile = {"type": "standalone + libretro", "cores": ["dolphin"], "files": []}
        both = platform_layouts("dolphin", profile, {"dolphin", DUAL_MODE_PREFIX + "dolphin"})
        self.assertEqual([standalone for _view, standalone in both], [False, True])
        only = platform_layouts("dolphin", profile, {"dolphin"})
        self.assertEqual([standalone for _view, standalone in only], [True])

    def test_the_batocera_manifest_carries_both(self):
        import json

        manifest = json.loads((REPO_ROOT / "install" / "batocera.json").read_text())
        dests = {entry["dest"] for entry in manifest["files"]}
        self.assertIn("dolphin-emu/Sys/GC/USA/IPL.bin", dests)
        self.assertIn("GC/USA/IPL.bin", dests)

    def test_retrobat_and_recalbox_name_theirs(self):
        from scripts.scraper.recalbox_scraper import system_ini_cores, system_ini_libretro
        from scripts.scraper.retrobat_scraper import es_systems_dual

        cfg = ("<systemList><system><emulators>"
               "<emulator name=\"libretro\"><cores><core>dolphin</core></cores></emulator>"
               "<emulator name=\"dolphin\"/></emulators></system></systemList>")
        self.assertEqual(es_systems_dual(cfg), {"dolphin"})
        ini = "[core.0]\nemulator = libretro\ncore = dolphin\n[core.1]\nemulator = dolphin\ncore = dolphin\n"
        _cores, standalone = system_ini_cores(ini)
        self.assertEqual(system_ini_libretro(ini) & standalone, {"dolphin"})

    def test_upstream_yaml_is_read_as_its_code_reads_it(self):
        """configgen-defaults.yml names rtcw's core twice. The strict loader
        stopped the rescrape, while Batocera's PyYAML keeps the last value."""
        from safeparse import yaml_load_upstream

        self.assertEqual(
            yaml_load_upstream("rtcw:\n  core: iortcw\n  core: taradino\n"),
            {"rtcw": {"core": "taradino"}},
        )


class DualModeNameReachesTheLibretroBuild(unittest.TestCase):
    """Batocera runs pcsx2 standalone and as LRPS2. The name matched the
    standalone profile's key and lrps2, which lists pcsx2 in cores:, was
    left out of the platform."""

    def test_both_builds_of_a_dual_mode_name_resolve(self):
        from common import resolve_platform_cores

        profiles = {
            "pcsx2": {"type": "standalone", "cores": ["pcsx2"]},
            "lrps2": {"type": "libretro", "cores": ["lrps2", "pcsx2"]},
            "mame0278": {"type": "libretro", "cores": ["pcsx2"], "built_by": ["x"]},
        }
        config = {"cores": ["pcsx2"], "standalone_cores": ["pcsx2"]}
        self.assertEqual(resolve_platform_cores(config, profiles), {"pcsx2"})
        config["dual_mode_cores"] = ["pcsx2"]
        self.assertEqual(resolve_platform_cores(config, profiles), {"pcsx2", "lrps2"})


class APlatformsOwnBuildWinsItsName(unittest.TestCase):
    """Recalbox's uae4all is the libretro uae4all-rpi it compiles, RetroPie's
    the standalone uae4all2: one name, two programs."""

    def test_built_by_beats_the_key_match_for_that_platform_only(self):
        from common import resolve_platform_cores

        profiles = {
            "uae4all": {"type": "standalone", "cores": ["uae4all"]},
            "uae4all-rpi": {"type": "libretro", "cores": ["uae4all"], "built_by": ["recalbox"]},
        }
        recalbox = {"_key": "recalbox", "cores": ["uae4all"]}
        retropie = {"_key": "retropie", "cores": ["uae4all"]}
        self.assertEqual(resolve_platform_cores(recalbox, profiles), {"uae4all-rpi"})
        self.assertEqual(resolve_platform_cores(retropie, profiles), {"uae4all"})


class APatchedLibretroBuildTakesItsNameOnly(unittest.TestCase):
    """Batocera and Recalbox compile LRPS2 with a patch that reads the BIOS
    from ps2/ instead of pcsx2/bios/. Their own build replaces the buildbot
    LRPS2 under the name they ship, and Batocera's standalone PCSX2, under
    the same name, stays."""

    def test_own_libretro_build_keeps_the_standalone_of_a_dual_name(self):
        from common import resolve_platform_cores

        profiles = {
            "pcsx2": {"type": "standalone", "source": "s", "cores": ["pcsx2"]},
            "lrps2": {"type": "libretro", "source": "l", "cores": ["lrps2", "pcsx2"]},
            "lrps2-own": {"type": "libretro", "source": "l", "cores": ["pcsx2"],
                          "built_by": ["x"]},
        }
        config = {"_key": "x", "cores": ["pcsx2"], "standalone_cores": ["pcsx2"],
                  "dual_mode_cores": ["pcsx2"]}
        self.assertEqual(resolve_platform_cores(config, profiles), {"pcsx2", "lrps2-own"})
        del config["dual_mode_cores"]
        self.assertEqual(resolve_platform_cores(config, profiles), {"lrps2-own"})

    def test_the_registry_resolves_each_platform_build(self):
        from common import load_emulator_profiles, load_platform_config, resolve_platform_cores

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        platforms = str(REPO_ROOT / "platforms")

        def ps2_cores(platform: str) -> set[str]:
            config = load_platform_config(platform, platforms)
            return {
                c for c in resolve_platform_cores(config, profiles)
                if c.startswith(("lrps2", "pcsx2", "pcee2"))
            }

        self.assertEqual(ps2_cores("batocera"), {"lrps2-416291a", "pcsx2", "pcee2"})
        self.assertEqual(ps2_cores("recalbox"), {"lrps2-9485a53", "pcsx2"})
        for platform in ("retroarch", "retrobat", "emudeck", "retrodeck"):
            with self.subTest(platform=platform):
                cores = ps2_cores(platform)
                self.assertIn("lrps2", cores)
                self.assertFalse({"lrps2-416291a", "lrps2-9485a53"} & cores)
        self.assertEqual(profiles["lrps2-416291a"]["files"][0]["path"], "ps2/<bios>.bin")
        self.assertEqual(profiles["lrps2-9485a53"]["files"][0]["path"], "ps2/<bios>.bin")


if __name__ == "__main__":
    unittest.main()
