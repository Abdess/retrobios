"""Batocera runs every emulator its ES lists, not only each system's default.

The platform scraper read configgen-defaults.yml alone, one core per system,
so DOSBox Staging, melonDS DS and nine other cores Batocera builds and lets a
user pick stayed outside the pack. The target scraper read es_systems.yml but
dropped a standalone emulator's own name, keeping only the machines listed
under it: amiberry, fsuae and vice were never in a target list.
"""

from __future__ import annotations

import tests

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

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


class OneWalkReadsEsSystems(unittest.TestCase):
    """The scraper and the target scraper read es_systems.yml through one walk."""

    def test_every_core_in_file_order(self):
        from scripts.scraper.batocera_scraper import es_systems_entries

        rows = [(s, e, c) for s, e, c, _spec in es_systems_entries(ES_SYSTEMS)]
        self.assertEqual(rows, [
            ("dos", "libretro", "dosbox_pure"),
            ("dos", "libretro", "dosbox_staging"),
            ("dos", "dosbox", "dosbox"),
            ("amiga500", "amiberry", "A500"),
        ])

    def test_an_emulator_without_core_is_yielded_once(self):
        from scripts.scraper.batocera_scraper import es_systems_entries

        text = "x:\n  emulators:\n    vice:\n      archs_include: [x86_64]\n"
        self.assertEqual(list(es_systems_entries(text)), [("x", "vice", None, None)])

    def test_a_file_that_is_not_a_mapping_is_refused(self):
        from scripts.scraper.batocera_scraper import es_systems_entries
        from scripts.scraper.targets.batocera_targets_scraper import _parse_es_systems

        with self.assertRaises(ValueError):
            list(es_systems_entries("- a\n- b\n"))
        with self.assertRaises(ValueError):
            _parse_es_systems("- a\n")


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
        from resolve.layout import DUAL_MODE_PREFIX
        from resolve.standalone import platform_layouts

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
        from scripts.scraper.es_emulators import es_cores, xml_systems

        cfg = ("<systemList><system><name>gamecube</name><emulators>"
               "<emulator name=\"libretro\"><cores><core>dolphin</core></cores></emulator>"
               "<emulator name=\"dolphin\"/></emulators></system></systemList>")
        self.assertEqual(es_cores(xml_systems(cfg), {"libretro": None})[2], ["dolphin"])
        ini = "[core.0]\nemulator = libretro\ncore = dolphin\n[core.1]\nemulator = dolphin\ncore = dolphin\n"
        _cores, standalone = system_ini_cores(ini)
        self.assertEqual(system_ini_libretro(ini) & standalone, {"dolphin"})

    def test_upstream_yaml_is_read_as_its_code_reads_it(self):
        """configgen-defaults.yml names rtcw's core twice. The strict loader
        stopped the rescrape, while Batocera's PyYAML keeps the last value."""
        from model.safeparse import yaml_load_upstream

        self.assertEqual(
            yaml_load_upstream("rtcw:\n  core: iortcw\n  core: taradino\n"),
            {"rtcw": {"core": "taradino"}},
        )


class DualModeNameReachesTheLibretroBuild(unittest.TestCase):
    """Batocera runs pcsx2 standalone and as LRPS2. The name matched the
    standalone profile's key and lrps2, which lists pcsx2 in cores:, was
    left out of the platform."""

    def test_both_builds_of_a_dual_mode_name_resolve(self):
        from resolve.cores import resolve_platform_cores

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
        from resolve.cores import resolve_platform_cores

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
        from resolve.cores import resolve_platform_cores

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
        from model.profiles import load_emulator_profiles
        from model.platforms import load_platform_config
        from resolve.cores import resolve_platform_cores

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        platforms = str(REPO_ROOT / "platforms")

        def ps2_cores(platform: str) -> set[str]:
            config = load_platform_config(platform, platforms)
            return {
                c for c in resolve_platform_cores(config, profiles)
                if c.startswith(("lrps2", "pcsx2", "pcee2"))
            }

        self.assertEqual(ps2_cores("batocera"), {"lrps2-416291a", "pcsx2", "pcee2"})
        # Recalbox ships two libretro PS2 builds on x86_64: LRPS2 as ps2 and
        # the wxWidgets-era libretro PCSX2 as pcsx2, beside standalone PCSX2.
        self.assertEqual(
            ps2_cores("recalbox"), {"lrps2-9485a53", "pcsx2-libretro-408e3b2", "pcsx2"}
        )
        own_builds = {"lrps2-416291a", "lrps2-9485a53", "pcsx2-libretro-408e3b2"}
        for platform in ("retroarch", "retrobat", "emudeck", "retrodeck"):
            with self.subTest(platform=platform):
                cores = ps2_cores(platform)
                self.assertIn("lrps2", cores)
                self.assertFalse(own_builds & cores)
        self.assertNotIn("pcsx2-libretro-408e3b2", ps2_cores("batocera"))
        for name in sorted(own_builds):
            self.assertEqual(profiles[name]["files"][0]["path"], "ps2/<bios>.bin")


class OneLocatorFindsTheSystemsDict(unittest.TestCase):
    """The scraper and the exporter cut batocera-systems at the same braces."""

    SCRIPT = (
        "import os\n"
        "systems = OrderedDict({\n"
        "    'a': { 'name': 'it''s }', \"biosFiles\": [ # } in a comment\n"
        "        { \"md5\": \"x\", \"file\": 'bios/#a.bin' } ] },\n"
        "    })\n"
        "def checkBios(): pass\n"
    )

    def test_the_braces_are_read_past_strings_and_comments(self):
        from scripts.scraper.batocera_scraper import extract_systems_dict, systems_span

        start, end = systems_span(self.SCRIPT)
        self.assertEqual(self.SCRIPT[start], "{")
        self.assertEqual(self.SCRIPT[end:end + 2], "})")
        self.assertEqual(extract_systems_dict(self.SCRIPT)["a"]["biosFiles"][0]["file"], "bios/#a.bin")

    def test_the_exporter_cuts_at_the_same_lines(self):
        from exporter.batocera_exporter import Exporter

        head, body, tail = Exporter._split_original(self.SCRIPT)
        self.assertEqual(head[-1], "systems = OrderedDict({")
        self.assertEqual(len(body), 2)
        self.assertEqual(tail[0], "    })")

    def test_a_comment_starts_outside_either_quote(self):
        from scripts.scraper.batocera_scraper import comment_start

        self.assertIsNone(comment_start("'a#b', \"c#d\""))
        self.assertEqual(comment_start("'a#b' # note"), 6)

    def test_an_unclosed_dict_is_refused(self):
        from scripts.scraper.batocera_scraper import systems_span

        with self.assertRaisesRegex(ValueError, "not closed"):
            systems_span("systems = {\n 'a': {}\n")
        with self.assertRaisesRegex(ValueError, "no 'systems = {'"):
            systems_span("other = {}\n")


if __name__ == "__main__":
    unittest.main()
