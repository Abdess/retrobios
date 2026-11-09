"""AmberELEC, EmuELEC and KNULLI publish Batocera's `systems` dict.

Each scraper reads its list with batocera_scraper's parser, so a dict written
with a key twice keeps the later value as Python does, paths keep the folder
the OS's checker prefixes, and the cores come from the OS's own
EmulationStation list. Trimmed copies of the three lists stand in for the
upstream files.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper import amberelec_scraper, emuelec_scraper, knulli_scraper  # noqa: E402
from scraper.es_emulators import (  # noqa: E402
    attach_system_cores,
    es_cores,
    json_systems,
    system_cores,
    xml_systems,
)

CHECKER = '''

def checkBios(systems, prefix):
    pass
'''

AMBERELEC = '''#!/usr/bin/env python
systems = {
    "atarilynx":  {"name": "Lynx", "biosFiles": [{"md5": "fcd403db69f54290b51035d82f835e7b", "file": "bios/lynxboot.img"}]},
    # Neo Geo
    "neogeo":   {"name": "NeoGeo", "biosFiles":    [{"md5": "", "file": "neogeo/neogeo.zip"},
                                                    {"md5": "", "file": "neogeo/aes.zip"}]},
}
''' + CHECKER

EMUELEC = '''#!/usr/bin/env python
systems = {
    "naomi":   { "name": "Naomi", "biosFiles":    [ { "md5": "e63d892cdb8b532351dc7020bb60b6f4", "file": "bios/dc/naomi.zip" } ] },
    "fmtowns": { "name": "Fujistu FM-Towns", "biosFiles": [
                 { "md5": "34847786d7de94b5d1133c956ab1d75d", "zippedFile": "fmt_dic.rom", "file": "bios/fmtowns.zip"} ] },
    "Diablo": { "name": "Diablo 1", "biosFiles": [ { "md5": "", "file": "ports/diablo/diabdat.mpq" } ] },
    "naomi":        { "name": "Naomi", "biosFiles":        [ { "md5": "3bffafac42a7767d8dcecf771f5552ba", "file": "bios/dc/naomi_boot.bin"   },
                                                             { "md5": "e63d892cdb8b532351dc7020bb60b6f4", "file": "bios/dc/naomi.zip"   } ] },
    }
''' + CHECKER

KNULLI = '''#!/usr/bin/env python
systems = {
    "msx1": { "name": "MSX1", "biosFiles": [ { "md5": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "file": "bios/MSX.ROM" } ] },
    "msu-md": { "name": "MSU-MD", "biosFiles": [ { "md5": "e66fa1dc5820d254611fdcdba0662372", "file": "bios/bios_CD_E.bin" } ] },
    "msx1": { "name": "MSX1", "emulator": "libretro", "core": "bluemsx", "biosFiles": [
              { "md5": "", "file": "bios/Machines/Shared Roms/MSX.rom" } ] },
}
''' + CHECKER

AMBERELEC_ES = """<?xml version="1.0" encoding="UTF-8"?>
<systemList>
  <system><name>advision</name><emulators>
    <emulator name="mame"><cores><core default="true">advision</core></cores></emulator>
  </emulators></system>
  <system><name>atarist</name><emulators>
    <emulator name="retroarch"><cores><core>hatari</core></cores></emulator>
    <emulator name="HATARISA"><cores><core>HATARISA</core></cores></emulator>
  </emulators></system>
  <system><name>psp</name><emulators>
    <emulator name="retroarch"><cores><core>ppsspp</core></cores></emulator>
    <emulator name="PPSSPPSDL"><cores><core>PPSSPPSDL</core></cores></emulator>
  </emulators></system>
  <system><name>dreamcast</name><emulators>
    <emulator name="retrorun"><cores><core>flycast</core></cores></emulator>
  </emulators></system>
</systemList>
"""

EMUELEC_ES = """{"systems": [
  {"name": "imageviewer", "command": "ignore"},
  {"name": "saturn", "emulators": [
    {"name": "libretro", "cores": [{"name": "yabasanshiro"}]},
    {"name": "yabasanshiro", "cores": [{"name": "yabasanshiroSA"}]}]},
  {"name": "atari2600", "emulators": [{"name": "STELLASA", "cores": [{"name": "STELLASA"}]}]}
]}"""


def _scraper(module, raw: str):
    scraper = module.Scraper(url="https://example.test/list")
    scraper._raw_data = raw
    return scraper


class TheListsReadAsPythonReadsThem(unittest.TestCase):
    def test_amberelec_keeps_paths_beside_bios(self):
        reqs = _scraper(amberelec_scraper, AMBERELEC).fetch_requirements()
        self.assertEqual(
            [(r.system, r.destination, r.native_id) for r in reqs],
            [("atari-lynx", "bios/lynxboot.img", "atarilynx"),
             ("snk-neogeo", "neogeo/neogeo.zip", "neogeo"),
             ("snk-neogeo", "neogeo/aes.zip", "neogeo")],
        )

    def test_emuelec_keeps_the_later_of_a_repeated_key(self):
        reqs = _scraper(emuelec_scraper, EMUELEC).fetch_requirements()
        naomi = [r.destination for r in reqs if r.native_id == "naomi"]
        self.assertEqual(naomi, ["bios/dc/naomi_boot.bin", "bios/dc/naomi.zip"])
        self.assertEqual(len(reqs), 4)

    def test_emuelec_files_a_port_under_its_engine_system(self):
        reqs = _scraper(emuelec_scraper, EMUELEC).fetch_requirements()
        diablo = next(r for r in reqs if r.native_id == "Diablo")
        self.assertEqual((diablo.system, diablo.destination),
                         ("diablo", "ports/diablo/diabdat.mpq"))

    def test_emuelec_carries_the_member_its_list_names(self):
        reqs = _scraper(emuelec_scraper, EMUELEC).fetch_requirements()
        towns = next(r for r in reqs if r.native_id == "fmtowns")
        self.assertEqual(towns.zipped_file, "fmt_dic.rom")

    def test_knulli_strips_bios_and_keeps_the_later_key(self):
        reqs = _scraper(knulli_scraper, KNULLI).fetch_requirements()
        self.assertEqual(
            [(r.system, r.destination, r.native_path) for r in reqs],
            [("microsoft-msx", "Machines/Shared Roms/MSX.rom", "bios/Machines/Shared Roms/MSX.rom"),
             ("sega-mega-cd", "bios_CD_E.bin", "bios/bios_CD_E.bin")],
        )

    def test_a_list_without_its_checker_is_refused(self):
        for module, raw in ((amberelec_scraper, AMBERELEC), (emuelec_scraper, EMUELEC),
                            (knulli_scraper, KNULLI)):
            with self.subTest(scraper=module.__name__), self.assertRaises(ValueError):
                _scraper(module, raw.replace("def checkBios", "def other")).fetch_requirements()


class TheCoresComeFromTheOsList(unittest.TestCase):
    def test_amberelec_runners_and_standalone_names(self):
        cores, standalone, dual = es_cores(
            xml_systems(AMBERELEC_ES), amberelec_scraper.RUNNERS, amberelec_scraper.BUILDS_OF
        )
        # mame lists MAME machines and loads the MAME core: advision is no core.
        self.assertIn("mame", cores)
        self.assertNotIn("advision", cores)
        self.assertNotIn("mame", standalone)
        self.assertIn("flycast", cores)
        # A standalone emulator keeps the name runemu.py dispatches on.
        self.assertEqual(standalone, ["HATARISA", "PPSSPPSDL"])
        self.assertEqual(dual, ["HATARISA", "PPSSPPSDL"])

    def test_emuelec_runners_and_standalone_names(self):
        cores, standalone, dual = es_cores(
            json_systems(EMUELEC_ES), emuelec_scraper.RUNNERS, emuelec_scraper.BUILDS_OF
        )
        self.assertEqual(standalone, ["STELLASA", "yabasanshiro"])
        self.assertNotIn("yabasanshiroSA", cores)
        self.assertEqual(dual, ["yabasanshiro"])

    def test_a_name_that_emulates_nothing_is_dropped(self):
        cores, standalone, _ = es_cores(
            json_systems(EMUELEC_ES), emuelec_scraper.RUNNERS, not_cores={"STELLASA"}
        )
        self.assertNotIn("STELLASA", cores + standalone)

    def test_each_system_keeps_its_cores_in_menu_order(self):
        by_system = system_cores(xml_systems(AMBERELEC_ES), amberelec_scraper.RUNNERS)
        self.assertEqual(by_system["atarist"], ["hatari", "HATARISA"])
        self.assertEqual(by_system["advision"], ["mame"])
        self.assertEqual(by_system["dreamcast"], ["flycast"])

    def test_a_slug_gathers_the_cores_of_its_native_systems(self):
        systems = {
            "diablo": {"native_id": "Diablo", "files": [
                {"native_system": "Diablo"}, {"native_system": "Hellfire"}]},
            "unlisted": {"native_id": "o2em", "files": []},
        }
        attach_system_cores(systems, {"Diablo": ["devilutionx"], "Hellfire": ["devilutionx", "x"]})
        self.assertEqual(systems["diablo"]["cores"], ["devilutionx", "x"])
        self.assertNotIn("cores", systems["unlisted"])

    def test_the_newest_prerelease_names_its_commit(self):
        body = "This is a prerelease based on the commit: AmberELEC/AmberELEC@" + "a" * 40 + "."
        self.assertEqual(amberelec_scraper.prerelease_commit(body), "a" * 40)
        with self.assertRaises(RuntimeError):
            amberelec_scraper.prerelease_commit("no commit here")


PORTS = """
2048:
  commands:
    - /usr/bin/emuelecRunEmu.sh "" -Pports "${2}" -C2048 "-SC${0}"

Diablo:
  check_bios: Diablo
  init_port: true
  port_exe: "devilutionx"
  commands:
    - devilutionx.sh >> $EE_LOG 2>&1

Flashback:
  check_bios: REminiscence
  commands:
    - /usr/bin/emuelecRunEmu.sh "/storage/roms/ports/reminiscence" -Pports "${2}" -Creminiscence "-SC${0}"
"""


class EmuelecPortsRunTheirEngine(unittest.TestCase):
    """The ES system `ports` has one emulator, `ports`, the dispatch to each
    port's script: what runs is the core or program the script names."""

    def test_each_port_names_its_engine(self):
        self.assertEqual(emuelec_scraper.port_engines(PORTS), [
            ("2048", "2048", None, True),
            ("Diablo", "devilutionx", "Diablo", False),
            ("Flashback", "reminiscence", "REminiscence", True),
        ])

    def test_engines_replace_the_dispatch(self):
        systems = emuelec_scraper.with_ports(
            {"ports": [("ports", ["ports"])]}, emuelec_scraper.port_engines(PORTS)
        )
        cores, standalone, _ = es_cores(systems, emuelec_scraper.RUNNERS)
        self.assertNotIn("ports", cores)
        self.assertEqual(standalone, ["devilutionx"])
        self.assertTrue({"2048", "reminiscence"} <= set(cores))
        by_system = system_cores(systems, emuelec_scraper.RUNNERS)
        self.assertEqual(by_system["Diablo"], ["devilutionx"])
        self.assertEqual(by_system["REminiscence"], ["reminiscence"])

    def test_a_port_without_an_engine_is_refused(self):
        with self.assertRaises(ValueError):
            emuelec_scraper.port_engines("Broken:\n  commands:\n    - true\n")


class CoreFilesGoUnderTheStatedFolder(unittest.TestCase):
    """EmuELEC's ports/ entries are a quarter of its list, so the most common
    root of its destinations fell under the 90% rule and core files went to
    /storage/roms itself, where no core reads them."""

    def test_core_destination_wins_over_the_guess(self):
        from common import declared_root

        files = [{"destination": f"bios/f{i}"} for i in range(3)]
        files.append({"destination": "ports/diablo/diabdat.mpq"})
        config = {"base_destination": "", "systems": {"s": {"files": files}}}
        self.assertEqual(declared_root(config), "")
        self.assertEqual(declared_root({**config, "core_destination": "bios"}), "bios")
        self.assertEqual(declared_root({**config, "base_destination": "bios",
                                        "core_destination": "x"}), "")

    def test_the_platforms_state_it(self):
        import yaml

        for name in ("amberelec", "emuelec"):
            with self.subTest(platform=name):
                config = yaml.safe_load((REPO_ROOT / "platforms" / f"{name}.yml").read_text())
                self.assertEqual((config["base_destination"], config["core_destination"]),
                                 ("", "bios"))


class TheExportKeepsTheirShape(unittest.TestCase):
    def test_an_indented_closing_brace_is_found(self):
        from exporter.emuelec_exporter import Exporter

        head, body, tail = Exporter._split_original(EMUELEC)
        self.assertEqual(head[-1], "systems = {")
        self.assertEqual(tail[0], "    }")
        self.assertIn("Diablo", "\n".join(body))

    def test_paths_start_where_the_list_starts(self):
        from exporter.amberelec_exporter import Exporter as Amber
        from exporter.baseline import NativeFile
        from exporter.knulli_exporter import Exporter as Knulli

        fe = NativeFile("neogeo.zip", "neogeo/neogeo.zip", "neogeo")
        self.assertEqual(Amber.declared_path(fe), "neogeo/neogeo.zip")
        fe = NativeFile("bios_CD_E.bin", "bios_CD_E.bin", "msu-md")
        self.assertEqual(Knulli.declared_path(fe), "bios/bios_CD_E.bin")


class TheCommittedListsAgree(unittest.TestCase):
    """A system's cores are a part of the platform's: a name only the system
    carries would escape every reader of the platform list. A system keeps
    the list its ES file writes, which says whose files its entries ask for,
    so the one name it may carry beyond the platform's is one no device
    image builds (EmuELEC's VVVVVV port engine, KNULLI's duckstation)."""

    def test_system_cores_are_platform_cores(self):
        import yaml

        for name in ("amberelec", "emuelec", "knulli"):
            with self.subTest(platform=name):
                config = yaml.safe_load((REPO_ROOT / "platforms" / f"{name}.yml").read_text())
                targets = yaml.safe_load(
                    (REPO_ROOT / "platforms" / "targets" / f"{name}.yml").read_text())["targets"]
                built = {c for entry in targets.values() for c in entry["cores"]}
                platform = {str(c) for c in config["cores"]}
                listed = {str(c) for s in config["systems"].values() for c in s.get("cores", [])}
                self.assertTrue(listed, "no system carries its cores")
                self.assertEqual(listed - platform - (listed - built), set())
                self.assertEqual(platform - built - {"lexaloffle", "mpv", "vox_official"}, set())


if __name__ == "__main__":
    unittest.main()
