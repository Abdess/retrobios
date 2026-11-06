"""Rom folder parsers of the card OSes and the menu-less frontends, offline.

The parsers run on fixture text through a fake Fetcher, so nothing here
reaches the network. The committed setup files are checked against the
schema and their own declared sources.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from romfolders import split_refs  # noqa: E402
from safeparse import yaml_load  # noqa: E402
from scraper.romfolders import SourceError, load_sources, scrape_setup  # noqa: E402
from scraper.romfolders.__main__ import dump_setup  # noqa: E402
from scraper.romfolders.card import (  # noqa: E402
    libretro_core,
    parse_allium,
    parse_bizhawk,
    parse_crossmix,
    parse_gmenu2x,
    parse_koriki,
    parse_minui,
    parse_mister,
    parse_muos,
    parse_onion,
    parse_plumos,
    parse_romm,
    parse_spruce,
    parse_toml_subset,
    ref,
)

FIXTURES = json.loads(
    (ROOT / "tests" / "fixtures" / "romfolders_card" / "files.json").read_text(encoding="utf-8")
)
SETUPS = (
    "onion", "allium", "spruceos", "miyoocfw", "koriki", "crossmix-os", "minui",
    "myminui", "nextui", "plumos-pixel2", "plumos-mf", "muos", "misterfpga", "romm",
    "bizhawk", "lakka", "retroarch",
)


class FakeFetcher:
    """Serves fixture files by source key, the Fetcher interface parsers use."""

    def __init__(self, files: dict[str, dict[str, str]]) -> None:
        self.files = files

    def text(self, key: str, path: str) -> str:
        try:
            return self.files[key][path]
        except KeyError as exc:
            raise SourceError(f"{key}:{path} does not exist") from exc

    def optional_text(self, key: str, path: str) -> str | None:
        return self.files.get(key, {}).get(path)

    def tree(self, key: str, prefix: str = "") -> list[str]:
        return sorted(p for p in self.files.get(key, {}) if p.startswith(prefix))


def spec(source: str, **params: object) -> dict:
    return {"params": {"source": source, **params}}


def by_folder(rows: list[dict]) -> dict[str, dict]:
    return {row["folder"]: row for row in rows}


class LaunchScriptTests(unittest.TestCase):
    def test_core_named_through_a_shell_variable(self) -> None:
        script = "default_core=gpsp\nretroarch -L cores/${default_core}_libretro.so\n"
        self.assertEqual(libretro_core(script), "gpsp")

    def test_core_named_by_emu_exe(self) -> None:
        self.assertEqual(libretro_core("EMU_EXE=fceumm\nminarch.elf x\n"), "fceumm")

    def test_standalone_script_names_no_core(self) -> None:
        self.assertIsNone(libretro_core("./drastic \"$1\"\n"))

    def test_space_in_a_cited_path_is_escaped(self) -> None:
        part = ref("os", "Emu/Commodore - Amiga/config.json", 3)
        self.assertEqual(split_refs(part), [("os", "Emu/Commodore%20-%20Amiga/config.json", "3")])


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fetcher = FakeFetcher(FIXTURES)

    def test_onion_emu_package_is_the_default_over_retroarch_section(self) -> None:
        rows = by_folder(parse_onion({"params": {"source": "onion"}}, self.fetcher))
        self.assertEqual(sorted(rows), ["GBA", "PCNINETYEIGHT"])
        self.assertEqual(rows["GBA"]["core"], "gpsp")
        self.assertEqual(rows["GBA"]["extensions"], [".gba", ".zip", ".7z"])
        self.assertIn("Nintendo - GBA (VBA-M)", rows["GBA"]["note"])
        self.assertNotIn("core", rows["PCNINETYEIGHT"])

    def test_spruce_reads_default_and_alternative_folders(self) -> None:
        rows = by_folder(parse_spruce(spec("spruce", skip=["-CUSTOM-SYSTEM-"]), self.fetcher))
        self.assertEqual(list(rows), ["PS"])
        self.assertEqual(rows["PS"]["aliases"], ["psx", "PS1"])
        self.assertEqual(rows["PS"]["core"], "pcsx_rearmed")
        self.assertEqual(rows["PS"]["extensions"], [".bin", ".cue", ".chd"])
        self.assertIn("neogeo.zip", rows["PS"]["note"])

    def test_crossmix_skips_separators_and_underscore_folders(self) -> None:
        rows = by_folder(parse_crossmix(spec("crossmix"), self.fetcher))
        self.assertEqual(list(rows), ["PS"])
        self.assertEqual(rows["PS"]["core"], "pcsx_rearmed")

    def test_koriki_first_launcher_wins(self) -> None:
        params = {"source": "koriki", "sections": "base/.simplemenu/section_groups/apps and games.ini",
                  "launchers": "base/.simplemenu/launchers", "roms_prefix": "/mnt/SDCARD/Roms/",
                  "skip": ["CONSOLES"]}
        rows = by_folder(parse_koriki({"params": params}, self.fetcher))
        self.assertEqual(rows["PS"]["core"], "pcsx_rearmed")
        self.assertEqual(rows["PS"]["extensions"], [".cue", ".chd", ".pbp"])
        self.assertEqual(rows["PS"]["source_ref"],
                         "koriki base/.simplemenu/section_groups/apps%20and%20games.ini:4")

    def test_allium_folder_is_the_first_pattern(self) -> None:
        rows = by_folder(parse_allium(spec("allium", consoles="consoles.toml", cores="cores.toml"),
                                      self.fetcher))
        self.assertEqual(sorted(rows), ["ARCADE", "GBA"])
        self.assertEqual(rows["ARCADE"]["core"], "mame2003_plus")
        self.assertEqual(rows["ARCADE"]["aliases"], ["mame"])
        self.assertEqual(rows["ARCADE"]["source_ref"], "allium consoles.toml:1")

    def test_toml_subset_matches_tomllib(self) -> None:
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11")
        def clean(node: object) -> object:
            if isinstance(node, dict):
                return {k: clean(v) for k, v in node.items() if k != "__line__"}
            if isinstance(node, list):
                return [clean(v) for v in node]
            return node

        for name in ("consoles.toml", "cores.toml"):
            text = FIXTURES["allium"][name]
            self.assertEqual(clean(parse_toml_subset(text)), tomllib.loads(text))

    def test_toml_outside_the_subset_is_refused(self) -> None:
        with self.assertRaises(SourceError):
            parse_toml_subset("when = 1979-05-27T07:32:00Z\n")

    def test_minui_takes_the_core_most_devices_run(self) -> None:
        rows = by_folder(parse_minui(spec("minui"), self.fetcher))
        ps = rows["Sony PlayStation (PS)"]
        self.assertEqual(ps["name"], "PS")
        self.assertEqual(ps["core"], "pcsx_rearmed")
        self.assertEqual(ps["board_defaults"]["tg5040"]["core"], "swanstation")
        self.assertNotIn("rg35xx", ps["board_defaults"])
        self.assertEqual(rows["A2600"]["core"], "stella2014")
        self.assertNotIn("extensions", ps)

    def test_plumos_shared_folder_goes_to_the_first_system(self) -> None:
        rows = by_folder(parse_plumos(spec("plumos", path="systems.json"), self.fetcher))
        self.assertEqual(rows["FC"]["name"], "nes")
        self.assertEqual(rows["FC"]["core"], "quicknes")
        self.assertEqual(rows["fds"]["emulator"], "standalone")
        self.assertIn("FC", rows["fds"]["aliases"])
        self.assertIn("disabled by default", rows["fds"]["note"])

    def test_muos_folder_is_the_friendly_name_of_the_catalogue(self) -> None:
        rows = by_folder(parse_muos(spec("muos", path="core.json"), self.fetcher))
        self.assertEqual(rows["sonyplaystation"]["core"], "pcsx_rearmed")
        self.assertEqual(rows["sonyplaystation"]["emulator"], "retroarch")
        self.assertEqual(rows["nintendods"]["core"], "drastic")
        self.assertEqual(rows["nintendods"]["emulator"], "external")

    def test_gmenu2x_link_and_shipped_folders(self) -> None:
        params = {"source": "gmenu2x", "shipped_roms": "board/miyoo/roms",
                  "link_roms_prefix": "/mnt/roms",
                  "links": [{"source": "gpsp", "path": "miyoo/opkg_assets/gpsp.lnk", "core": "gpsp"}]}
        rows = by_folder(parse_gmenu2x({"params": params}, self.fetcher))
        self.assertEqual(sorted(rows), ["GB", "GBA"])
        self.assertEqual(rows["GBA"]["extensions"], [".gba", ".zip"])
        self.assertEqual(rows["GBA"]["source_ref"], "gpsp miyoo/opkg_assets/gpsp.lnk:3")
        self.assertNotIn("core", rows["GB"])

    def test_mister_rows_are_the_shipped_core_folders(self) -> None:
        rows = by_folder(parse_mister(spec("dist", arcade=["mame"], arcade_note="mra"), self.fetcher))
        self.assertEqual(sorted(rows), ["SNES", "mame"])
        self.assertTrue(rows["mame"]["arcade"])
        self.assertIsNone(rows["SNES"]["arcade"])

    def test_romm_reads_multiline_arrays_and_bios_only_slugs(self) -> None:
        rows = by_folder(parse_romm(spec("romm", cores_map="index.ts",
                                         bios_fixture="known_bios_files.json"), self.fetcher))
        self.assertEqual(sorted(rows), ["3do", "3ds", "64dd", "arcade"])
        self.assertEqual(rows["arcade"]["core"], "mame2003_plus")
        self.assertIn("nightly", rows["3ds"]["note"])
        self.assertNotIn("core", rows["64dd"])

    def test_bizhawk_combined_systems_and_extension_lists(self) -> None:
        rows = by_folder(parse_bizhawk(spec("bizhawk", paths="PathEntryCollection.cs",
                                            rom_loader="RomLoader.cs", config="Config.cs"),
                                       self.fetcher))
        self.assertEqual(rows["Gameboy"]["name"], "GB")
        self.assertEqual(rows["Gameboy"]["aliases"], ["GBC", "SGB"])
        self.assertEqual(rows["Gameboy"]["extensions"], [".gb", ".gbc", ".sgb"])
        self.assertEqual(rows["NES"]["extensions"], [".nes", ".fds", ".unf"])
        self.assertIn("QuickNes", rows["NES"]["note"])
        self.assertEqual(rows["32X"]["extensions"], [])
        self.assertNotIn("core", rows["NES"])


class ScrapeTests(unittest.TestCase):
    def test_two_scrapes_write_the_same_bytes(self) -> None:
        setup = {
            "name": "Fixture", "platform": "retroarch", "format": "plumos",
            "params": {"source": "plumos", "path": "systems.json"},
            "sources": {"plumos": {"repo": "https://github.com/a/b", "commit": "0" * 40}},
            "roms_root": {"path": "/r", "from_bios": "../r", "source_ref": "plumos systems.json:1"},
            "case_sensitive": None,
        }
        first = dump_setup(scrape_setup("fixture", setup, FakeFetcher(FIXTURES)))
        second = dump_setup(scrape_setup("fixture", setup, FakeFetcher(FIXTURES)))
        self.assertEqual(first, second)
        self.assertEqual(yaml_load(first)["folders"][0]["folder"], "FC")

    def test_an_empty_read_fails_unless_allowed(self) -> None:
        setup = {"format": "mister", "params": {"source": "none", "arcade_note": "x"}}
        with self.assertRaises(SourceError):
            scrape_setup("empty", setup, FakeFetcher({}))


class CommittedSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = load_sources(ROOT / "platforms" / "romfolders" / "_sources")

    def documents(self) -> dict[str, dict]:
        out = {}
        for setup in SETUPS:
            path = ROOT / "platforms" / "romfolders" / f"{setup}.yml"
            with path.open(encoding="utf-8") as handle:
                out[setup] = yaml_load(handle)
        return out

    def test_every_owned_setup_has_sources_and_output(self) -> None:
        for setup in SETUPS:
            self.assertIn(setup, self.sources, setup)
        for setup, doc in self.documents().items():
            self.assertEqual(doc["setup"], setup)
            self.assertEqual(doc["platform"], self.sources[setup]["platform"])

    def test_every_ref_names_a_declared_source(self) -> None:
        for setup, doc in self.documents().items():
            declared = set(doc["sources"])
            refs = [doc["roms_root"]["source_ref"]]
            refs += [doc["case_ref"]] if doc.get("case_ref") else []
            for block in ("skip", "hidden", "media"):
                refs += [r["source_ref"] for r in doc.get(block, [])]
            refs += [row["source_ref"] for row in doc["folders"]]
            refs += [b["source_ref"] for row in doc["folders"]
                     for b in (row.get("board_defaults") or {}).values()]
            for source_ref in refs:
                for key, _, _ in split_refs(source_ref):
                    self.assertIn(key, declared, f"{setup}: {source_ref}")

    def test_committed_setups_validate_against_the_schema(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads((ROOT / "schemas" / "romfolders.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for setup, doc in self.documents().items():
            errors = [e.message for e in validator.iter_errors(doc)]
            self.assertEqual(errors, [], setup)

    def test_rows_with_folders_are_not_empty(self) -> None:
        for setup, doc in self.documents().items():
            if self.sources[setup].get("allow_empty"):
                self.assertEqual(doc["folders"], [], setup)
            else:
                self.assertGreater(len(doc["folders"]), 0, setup)


if __name__ == "__main__":
    unittest.main()
