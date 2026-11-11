"""EmulationStation-family rom folder parsers, on fixtures and on the
committed setup files.

The parsers run offline against tests/fixtures/romfolders/es/ through a
fetcher that reads files instead of a forge. The committed files under
platforms/romfolders/ are checked for shape: schema, every source_ref
naming a declared source, and a second dump giving the same bytes.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from romfolders import setup_paths, split_refs
from scraper.romfolders import (
    Fetcher,
    SourceError,
    load_formats,
    load_sources,
    scrape_setup,
)
from scraper.romfolders.__main__ import dump_setup
from scraper.romfolders.es import _module_valid

FIXTURES = ROOT / "tests" / "fixtures" / "romfolders" / "es"
ROMFOLDERS = ROOT / "platforms" / "romfolders"
ES_SETUPS = (
    "batocera", "knulli", "rocknix", "jelos", "kolos", "unofficialos", "archr",
    "amberelec", "chaos", "pan4elec", "emuelec", "recalbox", "retrobat", "arkos",
    "darkos", "retropie", "emudeck", "emudeck-windows", "retrodeck",
)


class FixtureFetcher(Fetcher):
    """Reads `<source key>/<path>` under one fixture directory."""

    def __init__(self, base: Path) -> None:
        super().__init__({"os": {"repo": "https://github.com/x/y", "commit": "0" * 40}})
        self.base = base

    def optional_text(self, key: str, path: str) -> str | None:
        target = self.base / path
        return target.read_text(encoding="utf-8") if target.is_file() else None

    def text(self, key: str, path: str) -> str:
        found = self.optional_text(key, path)
        if found is None:
            raise SourceError(f"{path} does not exist")
        return found

    def tree(self, key: str, prefix: str = "") -> list[str]:
        return sorted(
            p.relative_to(self.base).as_posix() for p in self.base.rglob("*")
            if p.is_file() and p.relative_to(self.base).as_posix().startswith(prefix)
        )

    def entries(self, key: str, directory: str) -> list[str]:
        return sorted(p.relative_to(self.base).as_posix() for p in (self.base / directory).iterdir())


def scrape(fmt: str, base: str, params: dict) -> dict:
    spec = {"name": "Fixture", "platform": "", "format": fmt, "params": params}
    return scrape_setup("fixture", spec, FixtureFetcher(FIXTURES / base))


def by_folder(doc: dict) -> dict[str, dict]:
    return {row["folder"]: row for row in doc["folders"]}


class BatoceraFormat(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = scrape("batocera-es", "batocera", {
            "es_systems": "es_systems.yml", "configgen_dir": "configs"})
        self.rows = by_folder(self.doc)

    def test_systems_without_emulator_or_outside_root_are_left_out(self) -> None:
        self.assertEqual(sorted(self.rows), ["mame", "snes"])

    def test_extensions_lowercased_with_dot(self) -> None:
        self.assertEqual(self.rows["snes"]["extensions"], [".sfc", ".smc", ".zip"])

    def test_default_and_board_override(self) -> None:
        snes = self.rows["snes"]
        self.assertEqual((snes["core"], snes["emulator"]), ("snes9x", "libretro"))
        self.assertEqual(snes["board_defaults"]["bcm2835"]["core"], "pocketsnes")
        # A symlinked board file is followed to its target.
        self.assertEqual(snes["board_defaults"]["bcm2836"]["core"], "pocketsnes")
        self.assertIn("configgen-defaults-bcm2835.yml",
                      snes["board_defaults"]["bcm2836"]["source_ref"])

    def test_arcade_flag_from_hardware(self) -> None:
        self.assertTrue(self.rows["mame"]["arcade"])
        self.assertNotIn("arcade", self.rows["snes"])

    def test_source_ref_names_the_lines(self) -> None:
        self.assertEqual(self.rows["snes"]["source_ref"],
                         "os es_systems.yml:1; os configs/configgen-defaults.yml:4")


class EsXmlFormat(unittest.TestCase):
    def setUp(self) -> None:
        self.params = {"file": "es_systems.cfg", "path_prefixes": ["/storage/roms/"], "default": "flagged"}
        self.rows = by_folder(scrape("es-xml", "xml", self.params))

    def test_ignored_commented_and_outside_systems_are_left_out(self) -> None:
        self.assertEqual(sorted(self.rows), ["advision", "mame", "psx"])

    def test_flagged_default_wins(self) -> None:
        self.assertEqual(self.rows["psx"]["core"], "swanstation")

    def test_first_rule_takes_the_first_core(self) -> None:
        rows = by_folder(scrape("es-xml", "xml", {**self.params, "default": "first"}))
        self.assertEqual(rows["psx"]["core"], "pcsx_rearmed")

    def test_core_read_from_command_when_no_emulator_is_listed(self) -> None:
        self.assertEqual((self.rows["advision"]["core"], self.rows["advision"]["emulator"]),
                         ("mess", "retroarch"))

    def test_arcade_flag_from_platform(self) -> None:
        self.assertTrue(self.rows["mame"]["arcade"])

    def test_board_file_gives_board_default(self) -> None:
        # es_systems.board.cfg flags duckstation where the main file flags swanstation.
        rows = by_folder(scrape("es-xml", "xml", {**self.params, "boards": {"rk3326": "es_systems.board.cfg"}}))
        self.assertEqual(rows["psx"]["board_defaults"]["rk3326"]["core"], "duckstation")
        self.assertNotIn("board_defaults", rows["mame"])

    def test_source_ref_points_at_the_name_line(self) -> None:
        self.assertEqual(self.rows["psx"]["source_ref"], "os es_systems.cfg:4")
        self.assertEqual(self.rows["advision"]["source_ref"], "os es_systems.cfg:20")


class EsJsonFormat(unittest.TestCase):
    def test_flagged_default_and_ignored_system(self) -> None:
        rows = by_folder(scrape("es-json", "json", {
            "file": "es_systems.json", "path_prefixes": ["/storage/roms/"]}))
        self.assertEqual(sorted(rows), ["pico", "pico-8", "psx"])
        self.assertEqual(rows["psx"]["core"], "duckstation")
        self.assertEqual(rows["psx"]["extensions"], [".cue"])

    def test_a_name_given_twice_names_neither_folder(self) -> None:
        rows = by_folder(scrape("es-json", "json", {
            "file": "es_systems.json", "path_prefixes": ["/storage/roms/"]}))
        for folder, line in (("pico-8", 19), ("pico", 25)):
            with self.subTest(folder=folder):
                self.assertNotIn("name", rows[folder])
                self.assertIn("2 systems pico8", rows[folder]["note"])
                self.assertEqual(rows[folder]["source_ref"], f"os es_systems.json:{line}")
        self.assertEqual(rows["pico"]["core"], "genesis_plus_gx")


class ElecConfFormat(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = by_folder(scrape("elec-conf", "elec", {
            "package": "package.mk", "conf_dir": "config/emulators",
            "path_prefixes": ["/storage/roms/"]}))

    def test_folders_from_conf_paths(self) -> None:
        self.assertEqual(sorted(self.rows), ["3do", "psx"])

    def test_star_branch_is_the_default_and_devices_are_boards(self) -> None:
        psx = self.rows["psx"]
        self.assertEqual(psx["core"], "swanstation")
        self.assertEqual(psx["board_defaults"], {
            "DEVICE=RK3326": {"core": "pcsx_rearmed", "emulator": "retroarch",
                              "source_ref": "os package.mk:11"}})

    def test_unconditional_default(self) -> None:
        self.assertEqual(self.rows["3do"]["core"], "opera")
        self.assertEqual(self.rows["3do"]["source_ref"],
                         "os config/emulators/3do.conf:3,4; os package.mk:7; os package.mk:6")


class EsdeFormat(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = by_folder(scrape("esde", "esde", {
            "systems": {"source": "os", "path": "es_systems.xml"},
            "custom": [{"source": "os", "path": "custom_systems.xml"}],
            "alternatives": {"source": "os", "path": "setup.sh", "function": "ESDE_setDefaultEmulators"},
        }))

    def test_alternative_emulator_label_picks_the_command(self) -> None:
        psx = self.rows["psx"]
        self.assertEqual((psx["core"], psx["emulator"]), ("duckstation", "duckstation"))
        self.assertIn("os setup.sh:3", psx["source_ref"])

    def test_custom_system_replaces_the_bundled_one(self) -> None:
        self.assertNotIn("model2", self.rows)
        model2 = self.rows["model2/roms"]
        self.assertEqual(model2["core"], "model-2")
        self.assertIn("names no command", model2["note"])

    def test_a_rom_search_path_names_the_folders_it_reads(self) -> None:
        # The Tano Dragon reads the Dragon 32 folder, the commented command
        # counts for nothing.
        (tano,) = self.rows["tanodragon"]["searched_by"]
        self.assertEqual(tano["reads"], ["dragon32"])
        self.assertEqual(tano["machines"], ["tanodr64"])
        self.assertNotIn("any_machine", tano)
        self.assertEqual(tano["source_ref"], "os es_systems.xml:20")

    def test_the_game_itself_as_machine_and_libretro_left_out(self) -> None:
        (arcade,) = self.rows["arcade"]["searched_by"]
        self.assertEqual(arcade["emulator"], "mame")
        self.assertTrue(arcade["any_machine"])
        self.assertNotIn("machines", arcade)
        self.assertNotIn("searched_by", self.rows["psx"])

    def test_first_command_without_alternative(self) -> None:
        rows = by_folder(scrape("esde", "esde", {"systems": {"source": "os", "path": "es_systems.xml"}}))
        self.assertEqual((rows["psx"]["core"], rows["psx"]["emulator"]), ("mednafen_psx", "retroarch"))


class RecalboxFormat(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = by_folder(scrape("recalbox", "recalbox", {"systems_dir": "systems", "configs_dir": "configs"}))

    def test_tie_goes_to_the_last_core(self) -> None:
        self.assertEqual(self.rows["psx"]["core"], "swanstation")

    def test_board_priority(self) -> None:
        self.assertEqual(self.rows["psx"]["board_defaults"]["rpi1"]["core"], "mednafen_psx")

    def test_a_core_no_board_builds_is_never_a_default(self) -> None:
        psx = self.rows["psx"]
        self.assertNotIn("pcsx", [psx["core"], *(b["core"] for b in psx["board_defaults"].values())])
        self.assertNotIn(".iso", psx["extensions"])

    def test_the_default_most_boards_share_heads_the_row(self) -> None:
        self.assertEqual(sorted(self.rows["psx"]["board_defaults"]), ["rpi1"])

    def test_a_board_section_overrides_the_plain_one(self) -> None:
        mame = self.rows["mame"]
        self.assertEqual(mame["core"], "mame2003_plus")
        self.assertEqual(mame["board_defaults"]["x86_64"]["core"], "mame")
        self.assertIn("configs/recalbox-x86_64_defconfig:5", mame["board_defaults"]["x86_64"]["source_ref"])

    def test_a_files_list_names_whole_files(self) -> None:
        self.assertEqual(self.rows["ports/Caesar3"]["files"], ["c3.exe"])
        self.assertNotIn("extensions", self.rows["ports/Caesar3"])
        self.assertEqual(self.rows["ports/Prince of Persia"]["files"], ["prince of persia (1990).zip"])

    def test_a_system_no_board_builds_has_no_folder(self) -> None:
        self.assertNotIn("vectrex", self.rows)

    def test_unopened_archive_extension(self) -> None:
        mame = self.rows["mame"]
        self.assertEqual(mame["extensions"], [".zip"])
        self.assertTrue(mame["arcade"])
        self.assertIn("!", mame["note"])


class CachedDirectory(unittest.TestCase):
    """A directory read from one archive knows its absent files without asking."""

    def test_file_missing_from_the_archive_is_absent(self) -> None:
        from unittest import mock

        import upstream

        fetcher = Fetcher({"os": {"repo": "https://gitlab.com/g/p", "commit": "0" * 40}})
        with mock.patch.object(upstream, "cache_gitlab_directory", return_value={"sys/a/system.ini"}):
            fetcher.cache_directory("os", "sys/")
        with mock.patch.object(upstream, "fetch_file", side_effect=AssertionError("network")):
            self.assertIsNone(fetcher.optional_text("os", "sys/b/system.ini"))


class RetroPieFormat(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = by_folder(scrape("retropie", "retropie", {
            "platforms_cfg": "platforms.cfg", "module_dirs": ["emulators", "libretrocores"],
            "install_sections": ["core", "main", "opt", "exp"],
            "platform_flags": ["native", "64bit", "gl", "vulkan", "x11", "x86"]}))

    def test_folders_and_loop_systems(self) -> None:
        self.assertEqual(sorted(self.rows), ["nes", "psx", "vectrex"])
        self.assertEqual(self.rows["nes"]["core"], "lr-fceumm")
        self.assertEqual(self.rows["nes"]["emulator"], "retroarch")

    def test_flags_and_section_order(self) -> None:
        # lr-pcsx-rearmed is excluded on x86, opt comes before exp.
        self.assertEqual(self.rows["psx"]["core"], "lr-swanstation")
        self.assertNotIn("core", self.rows["vectrex"])

    def test_module_flags_read_in_order(self) -> None:
        x86 = {"x86", "64bit"}
        self.assertFalse(_module_valid(["!all"], x86))
        self.assertTrue(_module_valid(["!all", "x86"], x86))
        self.assertFalse(_module_valid(["!x86"], x86))
        self.assertTrue(_module_valid(["!arm"], x86))


class Determinism(unittest.TestCase):
    def test_two_scrapes_dump_the_same_bytes(self) -> None:
        params = {"file": "es_systems.cfg", "path_prefixes": ["/storage/roms/"]}
        first = dump_setup(scrape("es-xml", "xml", params))
        second = dump_setup(scrape("es-xml", "xml", params))
        self.assertEqual(first, second)


class CommittedSetups(unittest.TestCase):
    """The setup files this parser family writes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = load_sources(ROMFOLDERS / "_sources")
        cls.paths = {p.stem: p for p in setup_paths(ROMFOLDERS)}

    def written(self, setup: str) -> Path:
        """The committed setup file."""
        return self.paths[setup]

    def test_every_es_setup_is_declared_and_written(self) -> None:
        formats = load_formats()
        for setup in ES_SETUPS:
            with self.subTest(setup=setup):
                self.assertIn(setup, self.sources)
                self.assertIn(self.sources[setup]["format"], formats)
                self.assertEqual(self.written(setup).stem, setup)

    def test_schema(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema not installed")
        from safeparse import yaml_load
        schema = json.loads((ROOT / "schemas" / "romfolders.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for setup in ES_SETUPS:
            with self.subTest(setup=setup):
                doc = yaml_load(self.written(setup).read_text(encoding="utf-8"))
                errors = [e.message for e in validator.iter_errors(doc)]
                self.assertEqual(errors, [])

    def test_every_source_ref_names_a_declared_source(self) -> None:
        from safeparse import yaml_load
        for setup in ES_SETUPS:
            with self.subTest(setup=setup):
                doc = yaml_load(self.written(setup).read_text(encoding="utf-8"))
            if setup not in self.paths:
                continue
            refs = [doc["roms_root"]["source_ref"]]
            for key in ("skip", "hidden", "media"):
                refs += [rule["source_ref"] for rule in doc.get(key, [])]
            for row in doc["folders"]:
                refs.append(row["source_ref"])
                refs += [b["source_ref"] for b in (row.get("board_defaults") or {}).values()]
            for ref in refs:
                for key, _path, _lines in split_refs(ref):
                    with self.subTest(setup=setup, ref=ref):
                        self.assertIn(key, doc["sources"])

    def test_committed_file_is_its_own_dump(self) -> None:
        from safeparse import yaml_load
        for setup in ES_SETUPS:
            with self.subTest(setup=setup):
                text = self.written(setup).read_text(encoding="utf-8")
                self.assertEqual(dump_setup(yaml_load(text)), text)

    def test_elec_family_skips_its_bios_folder(self) -> None:
        from safeparse import yaml_load
        for setup in ("rocknix", "jelos", "kolos", "unofficialos", "archr",
                      "amberelec", "chaos", "pan4elec", "emuelec", "arkos", "darkos"):
            doc = yaml_load(self.paths[setup].read_text(encoding="utf-8"))
            with self.subTest(setup=setup):
                self.assertEqual(doc["roms_root"]["from_bios"], "..")
                self.assertIn("bios", {rule.get("name") for rule in doc.get("skip", [])})
                self.assertNotIn("bios", {row["folder"] for row in doc["folders"]})


if __name__ == "__main__":
    unittest.main()
