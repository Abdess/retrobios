"""The gap report settles a core file as verify does: slot or size.

cross_reference counted a core file declared as soon as a platform named
it. RetroArch names Galaksija's 4 KiB galaksija/rom1.bin, so DOSBox's
32 KiB SC-55/ROM1.BIN left the gaps page while verify listed it undeclared.
"""

from __future__ import annotations

import tests
from tests.sources import script_source

import unittest
from pathlib import Path

from packs.crossref import cross_reference
from resolve.validation import case_folded_slots, declaration_settles

REPO_ROOT = Path(__file__).resolve().parents[1]

SC55 = {"name": "ROM1.BIN", "path": "SC-55/ROM1.BIN", "size": 32768,
        "validation": ["size"], "required": True}


class OneRule(unittest.TestCase):
    def test_a_same_named_file_of_another_size_does_not_settle(self):
        declared = {"ROM1.BIN": [(4096, "galaksija/rom1.bin")]}
        self.assertFalse(declaration_settles(SC55, "ROM1.BIN", declared, SC55["path"]))
        declared["ROM1.BIN"].append((32768, "rom1.bin"))
        self.assertTrue(declaration_settles(SC55, "ROM1.BIN", declared, SC55["path"]))

    def test_the_gap_report_reads_it(self):
        profiles = {"dosbox": {"emulator": "DOSBox", "type": "libretro",
                               "systems": ["dos"], "files": [SC55]}}
        report = cross_reference(
            profiles, {}, {"files": {}, "indexes": {}},
            all_declared={"ROM1.BIN": [(4096, "galaksija/rom1.bin")]},
        )
        self.assertEqual(
            [g["name"] for g in report["dosbox"]["gap_details"]], ["ROM1.BIN"]
        )

    def test_both_sides_call_it(self):
        for module in ("verify.py", "cross_reference.py"):
            source = script_source(module)
            self.assertIn("declaration_settles(", source, module)


class ACaseFoldingFilesystem(unittest.TestCase):
    """RetroBat declares 32X_G_BIOS.BIN, BlastEm opens 32X_G_BIOS.bin at the
    same place. The exact-case name test reported it undeclared before the
    slot was ever compared."""

    declared = {"32X_G_BIOS.BIN": [(256, "32x_g_bios.bin")]}
    entry = {"name": "32X_G_BIOS.bin"}

    def test_the_slot_settles_it_where_case_folds(self):
        folded = case_folded_slots({"case_insensitive_fs": True}, self.declared)
        self.assertTrue(
            declaration_settles(self.entry, "32X_G_BIOS.bin", self.declared, "", folded)
        )

    def test_two_spellings_are_two_files_elsewhere(self):
        folded = case_folded_slots({"case_insensitive_fs": False}, self.declared)
        self.assertFalse(
            declaration_settles(self.entry, "32X_G_BIOS.bin", self.declared, "", folded)
        )

    def test_another_place_settles_nothing(self):
        folded = case_folded_slots({"case_insensitive_fs": True}, self.declared)
        self.assertFalse(declaration_settles(
            self.entry, "32X_G_BIOS.bin", self.declared, "blastem/32X_G_BIOS.bin", folded
        ))


class TheRunningBuildPlacesTheGap(unittest.TestCase):
    """Batocera runs Cemu standalone, which reads keys.txt at its
    standalone_path. The gap report gave the libretro Cemu/keys.txt while
    verify gave keys.txt: 163 entries told apart, and the declaration was
    settled on a slot the platform never fills."""

    KEYS = {"name": "keys.txt", "path": "Cemu/keys.txt",
            "standalone_path": "keys.txt", "required": True}

    def _gap_paths(self, standalone: set[str]) -> list[str]:
        profiles = {"cemu": {"emulator": "Cemu", "type": "standalone + libretro",
                             "systems": ["nintendo-wiiu"], "files": [self.KEYS]}}
        report = cross_reference(
            profiles, {}, {"files": {}, "indexes": {}}, all_declared={},
            standalone_cores=standalone,
        )
        return [g["path"] for g in report["cemu"]["gap_details"]]

    def test_a_standalone_build_reads_its_own_path(self):
        self.assertEqual(self._gap_paths({"cemu"}), ["keys.txt"])

    def test_the_core_reads_the_libretro_path(self):
        self.assertEqual(self._gap_paths(set()), ["Cemu/keys.txt"])


class MissingRowsNameTheirPlatforms(unittest.TestCase):
    """The gaps page decided again which platforms a missing file affects,
    without installed_on: lzdoom's doom1.wad, which RetroPie's package
    downloads, was badged retropie."""

    PROFILE = {"emulator": "Engine", "type": "standalone + libretro", "systems": ["doom"],
               "files": [
                   {"name": "a.wad", "installed_on": ["beta"]},
                   {"name": "b.bin", "unread_on": ["alpha"]},
                   {"name": "c.bin", "mode": "standalone"},
                   {"name": "d.bin", "bundled": True, "not_bundled_on": ["alpha"]},
               ]}

    def platforms(self) -> dict[str, list[str]]:
        from packs.crossref import whole_tree_gaps

        configs = [
            {"_key": "alpha", "cores": ["engine"], "systems": {}},
            {"_key": "beta", "cores": ["engine"], "systems": {}},
            {"_key": "gamma", "cores": ["engine"], "standalone_cores": ["engine"],
             "systems": {}},
            {"_key": "delta", "cores": ["other"], "systems": {}},
        ]
        report = whole_tree_gaps(configs, {"files": {}, "indexes": {}},
                                 {"engine": self.PROFILE})
        return {g["name"]: g["platforms"] for g in report["engine"]["gap_details"]}

    def test_each_platform_rule_is_applied(self):
        self.assertEqual(self.platforms(), {
            "a.wad": ["alpha", "gamma"],
            "b.bin": ["beta", "gamma"],
            "c.bin": ["gamma"],
            "d.bin": ["alpha"],
        })

    def test_real_profiles_name_only_the_platforms_that_need_them(self):
        """cdbios.bin, read by standalone BlastEm only and never on RetroBat,
        was badged retroarch, lakka and retrobat."""
        import yaml

        from model.platforms import load_platform_config
        from packs.crossref import whole_tree_gaps

        profiles = {
            name: yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))
            for name in ("blastem", "lzdoom")
        }
        configs = [load_platform_config(name, str(REPO_ROOT / "platforms"))
                   for name in ("retroarch", "lakka", "retrobat", "retropie")]
        report = whole_tree_gaps(configs, {"files": {}, "indexes": {}}, profiles)
        found = {(emu, g["name"]): set(g["platforms"])
                 for emu, data in report.items() for g in data["gap_details"]}
        self.assertFalse(found[("blastem", "cdbios.bin")] & {"retroarch", "lakka", "retrobat"})
        self.assertNotIn("retropie", found[("lzdoom", "doom1.wad")])


class EveryGapReportFoldsCase(unittest.TestCase):
    """The command line passed folded_slots and the site did not, so the
    gaps page listed RetroBat files the CLI report settled. Later the CLI
    passed declared_contents and the site did not, 20 gaps apart. Both
    take their scope from packs.crossref.global_report_scope."""

    def test_each_cross_reference_call_reads_the_shared_scope(self):
        import ast

        for script in ("cross_reference.py", "generate_site.py"):
            source = script_source(script)
            calls = [
                node for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Call)
                and getattr(node.func, "id", "") in ("cross_reference", "run_cross_reference")
            ]
            with self.subTest(script=script):
                self.assertTrue(calls)
                self.assertIn("global_report_scope(", source)
                for call in calls:
                    self.assertIn(None, {kw.arg for kw in call.keywords})


if __name__ == "__main__":
    unittest.main()
