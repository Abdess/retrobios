"""The gap report settles a core file as verify does: slot or size.

cross_reference counted a core file declared as soon as a platform named
it. RetroArch names Galaksija's 4 KiB galaksija/rom1.bin, so DOSBox's
32 KiB SC-55/ROM1.BIN left the gaps page while verify listed it undeclared.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from cross_reference import cross_reference  # noqa: E402
from validation import case_folded_slots, declaration_settles  # noqa: E402

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
            source = (REPO_ROOT / "scripts" / module).read_text(encoding="utf-8")
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


class EveryGapReportFoldsCase(unittest.TestCase):
    """The command line passed folded_slots and the site did not, so the
    gaps page listed RetroBat files the CLI report settled."""

    def test_each_cross_reference_call_passes_the_folded_slots(self):
        import ast

        for script in ("cross_reference.py", "generate_site.py"):
            source = (REPO_ROOT / "scripts" / script).read_text(encoding="utf-8")
            calls = [
                node for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Call)
                and getattr(node.func, "id", "") in ("cross_reference", "run_cross_reference")
            ]
            with self.subTest(script=script):
                self.assertTrue(calls)
                for call in calls:
                    self.assertIn("folded_slots", {kw.arg for kw in call.keywords})


if __name__ == "__main__":
    unittest.main()
