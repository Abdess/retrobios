"""A core file the builder holds but cannot place is not counted packed.

The builder skips a core extra whose destination a case-insensitive
filesystem folds onto a packed file, or that a packed file blocks as a
directory. verify counted both in "Core files: N in pack": RetroPie's
openmsx fmpac.rom (the pack carries the platform's FMPAC.ROM, other bytes),
ROCKNIX's higan SGB1.sfc/program.rom under the file SGB1.sfc.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packpaths import placement_block  # noqa: E402


class OneRule(unittest.TestCase):
    def test_reasons(self):
        seen = {"bios/FMPAC.ROM", "bios/SGB1.sfc"}
        lower = {d.lower() for d in seen}
        parents = {"bios"}
        cases = {
            "bios/FMPAC.ROM": "taken",
            "bios/fmpac.rom": "case_twin",
            "bios/SGB1.sfc/program.rom": "path_conflict",
            "bios/other.rom": None,
        }
        for dest, reason in cases.items():
            with self.subTest(dest=dest):
                self.assertEqual(
                    placement_block(dest, seen, lower, parents, True), reason
                )
        self.assertIsNone(
            placement_block("bios/fmpac.rom", seen, lower, parents, False)
        )

    def test_builder_and_report_read_it(self):
        for module in ("generate_pack.py", "packextras.py"):
            source = (REPO_ROOT / "scripts" / module).read_text(encoding="utf-8")
            self.assertIn("placement_block(", source, module)
        builder = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("if full_dest.lower() in seen_lower and case_insensitive", builder)

    def test_a_refused_declaration_occupies_nothing(self):
        """verify counted a declaration whose hash the frontend refuses as
        occupying its path, but the builder leaves it out, and the core file
        that then takes the path was reported missing from the pack."""
        source = (REPO_ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        compact = " ".join(source.split())
        self.assertRegex(
            compact,
            r"baseline_verdict\( file_entry, local_path, resolve_status, mode.{0,60}?\)\[1\] is None",
        )


class TheIntegrityCheckFoldsCaseLikeTheBuilder(unittest.TestCase):
    """--verify-packs counted a file present through its case twin on Lakka,
    whose filesystem keeps bios.col and BIOS.col apart: a pack missing one
    of the two passed step 6."""

    def test_case_folding_reads_the_platform(self):
        source = (REPO_ROOT / "scripts" / "packverify.py").read_text(encoding="utf-8")
        compact = " ".join(source.split())
        self.assertRegex(
            compact,
            r"zip_lower = \( \{n\.lower\(\): n for n in zip_set\} "
            r"if config\.get\(\"case_insensitive_fs\", False\) else \{\} \)",
        )


class TheReportSaysSo(unittest.TestCase):
    """Reads the repository: skips when the database is absent."""

    @classmethod
    def setUpClass(cls):
        if not (REPO_ROOT / "database.json").exists():
            raise unittest.SkipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            from common import load_database, load_emulator_profiles
            from verify import verify_platform
            from common import load_platform_config

            db = load_database("database.json")
            profiles = load_emulator_profiles("emulators")
            # Platforms whose filesystem folds case. RetroPie and Lakka run on
            # Linux and keep both names.
            cls.results = {
                name: verify_platform(
                    load_platform_config(name, "platforms"), db, "emulators", profiles
                )
                for name in ("retroarch", "retrobat", "lakka")
            }
        finally:
            os.chdir(previous)

    def _entry(self, emulator: str, path: str, platform: str = "retroarch") -> dict:
        for u in self.results[platform]["undeclared_files"]:
            if u.get("emulator") == emulator and (u.get("path") or u.get("name")) == path:
                return u
        self.skipTest(f"{emulator} {path} is not in the cross-reference")

    def _listed(self, emulator: str, path: str, platform: str) -> bool:
        return any(
            u.get("emulator") == emulator and (u.get("path") or u.get("name")) == path
            for u in self.results[platform]["undeclared_files"]
        )

    def test_a_declaration_in_another_case_settles_the_slot(self):
        """On a filesystem that folds case the platform's file at the slot is
        the one the core opens, whatever its spelling, and the slot
        arbitration judges its bytes. Listed as a core file, RetroBat's
        32X_G_BIOS.BIN counted BlastEm's 32X_G_BIOS.bin in the pack twice."""
        for platform, emulator, path in (
            ("retrobat", "NP2kai", "np2kai/bios.rom"),
            ("retrobat", "BlastEm", "32X_G_BIOS.bin"),
            ("retroarch", "MesenCE", "bios.col"),
        ):
            with self.subTest(platform=platform, path=path):
                self.assertFalse(self._listed(emulator, path, platform))

    def test_a_filesystem_keeping_both_names_reports_the_other(self):
        """Lakka runs on Linux, where bios.col and BIOS.col are two files."""
        self.assertTrue(self._listed("MesenCE", "bios.col", "lakka"))

    def test_a_directory_under_a_packed_file_is_left_out(self):
        entry = self._entry("nSide (SFC Balanced)", "SGB1.sfc/lr35902.boot.rom")
        self.assertIs(entry.get("in_pack"), False)



class TheGapReportIsComputedOnce(unittest.TestCase):
    """verify_platform ran find_undeclared_files twice with the same
    arguments, once itself and once through hidden_extras: every
    resolution twice, 8% of verify --all."""

    def test_one_call_per_platform(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        from unittest import mock

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            import verify
            from common import load_database, load_emulator_profiles, load_platform_config

            db = load_database("database.json")
            profiles = load_emulator_profiles("emulators")
            config = load_platform_config("emudeck", "platforms")
            with mock.patch.object(
                verify, "find_undeclared_files", wraps=verify.find_undeclared_files
            ) as counted:
                verify.verify_platform(config, db, "emulators", profiles)
        finally:
            os.chdir(previous)
        self.assertEqual(counted.call_count, 1)


class TheReplayResolvesAsTheBuilder(unittest.TestCase):
    """verify replayed the builder's placement with a bare name lookup: it
    compared other bytes than the pack's, and an extra it could not resolve
    still took its path and blocked the next one the builder places."""

    def test_an_unresolved_extra_blocks_nothing(self):
        from unittest import mock

        import packextras

        extras = [
            {"destination": "box.bin/inner.rom", "name": "inner.rom",
             "source_emulator": "a", "source_name": "inner.rom", "source_path": ""},
            {"destination": "box.bin", "name": "box.bin",
             "source_emulator": "b", "source_name": "box.bin", "source_path": ""},
        ]

        class Resolver:
            def resolve(self, fe, dest):
                return (None, "not_found", "") if fe["name"] == "inner.rom" else (
                    "bios/box.bin", "sha1_exact", ""
                )

        placed: set[str] = set()
        with mock.patch.object(packextras, "_collect_emulator_extras", return_value=extras):
            hidden = packextras.hidden_extras(
                {"systems": {}}, "emulators", {"files": {}}, {}, {},
                placed=placed, resolver=Resolver(),
            )
        self.assertEqual(hidden, {})
        self.assertEqual(placed, {"box.bin"})


if __name__ == "__main__":
    unittest.main()
