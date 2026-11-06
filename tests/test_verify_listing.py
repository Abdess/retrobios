"""verify.py lists what generate_pack.py lists for the same request."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *argv], capture_output=True, check=False, text=True, cwd=REPO_ROOT, timeout=300
    )


class ListingsAgree(unittest.TestCase):
    def test_list_systems_honours_platform(self):
        verify = _run("scripts/verify.py", "--list-systems", "--platform", "bizhawk")
        pack = _run("scripts/generate_pack.py", "--list-systems", "--platform", "bizhawk")
        self.assertEqual(verify.returncode, 0)
        self.assertEqual(verify.stdout, pack.stdout)

    def test_listing_refuses_a_narrowing_flag(self):
        result = _run("scripts/verify.py", "--list-emulators", "--region", "us")
        self.assertNotEqual(result.returncode, 0)


class VerifyRefusesWhatAModeDoesNotRead(unittest.TestCase):
    """The mode x flag matrix generate_pack has, for verify.

    --list-emulators --standalone printed the full list, --list-systems --json
    printed columns, --platform --include-archived covered nothing more: each
    with rc 0, each letting the caller believe the flag applied.
    """

    MATRIX = (
        (("--list-emulators",), "--standalone"),
        (("--list-systems",), "--json"),
        (("--list-targets", "--platform", "retroarch"), "--include-archived"),
        (("--platform", "retroarch"), "--include-archived"),
        (("--emulator", "handy"), "--include-archived"),
        (("--platform", "retroarch"), "--standalone"),
        # Game data is categorized against a platform's list and its cores.
        (("--emulator", "handy"), "--no-game-data"),
        (("--system", "atari-lynx"), "--no-game-data"),
        (("--list-systems",), "--no-game-data"),
    )

    def test_each_combination_is_refused(self):
        for mode, flag in self.MATRIX:
            with self.subTest(mode=mode, flag=flag):
                result = _run("scripts/verify.py", *mode, flag)
                self.assertEqual(result.returncode, 2, result.stdout[-300:])
                self.assertIn(flag, result.stderr)

    def test_emulator_mode_reads_the_given_platforms_dir(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        seen: list[str] = []

        def registry(path: str) -> dict:
            seen.append(str(path))
            return {}

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}}}
        with mock.patch.object(verify, "load_data_dir_registry", registry):
            verify.verify_emulator(
                ["handy"], str(REPO_ROOT / "emulators"), db, platforms_dir="elsewhere"
            )
        self.assertEqual(seen, ["elsewhere"])


class VerifyAppliesWhatItAccepts(unittest.TestCase):
    """--verbose under --json was accepted in every mode and changed nothing;
    the refusal matrix above could not see it, since nothing was refused."""

    def test_verbose_changes_the_json_in_every_mode(self):
        for mode in (("--platform", "bizhawk"), ("--emulator", "handy"),
                     ("--system", "atari-lynx")):
            with self.subTest(mode=mode):
                plain = _run("scripts/verify.py", *mode, "--json")
                verbose = _run("scripts/verify.py", *mode, "--json", "--verbose")
                self.assertEqual((plain.returncode, verbose.returncode), (0, 0))
                self.assertNotEqual(plain.stdout, verbose.stdout)


class EmulatorPackReadsThePlatformsDir(unittest.TestCase):
    def test_the_registry_comes_from_the_given_dir(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack  # noqa: PLC0415

        seen: list[str] = []

        def registry(path: str) -> dict:
            seen.append(str(path))
            return {}

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}}}
        out = REPO_ROOT / "tmp" / "emupack-registry"
        with mock.patch.object(generate_pack, "load_data_dir_registry", registry):
            generate_pack.generate_emulator_pack(
                ["handy"], str(REPO_ROOT / "emulators"), db, "bios", str(out),
                zip_contents={}, platforms_dir="elsewhere",
            )
        for leftover in out.glob("*"):
            leftover.unlink()
        if out.exists():
            out.rmdir()
        self.assertEqual(seen, ["elsewhere"])



class CoreArchivesAreCounted(unittest.TestCase):
    def test_a_missing_required_bios_zip_is_printed(self):
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        result = {"undeclared_files": [
            {"name": "neogeo.zip", "category": "bios_zip", "required": True,
             "in_repo": False, "emulator": "fbneo"},
        ]}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            verify._print_undeclared_section(result, verbose=False)
        self.assertIn("1 required missing", out.getvalue())
        self.assertIn("neogeo.zip", out.getvalue())


class ExistenceReportsWhatThePackReports(unittest.TestCase):
    def test_a_contradicted_hash_is_a_discrepancy(self):
        """30 RetroArch entries printed DISCREPANCY in the pack, nothing in verify."""
        import tempfile  # noqa: PLC0415

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            path = Path(tmp) / "aes.zip"
            path.write_bytes(b"local dump")
            entry = {"name": "aes.zip", "md5": "9d2ff2333e23910cf56f7f785609d36a"}
            result = verify.verify_entry_existence(
                entry, str(path), resolve_status="hash_mismatch", platform_display="RetroArch"
            )
        self.assertEqual(result["status"], verify.Status.OK)
        self.assertIn("declared hash 9d2ff233", result["discrepancy"])

    def test_the_file_found_is_named(self):
        """RetroArch, Lakka and RetroPie pages showed no "Served by" line:
        existence mode returned no path, where the hash modes return one."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        found = verify.verify_entry_existence({"name": "a.bin"}, "bios/X/Y/a.bin")
        self.assertEqual(found["path"], "bios/X/Y/a.bin")
        self.assertNotIn("path", verify.verify_entry_existence({"name": "a.bin"}, None))


class TheDestinationsFlagNeedsAPack(unittest.TestCase):
    """--destinations describes a platform's full pack: another mode refuses it."""

    def test_refused_outside_platform_modes(self):
        for mode in (("--emulator", "handy"), ("--platform", "retroarch", "--region", "us")):
            with self.subTest(mode=mode):
                result = _run("scripts/verify.py", *mode, "--destinations", "tmp/never.json")
                self.assertEqual(result.returncode, 2, result.stdout[-300:])
                self.assertIn("--destinations", result.stderr)

    def test_the_lock_stack_is_not_rebound(self):
        """The --destinations branch reused `held`, the ExitStack that holds
        the data directory locks, for its dict: a later enter_context in
        that mode raised AttributeError."""
        import ast

        tree = ast.parse((REPO_ROOT / "scripts" / "verify.py").read_text(encoding="utf-8"))
        body = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_main")
        stack = body.args.args[0].arg
        rebound = [
            node.lineno for node in ast.walk(body)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name) and target.id == stack
        ]
        self.assertEqual(rebound, [])


class EveryGapCountedIsNamed(unittest.TestCase):
    """verify --platform batocera --verbose counted 3 optional core files and
    427 game data files missing and named none of them."""

    def test_verbose_names_them_and_the_summary_says_how(self):
        import contextlib
        import io

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        result = {"undeclared_files": [
            {"name": "opt.rom", "emulator": "core", "required": False, "in_repo": False},
            {"name": "level.dat", "emulator": "engine", "required": True, "in_repo": False,
             "category": "game_data"},
        ]}
        with contextlib.redirect_stdout(io.StringIO()) as quiet:
            verify._print_undeclared_section(result, verbose=False)
        self.assertIn("1 optional missing (--verbose lists them)", quiet.getvalue())
        self.assertIn("1 missing (--verbose lists them)", quiet.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as verbose:
            verify._print_undeclared_section(result, verbose=True)
        self.assertIn("MISSING (optional): core needs opt.rom", verbose.getvalue())
        self.assertIn("MISSING (game data): engine needs level.dat", verbose.getvalue())


class BundledGameDataIsNotMissing(unittest.TestCase):
    """cross_reference put Abuse's abuse.lsp, defaults.prp and english.lsp
    under bundled while verify called them missing game data: 24 of the 427
    Batocera counted."""

    def test_bundled_game_data_is_counted_apart(self):
        import contextlib
        import io

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        result = {"undeclared_files": [
            {"name": "abuse.lsp", "emulator": "Abuse", "required": True,
             "in_repo": False, "category": "game_data", "bundled": True,
             "in_pack": False},
            {"name": "level.dat", "emulator": "engine", "required": True,
             "in_repo": False, "category": "game_data"},
        ]}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            verify._print_undeclared_section(result, verbose=True)
        self.assertIn("Game data: 0 in pack, 1 missing", out.getvalue())
        self.assertNotIn("needs abuse.lsp", out.getvalue())
        self.assertIn("Bundled with their emulator, not collected: 1 (abuse.lsp)",
                      out.getvalue())


class CoreCopiesWithoutAGapEntryAreCounted(unittest.TestCase):
    """verify --platform recalbox --system nec-pc-engine printed no Core
    files line while the pack held six geargrafx syscard copies: the gap
    report was empty, and the section returned before reading the pack's
    count."""

    def test_the_packed_count_is_printed(self):
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        for packed, expected in (({"bios": 6, "game_data": 0}, "Core files: 6 in pack"),
                                 ({"bios": 0, "game_data": 3}, "Game data: 3 in pack")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                verify._print_undeclared_section(
                    {"undeclared_files": [], "packed_extras": packed}, verbose=False
                )
            with self.subTest(packed=packed):
                self.assertIn(expected, out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            verify._print_undeclared_section(
                {"undeclared_files": [], "packed_extras": {"bios": 0, "game_data": 0}}, False
            )
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
