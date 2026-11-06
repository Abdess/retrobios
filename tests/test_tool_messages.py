"""What the maintainer tools print: names a user can act on, counts that add up."""

from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import diff_truth  # noqa: E402
import pipeline  # noqa: E402
import truth  # noqa: E402
import verify  # noqa: E402


class ABuildbotNameSelectsItsProfile(unittest.TestCase):
    """`--emulator pcfx` was refused and pointed at two PlayStation cores,
    though pcfx is in the cores: of beetle_pcfx."""

    PROFILES = {
        "beetle_pcfx": {"type": "libretro", "cores": ["pcfx"]},
        "pcsx1": {"type": "libretro"},
        "pcsx2": {"type": "standalone"},
        "a": {"type": "libretro", "cores": ["shared"]},
        "b": {"type": "libretro", "cores": ["shared"]},
    }

    def test_a_core_name_serves_the_profile(self):
        selected = common.select_emulator_profiles(["pcfx"], self.PROFILES)
        self.assertEqual([name for name, _profile in selected], ["beetle_pcfx"])

    def test_a_name_two_profiles_claim_names_both(self):
        with self.assertRaises(common.ProfileSelectionError) as caught:
            common.select_emulator_profiles(["shared"], self.PROFILES)
        self.assertIn("a, b", str(caught.exception))

    def test_an_unknown_name_still_gets_a_hint(self):
        with self.assertRaises(common.ProfileSelectionError) as caught:
            common.select_emulator_profiles(["pcsx3"], self.PROFILES)
        self.assertIn("Did you mean", str(caught.exception))

    def test_cross_reference_reports_the_resolved_profile(self):
        """cross_reference filtered on the typed name, found no profile under
        it and answered `pcfx is not run by None`."""
        def report(name: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, "scripts/cross_reference.py", "--emulator", name],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
            )
        by_core, by_profile = report("pcfx"), report("beetle_pcfx")
        self.assertEqual(by_core.returncode, 0, by_core.stderr)
        self.assertEqual(by_core.stdout, by_profile.stdout)


class AMistypedTargetGetsTheClosestName(unittest.TestCase):
    """`--target swich` printed every target and alias on two lines."""

    def test_did_you_mean(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            targets = Path(tmp) / "targets"
            targets.mkdir()
            names = [f"board-{n}" for n in range(30)] + ["nintendo-switch"]
            (targets / "p.yml").write_text(
                "targets:\n" + "".join(f"  {n}:\n    cores: [a]\n" for n in names)
            )
            (targets / "_overrides.yml").write_text(
                "p:\n  targets:\n    nintendo-switch:\n      aliases: [switch]\n"
            )
            with self.assertRaises(ValueError) as caught:
                common.load_target_config("p", "swich", tmp)
        message = str(caught.exception)
        self.assertIn("Did you mean: switch?", message)
        self.assertIn("lists all 31", message)
        self.assertNotIn("board-0", message)



class TheSystemHintCountsTheListing(unittest.TestCase):
    """`--system sony-playstaton` said "--list-systems lists all 579" and
    --list-systems printed 532: the hint counted spellings, the listing
    merges the ones that differ in case or separator."""

    def test_both_tools_count_the_lines_the_listing_prints(self):
        listing = subprocess.run(
            [sys.executable, "scripts/verify.py", "--list-systems"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=True,
        )
        printed = sum(1 for line in listing.stdout.splitlines() if "emulator" in line)
        for script in ("verify.py", "generate_pack.py"):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as out:
                argv = [sys.executable, f"scripts/{script}", "--system", "sony-playstaton"]
                if script == "generate_pack.py":
                    argv += ["--output-dir", out]
                proc = subprocess.run(
                    argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
                    check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn(f"--list-systems lists all {printed}.", proc.stderr)


class ADamagedProfileNamesItself(unittest.TestCase):
    """One misindented key in an unrelated profile stopped `verify.py
    --emulator handy` and generate_pack on a 37-line yaml traceback, the
    faulty file named near its end."""

    def test_one_line_names_the_file_and_line(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as folder:
            profiles = Path(folder)
            (profiles / "handy.yml").write_text(
                (REPO_ROOT / "emulators" / "handy.yml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (profiles / "bad.yml").write_text(
                "emulator: Bad\nfiles:\n  - name: a\n   size: 3\n", encoding="utf-8"
            )
            for script, extra in (("verify.py", []),
                                  ("generate_pack.py", ["--output-dir", folder])):
                with self.subTest(script=script):
                    proc = subprocess.run(
                        [sys.executable, f"scripts/{script}", "--emulator", "handy",
                         "--emulators-dir", folder, *extra],
                        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 1, proc.stderr)
                    self.assertNotIn("Traceback", proc.stderr)
                    self.assertEqual(proc.stderr.strip().splitlines(), [
                        f"ERROR: {profiles / 'bad.yml'}:4: did not find expected '-' "
                        "indicator. Check it with: python scripts/validate_schemas.py "
                        "--source-only"
                    ])

    def test_a_damaged_file_is_not_an_absent_one(self):
        """Ten callers skip a platform whose file is absent (except
        FileNotFoundError): a damaged one has to stop them instead."""
        self.assertFalse(issubclass(common.SourceUnreadable, FileNotFoundError))


class TheVerdictClosesARedirectedReport(unittest.TestCase):
    """`verify.py --emulator fbneo --strict > log 2>&1` put the --strict
    ERROR on the first line of the log: stdout redirected is block-buffered,
    stderr is not, and the report it closes came after."""

    def test_stderr_stays_after_what_stdout_wrote_first(self):
        program = (
            "import sys\n"
            "sys.path.insert(0, 'scripts')\n"
            "from common import run_cli\n"
            "def main():\n"
            "    print('report')\n"
            "    print('ERROR: verdict', file=sys.stderr)\n"
            "    return 1\n"
            "run_cli(main)\n"
        )
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        proc = subprocess.run(
            [sys.executable, "-c", program], cwd=REPO_ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=60, check=False, env=env,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout.splitlines(), ["report", "ERROR: verdict"])


class TheAllHelpNamesWhatItCovers(unittest.TestCase):
    """`verify.py --help` kept 'Verify all active platforms' after the
    archived status was dropped: --all covers every registered platform,
    and a reader looked for an --include-archived that no longer exists."""

    def test_no_help_text_speaks_of_active_platforms(self):
        proc = subprocess.run(
            [sys.executable, "scripts/verify.py", "--help"], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=60, check=True,
        )
        self.assertIn("Verify every registered platform", proc.stdout)
        stale = [path.name for path in sorted((REPO_ROOT / "scripts").rglob("*.py"))
                 if "active platform" in path.read_text(encoding="utf-8")]
        self.assertEqual(stale, [])


class ReadOnlyToolsRunFromAnyFolder(unittest.TestCase):
    """Only verify.py and generate_pack.py moved to the repository root.
    From another folder slots, region_audit, provenance_report and
    bundled_only said database.json was missing and to rebuild it,
    identity and list_platforms named a missing folder, and game_rules
    ended on a FileNotFoundError traceback."""

    COMMANDS = (
        ["slots.py", "--platform", "retroarch"],
        ["identity.py"],
        ["cross_reference.py", "--emulator", "handy"],
        ["list_platforms.py"],
        ["region_audit.py"],
        ["provenance_report.py"],
        ["bundled_only.py"],
        ["game_rules.py"],
    )

    def test_each_reads_the_repository_from_a_subfolder(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as folder:
            for command in self.COMMANDS:
                with self.subTest(command=command[0]):
                    proc = subprocess.run(
                        [sys.executable, str(REPO_ROOT / "scripts" / command[0]),
                         *command[1:]],
                        cwd=folder, capture_output=True, text=True, timeout=300,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
                    self.assertNotIn("Traceback", proc.stderr)
                    self.assertEqual(os.listdir(folder), [])

    def test_a_typed_path_is_read_from_where_it_was_typed(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as folder:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "slots.py"),
                 "--db", "nosuch.json"],
                cwd=folder, capture_output=True, text=True, timeout=300, check=False,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertIn(str(Path(folder) / "nosuch.json"), proc.stderr)


class AMistypedTargetAcrossAllPlatforms(unittest.TestCase):
    """`verify --all --target swich` ended on "no platform has it" after 17
    INFO lines, two of which held the suggestion."""

    def test_the_refusal_suggests_and_names_the_platforms(self):
        platforms = common.list_registered_platforms(str(REPO_ROOT / "platforms"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(ValueError) as caught:
            common.build_target_cores_cache(
                platforms, "swich", str(REPO_ROOT / "platforms"), is_all=True
            )
        self.assertIn("Did you mean: switch (", str(caught.exception))
        self.assertIn("retroarch", str(caught.exception))
        self.assertEqual(out.getvalue(), "")


class AMistypedDataKeyGetsTheClosestName(unittest.TestCase):
    """`--key dolphin-sis` printed all 27 keys on one line."""

    def test_did_you_mean(self):
        proc = subprocess.run(
            [sys.executable, "scripts/refresh_data_dirs.py", "--key", "dolphin-sis", "--dry-run"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("unknown key: dolphin-sis. Did you mean: dolphin-sys? --dry-run lists all",
                      proc.stderr)
        self.assertNotIn("ppsspp-assets", proc.stderr)

class TheGapHeadingAddsUp(unittest.TestCase):
    """Amiberry read 261 files in profile, 7 declared and 238 undeclared:
    16 entries were set aside without a word."""

    def test_every_entry_is_counted_once(self):
        import cross_reference as xref

        files = [
            {"name": "kick.rom", "required": True},
            {"name": "game.grp", "size": 10},
            {"name": "game.grp", "size": 20},
            {"name": "a.bin", "archive": "set.zip"},
            {"name": "b.bin", "archive": "set.zip"},
            {"name": "picked.bin", "path": None},
            {"name": "gone.bin", "unsourceable": "never distributed"},
        ]
        profiles = {"emu": {"emulator": "Emu", "type": "libretro", "systems": ["s"],
                            "files": files}}
        report = xref.cross_reference(profiles, {}, {"files": {}, "indexes": {}},
                                      all_declared={"kick.rom": [(None, "kick.rom")]})
        data = report["emu"]
        self.assertEqual(
            xref.profile_breakdown(data),
            "1 declared by platforms, 3 undeclared, 1 unsourceable, "
            "2 set aside (1 other versions of a slot, 1 outside the pack)",
        )
        self.assertEqual(
            data["declared_files"] + data["undeclared_files"] + data["unsourceable_files"]
            + sum(data["set_aside"].values()),
            data["total_files"],
        )


class AnOfflineRunWithNoCacheStopsFirst(unittest.TestCase):
    """On a fresh clone, pipeline.py --offline built every pack before saying
    the data directories had never been fetched."""

    def _args(self, **flags):
        import argparse

        return argparse.Namespace(**{"offline": True, "skip_packs": False, **flags})

    def test_refused_before_any_step(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            cache = Path(tmp) / "cache"
            (Path(tmp) / "_data_dirs.yml").write_text(
                f"data_directories:\n  a:\n    local_cache: {cache}\n"
            )
            parser = mock.Mock()
            pipeline._refuse_offline_without_caches(parser, self._args(), tmp)
            self.assertIn("refresh_data_dirs.py", parser.error.call_args.args[0])
            for args in (self._args(offline=False), self._args(skip_packs=True)):
                parser = mock.Mock()
                pipeline._refuse_offline_without_caches(parser, args, tmp)
                parser.error.assert_not_called()
            cache.mkdir()
            parser = mock.Mock()
            pipeline._refuse_offline_without_caches(parser, self._args(), tmp)
            parser.error.assert_not_called()


class AnOfflineExportWithNoOriginalsStopsFirst(unittest.TestCase):
    """pipeline.py --offline --with-export, which tools.md listed as a
    standard command, built the database, verify and the truth model on a
    fresh clone, then failed step 2e on every platform whose own file it
    patches: --offline never passes --fetch."""

    def _args(self, **flags):
        import argparse

        return argparse.Namespace(**{"offline": True, "with_export": True, **flags})

    def test_refused_before_any_step(self):
        from exporter import discover_exporters

        patched = sorted(n for n, e in discover_exporters().items() if e.needs_original())
        self.assertIn("batocera", patched)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            parser = mock.Mock()
            pipeline._refuse_offline_export_without_originals(parser, self._args(), tmp)
            message = parser.error.call_args.args[0]
            self.assertIn("export_native.py --all --refresh-cache", message)
            self.assertIn("batocera", message)
            for args in (self._args(offline=False), self._args(with_export=False)):
                parser = mock.Mock()
                pipeline._refuse_offline_export_without_originals(parser, args, tmp)
                parser.error.assert_not_called()
            for name in patched:
                (Path(tmp) / name).mkdir()
                (Path(tmp) / name / "original").write_text("x")
            parser = mock.Mock()
            pipeline._refuse_offline_export_without_originals(parser, self._args(), tmp)
            parser.error.assert_not_called()

    def test_the_tools_page_says_so(self):
        text = (REPO_ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        self.assertIn("export_native.py --all --refresh-cache", text)


class ThePipelineFlagTableSaysEveryRefusal(unittest.TestCase):
    """tools.md said --full-narrowings is refused with --skip-packs only, and
    advanced-usage.md kept its own shorter list: `--source truth
    --full-narrowings` failed with nothing on either page saying so."""

    PAIRS = {"--source": "platform", "--all-variants": True, "--full-narrowings": True,
             "--skip-packs": True}

    def _refused(self, flags: dict) -> bool:
        import argparse

        args = argparse.Namespace(source=None, all_variants=False, full_narrowings=False,
                                  skip_packs=False)
        for flag, value in flags.items():
            setattr(args, flag.lstrip("-").replace("-", "_"), value)
        parser = mock.Mock()
        pipeline._refuse_unapplied_flags(parser, args)
        return parser.error.called

    def test_each_refused_pair_is_in_the_row_of_a_flag(self):
        import itertools

        text = (REPO_ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        rows = {line.split("`")[1].split()[0]: line for line in text.splitlines()
                if line.startswith("| `--")}
        for (a, va), (b, vb) in itertools.combinations(self.PAIRS.items(), 2):
            if not self._refused({a: va, b: vb}):
                continue
            with self.subTest(pair=(a, b)):
                self.assertTrue(f"`{b}" in rows.get(a, "") or f"`{a}" in rows.get(b, ""),
                                f"{a} with {b} is refused, and neither row says so")
        self.assertIn("`--source truth`", rows["--full-narrowings"])

    def test_one_list_of_refusals(self):
        text = (REPO_ROOT / "wiki" / "advanced-usage.md").read_text(encoding="utf-8")
        self.assertNotIn("are refused with", text)
        self.assertIn("tools.md#pipeline", text)


class TheTruthDiffShowsWhereAndAsksNothing(unittest.TestCase):
    """The markdown wrote `**Remove** hiscore.dat (phantom)` beside six
    `**Add** hiscore.dat`, none with a path, for files profiled cores read."""

    def _report(self) -> dict:
        truth_sys = {"files": [
            {"name": "hiscore.dat", "path": "mame2003/hiscore.dat",
             "md5": "a" * 32, "_cores": ["mame2003"]},
        ], "_coverage": {"cores_unprofiled": []}}
        scraped_sys = {"files": [
            {"name": "hiscore.dat", "destination": "fbneo/hiscore.dat", "md5": "b" * 32},
        ]}
        report = truth.diff_platform_truth(
            {"systems": {"arcade": truth_sys}}, {"systems": {"arcade": scraped_sys}}
        )
        report["platform"] = "p"
        return report

    def test_entries_carry_their_destination(self):
        div = self._report()["divergences"]["arcade"]
        self.assertEqual(div["extra_phantom"][0]["destination"], "fbneo/hiscore.dat")
        self.assertEqual(div["missing"][0]["destination"], "mame2003/hiscore.dat")

    def test_neither_format_asks_for_a_removal(self):
        report = self._report()
        for text in (diff_truth._format_markdown(report),
                     diff_truth._format_terminal(report)):
            self.assertNotIn("Remove", text)
            self.assertNotIn("phantom", text.lower())
            self.assertIn("fbneo/hiscore.dat", text)
            self.assertIn("mame2003/hiscore.dat", text)


class TheVerifySummaryCountsDiscrepancies(unittest.TestCase):
    """19 DISCREPANCY lines above a last line that read clean."""

    def test_the_closing_line_names_them(self):
        details = [
            {"system": "arcade", "name": "aes.zip", "status": verify.Status.OK,
             "discrepancy": "file present (OK) but hash differs"},
            # Printed as MISSING, so not a second time as a discrepancy.
            {"system": "arcade", "name": "x.zip", "status": verify.Status.MISSING,
             "discrepancy": "unmet"},
            {"system": "arcade", "name": "x.zip", "status": verify.Status.MISSING},
        ]
        summary = verify._overall_summary([
            ({"severity_counts": {}, "details": details}, ["RetroArch"]),
            ({"severity_counts": {}, "details": []}, ["Batocera"]),
        ])
        self.assertIn("1 discrepancy (RetroArch 1)", summary)

    def test_a_shared_destination_names_the_path_and_both_sides(self):
        result = {"name": "disk.rom", "status": verify.Status.UNTESTED}
        entry = {"name": "disk.rom", "md5": "793f8678" + "0" * 24}
        self.assertTrue(verify._twin_unmet(
            result, "coco", entry, "nec-pc-88", "bios/disk.rom"
        ))
        message = result["discrepancy"]
        for part in ("bios/disk.rom", "nec-pc-88", "coco", "md5 793f8678"):
            self.assertIn(part, message)


class EveryPlatformInTheSummaryCarriesItsCount(unittest.TestCase):
    """'17 discrepancies (Lakka 5, RetroArch 5, RetroBat 2, RetroDECK 4,
    ROCKNIX)': the one platform with a single entry had no number, and the
    named counts did not add up to the total."""

    def test_a_count_of_one_is_written(self):
        one = {"severity_counts": {verify.Severity.WARNING: 1}, "details": []}
        two = {"severity_counts": {verify.Severity.WARNING: 2}, "details": []}
        summary = verify._overall_summary([(two, ["Lakka"]), (one, ["ROCKNIX"])])
        self.assertIn("3 warning (Lakka 2, ROCKNIX 1)", summary)


class HeldButNotPackedNamesEachReason(unittest.TestCase):
    """'Core files held but not packed: 16 (a packed file occupies its
    directory)' on Lakka, where 14 of the 16 are installed with their
    emulator: the first entry's reason stood for the whole count."""

    @staticmethod
    def _entry(name: str, reason: str, category: str = "bios") -> dict:
        return {"name": name, "emulator": "x", "required": True, "in_repo": True,
                "in_pack": False, "omitted": reason, "category": category}

    def _printed(self, entries: list[dict]) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            verify._print_undeclared_section({"undeclared_files": entries}, False)
        return out.getvalue()

    def test_each_reason_carries_its_count(self):
        entries = [self._entry("a.rom", "a packed file occupies its directory")]
        entries += [self._entry(f"{i}.rom", "installed with its emulator") for i in range(3)]
        entries += [self._entry(f"g{i}", "installed with its emulator", "game_data")
                    for i in range(2)]
        entries.append(self._entry("g9", "no platform slug for its system", "game_data"))
        text = self._printed(entries)
        self.assertIn(
            "Core files held but not packed: 4 (3 installed with its emulator, "
            "1 a packed file occupies its directory)", text)
        self.assertIn(
            "Game data held but not packed: 3 (2 installed with its emulator, "
            "1 no platform slug for its system)", text)

    def test_a_missing_file_follows_the_line_that_counts_it(self):
        """Indented under 'held but not packed: 102 (installed with its
        emulator)', Batocera's one missing sfiii2a.zip read as one of them."""
        missing = {"name": "sfiii2a.zip", "emulator": "FinalBurn Neo", "required": True,
                   "in_repo": False, "category": "bios"}
        lines = self._printed(
            [missing, self._entry("a.rom", "installed with its emulator")]
        ).splitlines()
        self.assertTrue(lines[0].startswith("  Core files: "), lines)
        self.assertIn("MISSING (required): FinalBurn Neo needs sfiii2a.zip", lines[1])
        self.assertTrue(lines[2].startswith("  Core files held but not packed: "), lines)

    def test_one_name_read_at_two_paths_prints_both_paths(self):
        """MyMinUI printed 'FinalBurn Neo needs sfiii2a.zip' twice, word for
        word, for Bios/FBN/ and Bios/NG/."""
        base = {"name": "sfiii2a.zip", "emulator": "FinalBurn Neo", "required": True,
                "in_repo": False, "category": "bios"}
        lone = dict(base, name="other.zip", path="Bios/FBN/other.zip")
        text = self._printed([dict(base, path="Bios/FBN/sfiii2a.zip"),
                              dict(base, path="Bios/NG/sfiii2a.zip"), lone])
        self.assertIn("FinalBurn Neo needs Bios/FBN/sfiii2a.zip", text)
        self.assertIn("FinalBurn Neo needs Bios/NG/sfiii2a.zip", text)
        self.assertIn("FinalBurn Neo needs other.zip\n", text)

    def test_a_single_reason_reads_as_before(self):
        text = self._printed([self._entry("a.rom", "installed with its emulator")] * 2)
        self.assertIn("Core files held but not packed: 2 (installed with its emulator)", text)


class APlatformWithoutTargetsSaysSo(unittest.TestCase):
    """`--platform misterfpga --target switch` printed 'No target config for
    platform 'misterfpga': platforms/targets/misterfpga.yml', which reads as
    a file missing from the repository."""

    def test_the_message_names_the_reason_and_the_platforms_with_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "targets").mkdir()
            for name in ("retroarch", "batocera", "_overrides"):
                (Path(tmp) / "targets" / f"{name}.yml").write_text("targets: {}\n")
            with self.assertRaises(FileNotFoundError) as caught:
                common.load_target_config("misterfpga", "switch", tmp)
        self.assertEqual(
            str(caught.exception),
            "misterfpga has no hardware targets: drop --target "
            "(platforms with targets: batocera, retroarch)",
        )


class OneNameListsThePlatforms(unittest.TestCase):
    """install.py --list-platforms, generate_pack.py --list, and no listing
    at all in verify.py: three scripts, three answers to one question."""

    def _run(self, script: str, flag: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, f"scripts/{script}", flag], capture_output=True, text=True,
            cwd=str(REPO_ROOT), timeout=120, check=False,
        )

    def test_both_tools_take_it_and_agree(self):
        verify_out = self._run("verify.py", "--list-platforms")
        pack_out = self._run("generate_pack.py", "--list-platforms")
        self.assertEqual(verify_out.returncode, 0, verify_out.stderr)
        self.assertEqual(pack_out.returncode, 0, pack_out.stderr)
        self.assertEqual(verify_out.stdout, pack_out.stdout)
        self.assertIn("retroarch", verify_out.stdout.split())
        self.assertIn("--list-platforms", (REPO_ROOT / "install.py").read_text())

    def test_the_installer_name_is_the_one_documented(self):
        tools = (REPO_ROOT / "wiki" / "tools.md").read_text()
        self.assertIn("generate_pack.py --list-platforms", tools)
        self.assertIn("verify.py --list-platforms", tools)


class OneSpellingPerOption(unittest.TestCase):
    """verify.py -p batocera worked and slots.py -p batocera was refused."""

    SHORT = {"--platform": "-p", "--target": "-t"}
    # migrate.py's --target is the directory files move to, not a hardware target.
    OTHER_MEANING = {("migrate.py", "--target")}

    def test_every_script_takes_the_short_forms(self):
        import ast  # noqa: PLC0415

        missing = []
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and getattr(node.func, "attr", None) == "add_argument"):
                    continue
                flags = [a.value for a in node.args
                         if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                for long, short in self.SHORT.items():
                    if (path.name, long) in self.OTHER_MEANING:
                        continue
                    if long in flags and short not in flags:
                        missing.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} {long}")
        self.assertEqual(missing, [])


class ThePipelineRefreshesTheCommittedExport(unittest.TestCase):
    """Step 2e wrote to <output-dir>/upstream while exports/ is the copy the
    site and the platforms read, so a green run left it stale."""

    def test_the_export_step_writes_the_default_directory(self):
        import ast

        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Assign)
                    and any(getattr(t, "id", "") == "export_cmd" for t in node.targets)):
                words = [getattr(e, "value", None) for e in node.value.elts]
                self.assertIn("scripts/export_native.py", words)
                self.assertNotIn("--output-dir", words)
                return
        self.fail("no export_cmd in pipeline.py")


class ThePipelineCountsItsRealSteps(unittest.TestCase):
    """Labels read N/8 for a run of 24 steps, and the summary used keys
    the log never printed."""

    def test_every_recorded_step_has_a_label(self):
        import re  # noqa: PLC0415

        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        keys = set(re.findall(r'results\["(\w+)"\] =', source))
        self.assertEqual(keys - set(pipeline.STEP_LABELS), set())

    def test_a_label_written_out_is_one_of_the_list(self):
        import re  # noqa: PLC0415

        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        written = re.findall(r'run\([^()]*?, "([^"]+)"\)', source)
        numbers = {label.split(" ", 1)[0] for label in pipeline.STEP_LABELS.values()}
        for label in written:
            with self.subTest(label=label):
                # A step's own label, or a second command of a listed step.
                self.assertIn(label.split(" ", 1)[0], numbers)

    def test_no_title_counts_eight_steps(self):
        """Three print() headers of step 5 still read "5/8" beside the
        computed "5 consistency check [20/24]"."""
        import re  # noqa: PLC0415

        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'"[^"\n]*---[^"\n]*\b\d+[a-z]?/\d+\b[^"\n]*"', source), [])

    def test_progress_comes_from_the_list(self):
        total = len(pipeline.STEP_LABELS)
        title = pipeline.step_title(pipeline.STEP_LABELS["render_site"])
        self.assertEqual(title, f"8b render site [{total}/{total}]")
        self.assertNotIn("/8", pipeline.step_title(pipeline.STEP_LABELS["verify"]))

    def test_a_skipped_schema_check_says_how_to_run_it(self):
        """Step 0 said only "jsonschema not installed", then the run read
        COMPLETE and the schema failed in PR validation."""
        argv = ["pipeline.py", "--offline", "--skip-packs", "--skip-docs"]
        out = io.StringIO()
        real_find_spec = pipeline.importlib.util.find_spec
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            pipeline, "run", return_value=(True, "")
        ), mock.patch.object(
            pipeline.importlib.util, "find_spec",
            side_effect=lambda name, *a: None if name == "jsonschema"
            else real_find_spec(name, *a),
        ), contextlib.redirect_stdout(out), contextlib.suppress(SystemExit):
            pipeline.main()
        line = next(
            row for row in out.getvalue().splitlines()
            if "0 validate schemas" in row and "SKIPPED" in row
        )
        self.assertIn('pip install "jsonschema[format-nongpl]"', line)
        self.assertIn("PR validation runs this check", line)

    def test_an_offline_buildbot_check_has_a_summary_row(self):
        argv = ["pipeline.py", "--offline", "--check-buildbot", "--skip-packs",
                "--skip-docs"]
        out = io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            pipeline, "run", return_value=(True, "RetroArch: 1/1 OK\n")
        ), contextlib.redirect_stdout(out), contextlib.suppress(SystemExit):
            pipeline.main()
        summary = out.getvalue().split("=" * 60)[1]
        self.assertIn("2b   check_buildbot", summary)
        # The number the run printed for the step leads its summary row.
        self.assertIn("4d   bundled_only", summary)
        self.assertTrue(
            pipeline.step_title(pipeline.STEP_LABELS["bundled_only"]).startswith("4d ")
        )


class AHashConflictNamesBothCores(unittest.TestCase):
    """The warning named the second core only, and not which value stayed."""

    def test_both_cores_and_the_kept_value(self):
        truth._CONFLICTS_SHOWN.clear()
        system: dict = {}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            truth._merge_file_into_system(
                system, {"name": "G.yaml", "path": "r/G.yaml", "sha1": "5e" * 20},
                "pcsx2", None,
            )
            truth._merge_file_into_system(
                system, {"name": "G.yaml", "path": "r/G.yaml", "sha1": "7e" * 20},
                "yaps2", None,
            )
        self.assertIn(f"{'5e' * 20} (pcsx2) kept", err.getvalue())
        self.assertIn(f"{'7e' * 20} (yaps2)", err.getvalue())

    def test_the_origin_is_not_written_to_the_model(self):
        profile = {"type": "libretro", "systems": ["sony-playstation"],
                   "files": [{"name": "a.bin", "system": "sony-playstation",
                              "md5": "a" * 32}]}
        model = truth.generate_platform_truth(
            "p", {"cores": ["c"], "systems": {}}, {}, {"c": profile}
        )
        entries = [f for s in model["systems"].values() for f in s.get("files", [])]
        self.assertTrue(entries)
        self.assertFalse(any("_hash_by" in f for f in entries))


class HelpTextsWrapBetweenWords(unittest.TestCase):
    def test_check_freshness_areas(self):
        proc = subprocess.run(
            [sys.executable, "scripts/check_freshness.py", "--help"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=False,
            env={**os.environ, "COLUMNS": "80"}, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("coreinfo", " ".join(proc.stdout.split()))

    def test_docstring_descriptions_keep_their_layout(self):
        """romset_recipes ran its two questions into one paragraph and both
        help texts printed reST double backquotes."""
        for script, line in (("romset_recipes.py", "--identify"),
                              ("validate_site.py", None)):
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--help"],
                    capture_output=True, text=True, cwd=REPO_ROOT, check=False,
                    env={**os.environ, "COLUMNS": "80"}, timeout=60,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn("``", proc.stdout)
                if line:
                    self.assertIn(line, proc.stdout.splitlines())


class PlatformListsNameEveryPlatform(unittest.TestCase):
    def test_list_platforms_prints_every_registered_platform(self):
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_OUTPUT"}
        proc = subprocess.run(
            [sys.executable, "scripts/list_platforms.py"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=False,
            env=env, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("retropie", proc.stdout)

    def test_the_pack_list_marks_installer_only_platforms(self):
        """generate_pack --list printed retropie like a platform with a
        release pack."""
        proc = subprocess.run(
            [sys.executable, "scripts/generate_pack.py", "--list"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=False, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        self.assertIn("retropie (installer only)", lines)
        self.assertIn("knulli (installer only)", lines)
        self.assertIn("retroarch", lines)


class NoScriptReadsTheTokenOnItsOwn(unittest.TestCase):
    """Nine scripts read GITHUB_TOKEN from the environment after
    github_token() existed, and went anonymous when run on their own.
    download.py is the user's downloader: it runs without the repository and
    a user's gh session is not its business."""

    READS = ('environ.get("GITHUB_TOKEN"', "environ['GITHUB_TOKEN']",
             'environ["GITHUB_TOKEN"]', 'environ.get("GH_TOKEN"')
    OWNERS = {"scripts/common.py", "scripts/download.py"}

    def test_every_reader_asks_github_token(self):
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative in self.OWNERS:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if " = " in line and line.split(" = ")[0].strip().startswith("env["):
                    continue
                with self.subTest(file=relative, line=number):
                    self.assertFalse(any(read in line for read in self.READS), line.strip())


class TheGitHubTokenComesFromGh(unittest.TestCase):
    """Only refresh_stale asked gh: profile_sync refused the run and the
    scrapers went anonymous for a maintainer logged in to gh."""

    def setUp(self):
        common._gh_cli_token.cache_clear()
        self.addCleanup(common._gh_cli_token.cache_clear)
        env = {k: v for k, v in os.environ.items()
               if k not in ("GITHUB_TOKEN", "GH_TOKEN", "RETROBIOS_OFFLINE")}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _gh(token: str = "gho_fromgh", code: int = 0):
        return mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(["gh"], code, token, ""),
        )

    def test_gh_answers_when_the_variable_is_unset(self):
        with self._gh():
            self.assertEqual(common.github_token(), "gho_fromgh")
        # Subprocesses of the run inherit it.
        self.assertEqual(os.environ.get("GITHUB_TOKEN"), "gho_fromgh")

    def test_the_variable_wins(self):
        os.environ["GITHUB_TOKEN"] = "set"
        with self._gh() as run:
            self.assertEqual(common.github_token(), "set")
        run.assert_not_called()

    def test_no_gh_means_anonymous(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("gh")):
            self.assertEqual(common.github_token(), "")
        with self._gh("", 1):
            common._gh_cli_token.cache_clear()
            self.assertEqual(common.github_token(), "")

    def test_offline_runs_never_ask(self):
        os.environ["RETROBIOS_OFFLINE"] = "1"
        with self._gh() as run:
            self.assertEqual(common.github_token(), "")
        run.assert_not_called()

    def test_every_api_caller_reads_it(self):
        import profile_sync  # noqa: PLC0415
        import upstream  # noqa: PLC0415
        from scraper import base_scraper  # noqa: PLC0415

        with self._gh():
            self.assertEqual(
                upstream._headers("https://api.github.com/repos/o/n")["Authorization"],
                "token gho_fromgh",
            )
        os.environ.pop("GITHUB_TOKEN")
        with self._gh():
            self.assertEqual(base_scraper.github_headers()["Authorization"],
                             "Bearer gho_fromgh")
        os.environ.pop("GITHUB_TOKEN")
        with self._gh(), contextlib.redirect_stderr(io.StringIO()):
            profile_sync._check_quota(606, offline=False)

    def test_another_forge_never_triggers_gh(self):
        import upstream  # noqa: PLC0415

        with self._gh() as run:
            headers = upstream._headers("https://gitlab.com/api/v4/projects/1")
        self.assertNotIn("Authorization", headers)
        run.assert_not_called()


class CitedCommandsRunWhenPasted(unittest.TestCase):
    """check_freshness wrote "run python scripts/generate_truth.py" on one
    line and "export_native.py --platform bizhawk writes it again" two lines
    below: pasted from the repository root, the second is command not found.
    A message that hands the reader a command spells the whole command."""

    CITED = re.compile(r"(?:^|run |with |then |, )([a-z_]+\.py) --[a-z]")

    def test_no_message_cites_a_bare_script(self):
        import ast  # noqa: PLC0415

        offenders = []
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docs = {
                id(node.body[0].value)
                for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)
            }
            offenders += [
                f"{path.relative_to(REPO_ROOT)}:{node.lineno} {node.value.strip()[:60]}"
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docs and self.CITED.search(node.value)
            ]
        self.assertEqual(offenders, [])

    def test_the_target_hint_is_a_whole_command(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            targets = Path(tmp) / "targets"
            targets.mkdir()
            (targets / "p.yml").write_text("targets:\n  switch:\n    cores: [a]\n")
            with self.assertRaises(ValueError) as caught:
                common.load_target_config("p", "swich", tmp)
        self.assertIn("python scripts/verify.py --platform p --list-targets",
                      str(caught.exception))


if __name__ == "__main__":
    unittest.main()
