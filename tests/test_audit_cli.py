"""Audit regressions on the command line tools and the pipeline: flags, refusals, exits and summaries."""

from __future__ import annotations

import tests
from tests.sources import script_source
import ast
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from scripts import pipeline
from orchestrate import checks, consistency, results, runner
from tests import REPO_ROOT


class VerboseAppliesToJson(unittest.TestCase):
    """verify accepted --verbose beside --json in every mode and dropped it:
    the output was byte for byte the same, and the passing entries a script
    asked for never came."""

    def _run(self, *args: str) -> dict:
        import json
        import subprocess

        completed = subprocess.run(
            [sys.executable, "scripts/verify.py", *args, "--json"],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=900, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        return json.loads(completed.stdout)

    def test_emulator_and_system_modes_list_the_passing_entries(self):
        for mode in (("--emulator", "handy"), ("--system", "atari-lynx")):
            with self.subTest(mode=mode[0]):
                plain = self._run(*mode)
                verbose = self._run(*mode, "--verbose")
                self.assertGreater(len(verbose["details"]), len(plain["details"]))
                self.assertIn("ok", {d["status"] for d in verbose["details"]})

    def test_every_json_branch_reads_the_flag(self):
        source = script_source("verify.py")
        # Defined once, called by the emulator and system output and the platform output.
        self.assertEqual(source.count("json_details("), 3)
        self.assertNotIn('if d["status"] != Status.OK\n            ]', source)


class OnePlatformPerFlag(unittest.TestCase):
    """generate_pack validated --platform as a comma list, then used the whole
    string as one name: `--platform bizhawk,misterfpga` passed and ended in a
    FileNotFoundError traceback. Every script now says it takes one name."""

    def test_a_list_is_refused_with_a_message(self):
        import subprocess

        runs = {
            "generate_pack.py": ["--list-systems"],
            "verify.py": [],
            "cross_reference.py": [],
        }
        for script, extra in runs.items():
            with self.subTest(script=script):
                completed = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--platform",
                     "bizhawk,misterfpga", *extra],
                    capture_output=True, text=True, cwd=REPO_ROOT, timeout=600, check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("takes one platform", completed.stderr)
                self.assertNotIn("Traceback", completed.stderr)

    def test_unknown_names_still_get_a_suggestion(self):
        from model.cliargs import require_platform

        with self.assertRaises(SystemExit) as caught:
            require_platform("batocra", str(REPO_ROOT / "platforms"))
        self.assertIn("batocera", str(caught.exception))

    def test_a_file_that_is_no_platform_is_refused(self):
        """_shared and the emulatorjs base config are YAML files under
        platforms/, not platforms: verify --platform _shared reported 0/0."""
        from model.cliargs import require_platform

        for name in ("_shared", "_registry", "emulatorjs"):
            with self.subTest(name=name), self.assertRaises(SystemExit) as caught:
                require_platform(name, str(REPO_ROOT / "platforms"))
            self.assertIn("unknown platform", str(caught.exception))


class PipelineRegressions(unittest.TestCase):
    def test_integrity_checks_the_variants_step_4_built(self):
        """Step 6 ran --verify-packs without --all-variants: the five
        narrowed packs were never opened and an empty _Platform passed."""
        import argparse

        def command(**flags) -> list[str]:
            base = {"output_dir": "dist", "target": None, "all_variants": False}
            return checks.integrity_command(argparse.Namespace(**{**base, **flags}))

        self.assertIn("--all-variants", command(all_variants=True))
        self.assertNotIn("--all-variants", command())
        self.assertEqual(command(target="switch")[-2:], ["--target", "switch"])

    @staticmethod
    def _verified(label: str, ok: int, total: int, core_files: int = 0) -> dict:
        """One platform as verify.py --destinations records it."""
        key = label.lower().replace(" ", "")
        return {key: {"platform": key, "label": label, "ok": ok, "total": total,
                      "core_files": core_files, "pack_destinations": []}}

    @staticmethod
    def _packed(label: str, ok: int, total: int, core_files: int = 0,
                unsafe_excluded: int = 0) -> dict:
        """One full pack as generate_pack.py --counts records it."""
        return {"label": label, "platforms": [label.lower().replace(" ", "")],
                "archive": "pack.zip", "ok": ok, "total": total,
                "core_files": core_files, "unsafe_excluded": unsafe_excluded, "trees": []}

    def test_missing_pack_is_a_consistency_failure(self):
        verify = self._verified("RetroArch", 2, 2)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(consistency.compare_counts(verify, []))

    def test_display_name_and_registry_id_meet_by_id(self):
        verify = self._verified("MiSTer FPGA", 65, 65)
        pack = {**self._packed("misterfpga", 65, 65), "platforms": ["misterfpga"]}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(consistency.compare_counts(verify, [pack]))

    def test_the_cores_share_is_compared_too(self):
        """RomM passed this step while verify counted 412 core files and game
        data in the pack and the builder placed 60."""
        verify = self._verified("RomM", 383, 383, core_files=412)
        pack = self._packed("RomM", 383, 383, core_files=60)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertFalse(consistency.compare_counts(verify, [pack]))
        self.assertIn("RomM: MISMATCH core files verify 412 != pack 60", out.getvalue())
        agreed = self._verified("RomM", 383, 383, core_files=60)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(consistency.compare_counts(agreed, [pack]))

    def test_an_exclusion_never_covers_a_file_verify_counts_ok(self):
        """An existence platform packs a file whose hash disagrees and a hash
        platform's verify reports it untested: exclusions that make up the
        difference hid the very divergence this step exists to catch."""
        verify = self._verified("RetroArch", 3, 3)
        pack = self._packed("RetroArch", 2, 3, unsafe_excluded=1)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertFalse(consistency.compare_counts(verify, [pack]))
        self.assertIn("(1 unsafe excluded)", out.getvalue())

    def test_a_pack_more_optimistic_than_verify_is_a_failure(self):
        """The invariant held one way only: a pack counting more OK files
        than the report passed as 'pack resolves more'."""
        verify = self._verified("DupTest", 0, 1)
        pack = self._packed("DupTest", 1, 1)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(consistency.compare_counts(verify, [pack]))

    def test_nothing_read_is_not_consistent(self):
        """A build that recorded nothing must not pass with no platform compared."""
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(consistency.compare_counts(self._verified("RetroArch", 2, 2), []))
            self.assertFalse(consistency.compare_counts({}, []))

    def test_an_unwritten_record_file_is_a_failure(self):
        """A step that crashed leaves its file empty: the check fails, it
        does not compare nothing and pass."""
        with tempfile.TemporaryDirectory() as root:
            empty = os.path.join(root, "empty.json")
            Path(empty).write_text("")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertFalse(consistency.check_consistency(empty, empty))
                self.assertFalse(consistency.check_pack_destinations(empty, empty))
        self.assertIn("unreadable counts", out.getvalue())

    def test_pack_without_verify_result_is_a_failure(self):
        verify = self._verified("RetroArch", 2, 2)
        packs = [self._packed("RetroArch", 2, 2), self._packed("Batocera", 2, 2)]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertFalse(consistency.compare_counts(verify, packs))
        self.assertIn("Batocera: pack with no verify result", out.getvalue())

    def test_a_build_that_recorded_nothing_skips_step_five(self):
        """An empty counts file is a build that stopped before its record:
        step 4 already fails, and step 5 has nothing to compare."""
        import argparse

        args = argparse.Namespace(source="full", all_variants=False, skip_packs=True)
        with tempfile.TemporaryDirectory() as root:
            empty = os.path.join(root, "counts.json")
            Path(empty).write_text("")
            step_results: dict = {}
            with contextlib.redirect_stdout(io.StringIO()):
                checks.check_steps(args, step_results, pack_counts_file=empty,
                                   destinations_file=empty)
        self.assertIs(step_results["consistency"], results.SKIPPED)

    def test_only_the_full_variant_is_recorded(self):
        """--all-variants built six packs under one label, and the last won."""
        source = script_source("generate_pack.py")
        self.assertIn('[] if record_counts and (source, required_only) == ("full", False) else None',
                      source)

    def test_slot_step_reaches_the_summary(self):
        source = script_source("pipeline.py")
        self.assertIn('results["slots"] = ok', source)

    def test_every_refresh_failure_reaches_pipeline_exit_status(self):
        for failed_label in (
            "2 refresh data directories",
            "2a refresh MAME hashes",
            "2a2 refresh FBNeo hashes",
        ):
            with self.subTest(failed_label=failed_label):
                def fake_run(_command, label, failed_label=failed_label):
                    return label != failed_label, "RetroArch: 1/1 OK\n"

                argv = ["pipeline.py", "--skip-packs", "--skip-docs"]
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(runner, "run", side_effect=fake_run),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    pipeline.main()
                self.assertEqual(raised.exception.code, 1)


    def test_a_targeted_export_reads_a_full_model(self):
        """--target wrote truth/<target>/ only, but the export read truth/."""
        commands: list[list[str]] = []

        def fake_run(command, _label):
            commands.append([str(part) for part in command])
            return True, "RetroArch: 1/1 OK\n"

        argv = ["pipeline.py", "--offline", "--skip-packs", "--skip-docs",
                "--with-export", "--target", "switch"]
        # The originals the offline export patches are not cached in a
        # checkout: the run would be refused before any step.
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            runner, "run", side_effect=fake_run
        ), mock.patch.object(pipeline, "refuse_offline_export_without_originals"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.suppress(SystemExit):
            pipeline.main()
        truth_runs = [c for c in commands if "scripts/generate_truth.py" in c]
        export = next(c for c in commands if "scripts/export_native.py" in c)
        read_dir = export[export.index("--truth-dir") + 1]
        full_models = [
            c for c in truth_runs
            if "--target" not in c and c[c.index("--output-dir") + 1] == read_dir
        ]
        self.assertTrue(full_models, truth_runs)


class OneRefreshPerOnlineRun(unittest.TestCase):
    """An online run refreshed the data trees at step 2, again in the pack
    build and again in the manifest build: a moving tree (fbneo-cheats on
    master) could change between the two, and the pack and the manifest
    described different revisions."""

    def test_the_builds_reuse_step_twos_trees(self):
        import contextlib
        import io
        from unittest import mock

        from scripts import pipeline

        commands: dict[str, list[str]] = {}

        def record(cmd, label):
            commands[label] = cmd
            return True, ""

        # A scratch output directory: step 4 purges the ZIPs of the one it
        # is given, and this run must never touch dist/.
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(runner, "run", record), \
                mock.patch.object(
                    sys, "argv", ["pipeline.py", "--skip-docs", "--output-dir", out]
                ), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit):
            pipeline.main()
        self.assertIn("2 refresh data directories", commands)
        for label in ("4 generate packs", "4b generate install manifests"):
            with self.subTest(step=label):
                self.assertIn("--no-refresh-data", commands[label])
                self.assertNotIn("--offline", commands[label])


class PipelineReportsWhatItDid(unittest.TestCase):
    """A step that did not run must not be summarised as OK.

    --offline skips the network steps and --with-export gates three more.
    Reporting them as OK claims work nobody did, and a run whose export
    never happened read exactly like one where it had.
    """

    def test_a_skipped_step_is_not_reported_as_done(self):
        self.assertTrue(bool(results.SKIPPED), "a skip must not fail the run")
        self.assertEqual(repr(results.SKIPPED), "SKIPPED")
        self.assertIsNot(results.SKIPPED, True)

    def test_every_skip_branch_uses_the_sentinel(self):
        source = script_source("pipeline.py")
        stale = re.findall(r'results\["(\w+)"\] = True', source)
        self.assertEqual(stale, [], f"steps still claiming OK when skipped: {stale}")


class ACheckThatCannotAnswerDoesNotPass(unittest.TestCase):
    """Exiting zero says the question was answered and the answer was yes.

    Four scripts said that without answering: a refresh that reached no
    remote, a freshness check whose upstream was unreachable, a restore whose
    cache could not supply a declared path, and a pack verification asked
    about one platform whose pack was not there.
    """

    def test_naming_a_platform_with_no_pack_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            named = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform",
                 "retroarch", "--verify-packs", "--output-dir", directory],
                capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300,
                check=False,
            )
            self.assertNotEqual(
                named.returncode, 0,
                "a named platform with no pack reported success:\n"
                + named.stdout + named.stderr,
            )
            # --all is a sweep: a platform nobody built is out of scope and
            # skipped, but a sweep that found no pack at all checked nothing.
            swept = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--all",
                 "--verify-packs", "--output-dir", directory],
                capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300,
                check=False,
            )
            self.assertIn("SKIP (no pack in", swept.stdout)
            self.assertNotEqual(swept.returncode, 0, swept.stdout + swept.stderr)

    def test_an_unsatisfiable_declared_path_is_reported(self):
        from scripts.release.restore import restore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            (root / ".gitignore").write_text("bios/absent.bin\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {"a" * 40: {"path": "bios/absent.bin"}}}),
                encoding="utf-8",
            )
            result = restore(
                str(cache), str(root / "database.json"), str(root / ".gitignore"),
                root=root,
            )
            self.assertEqual(result.restored, [])
            self.assertEqual(result.unsatisfied, ["bios/absent.bin"])

    def test_an_unreachable_buildbot_is_not_a_fresh_verdict(self):
        """Every HEAD unanswered printed "16 unknown" and exited 0, so the
        online pipeline printed check_buildbot OK."""
        import check_buildbot_system as cbs
        from freshness import buildbot

        registry = str(REPO_ROOT / "platforms" / "_data_dirs.yml")
        tracked = buildbot.load_tracked_entries(registry)
        self.assertTrue(tracked)
        cases = {
            "index unreachable": mock.patch.object(
                buildbot, "fetch_index", side_effect=OSError("down")),
            "every HEAD unanswered": mock.patch.object(
                buildbot, "fetch_index", return_value=set(tracked)),
        }
        for label, index in cases.items():
            with self.subTest(label), index, \
                    mock.patch.object(buildbot, "get_remote_etag", return_value=None), \
                    mock.patch.object(sys, "argv", ["check_buildbot_system.py",
                                                    "--registry", registry]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as stop:
                cbs.main()
            self.assertEqual(stop.exception.code, 1)

    def test_a_missing_profile_directory_says_so(self):
        # Bare names, as the loader imports them: scripts.core.cli would be a
        # second copy of the module, with a second InputMissing.
        from core.cli import InputMissing
        from model.profiles import load_emulator_profiles

        with self.assertRaisesRegex(InputMissing, "no emulator profile directory"):
            load_emulator_profiles(str(REPO_ROOT / "no-such-emulator-dir"))


class PipelineStepsSpeakAsTheyGo(unittest.TestCase):
    """run() captured a step and printed it at the end, stderr after stdout:
    a twenty-minute pack build was silent and a warning lost its place."""

    def test_output_keeps_its_order_and_is_returned(self):
        script = ("import sys; print('one', flush=True); "
                  "print('two', file=sys.stderr, flush=True); print('three')")
        echoed = io.StringIO()
        with contextlib.redirect_stdout(echoed):
            ok, output = runner.run([sys.executable, "-c", script], "probe")
        self.assertTrue(ok)
        self.assertEqual(output, "one\ntwo\nthree\n")
        text = echoed.getvalue()
        self.assertLess(text.index("one"), text.index("two"))
        self.assertLess(text.index("two"), text.index("three"))
        self.assertLess(text.index("three"), text.index("--- probe: OK"))


class TriageSurvivesAForgeRefusal(unittest.TestCase):
    """git.eden-emu.dev answers 403 to commit lookups: `--all --triage`
    died on the traceback after half an hour and printed no ranking."""

    def test_the_ranking_is_printed_with_the_profile_marked(self):
        from types import SimpleNamespace

        from scripts.profiling import reports as profiling_reports
        from scripts.profiling import triage

        reports = [
            profiling_reports.ProfileReport(name="eden", pin="a" * 40, head="b" * 40),
            profiling_reports.ProfileReport(name="vice", pin="c" * 40, head="d" * 40),
        ]
        selected = {
            "eden": {"source": "https://git.eden-emu.dev/eden-emu/eden", "core_version": "1"},
            "vice": {"source": "https://github.com/libretro/vice-libretro", "core_version": "1"},
        }

        def check_version(named, *_args):
            if "eden" in named.repo.slug:
                raise triage.forgehttp.UpstreamError("HTTP 403")
            return

        args = SimpleNamespace(cache_dir="", offline=True)
        out = io.StringIO()
        with mock.patch.object(triage, "check_version", check_version), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            triage.print_triage(args, selected, reports)
        # A header row and a closing count frame the ranking.
        lines = out.getvalue().splitlines()[1:-1]
        self.assertEqual(len(lines), 2)
        self.assertTrue(any("eden" in line and "unreachable" in line for line in lines))


class VerifyStrictAppliesInEveryMode(unittest.TestCase):
    """--strict was read only by the platform branch: `--emulator x --strict`
    printed MISSING (required) and exited 0, and the listings accepted it."""

    @classmethod
    def setUpClass(cls):
        if not (REPO_ROOT / "database.json").exists():
            raise unittest.SkipTest("database.json is not built")
        cls.dir = Path(tempfile.mkdtemp())
        (cls.dir / "fakeemu.yml").write_text(
            "emulator: FakeEmu\ntype: libretro\nsystems: [zz-console]\nfiles:\n"
            "  - name: does_not_exist_strict.bin\n    required: true\n"
            "    md5: 0123456789abcdef0123456789abcdef\n    validation: [md5]\n"
        )

    @classmethod
    def tearDownClass(cls):
        __import__("shutil").rmtree(cls.dir, True)

    def run_verify(self, *flags: str) -> int:
        return subprocess.run(
            [sys.executable, "scripts/verify.py", *flags], cwd=REPO_ROOT,
            capture_output=True, text=True,
            check=False,
        ).returncode

    def test_emulator_and_system_modes_fail_on_a_missing_required_file(self):
        for mode in (["--emulator", "fakeemu"], ["--system", "zz-console"]):
            with self.subTest(mode=mode[0]):
                flags = [*mode, "--emulators-dir", str(self.dir)]
                self.assertEqual(self.run_verify(*flags), 0)
                self.assertEqual(self.run_verify(*flags, "--strict"), 1)

    def test_a_listing_refuses_strict(self):
        self.assertEqual(self.run_verify("--list-emulators", "--strict"), 2)


class EveryToolRefusesAFlagItWouldDrop(unittest.TestCase):
    """The mode x flag matrix existed for generate_pack only: verify took
    --strict in --emulator mode and ignored it, pipeline took --source with
    --skip-packs and built nothing. Each pair here must exit non-zero
    before doing any work."""

    REFUSED = {
        "scripts/verify.py": [
            ["--list-emulators", "--strict"],
            ["--list-emulators", "--verbose"],
            ["--list-emulators", "--json"],
            ["--list-systems", "--region", "us"],
            ["--emulator", "handy", "--target", "switch"],
            ["--platform", "retroarch", "--standalone"],
            ["--all", "--system", "sony-playstation", "--standalone"],
        ],
        "scripts/cross_reference.py": [
            ["--all", "--platform", "retroarch"],
            ["--list-emulators", "--all"],
        ],
        "scripts/pipeline.py": [
            ["--offline", "--skip-packs", "--source", "truth"],
            ["--offline", "--skip-packs", "--all-variants"],
            ["--offline", "--skip-packs", "--full-narrowings"],
            ["--offline", "--all-variants", "--source", "platform"],
            ["--offline", "--all-variants", "--source", "full"],
            ["--offline", "--skip-packs", "--source", "full"],
            ["--offline", "--source", "truth", "--full-narrowings"],
            ["--offline", "--source", "platform", "--full-narrowings"],
        ],
        # The expert narrowings: what the pack builder refuses beside its
        # option of the same name, and a flag with no mode to apply it.
        "install.py": [
            ["--json"],
            ["--standalone"],
            ["--emulator", "duckstation", "--standalone", "--region", "us"],
            ["--emulator", "duckstation", "--standalone", "--one-per-slot"],
            ["--one-per-slot", "--system", "sony-playstation"],
            ["--one-per-slot", "--emulator", "duckstation"],
            ["--one-per-slot", "--for-games"],
            ["--one-per-slot", "--declared-only"],
            ["--one-per-slot", "--list-systems"],
            ["--source", "truth", "--system", "sony-playstation"],
            ["--source", "truth", "--target", "switch"],
            ["--source", "truth", "--one-per-slot"],
            ["--source", "truth", "--tui"],
            ["--source", "platform"],
            ["--find", "0" * 40, "--system", "sony-playstation"],
            ["--find", "0" * 40, "--one-per-slot"],
            ["--find", "0" * 40, "--check"],
            ["--find", "0" * 40, "--list-systems"],
            ["--find", "0" * 40, "--json", "--events"],
            ["--find", "0" * 40, "--json", "--pack", "tmp/"],
            ["--find", "0" * 40, "--json", "--add-app"],
            ["--find", "0" * 40, "--json", "--standalone-copies"],
            ["--find", "0" * 40, "--json", "--romm-firmware", "{platform}/bios"],
            ["--find", "0" * 40, "--json", "--from", "tmp"],
            ["--find", "0" * 40, "--pack", "tmp/"],
            ["--find", "not-a-hash"],
            ["--find", "0" * 12],
        ],
    }

    def test_each_pair_is_refused(self):
        for script, cases in self.REFUSED.items():
            for argv in cases:
                with self.subTest(script=script, argv=argv):
                    proc = subprocess.run(
                        [sys.executable, script, *argv], cwd=REPO_ROOT,
                        capture_output=True, text=True, timeout=120,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)


class AReaderThatLeavesEarlyIsNoCrash(unittest.TestCase):
    """`verify.py --list-emulators | head -1` ended on a BrokenPipeError
    traceback, and so did every listing and report."""

    def test_a_closed_pipe_ends_quietly(self):
        proc = subprocess.Popen(
            [sys.executable, "scripts/verify.py", "--list-emulators"], cwd=REPO_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # The listing fits a 64 KiB pipe: a child that wrote it all before
        # the close below never met the broken pipe and exited 0. A 4 KiB
        # pipe keeps it writing when the reader leaves.
        try:
            import fcntl

            fcntl.fcntl(proc.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        except (ImportError, AttributeError, OSError):
            pass
        proc.stdout.readline()
        proc.stdout.close()
        _, err = proc.communicate(timeout=120)
        self.assertNotIn(b"Traceback", err)
        self.assertEqual(proc.returncode, 141)

    def test_every_entry_point_goes_through_run_cli(self):
        plain = re.compile(r'if __name__ == "__main__":\n    (main\(\)|sys\.exit\(main\(\)\))')
        found = [p.name for p in sorted((REPO_ROOT / "scripts").glob("*.py"))
                 if plain.search(p.read_text())]
        self.assertEqual(found, [])


class VerifyPacksSaysWhatItExcluded(unittest.TestCase):
    """--verify-packs read the result tuple by position, dropped the unsafe
    exclusions (352/353 shown as OK with no reason) and printed 5 errors."""

    def test_the_result_is_unpacked_whole_and_every_error_printed(self):
        source = script_source("generate_pack.py")
        body = source[source.index("def _check_pack"):]
        body = body[:body.index("\ndef ")]
        self.assertIn("result.shortfall", body)
        self.assertIn("for err in result.errors", body)
        shortfall = source[source.index("def baseline_shortfall"):]
        self.assertIn("unsafe excluded", shortfall[:shortfall.index("\ndef ")])
        self.assertNotIn("errors[:5]", body)
        self.assertNotRegex(body, r"result\[\d\]")


class TargetListsReadThePinnedRelease(unittest.TestCase):
    """Each target scraper asked upstream for its latest tag: a Recalbox
    10.2 board list could filter 10.1.1 systems, and Batocera's target file
    did not even record the tag it read."""

    def test_the_revision_comes_from_the_platform_yaml(self):
        from scripts.scraper.targets import BaseTargetScraper

        with tempfile.TemporaryDirectory() as tmp:
            for name, source, tag in (
                ("a", "https://raw.githubusercontent.com/o/r/batocera-43.1/x/y", "batocera-43.1"),
                ("b", "https://gitlab.com/recalbox/recalbox/-/raw/10.1.1/a/b.xml", "10.1.1"),
                ("c", "https://github.com/o/r/blob/v2/f.cs", "v2"),
            ):
                Path(tmp, f"{name}.yml").write_text(f"source: {source}\n")
                self.assertEqual(BaseTargetScraper.pinned_revision(name, tmp), tag)
            Path(tmp, "d.yml").write_text("source: https://example.test/x\n")
            with self.assertRaises(RuntimeError):
                BaseTargetScraper.pinned_revision("d", tmp)

    def test_no_target_scraper_asks_for_the_latest_tag(self):
        for name in ("batocera", "rocknix", "recalbox"):
            source = (REPO_ROOT / "scripts" / "scraper" / "targets" / f"{name}_targets_scraper.py").read_text()
            with self.subTest(scraper=name):
                # The Batocera scraper reads the pin of the platform it is
                # instantiated for (KNULLI subclasses it).
                self.assertTrue(
                    "self.pinned_revision(PLATFORM_NAME)" in source
                    or "self.pinned_revision(self.PLATFORM)" in source
                )
                self.assertNotIn("fetch_stable_tag()", source)
                self.assertNotIn("fetch_github_latest_version(", source)
        # Lakka inherits its BIOS list and pins the release in its own version:.
        source = (REPO_ROOT / "scripts" / "scraper" / "targets" / "lakka_targets_scraper.py").read_text()
        self.assertIn("self.pinned_version(PLATFORM_NAME)", source)
        self.assertNotIn("fetch_github_latest_version(", source)


class VerifyAllSummaryNamesWhatIsWrong(unittest.TestCase):
    """The closing line counted platform severities only: a required core
    file missing on ROCKNIX was absent from it, and the one warning did not
    say which platform carried it."""

    def test_counts_carry_platforms_and_core_misses(self):
        from packs import verifysummary
        from packs import verdicts

        clean = {"severity_counts": {}, "undeclared_files": []}
        warned = {"severity_counts": {verdicts.Severity.WARNING: 1}, "undeclared_files": []}
        core_miss = {
            "severity_counts": {},
            "undeclared_files": [{
                "name": "n64.psh", "required": True, "in_repo": False,
                "category": "bios", "in_pack": True,
            }],
        }
        summary = verifysummary.overall_summary(
            [(clean, ["RetroArch"]), (warned, ["RetroDECK"]), (core_miss, ["ROCKNIX"])]
        )
        self.assertIn("1 warning (RetroDECK 1)", summary)
        self.assertIn("n64.psh (ROCKNIX)", summary)
        self.assertIn("0 critical,", summary)

    def test_a_file_missing_on_several_platforms_is_counted_once(self):
        """sfiii2a.zip missing on 15 platforms read '24 core file(s)' for 10
        distinct files, the name printed 15 times on one line."""
        from packs import verifysummary

        def missing(*names: str) -> dict:
            return {"severity_counts": {}, "undeclared_files": [
                {"name": name, "required": True, "in_repo": False,
                 "category": "bios", "in_pack": True} for name in names
            ]}

        summary = verifysummary.overall_summary([
            (missing("sfiii2a.zip"), ["Batocera"]),
            (missing("sfiii2a.zip", "ROM"), ["RetroPie"]),
            (missing("sfiii2a.zip"), ["RomM"]),
            (missing(), ["MinUI"]),
        ])
        self.assertIn(
            "2 core file(s) a core cannot run without are missing: "
            "sfiii2a.zip (every platform but MinUI); ROM (RetroPie)",
            summary,
        )
        self.assertEqual(summary.count("sfiii2a.zip"), 1)


class OneOutputFormPerRun(unittest.TestCase):
    """`diff_truth.py --json --format markdown` printed JSON with rc 0, the
    markdown asked for dropped without a word."""

    def test_json_and_markdown_are_refused_together(self):
        for script, argv in (
            ("diff_truth.py", ["--platform", "romm", "--json", "--format", "markdown"]),
            ("diff_truth.py", ["--platform", "romm", "--json", "--markdown"]),
            ("validate_pr.py", ["--json", "--markdown", "bios/Sony/PlayStation/scph5501.bin"]),
        ):
            with self.subTest(script=script, argv=argv):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", *argv], capture_output=True,
                    text=True, cwd=str(REPO_ROOT), timeout=120, check=False,
                )
                self.assertEqual(proc.returncode, 2, proc.stdout[-300:])
                self.assertIn("not allowed with", proc.stderr)


class ATargetIsNamedWhenItRemovesTheCore(unittest.TestCase):
    """--platform batocera --target rpi4 --emulator dolphin said "dolphin is
    not run by batocera", which runs it on every x86 board."""

    def test_the_message_names_the_target(self):
        result = subprocess.run(
            [sys.executable, "scripts/cross_reference.py", "--platform", "batocera",
             "--target", "bcm2711", "--emulator", "dolphin"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("bcm2711 target", result.stderr)
        self.assertNotIn("is not run by", result.stderr)


class ANamedPackThatIsAbsentFails(unittest.TestCase):
    """--verify-packs --platform retroarch on an empty directory printed
    "SKIP" and exited 1: a skip label on a failure, and no next step."""

    def test_the_line_says_fail_and_how_to_build(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform", "retroarch",
                 "--verify-packs", "--output-dir", directory],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("retroarch: FAIL (no pack in", result.stdout)
        self.assertIn("generate_pack.py --platform retroarch", result.stdout)

    def test_all_with_no_pack_is_a_failure(self):
        """--all on a mistyped or purged directory skipped every platform
        and exited 0, a passed integrity check that checked nothing."""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--all",
                 "--verify-packs", "--output-dir", directory],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("no pack to verify", result.stderr)


class AnAliasSelectsItsProfile(unittest.TestCase):
    """`--emulator mednafen_psx` refused with "use --emulator beetle_psx",
    a step the tool could take itself: the name a user reads in RetroArch
    now selects the profile it is an alias of, and says so on stderr. An
    alias without alias_of is found through the profile whose cores: names
    it."""

    def test_the_alias_selects_its_profile(self):
        import contextlib as _contextlib
        import io as _io

        from scripts.model.profiles import ProfileSelectionError, select_emulator_profiles

        profiles = {
            "flycast": {"type": "libretro", "cores": ["flycast", "flycast_gles2"]},
            "flycast_gles2": {"type": "alias", "alias_of": "flycast"},
            "orphan": {"type": "alias"},
            "core": {"type": "libretro", "cores": ["orphan"]},
            "lost": {"type": "alias"},
        }
        for name, expected in (("flycast_gles2", "flycast"), ("orphan", "core")):
            err = _io.StringIO()
            with self.subTest(name=name), _contextlib.redirect_stderr(err):
                selected = select_emulator_profiles([name], profiles)
            self.assertEqual([key for key, _ in selected], [expected])
            self.assertIn(f"{name} is {expected}", err.getvalue())
        with _contextlib.redirect_stderr(_io.StringIO()):
            both = select_emulator_profiles(["flycast", "flycast_gles2"], profiles)
        self.assertEqual([key for key, _ in both], ["flycast"])
        with self.assertRaises(ProfileSelectionError):
            select_emulator_profiles(["lost"], profiles)

    def test_verify_runs_the_alias(self):
        result = subprocess.run(
            [sys.executable, "scripts/verify.py", "--emulator", "mednafen_psx"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("beetle_psx", result.stdout)
        self.assertIn("mednafen_psx is beetle_psx", result.stderr)


class AFailedVerificationIsAnError(unittest.TestCase):
    """--all ended on "WARNING: some packs have verification errors" and
    exit 1: a warning that fails the run, naming no pack."""

    def test_the_last_line_names_the_packs(self):
        source = script_source("generate_pack.py")
        self.assertNotIn("WARNING: some packs have verification errors", source)
        self.assertIn('print(f"ERROR: packs failed verification: {\', \'.join(failing)}", file=sys.stderr)', source)


class TheGroundTruthFooterSaysWhatItCounts(unittest.TestCase):
    """"417 platform-only (no emulator profile)" where 369 of 526 files had
    a profile, 20% here for 21% on the site, and "0/81 (0%)" for MiSTer,
    which declares no core by design."""

    def _footer(self, coverage):
        import io as _io
        from contextlib import redirect_stdout

        from scripts.packs.verdicts import Severity
        from scripts.packs.report import print_platform_result

        out = _io.StringIO()
        counts = {Severity.OK: 1, Severity.INFO: 0, Severity.WARNING: 0, Severity.CRITICAL: 0}
        result = {"platform": "X", "verification_mode": "existence", "total_files": 1,
                  "severity_counts": counts, "status_counts": {"ok": 1},
                  "undeclared_files": [], "exclusion_notes": [], "details": [],
                  "ground_truth_coverage": coverage}
        with redirect_stdout(out):
            print_platform_result(result, ["X"])
        return out.getvalue()

    def test_counts_and_rounding(self):
        text = self._footer({"with_validation": 109, "with_profile": 369,
                             "platform_only": 417, "total": 526, "applicable": True})
        self.assertIn("(21%)", text)
        self.assertIn("157 platform-only", text)

    def test_not_applicable(self):
        text = self._footer({"with_validation": 0, "with_profile": 0,
                             "platform_only": 81, "total": 81, "applicable": False})
        self.assertIn("not applicable", text)
        self.assertNotIn("0/81", text)


class ThePipelineSummaryTimesEachStep(unittest.TestCase):
    """The summary gave OK per step and one total: the slow step of a
    twenty-minute run could only be found by reading the log."""

    def test_each_outcome_carries_its_time(self):
        from unittest import mock

        clock = iter([10.0, 12.5, 12.5, 20.0])
        with mock.patch.object(results.time, "monotonic", lambda: next(clock)):
            outcomes = results.StepResults(results.time.monotonic())
            outcomes["generate_db"] = True
            outcomes["refresh_data"] = results.SKIPPED
            outcomes["verify"] = True
        self.assertEqual(outcomes.seconds, {"generate_db": 2.5, "refresh_data": 0.0, "verify": 7.5})
        self.assertEqual(dict(outcomes), {"generate_db": True, "refresh_data": results.SKIPPED,
                                          "verify": True})


class StrictFailsOnMissingOnly(unittest.TestCase):
    """The docstring promised exit 1 on a required file missing or rejected,
    but a rejected file is UNTESTED, a warning, and --strict never saw it."""

    def test_the_contract(self):
        from scripts.packs.strictgate import platform_strict_failure
        from scripts.packs.verdicts import Severity

        self.assertIsNone(platform_strict_failure([{"severity_counts": {Severity.WARNING: 2}}]))
        self.assertIsNotNone(
            platform_strict_failure([{"severity_counts": {Severity.CRITICAL: 1}}]))
        self.assertNotIn("or rejected", platform_strict_failure.__doc__)


class TheRepairCommandWritesTheFileNamed(unittest.TestCase):
    """--db nosuch.json said to rebuild with --output database.json: the
    command wrote another file and the next run failed the same way."""

    def test_the_command_names_the_path(self):
        from scripts.model.database import DatabaseUnreadable, load_database

        with tempfile.TemporaryDirectory() as directory:
            target = str(Path(directory) / "nosuch.json")
            with self.assertRaises(DatabaseUnreadable) as caught:
                load_database(target)
            self.assertIn(f"--output {target}", str(caught.exception))
            Path(target).write_text("{")
            with self.assertRaises(DatabaseUnreadable) as caught:
                load_database(target)
            self.assertIn(f"--output {target}", str(caught.exception))

    def test_a_typo_beside_the_database_names_the_database(self):
        """--db databse.json beside database.json was told to rescan the whole
        collection into a second file named after the typo."""
        from scripts.model.database import DatabaseUnreadable, load_database

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "database.json").write_text("{}")
            typo = Path(directory) / "databse.json"
            with self.assertRaises(DatabaseUnreadable) as caught:
                load_database(str(typo))
        message = str(caught.exception)
        self.assertIn(f"Close match: {typo.with_name('database.json')}", message)
        self.assertNotIn("generate_db.py", message)


class VerifyPacksRefusesWhatItCannotDo(unittest.TestCase):
    """The --verify-packs refusals lived in the --all-variants checks, which
    return without that flag: --split and --one-per-slot went through, and
    a run with neither --platform nor --all failed after taking the lock."""

    def test_usage_errors_exit_2_before_any_lock(self):
        cases = (
            ["--verify-packs"],
            ["--verify-packs", "--platform", "retroarch", "--split"],
            ["--verify-packs", "--platform", "retroarch", "--one-per-slot"],
        )
        for extra in cases:
            with self.subTest(args=extra), tempfile.TemporaryDirectory() as out:
                result = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", *extra, "--output-dir", out],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
                    check=False,
                )
                self.assertEqual(result.returncode, 2, result.stderr[-300:])
                self.assertIn("--verify-packs", result.stderr)
                self.assertFalse((Path(out) / ".lock").exists())


class ABrokenRegistryIsNotAnEmptyOne(unittest.TestCase):
    """A registered platform whose YAML was renamed was skipped without a
    word, and a missing registry read as no platforms: verify --all --strict
    and every --all build passed having checked nothing."""

    def test_both_raise(self):
        from scripts.model.registry import list_registered_platforms

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                list_registered_platforms(tmp)
            Path(tmp, "_registry.yml").write_text(
                "platforms:\n  rocknix:\n    config: rocknix.yml\n", encoding="utf-8"
            )
            with self.assertRaises(FileNotFoundError) as caught:
                list_registered_platforms(tmp)
            self.assertIn("rocknix", str(caught.exception))


class AForcedRehashIsCheckedAgainstTheLastOne(unittest.TestCase):
    """This host has computed a wrong SHA-1 under load. The pipeline's forced
    rebuild threw the previous digests away and wrote whatever it read."""

    def test_a_reading_the_cache_and_a_second_reading_contradict_is_outvoted(self):
        from unittest import mock

        from collection import scan

        cached = {"sha1": "a" * 40, "mtime": 1.0, "size": 4}
        readings = iter([{"sha1": "b" * 40}, {"sha1": "a" * 40}])
        with mock.patch.object(scan, "compute_hashes", lambda *a, **k: next(readings)), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            settled = scan._settled_hashes(Path("x.bin"), cached, 1.0, 4)
        self.assertEqual(settled["sha1"], "a" * 40)
        self.assertIn("WARNING", err.getvalue())

    def test_two_agreeing_readings_against_an_unmoved_file_stop_the_run(self):
        """The host has returned the same wrong SHA-1 twice in a row
        (DSi_Nand_USA.bin as 62b100f2, 2026-10-22). Taking two agreeing
        readings as a rewrite put the wrong value in the cache, where every
        later run read it back. An unmoved file is never rewritten silently."""
        from unittest import mock

        from collection import scan

        cached = {"sha1": "a" * 40, "mtime": 1.0, "size": 4}
        with mock.patch.object(scan, "compute_hashes", lambda *a, **k: {"sha1": "b" * 40}), \
                self.assertRaisesRegex(RuntimeError, "touch"):
            scan._settled_hashes(Path("x.bin"), cached, 1.0, 4)

    def test_a_changed_file_takes_its_new_digest(self):
        from unittest import mock

        from collection import scan

        cached = {"sha1": "a" * 40, "mtime": 1.0, "size": 4}
        with mock.patch.object(scan, "compute_hashes", lambda *a, **k: {"sha1": "c" * 40}):
            self.assertEqual(
                scan._settled_hashes(Path("x.bin"), cached, 2.0, 4)["sha1"], "c" * 40
            )


class AnUnknownTargetIsRefusedUnderAll(unittest.TestCase):
    """--all --target swtich skipped every platform with targets and checked
    BizHawk and MiSTer unfiltered: a green run about no Switch at all."""

    def test_a_typo_is_refused_and_targetless_platforms_are_left_out(self):
        from scripts.model.targets import build_target_cores_cache
        from scripts.model.registry import list_registered_platforms

        platforms = list_registered_platforms(str(REPO_ROOT / "platforms"))
        with self.assertRaises(ValueError):
            build_target_cores_cache(platforms, "swtich", str(REPO_ROOT / "platforms"), is_all=True)
        _cache, kept, _notes = build_target_cores_cache(
            platforms, "switch", str(REPO_ROOT / "platforms"), is_all=True
        )
        self.assertNotIn("bizhawk", kept)
        self.assertIn("retroarch", kept)


class AScraperThatCannotStartSaysWhy(unittest.TestCase):
    """Scrapers resolve their tag or branch head in the constructor, and
    scraper_cli built the scraper outside its try: a refused API call ended
    in a traceback instead of a message saying to set GITHUB_TOKEN."""

    def _run(self, scraper_class, token: str | None):
        import contextlib
        import io
        from unittest import mock

        from scraper.base_scraper import scraper_cli

        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        if token:
            env["GITHUB_TOKEN"] = token
        err = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sys, "argv", ["x", "--dry-run"]), \
                contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as stop:
            scraper_cli(scraper_class)
        return stop.exception.code, err.getvalue()

    def test_a_failing_constructor_exits_with_a_hint(self):
        class Refused:
            def __init__(self):
                raise RuntimeError("cannot read the head of a/b@main: HTTP 403")

        code, err = self._run(Refused, None)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", err)
        self.assertIn("GITHUB_TOKEN", err)

    def test_with_a_token_the_hint_points_elsewhere(self):
        class Offline:
            def fetch_requirements(self):
                raise ConnectionError("no route to host")

        code, err = self._run(Offline, "t")
        self.assertEqual(code, 1)
        self.assertNotIn("GITHUB_TOKEN", err)


class AStepThatCannotFailTheRunIsNotShownFailed(unittest.TestCase):
    """check_buildbot leaves all_ok alone, and the summary printed it FAILED
    right above "Pipeline COMPLETE". The total also missed the duration
    column by fourteen characters."""

    def test_every_step_outside_all_ok_is_declared_non_blocking(self):
        lines = script_source("pipeline.py").splitlines()
        loose = set()
        for number, line in enumerate(lines):
            found = re.search(r'results\["(\w+)"\] = ok$', line.strip())
            if not found:
                continue
            after = " ".join(lines[number + 1:number + 4])
            if "all_ok" not in after and "sys.exit" not in after:
                loose.add(found.group(1))
        self.assertEqual(loose, set(results.NON_BLOCKING))

    def test_the_total_sits_under_the_durations(self):
        step = f"  {'x':.<40} {'OK':<7}{1.0:>8.1f}s"
        total = f"  {'total':.<40} {'':<7}{12.5:>8.1f}s"
        self.assertEqual(len(step), len(total))
        self.assertIn("{'':<7}{total_elapsed:>8.1f}s",
                      script_source("pipeline.py"))


class AHashConflictIsReportedOnce(unittest.TestCase):
    """check_freshness opened on six copies of one truth.py warning, one per
    platform whose model met the same two GameIndex.yaml declarations."""

    def test_the_same_pair_prints_once(self):
        from resolve import truth

        truth._CONFLICTS_SHOWN.clear()
        with self.assertLogs(truth.log, "WARNING") as logged:
            for _platform in range(6):
                existing = {"name": "x.yaml", "sha1": "a" * 40}
                truth._merge_hashes(existing, {"name": "x.yaml", "sha1": "b" * 40}, "core")
        self.assertEqual(len(logged.records), 1)


class ThePipelineRunsTheSchemaCheckCIRuns(unittest.TestCase):
    """The pipeline the repository asks for after every change never ran
    validate_schemas.py, which PR validation does: a profile with an
    unquoted numeric core name passed it and failed CI on push."""

    def test_the_ci_command_is_a_pipeline_step(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        command = re.search(r"python (scripts/validate_schemas\.py[^\n]*)", workflow).group(1)
        script, *flags = command.split()
        source = script_source("pipeline.py")
        self.assertIn(f'"{script}"', source)
        for flag in flags:
            self.assertIn(f'"{flag}"', source)

    def test_the_site_is_rendered_as_the_deploy_renders_it(self):
        """The pipeline generated pages without rendering them: 20 pages with
        duplicate ids passed it and failed the deploy."""
        workflow = (REPO_ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8")
        source = script_source("pipeline.py")
        self.assertIn("npm run build --prefix website", workflow)
        self.assertIn('["npm", "run", "build", "--prefix", "website"]', source)
        self.assertIn("scripts/validate_site.py", workflow)
        self.assertIn('"scripts/validate_site.py"', source)


class TheReleaseBuildsEveryServedPackInOneRun(unittest.TestCase):
    """The release ran the pipeline, then built and checked RetroPie by hand:
    the consistency check between verify and the pack never covered it."""

    def test_the_pipeline_step_covers_every_platform(self):
        page = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertIn("python scripts/pipeline.py\n", page)
        self.assertNotIn("generate_pack.py --platform retropie", page)


class PlatformSystemTypoGetsTheClosestNames(unittest.TestCase):
    """--platform retroarch --system sony-playstaton listed the first ten
    systems of the alphabet, 3do to coleco-colecovision."""

    def test_the_hint_names_the_close_systems(self):
        from scripts.packs import platformpack

        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stdout(out):
            result = platformpack.generate_pack(
                "retroarch", str(REPO_ROOT / "platforms"), {"files": {}, "indexes": {}},
                str(REPO_ROOT / "bios"), tmp, emulators_dir=str(REPO_ROOT / "emulators"),
                system_filter=["sony-playstaton"], offline=True,
            )
        self.assertIsNone(result)
        printed = out.getvalue()
        self.assertIn("Close matches: sony-playstation", printed)
        self.assertIn("--platform retroarch --list-systems", printed)
        self.assertNotIn("3do", printed)


class HashInputNamesWhatItAccepts(unittest.TestCase):
    """A 12-digit value was looked up as an MD5 and reported NOT FOUND, a
    SHA-256 vanished from the input, and the run said only "No valid hashes
    found in input"."""

    def test_digests_are_read_by_length(self):
        from scripts.packs.hashinput import parse_hash_input

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(parse_hash_input(f"0x1A2B3C4D,{sha256}"), [
            ("crc32", "1a2b3c4d"), ("sha256", sha256),
        ])
        self.assertEqual(parse_hash_input("a" * 29), [("md5", "a" * 29)])

    def test_anything_else_is_refused_with_the_formats(self):
        from scripts.packs.hashinput import parse_hash_file, parse_hash_input

        for raw in ("1234567890ab", "zz", "490f666e1afb15b7362b406ed1cea246,zz"):
            with self.subTest(raw=raw), self.assertRaises(ValueError) as ctx:
                parse_hash_input(raw)
            self.assertIn("SHA-256 (64)", str(ctx.exception))
        with tempfile.TemporaryDirectory() as tmp:
            listing = Path(tmp, "hashes.txt")
            listing.write_text("# list\n490f666e1afb15b7362b406ed1cea246  a.bin\nb.bin\n")
            with self.assertRaises(ValueError) as ctx:
                parse_hash_file(str(listing))
        self.assertIn("line 3 (b.bin)", str(ctx.exception))

    def test_a_sha256_finds_its_file(self):
        from scripts.resolve.packfiles import sha1_for_hash

        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        sha1, entry = next(
            (k, e) for k, e in db["files"].items() if e.get("sha256")
        )
        self.assertEqual(sha1_for_hash("sha256", entry["sha256"], db), sha1)
        self.assertEqual(sha1_for_hash("md5", entry["md5"][:29], db), sha1)

    def test_the_truth_anchors_a_sha256_only_entry(self):
        """rust_dos and ares name files by sha256 alone: the truth left their
        md5 empty, so md5 platforms never received them."""
        from scripts.resolve.truthsystems import enrich_hashes

        db = {"files": {"s" * 40: {"sha1": "s" * 40, "md5": "m" * 32, "sha256": "f" * 64,
                                   "crc32": "0badf00d", "size": 16}},
              "indexes": {"by_sha256": {"f" * 64: "s" * 40}}}
        entry = {"name": "5200.rom", "sha256": "F" * 64}
        enrich_hashes(entry, db)
        self.assertEqual((entry["md5"], entry["sha1"], entry["size"]), ("m" * 32, "s" * 40, 16))


class ErrorsGoToStderr(unittest.TestCase):
    """The lock refusal and "no pack for" went to stdout: a run redirected to
    a log showed nothing on the terminal and exited 1."""

    @staticmethod
    def _leading_text(node: ast.expr) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr) and node.values:
            return ErrorsGoToStderr._leading_text(node.values[0])
        return ""

    def test_no_error_line_is_printed_to_stdout(self):
        for script in ("generate_pack.py", "pipeline.py"):
            tree = ast.parse(script_source(script))
            seen = 0
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print"
                        and node.args):
                    continue
                text = self._leading_text(node.args[0])
                # Detail lines under a pack's own verdict stay with it.
                if not text.lstrip().startswith("ERROR") or text.startswith("    "):
                    continue
                seen += 1
                with self.subTest(script=script, line=node.lineno):
                    self.assertIn("file", [k.arg for k in node.keywords])
            self.assertGreater(seen, 0, script)


class PipelineOutputDirIsTheOneItWrites(unittest.TestCase):
    """Started from scripts/, the pipeline locked and purged scripts/dist/
    while every step, run from the repository root, wrote to dist/."""

    def test_the_default_is_the_root_dist_wherever_the_run_starts(self):
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(REPO_ROOT / "scripts")
        self.assertEqual(runner.pack_output_dir(None), str(REPO_ROOT / "dist"))
        self.assertEqual(runner.pack_output_dir("out"), str(REPO_ROOT / "scripts" / "out"))

    def test_main_resolves_it_before_the_lock(self):
        source = script_source("pipeline.py")
        body = source[source.index("def main("):]
        self.assertLess(
            body.index("args.output_dir = pack_output_dir(args.output_dir)"),
            body.index("hold_artifact_lock(args.output_dir)"),
        )


class ToolsRunFromAnyDirectory(unittest.TestCase):
    """From scripts/, verify.py and generate_pack.py ended on a
    FileNotFoundError traceback about platforms/_registry.yml."""

    def _run(self, cwd: Path, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *argv], cwd=cwd, capture_output=True, text=True,
            timeout=600,
            check=False,
        )

    def test_listing_works_from_scripts(self):
        for script in ("verify.py", "generate_pack.py"):
            with self.subTest(script=script):
                proc = self._run(
                    REPO_ROOT / "scripts", str(REPO_ROOT / "scripts" / script),
                    "--platform", "RetroArch", "--list-systems",
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertIn("sony-playstation", proc.stdout)

    def test_a_typed_path_is_read_from_where_it_was_typed(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(
                Path(tmp), str(REPO_ROOT / "scripts" / "generate_pack.py"),
                "--manifest-targets", "--output-dir", "lists",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(Path(tmp, "lists", "retroarch.json").is_file())


class ATargetTypoIsAnErrorInEveryTool(unittest.TestCase):
    """cross_reference.py ended a mistyped --target in a traceback, and the
    hint sent cross_reference and slots users to a flag they do not have."""

    def test_each_tool_names_the_closest_target(self):
        for script in ("cross_reference.py", "slots.py", "verify.py"):
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--platform", "retroarch",
                     "--target", "swich"],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
                    check=False,
                )
                output = proc.stdout + proc.stderr
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("Traceback", output)
                self.assertIn("Close matches: switch.", output)
                self.assertIn("verify.py --platform retroarch --list-targets", output)


class AnUnknownSystemIsRefusedBeforeAnyWork(unittest.TestCase):
    """generate_pack checked --system inside the build: a typo took the
    output lock and refreshed every data directory, then ended on a WARNING."""

    def test_refused_before_the_lock_and_the_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "never"
            with mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}):
                proc = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", "--platform", "batocera",
                     "--system", "playstaton-nothing", "--output-dir", str(out)],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
                    check=False,
                )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn(
                "error: --system playstaton-nothing: unknown system playstaton-nothing",
                proc.stderr,
            )
            self.assertFalse(out.exists())

    def test_a_known_system_passes_the_early_check(self):
        import argparse

        from model.cliargs import resolve_system_ids

        parser = argparse.ArgumentParser()
        args = argparse.Namespace(
            system="sony-playstation", platform="retroarch", all=False,
            platforms_dir=str(REPO_ROOT / "platforms"), manifest=False,
        )
        self.assertEqual(resolve_system_ids(args, parser), ["sony-playstation"])


if __name__ == "__main__":
    unittest.main()
