"""One system, two spellings, one pack.

stella2014 and stella2023 write atari_2600 where every other profile writes
atari-2600. --system matched the spelling exactly and named the ZIP from
it, so the two spellings built two different packs under one file name,
the second replacing the first; --from-md5 --emulator X --standalone
accepted a libretro-only core and named a standalone pack that was the
libretro pack.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_pack as builder  # noqa: E402


class SpellingsAgree(unittest.TestCase):
    def test_both_spellings_select_the_same_profiles(self):
        profiles = common.load_emulator_profiles(str(REPO_ROOT / "emulators"))
        dashed = common.profiles_for_systems(profiles, ["atari-2600"])
        underscored = common.profiles_for_systems(profiles, ["atari_2600"])
        self.assertEqual(dashed, underscored)
        self.assertIn("stella2014", dashed)
        self.assertIn("gopher2600", dashed)

    def test_the_pack_name_normalizes_the_spelling(self):
        self.assertEqual(
            builder._system_display_name("atari_2600"), builder._system_display_name("atari-2600")
        )
        self.assertEqual(builder._system_display_name("msxturboR"), builder._system_display_name("msxturbor"))


class TheListingCountsLikeTheSelection(unittest.TestCase):
    def test_one_system_is_listed_once_with_every_profile(self):
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            common.list_system_ids(str(REPO_ROOT / "emulators"))
        lines = {line.split()[0]: line for line in out.getvalue().splitlines() if line.strip()}
        profiles = common.load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for spellings in (("3do", "panasonic-3do"), ("atari-2600", "atari_2600")):
            listed = [s for s in spellings if s in lines]
            self.assertEqual(len(listed), 1, f"{spellings}: one line per system")
            count = len(common.profiles_for_systems(profiles, [spellings[0]]))
            self.assertIn(f"({count} emulator", lines[listed[0]])


class StandaloneNeedsAStandaloneBuild(unittest.TestCase):
    def test_a_custom_pack_refuses_it_for_a_libretro_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "emulators").mkdir()
            Path(tmp, "emulators", "handy.yml").write_text(
                "emulator: Handy\ntype: libretro\nsystems: [atari-lynx]\nfiles:\n  - name: lynxboot.img\n"
            )
            common._emulator_profiles_cache.clear()
            self.addCleanup(common._emulator_profiles_cache.clear)
            db = {"files": {}, "indexes": {"by_md5": {}, "by_crc32": {}, "by_name": {}}}
            result = builder.generate_md5_pack(
                [("md5", "d8f1206299c48946e6ec5ef96d014eaa")], db, tmp, tmp,
                emulator_name="handy", emulators_dir=str(Path(tmp, "emulators")), standalone=True,
            )
            self.assertIsNone(result)
            self.assertEqual([p for p in os.listdir(tmp) if p.endswith(".zip")], [])


class ADeclinedBuildIsAFailure(unittest.TestCase):
    def test_a_target_that_removes_every_requested_system_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform", "retroarch",
                 "--system", "sony-playstation-2", "--target", "switch", "--offline",
                 "--output-dir", tmp],
                capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600, check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("Traceback", proc.stderr, proc.stderr)
            self.assertEqual([p for p in os.listdir(tmp) if p.endswith(".zip")], [])



class AMistypedPlatformIsNamed(unittest.TestCase):
    """verify and cross_reference ended a typo on a traceback, and generate_pack
    ran its whole build first and then said "no pack for batocra"."""

    # Every script taking --platform: slots ended on a traceback, and
    # generate_truth, refresh_data_dirs and auto_fetch exited 0 having done
    # nothing (or, for refresh_data_dirs, refreshed every unscoped entry).
    CLIS = {
        "verify.py": [],
        "cross_reference.py": [],
        "slots.py": [],
        "diff_truth.py": [],
        "auto_fetch.py": ["--dry-run"],
        "refresh_data_dirs.py": ["--dry-run"],
        "pack_probe.py": ["plan"],
    }

    def test_every_cli_names_the_platform_it_meant(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        out = Path(scratch.name) / "packs"
        writers = {
            "generate_pack.py": ["--offline", "--output-dir", str(out)],
            "generate_truth.py": ["--output-dir", str(out)],
            "export_native.py": ["--output-dir", str(out)],
        }
        for script, extra in {**self.CLIS, **writers}.items():
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--platform", "batocra", *extra],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300,
                    check=False,
                )
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("Traceback", proc.stderr, proc.stderr)
                self.assertIn("Did you mean 'batocera'?", proc.stderr)
        self.assertFalse(out.exists())

    def test_the_names_the_site_prints_are_accepted(self):
        """`--platform RetroArch` and `--platform "MiSTer FPGA"` were refused
        by verify and generate_pack while install.py took them."""
        from common import platform_arg  # noqa: PLC0415

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        self.assertEqual(platform_arg("RetroArch"), "retroarch")
        self.assertEqual(platform_arg("MiSTer FPGA"), "misterfpga")
        self.assertEqual(platform_arg("retroarh"), "retroarh")
        for name in [p.name for p in (REPO_ROOT / "scripts").glob("*.py")
                     if re.search(r'add_argument\(\s*"--platform"', p.read_text(encoding="utf-8"))]:
            with self.subTest(script=name):
                source = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
                call = re.search(r'add_argument\(\s*"--platform"[^)]*\)', source).group(0)
                self.assertIn("type=platform_arg", call)

    def test_the_list_holds_every_script_taking_a_platform(self):
        taking = {
            path.name for path in (REPO_ROOT / "scripts").glob("*.py")
            if re.search(r'add_argument\(\s*"--platform"', path.read_text(encoding="utf-8"))
        }
        listed = set(self.CLIS) | {"generate_pack.py", "generate_truth.py", "export_native.py"}
        self.assertEqual(taking - listed, set())


class CrossReferenceAnswersForTheEmulatorAsked(unittest.TestCase):
    """`--emulator dolhpin` printed "No emulator profiles found" with exit 0,
    and `--emulator dolphin` showed only a header and a total "across all
    emulators": an emulator with nothing undeclared was skipped."""

    def _run(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "scripts/cross_reference.py", *argv],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
            check=False,
        )

    def test_a_mistyped_emulator_fails_and_names_the_one_meant(self):
        proc = self._run("--emulator", "dolhpin")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("Did you mean: dolphin", proc.stderr)
        listing = self._run("--list-emulators")
        self.assertEqual(listing.returncode, 0)
        self.assertIn("dolphin", listing.stdout.split())

    def test_the_named_emulator_is_reported_even_without_gaps(self):
        proc = self._run("--emulator", "dolphin")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("files in profile", proc.stdout)
        self.assertIn("across dolphin", proc.stdout)
        self.assertNotIn("all emulators", proc.stdout)

    def test_an_emulator_the_platform_does_not_run_is_refused(self):
        proc = self._run("--emulator", "dolphin", "--platform", "misterfpga")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not run by misterfpga", proc.stderr)


class AMissingDatabaseIsNamed(unittest.TestCase):
    """`slots.py --db nosuch.json` and `verify.py --all --db nosuch.json`
    ended on a FileNotFoundError at the bottom of a stack trace;
    generate_truth and validate_pr carried on without one."""

    EXTRA = {
        "auto_fetch.py": ["--all", "--dry-run"],
        "generate_truth.py": ["--all", "--output-dir", "{out}"],
        "generate_site.py": ["--docs-dir", "{out}"],
        "generate_pack.py": ["--platform", "retroarch", "--offline", "--output-dir", "{out}"],
        "validate_pr.py": ["bios/Sony/PlayStation/scph5501.bin"],
        "verify.py": ["--all"],
    }

    def _taking_db(self) -> list[str]:
        return sorted(
            path.name for path in (REPO_ROOT / "scripts").glob("*.py")
            if re.search(r'add_argument\(\s*"--db"', path.read_text(encoding="utf-8"))
        )

    def test_every_script_names_the_missing_file(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        out = str(Path(scratch.name) / "out")
        for script in self._taking_db():
            extra = [arg.format(out=out) for arg in self.EXTRA.get(script, [])]
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--db", "nosuch.json", *extra],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
                    check=False,
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout[-500:])
                self.assertNotIn("Traceback", proc.stderr, proc.stderr[-1500:])
                self.assertIn("nosuch.json", proc.stderr)


class AMissingBiosDirIsRefused(unittest.TestCase):
    """identity --strict passed on a mistyped --bios-dir with "0 contents",
    dedup saved 0 MB, and generate_pack wrote a pack of nothing: a folder
    that does not exist read as an empty collection."""

    EXTRA = {
        "auto_fetch.py": ["--platform", "batocera", "--dry-run"],
        "generate_pack.py": ["--platform", "batocera", "--offline", "--output-dir", "{out}"],
        "dedup.py": ["--dry-run"],
        "identity.py": ["--strict"],
    }

    def test_every_script_taking_a_bios_dir_refuses_a_missing_one(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        out = str(Path(scratch.name) / "out")
        taking = sorted(
            path.name for path in (REPO_ROOT / "scripts").glob("*.py")
            if re.search(r'add_argument\(\s*"--bios-dir"', path.read_text(encoding="utf-8"))
            and path.name != "generate_db.py"
        )
        self.assertGreater(len(taking), 4)
        for script in taking:
            extra = [arg.format(out=out) for arg in self.EXTRA.get(script, [])]
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--bios-dir", "nosuch", *extra],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
                    check=False,
                )
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("--bios-dir nosuch is not a directory", proc.stderr)
        self.assertFalse(Path(out).exists())


def _scripts_taking(flag: str) -> list[Path]:
    pattern = re.compile(r'add_argument\(\s*"%s"' % re.escape(flag))
    return [
        path for path in sorted((REPO_ROOT / "scripts").glob("*.py"))
        + sorted((REPO_ROOT / "scripts" / "scraper").glob("*.py"))
        if pattern.search(path.read_text(encoding="utf-8"))
    ]


def _command(path: Path) -> list[str]:
    if path.parent.name == "scraper":
        return [sys.executable, "-m", f"scripts.scraper.{path.stem}"]
    return [sys.executable, f"scripts/{path.name}"]


class AMissingProfileDirIsRefused(unittest.TestCase):
    """A mistyped --emulators-dir read as "no emulator": generate_pack built
    a pack without its core files marked OK, verify --strict passed, and
    sitesources wrote {} over source-paths.json, every one exiting 0."""

    EXTRA = {
        "arcade_parent_importer": ["--all", "--offline"],
        "fileless_audit": ["--all"],
        "generate_pack": ["--platform", "retroarch", "--system", "atari-lynx",
                          "--offline", "--output-dir", "{out}"],
        "generate_site": ["--docs-dir", "{out}"],
        "generate_truth": ["--all", "--output-dir", "{out}"],
        "mame_ref_audit": ["mame"],
        "profile_sync": ["--all", "--triage"],
        "romset_dat_importer": ["--source", "mame", "--pack", "{dat}", "--output", "{out}/r.json"],
        "sitesources": ["--cache-dir", "{cache}", "--output", "{out}/source-paths.json"],
        "validate_pr": ["bios/Sony/PlayStation/scph5501.bin"],
        "verify": ["--platform", "retroarch", "--strict"],
    }

    def test_every_script_taking_an_emulators_dir_refuses_a_missing_one(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        (root / "cache").mkdir()
        (root / "empty.dat").write_bytes(b"")
        values = {"out": str(root / "out"), "cache": str(root / "cache"),
                  "dat": str(root / "empty.dat")}
        taking = _scripts_taking("--emulators-dir")
        self.assertGreater(len(taking), 15)
        tracked = ["git", "diff", "--name-only"]
        before = subprocess.run(tracked, cwd=REPO_ROOT, capture_output=True, text=True).stdout
        for path in taking:
            extra = [arg.format(**values) for arg in self.EXTRA.get(path.stem, [])]
            with self.subTest(script=path.stem):
                proc = subprocess.run(
                    [*_command(path), "--emulators-dir", "nosuch", *extra],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
                    check=False, env={**os.environ, "RETROBIOS_OFFLINE": "1"},
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout[-500:])
                self.assertNotIn("Traceback", proc.stderr, proc.stderr[-1500:])
                self.assertRegex(proc.stderr, r"ERROR: .*nosuch")
        written = [
            str(p.relative_to(root)) for p in (root / "out").rglob("*")
            if p.is_file() and p.name != ".lock"
        ]
        self.assertEqual(written, [])
        # Read as empty, generate_site rewrote published-parts.json and the
        # FAQ, and sitesources source-paths.json.
        after = subprocess.run(tracked, cwd=REPO_ROOT, capture_output=True, text=True).stdout
        self.assertEqual(after, before)


class AMissingPlatformsDirIsRefused(unittest.TestCase):
    """`verify.py --platforms-dir noplat` ended on a FileNotFoundError at the
    bottom of a stack trace, and validate_pr read it as no platform at all
    and exited 0."""

    EXTRA = {
        "auto_fetch": ["--all", "--dry-run"],
        "check_release": ["--tag", "v1"],
        "diff_truth": ["--all"],
        "export_native": ["--all", "--output-dir", "{out}"],
        "generate_pack": ["--platform", "retroarch", "--offline", "--output-dir", "{out}"],
        "generate_site": ["--docs-dir", "{out}"],
        "generate_truth": ["--all", "--output-dir", "{out}"],
        "release_notes": ["--whats-new", "{notes}", "--output", "{out}/notes.md"],
        "release_record": ["{out}", "--tag", "v1"],
        "romset_dat_importer": ["--source", "mame", "--pack", "{dat}", "--output", "{out}/r.json"],
        "validate_pr": ["bios/Sony/PlayStation/scph5501.bin"],
        "validate_site": ["--site-dir", "{out}"],
        "verify": ["--platform", "retroarch"],
    }

    def test_every_script_taking_a_platforms_dir_refuses_a_missing_one(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        (root / "empty.dat").write_bytes(b"")
        (root / "notes.md").write_text("Notes.\n")
        values = {"out": str(root / "out"), "dat": str(root / "empty.dat"),
                  "notes": str(root / "notes.md")}
        taking = _scripts_taking("--platforms-dir")
        self.assertGreater(len(taking), 15)
        for path in taking:
            extra = [arg.format(**values) for arg in self.EXTRA.get(path.stem, [])]
            with self.subTest(script=path.stem):
                proc = subprocess.run(
                    [*_command(path), "--platforms-dir", "nosuch", *extra],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
                    check=False, env={**os.environ, "RETROBIOS_OFFLINE": "1"},
                )
                self.assertNotEqual(proc.returncode, 0, proc.stdout[-500:])
                self.assertNotIn("Traceback", proc.stderr, proc.stderr[-1500:])
                self.assertRegex(proc.stderr, r"ERROR: .*nosuch")


class AMissingInputFileIsNamed(unittest.TestCase):
    """The documented `--from-md5-file missing.txt` ended on a
    FileNotFoundError at the bottom of a stack trace."""

    def _refused(self, argv: list[str], message: str) -> None:
        proc = subprocess.run(
            [sys.executable, *argv], capture_output=True, text=True,
            cwd=str(REPO_ROOT), timeout=600, check=False,
            env={**os.environ, "RETROBIOS_OFFLINE": "1"},
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout[-500:])
        self.assertNotIn("Traceback", proc.stderr, proc.stderr[-1500:])
        self.assertIn(message, proc.stderr)

    def test_a_missing_hash_list_is_named(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            self._refused(
                ["scripts/generate_pack.py", "--platform", "batocera", "--from-md5-file",
                 "nosuch.txt", "--offline", "--output-dir", tmp],
                "ERROR: --from-md5-file nosuch.txt: No such file or directory",
            )

    def test_a_missing_data_directory_registry_is_named(self):
        for argv in (["scripts/refresh_data_dirs.py", "--registry", "nosuch.yml", "--dry-run"],
                     ["scripts/check_buildbot_system.py", "--registry", "nosuch.yml"]):
            with self.subTest(script=argv[0]):
                self._refused(argv, "ERROR: Registry not found: nosuch.yml")


class ASystemReportCountsTheClaimsThePackCounts(unittest.TestCase):
    """`--platform retroarch --system panasonic-3do` packed MAME 2009's
    taitofx1.zip, which MAME 2016 claims for that system, and the report's
    core coverage did not name it: the builder read other_claims, verify
    read only the entry's own system."""

    def test_a_claim_riding_on_an_entry_selects_it(self):
        from packextras import extras_for_systems, report_owned_by_systems

        entry = {
            "name": "taitofx1.zip", "system": "arcade", "systems": ["arcade"],
            "other_claims": [{"name": "taitofx1.zip", "system": None,
                              "systems": ["arcade", "panasonic-3do"]}],
        }
        extra = {"source_system": "arcade", "source_systems": ["arcade"],
                 "other_claims": [{"source_system": None,
                                   "source_systems": ["arcade", "panasonic-3do"]}]}
        for system in ("panasonic-3do", "arcade", "sony-playstation"):
            with self.subTest(system=system):
                self.assertEqual(
                    bool(report_owned_by_systems([entry], [system])),
                    bool(extras_for_systems([extra], [system])),
                )
        self.assertEqual(report_owned_by_systems([entry], ["panasonic-3do"]), [entry])


class VerifyReportsTheRequiredOnlyPack(unittest.TestCase):
    """`generate_pack --emulator mame --required-only` held 164 archives and
    the only report, `verify --emulator mame`, credited 2302 paths:
    --required-only was refused by verify, and the archive rule existed in
    the builder only."""

    def setUp(self):
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)

    def test_the_report_holds_the_paths_the_pack_holds(self):
        import contextlib
        import io

        from verify import verify_emulator

        db = common.load_database("database.json")
        for name in ("beetle_psx", "dolphin", "fbneo", "geolith", "mame"):
            with self.subTest(emulator=name):
                record = builder.PackRecord()
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    builder.generate_emulator_pack(
                        [name], "emulators", db, "bios", "", offline=True,
                        platforms_dir="platforms", record=record, required_only=True,
                    )
                    report = verify_emulator([name], "emulators", db,
                                             platforms_dir="platforms", required_only=True)
                    full = verify_emulator([name], "emulators", db, platforms_dir="platforms")
                self.assertEqual(sorted(report["pack_destinations"]), sorted(record.files))
                self.assertLessEqual(set(report["pack_destinations"]),
                                     set(full["pack_destinations"]))

    def test_every_mode_takes_the_flag(self):
        for argv in (["--platform", "lakka"], ["--emulator", "handy"],
                     ["--system", "atari-lynx"]):
            with self.subTest(argv=argv):
                proc = subprocess.run(
                    [sys.executable, "scripts/verify.py", *argv, "--required-only"],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr[-1500:])


class StrictVerifyFailsOnACriticalMiss(unittest.TestCase):
    """verify exited 0 with a required file missing on an md5 platform, so
    the pipeline printed "verify OK" over a pack the frontend rejects."""

    def test_strict_exits_nonzero_and_plain_does_not(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            root = Path(tmp)
            (root / "plat").mkdir()
            (root / "emu").mkdir()
            (root / "plat" / "fx.yml").write_text(
                "platform: Fx\nverification_mode: md5\nbase_destination: bios\n"
                "systems:\n  sony-playstation:\n    files:\n    - name: absent.bin\n"
                "      destination: absent.bin\n      required: true\n"
                "      md5: 00000000000000000000000000000000\n"
            )
            (root / "db.json").write_text(
                '{"files": {}, "indexes": {"by_md5": {}, "by_name": {}, '
                '"by_crc32": {}, "by_path_suffix": {}}}'
            )
            base = [sys.executable, "scripts/verify.py", "--platform", "fx",
                    "--platforms-dir", str(root / "plat"), "--emulators-dir",
                    str(root / "emu"), "--db", str(root / "db.json")]
            plain = subprocess.run(base, capture_output=True, text=True,
                                   cwd=str(REPO_ROOT), timeout=300, check=False)
            strict = subprocess.run([*base, "--strict"], capture_output=True, text=True,
                                    cwd=str(REPO_ROOT), timeout=300, check=False)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertEqual(strict.returncode, 1, strict.stderr)
        self.assertIn("1 required file(s) missing", strict.stderr)

    def test_the_pipeline_asks_for_it(self):
        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text()
        self.assertIn('"scripts/verify.py", "--all", "--strict"', source)


class ExclusionNotesListedOnAsk(unittest.TestCase):
    """verify --all repeated every core's exclusion note under every
    platform: 985 of its 1114 lines, the platform results lost among them."""

    def test_counted_by_default_listed_with_verbose(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        cmd = [sys.executable, "scripts/verify.py", "--platform", "retroarch"]
        plain = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT),
                               timeout=900, check=True).stdout
        verbose = subprocess.run([*cmd, "--verbose"], capture_output=True, text=True,
                                 cwd=str(REPO_ROOT), timeout=900, check=True).stdout
        self.assertRegex(plain, r"No external files: \d+ cores \(--verbose lists them\)")
        self.assertRegex(verbose, r"No external files \(\d+\):")
        self.assertLess(len(plain.splitlines()), len(verbose.splitlines()))


class ATypoGetsTheNearestNames(unittest.TestCase):
    """The hint listed the first names of the alphabet behind "...":
    sony-playstaton was answered with 3do to apple-iie."""

    def test_suggestions_follow_the_typed_name(self):
        hint = common.suggest_names(["sony-playstaton"],
                                    ["3do", "apple-ii", "sony-playstation"], "--list-systems")
        self.assertEqual(hint, "Did you mean: sony-playstation? --list-systems lists all 3.")
        self.assertEqual(common.suggest_names(["zzz"], ["3do"], "--list-systems"),
                         "Known: 3do.")
        many = [f"system-{i}" for i in range(40)]
        self.assertEqual(common.suggest_names(["zzz"], many, "--list-systems"),
                         "--list-systems lists all 40.")


class EmulatorVerifyReadsNoArchiveItDoesNotNeed(unittest.TestCase):
    """verify --emulator decompressed every archive of the collection to
    index ZIP members, for zipped_file entries no profile declares: 23 of
    the 24 seconds of a run."""

    def test_the_member_index_is_not_built(self):
        from unittest import mock  # noqa: PLC0415

        import verify  # noqa: PLC0415

        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = common.load_database(str(REPO_ROOT / "database.json"))
        with mock.patch.object(verify, "build_zip_contents_index",
                               side_effect=AssertionError("index built")):
            result = verify.verify_emulator(["handy"], str(REPO_ROOT / "emulators"), db)
        self.assertTrue(result)


class CoverageWithoutProfilesMatchesTheCli(unittest.TestCase):
    """verify_platform built the slot overrides from the profiles the caller
    passed, before loading them: the README's coverage passes none and listed
    a neocdz.zip discrepancy the pack and the CLI do not have."""

    def test_omitting_profiles_gives_the_same_report(self):
        import verify  # noqa: PLC0415

        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = common.load_database(str(REPO_ROOT / "database.json"))
        config = common.load_platform_config("retroarch", str(REPO_ROOT / "platforms"))
        emulators = str(REPO_ROOT / "emulators")
        bare = verify.verify_platform(config, db, emulators)
        full = verify.verify_platform(config, db, emulators,
                                      common.load_emulator_profiles(emulators))

        def discrepancies(result):
            return sorted(d["name"] for d in result["details"] if d.get("discrepancy"))

        self.assertEqual(discrepancies(bare), discrepancies(full))

class ASystemPackHoldsThatSystem(unittest.TestCase):
    """--system atari-lynx without --platform shipped 36 files: every entry
    of mednafen.yml, PlayStation, Saturn and Apple II included, though each
    declares its system. A platform pack narrows core extras per entry."""

    def test_pack_and_report_keep_the_entries_of_the_system(self):
        import hashlib
        import io
        import shutil
        import zipfile
        from contextlib import redirect_stdout

        import yaml
        from verify import verify_system

        common._emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}, "by_crc32": {},
                                      "by_path_suffix": {}}}
        for name in ("lynx.img", "psx.bin", "shared.dat"):
            data = name.encode() * 4
            rel = f"bios/Maker/Console/{name}"
            Path(rel).parent.mkdir(parents=True, exist_ok=True)
            Path(rel).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            db["files"][sha1] = {"path": rel, "name": name, "size": len(data),
                                 "md5": hashlib.md5(data).hexdigest(), "crc32": ""}
            db["indexes"]["by_name"][name] = [sha1]
        Path("emulators").mkdir()
        Path("emulators/multi.yml").write_text(yaml.safe_dump({
            "emulator": "Multi", "type": "libretro", "cores": ["multi"],
            "systems": ["atari-lynx", "sony-playstation"],
            "files": [
                {"name": "lynx.img", "system": "atari-lynx", "required": True},
                {"name": "psx.bin", "system": "sony-playstation", "required": True},
                {"name": "shared.dat", "required": False},
            ],
        }))
        report = verify_system(["atari-lynx"], "emulators", db)
        with redirect_stdout(io.StringIO()):
            path = builder.generate_system_pack(
                ["atari-lynx"], "emulators", db, "bios", "out", offline=True,
            )
        with zipfile.ZipFile(path) as zf:
            packed = sorted(zf.namelist())
        self.assertEqual(packed, ["lynx.img", "shared.dat"])
        self.assertEqual(report["total_files"], 2)


class ATreeHoldsAPathForAnotherProfile(unittest.TestCase):
    """--system colecovision --standalone: bluemsx keeps no file of the
    system but its Machines/ tree is packed, and holds msx-emu's coleco.rom
    path. verify skipped the tree of a profile left without files and
    credited msx-emu's copy the pack never wrote."""

    def test_report_and_pack_agree(self):
        import hashlib
        import io
        import shutil
        from contextlib import redirect_stdout

        import yaml
        from verify import verify_emulator

        common._emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        data = b"coleco" * 4
        sha1 = hashlib.sha1(data).hexdigest()
        rel = "bios/Coleco/ColecoVision/coleco.rom"
        Path(rel).parent.mkdir(parents=True)
        Path(rel).write_bytes(data)
        tree = Path("data/tree/Machines/COL")
        tree.mkdir(parents=True)
        (tree / "coleco.rom").write_bytes(data)
        db = {"files": {sha1: {"path": rel, "name": "coleco.rom", "size": len(data),
                               "md5": hashlib.md5(data).hexdigest(), "crc32": ""}},
              "indexes": {"by_md5": {}, "by_name": {"coleco.rom": [sha1]},
                          "by_crc32": {}, "by_path_suffix": {}}}
        Path("platforms").mkdir()
        Path("platforms/_data_dirs.yml").write_text(yaml.safe_dump(
            {"data_directories": {"tree": {"local_cache": "data/tree"}}}))
        Path("emulators").mkdir()
        Path("emulators/atree.yml").write_text(yaml.safe_dump({
            "emulator": "ATree", "type": "libretro", "cores": ["atree"],
            "systems": ["colecovision", "msx"],
            "data_directories": [{"ref": "tree"}],
            "files": [{"name": "msx.rom", "system": "msx"}],
        }))
        Path("emulators/msxemu.yml").write_text(yaml.safe_dump({
            "emulator": "MsxEmu", "type": "libretro", "cores": ["msxemu"],
            "systems": ["colecovision"],
            "files": [{"name": "coleco.rom", "path": "Machines/COL/coleco.rom"}],
        }))
        names = ["atree", "msxemu"]
        report = verify_emulator(names, "emulators", db, platforms_dir="platforms",
                                 system_ids=["colecovision"])
        record = builder.PackRecord()
        with redirect_stdout(io.StringIO()):
            builder.generate_emulator_pack(
                names, "emulators", db, "bios", "", offline=True,
                platforms_dir="platforms", record=record, system_ids=["colecovision"],
            )
        self.assertEqual(sorted(report["pack_destinations"]), sorted(record.files))


class ListingsKeepTheirColumns(unittest.TestCase):
    """--list-systems and --list-emulators started their last column at a
    position that moved with the file count and the profile type."""

    def test_the_last_column_starts_in_one_place(self):
        listing = subprocess.run(
            [sys.executable, "scripts/generate_pack.py", "--platform", "retroarch",
             "--list-systems"], cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        ).stdout.splitlines()
        starts = {line.index("[") for line in listing if "[" in line}
        self.assertEqual(len(starts), 1, listing[:5])
        emulators = subprocess.run(
            [sys.executable, "scripts/verify.py", "--list-emulators"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
        ).stdout.splitlines()
        ends = {line.index("]") + 1 for line in emulators if "]" in line}
        tails = {len(line) - len(line[line.index("]") + 1:].lstrip())
                 for line in emulators if "]" in line and line[line.index("]") + 1:].strip()}
        self.assertEqual(len(tails), 1, sorted(ends))
        self.assertFalse([line for line in listing + emulators if line != line.rstrip()])


if __name__ == "__main__":
    unittest.main()
