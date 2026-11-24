"""A targeted pack is checked under the target reading it was built with.

`--all --target x86_64` packs a platform that has no target file unnarrowed
under the target's name (Recalbox, Lakka, BizHawk, MiSTer, ROCKNIX). The
conformance check read the same target without the --all tolerance, raised
FileNotFoundError on the first of those packs and stopped the run in a
traceback after every pack had been written. Such a platform is now left
out of a targeted --all run, and the check refuses it as the build does.
"""

from __future__ import annotations

import tests

import os
import sys
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from model.targets import build_target_cores_cache
from packs.finalize import _target_cores_for

REPO_ROOT = Path(__file__).resolve().parent.parent


class CheckReadsTheTargetLikeTheBuild(unittest.TestCase):
    def test_a_platform_without_a_target_file(self):
        # Left out of a targeted --all run rather than built unfiltered, and
        # a run where no platform has the target is refused.
        with tempfile.TemporaryDirectory() as platforms, self.assertRaises(ValueError):
            build_target_cores_cache(["recalbox"], "x86_64", platforms, is_all=True)
        # The build never packs such a platform under the target, so the
        # check refuses it too instead of reading the full pack.
        with self.assertRaises(FileNotFoundError):
            _target_cores_for("recalbox", "x86_64", platforms)

    def test_a_platform_with_a_target_file_is_narrowed(self):
        cores = _target_cores_for("retroarch", "switch", str(REPO_ROOT / "platforms"))
        self.assertTrue(cores)


class ANameClaimsOnlyANarrowingThatHappened(unittest.TestCase):
    """--all --target switch packed BizHawk and MiSTer whole, and named them
    BizHawk_..._Switch_BIOS_Pack.zip with a README saying 'cores available
    on switch'."""

    def test_a_platform_without_the_target_is_named_plainly(self):
        from packs.naming import pack_narrowings, platform_target

        platforms = str(REPO_ROOT / "platforms")
        self.assertIsNone(platform_target("bizhawk", "switch", platforms))
        self.assertEqual(pack_narrowings("full", None, None, False, False), [])
        self.assertEqual(
            platform_target("retroarch", "nx", platforms), "nintendo-switch"
        )


class AMistypedTargetIsRefusedFirst(unittest.TestCase):
    """`--platform retroarch --target swich` took the dist lock and waited on
    the data directory refresh, 22 s here and hours behind a pipeline, before
    saying the target does not exist."""

    def test_no_lock_and_no_refresh_before_the_refusal(self):
        from unittest import mock

        import generate_pack
        from packs import packmodes, platformrun

        def touched(*_a, **_kw):
            raise AssertionError("lock or refresh taken before the target check")

        argv = ["generate_pack.py", "--platform", "retroarch", "--target", "swich",
                "--output-dir", str(REPO_ROOT / "tmp" / "never-written")]
        err = io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(packmodes, "pack_output_lock", touched), \
                mock.patch.object(packmodes, "hold_data_dirs", touched), \
                mock.patch.object(platformrun, "pack_output_lock", touched), \
                mock.patch.object(platformrun, "hold_data_dirs", touched), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as ctx:
            generate_pack.main()
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Unknown target 'swich'", err.getvalue())


class ASystemTheTargetDropsIsNamedAsSuch(unittest.TestCase):
    """`--platform retroarch --system sony-playstation-2 --target switch`:
    verify printed 0/0 with exit 0 under --strict, and generate_pack said
    RetroArch has no such system and suggested sony-playstation."""

    PLATFORMS = str(REPO_ROOT / "platforms")

    def test_both_tools_read_one_scope(self):
        from model.profiles import load_emulator_profiles
        from model.platforms import load_platform_config
        from resolve.cores import platform_scope_systems

        config = load_platform_config("retroarch", self.PLATFORMS)
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        switch = _target_cores_for("retroarch", "switch", self.PLATFORMS)
        wanted = ["sony-playstation-2"]
        self.assertEqual(platform_scope_systems(config, profiles, switch, wanted), {})
        self.assertEqual(list(platform_scope_systems(config, profiles, None, wanted)), wanted)

    def test_the_manifest_reads_the_same_scope(self):
        """install/<platform>.json copied the body of platform_scope_systems,
        so a change to how a target narrows the systems reached the pack and
        verify but not the installer."""
        import inspect

        from packs import manifest

        source = inspect.getsource(manifest._start_manifest)
        self.assertIn("platform_scope_systems(", source)
        self.assertNotIn("filter_systems_by_target(", source)

    def test_the_message_names_the_target(self):
        from resolve.cores import system_scope_error

        config = {"systems": {"sony-playstation-2": {}, "sony-playstation": {}}}
        self.assertEqual(
            system_scope_error(config, "retroarch", ["sony-playstation-2"], "switch"),
            "no core retroarch runs on target switch emulates sony-playstation-2",
        )
        undeclared = system_scope_error(config, "retroarch", ["nec-pc-98"], "switch")
        self.assertTrue(undeclared.startswith("retroarch has no system matching nec-pc-98."))

    def test_verify_refuses_it(self):
        import subprocess

        proc = subprocess.run(
            [sys.executable, "scripts/verify.py", "--platform", "retroarch",
             "--system", "sony-playstation-2", "--target", "switch", "--strict"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600, check=False,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout[-300:])
        self.assertIn("no core retroarch runs on target switch emulates sony-playstation-2",
                      proc.stderr)


class ASplitBuildsOnlyTheTargetsSystems(unittest.TestCase):
    """`--split --target switch` asked for a part per declared system, and
    each one the target drops ended on 'retroarch has no system matching'."""

    def test_no_part_is_asked_for_a_dropped_system(self):
        from unittest import mock

        from packs import manifestbuild, platformpack, platformzip
        from packs import platformpack as packs_platformpack
        from model.profiles import load_emulator_profiles

        platforms = str(REPO_ROOT / "platforms")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        asked: list[list[str]] = []

        def record(*_a, **kw):
            if kw.get("system_filter"):
                asked.append(kw["system_filter"])
            return platformzip.PlatformPackOutcome(zip_path=None)

        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(platformpack, "build_platform_pack", record), \
                mock.patch.object(platformpack, "print_split_packs"), \
                mock.patch.object(platformpack, "collect_emulator_extras", return_value=[]), \
                mock.patch.object(platformzip, "collect_emulator_extras", return_value=[]), \
                mock.patch.object(manifestbuild, "collect_emulator_extras", return_value=[]):
            packs_platformpack.generate_split_packs(
                "retroarch", platforms, {"files": {}}, "bios", out,
                emu_profiles=profiles,
                target_cores=_target_cores_for("retroarch", "switch", platforms),
                target_name="nintendo-switch",
            )
        systems = {sid for ids in asked for sid in ids}
        self.assertTrue(systems)
        self.assertNotIn("sony-playstation-2", systems)
        self.assertIn("sony-playstation", systems)


class APlatformWithoutTheSystemIsOutOfScope(unittest.TestCase):
    """`--all --system sony-playstation-2` built the five PS2 packs and
    exited 1 on 'no pack for misterfpga', which has no PS2."""

    def _scope(self, **args):
        from model.profiles import load_emulator_profiles
        from resolve.cores import platforms_with_systems

        values = {"target": None, "all": True}
        values.update(args)
        return platforms_with_systems(
            ["retroarch", "misterfpga"], ["sony-playstation-2"],
            load_emulator_profiles(str(REPO_ROOT / "emulators")), {},
            str(REPO_ROOT / "platforms"), values["target"], values["all"],
        )

    def test_all_skips_it(self):
        scope = self._scope()
        self.assertEqual(scope.kept, ["retroarch"])
        self.assertIsNone(scope.refusal)
        self.assertIn("INFO: Skipping misterfpga: no system sony-playstation-2",
                      scope.notices)

    def test_a_named_platform_is_refused(self):
        from packs.runscope import settle_scope

        scope = self._scope(all=False)
        self.assertIn("misterfpga", scope.refusal or "")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            settle_scope(scope, io.StringIO())
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(err.getvalue(), f"ERROR: {scope.refusal}\n")

    def test_a_profile_blind_platform_prints_nothing_itself(self):
        """verify --all --region us --json printed the left-out notice on
        stdout, ahead of the JSON document."""
        from model.profiles import load_emulator_profiles
        from resolve.cores import without_profile_blind

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            scope = without_profile_blind(
                ["retroarch", "misterfpga"], ["--region"], str(REPO_ROOT / "platforms"),
                load_emulator_profiles(str(REPO_ROOT / "emulators")), None, True,
            )
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(scope.kept, ["retroarch"])
        self.assertEqual(scope.notices, [
            "  misterfpga runs no core a profile describes, and --region reads "
            "the profiles: left out",
        ])
        named = without_profile_blind(
            ["misterfpga"], ["--region"], str(REPO_ROOT / "platforms"),
            load_emulator_profiles(str(REPO_ROOT / "emulators")), None, False,
        )
        self.assertEqual(named.refusal, "misterfpga runs no core a profile describes, "
                         "and --region reads the profiles: drop --region")

    def test_verify_reports_on_the_packs_generate_pack_builds(self):
        """verify --all --system exited 2 'mutually exclusive' while
        generate_pack built a pack per platform for the same request."""
        import json
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "scripts/verify.py", "--all", "--system", "sony-playstation-2",
             "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=900,
        )
        self.assertIn(proc.returncode, (0, 1), proc.stderr[-500:])
        self.assertIn("INFO: Skipping misterfpga: no system sony-playstation-2", proc.stderr)
        report = json.loads(proc.stdout)
        self.assertIn("retroarch", report)
        self.assertNotIn("misterfpga", report)


class CrossReferenceReadsTheTargetAcrossPlatforms(unittest.TestCase):
    """cross_reference refused --target without --platform, where verify and
    generate_pack read --all --target as every platform with the target,
    each narrowed to the cores it builds for it."""

    def test_the_scope_is_the_union_of_each_platforms_target_cores(self):
        from packs.crossrefscope import tree_scope
        from model.platforms import load_platform_config
        from model.profiles import load_emulator_profiles
        from model.registry import list_registered_platforms
        from resolve.cores import resolve_platform_cores

        platforms_dir = str(REPO_ROOT / "platforms")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        with contextlib.redirect_stderr(io.StringIO()):
            tree = tree_scope(None, "switch", platforms_dir, profiles, profiles)
        cache, kept, _notes = build_target_cores_cache(
            list_registered_platforms(platforms_dir), "switch", platforms_dir, is_all=True,
        )
        self.assertEqual(tree.selected, kept)
        self.assertIsNone(tree.platform)
        expected: set[str] = set()
        for name in kept:
            expected |= set(resolve_platform_cores(
                load_platform_config(name, platforms_dir), profiles, target_cores=cache[name],
            ))
        self.assertEqual(set(tree.profiles), expected)
        self.assertLess(len(tree.profiles), len(profiles))

    def test_the_command_line(self):
        import json
        import subprocess

        def run(*argv: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, "scripts/cross_reference.py", *argv],
                cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=600,
            )

        proc = run("--all", "--target", "switch", "--emulator", "snes9x", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertIn("snes9x", json.loads(proc.stdout))
        proc = run("--target", "switch", "--emulator", "xemu")
        self.assertEqual(proc.returncode, 1, proc.stderr[-500:])
        self.assertIn("no platform with the switch target builds xemu", proc.stderr)
        proc = run("--all", "--target", "swtich")
        self.assertEqual(proc.returncode, 1, proc.stderr[-500:])
        self.assertIn("Close matches: switch", proc.stderr)


class TheSplitDirectoryReadsThePackStem(unittest.TestCase):
    """The split prefix was assembled by hand: a version 'release/1.22' made
    'RetroArch_release/1.22_Split', a nested directory the check never
    found, beside a full pack named 'RetroArch_release-1.22_BIOS_Pack.zip'."""

    def test_a_reserved_character_is_made_safe_as_in_the_full_pack(self):
        from unittest import mock

        from packs import manifest, manifestbuild, md5pack, naming, packplan, platformzip
        from packs import platformpack as packs_platformpack

        config = {"platform": "Foo: Bar", "version": "release/1.22", "systems": {}}
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(packs_platformpack, "load_platform_config", return_value=config), \
                mock.patch.object(packplan, "load_platform_config", return_value=config), \
                mock.patch.object(naming, "load_platform_config", return_value=config), \
                mock.patch.object(manifest, "load_platform_config", return_value=config), \
                mock.patch.object(md5pack, "load_platform_config", return_value=config), \
                mock.patch.object(packs_platformpack, "collect_emulator_extras", return_value=[]), \
                mock.patch.object(platformzip, "collect_emulator_extras", return_value=[]), \
                mock.patch.object(manifestbuild, "collect_emulator_extras", return_value=[]):
            packs_platformpack.generate_split_packs(
                "foo", "platforms", {"files": {}}, "bios", out, emu_profiles={},
            )
            stem = naming.platform_pack_stem(["foo"], "foo", "platforms")
            self.assertEqual(os.listdir(out), [f"{stem}_Split"])
        self.assertEqual(stem, "Foo-_Bar_release-1.22")


if __name__ == "__main__":
    unittest.main()
