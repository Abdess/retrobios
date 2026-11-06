"""A targeted pack is checked under the target reading it was built with.

`--all --target x86_64` packs a platform that has no target file unnarrowed
under the target's name (Recalbox, Lakka, BizHawk, MiSTer, ROCKNIX). The
conformance check read the same target without the --all tolerance, raised
FileNotFoundError on the first of those packs and stopped the run in a
traceback after every pack had been written. Such a platform is now left
out of a targeted --all run, and the check refuses it as the build does.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import build_target_cores_cache  # noqa: E402
from generate_pack import _target_cores_for  # noqa: E402


class CheckReadsTheTargetLikeTheBuild(unittest.TestCase):
    def test_a_platform_without_a_target_file(self):
        # Left out of a targeted --all run rather than built unfiltered, and
        # a run where no platform has the target is refused.
        with tempfile.TemporaryDirectory() as platforms, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
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
        from generate_pack import _narrowings, _platform_target

        platforms = str(REPO_ROOT / "platforms")
        self.assertIsNone(_platform_target("bizhawk", "switch", platforms))
        self.assertEqual(_narrowings("full", None, None, False, False), [])
        self.assertEqual(
            _platform_target("retroarch", "nx", platforms), "nintendo-switch"
        )


class AMistypedTargetIsRefusedFirst(unittest.TestCase):
    """`--platform retroarch --target swich` took the dist lock and waited on
    the data directory refresh, 22 s here and hours behind a pipeline, before
    saying the target does not exist."""

    def test_no_lock_and_no_refresh_before_the_refusal(self):
        from unittest import mock

        import generate_pack

        def touched(*_a, **_kw):
            raise AssertionError("lock or refresh taken before the target check")

        argv = ["generate_pack.py", "--platform", "retroarch", "--target", "swich",
                "--output-dir", str(REPO_ROOT / "tmp" / "never-written")]
        err = io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(generate_pack, "_pack_output_lock", touched), \
                mock.patch.object(generate_pack, "hold_data_dirs", touched), \
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
        from common import (
            load_emulator_profiles, load_platform_config, platform_scope_systems,
        )

        config = load_platform_config("retroarch", self.PLATFORMS)
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        switch = _target_cores_for("retroarch", "switch", self.PLATFORMS)
        wanted = ["sony-playstation-2"]
        self.assertEqual(platform_scope_systems(config, profiles, switch, wanted), {})
        self.assertEqual(list(platform_scope_systems(config, profiles, None, wanted)), wanted)

    def test_the_message_names_the_target(self):
        from common import system_scope_error

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

        import generate_pack
        from common import load_emulator_profiles

        platforms = str(REPO_ROOT / "platforms")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        asked: list[list[str]] = []

        def record(*_a, **kw):
            if kw.get("system_filter"):
                asked.append(kw["system_filter"])
            return None

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out, \
                mock.patch.object(generate_pack, "generate_pack", record), \
                mock.patch.object(generate_pack, "_collect_emulator_extras",
                                  return_value=[]):
            generate_pack.generate_split_packs(
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
        import argparse

        import generate_pack
        from common import load_emulator_profiles

        values = {"platforms_dir": str(REPO_ROOT / "platforms"), "target": None,
                  "all": True}
        values.update(args)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            kept = generate_pack._platforms_with_systems(
                argparse.Namespace(**values), ["retroarch", "misterfpga"],
                ["sony-playstation-2"],
                load_emulator_profiles(str(REPO_ROOT / "emulators")), {},
            )
        return kept, out.getvalue()

    def test_all_skips_it(self):
        kept, out = self._scope()
        self.assertEqual(kept, ["retroarch"])
        self.assertIn("INFO: Skipping misterfpga: no system sony-playstation-2", out)

    def test_a_named_platform_is_refused(self):
        with self.assertRaises(SystemExit) as ctx:
            self._scope(all=False)
        self.assertEqual(ctx.exception.code, 1)


class TheSplitDirectoryReadsThePackStem(unittest.TestCase):
    """The split prefix was assembled by hand: a version 'release/1.22' made
    'RetroArch_release/1.22_Split', a nested directory the check never
    found, beside a full pack named 'RetroArch_release-1.22_BIOS_Pack.zip'."""

    def test_a_reserved_character_is_made_safe_as_in_the_full_pack(self):
        from unittest import mock

        import generate_pack

        config = {"platform": "Foo: Bar", "version": "release/1.22", "systems": {}}
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out, \
                mock.patch.object(generate_pack, "load_platform_config",
                                  return_value=config), \
                mock.patch.object(generate_pack, "_collect_emulator_extras",
                                  return_value=[]):
            generate_pack.generate_split_packs(
                "foo", "platforms", {"files": {}}, "bios", out, emu_profiles={},
            )
            stem = generate_pack._platform_pack_stem(["foo"], "foo", "platforms")
            self.assertEqual(os.listdir(out), [f"{stem}_Split"])
        self.assertEqual(stem, "Foo-_Bar_release-1.22")


if __name__ == "__main__":
    unittest.main()
