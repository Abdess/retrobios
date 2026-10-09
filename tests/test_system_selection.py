"""One system, two spellings, one pack.

stella2014 and stella2023 write atari_2600 where every other profile writes
atari-2600. --system matched the spelling exactly and named the ZIP from
it, so the two spellings built two different packs under one file name,
the second replacing the first; --from-md5 --emulator X --standalone
accepted a libretro-only core and named a standalone pack that was the
libretro pack.
"""

from __future__ import annotations

import os
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


if __name__ == "__main__":
    unittest.main()
