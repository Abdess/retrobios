"""--verify-packs opens the pack the flags name, by its exact file name.

The check took the first sorted *_BIOS_Pack.zip whose name contained the
platform name. With a full and a regional pack side by side, --region us
judged the full pack against the regional expectation and never opened the
regional one; a pack built with --source truth answered SKIP and exit 0.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _ok_result() -> tuple:
    return (True, 0, 0, [], 1, 1, 1, 1, 0)


class VerifyPackChoice(unittest.TestCase):
    def setUp(self):
        import generate_pack

        self.gp = generate_pack
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        self.tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.db = self.out / "db.json"
        self.db.write_text(json.dumps({"files": {}}))
        self.stem = generate_pack._platform_pack_stem(
            ["retroarch", "lakka"], "retroarch", "platforms"
        )

    def _args(self, **overrides) -> argparse.Namespace:
        values = {
            "db": str(self.db),
            "platform": "retroarch",
            "all": False,
            "include_archived": False,
            "emulators_dir": "emulators",
            "platforms_dir": "platforms",
            "output_dir": str(self.out),
            "target": None,
            "regions": [],
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _run(self, args) -> list[str]:
        checked: list[str] = []

        def record(zip_path, platform_name, *a, **kw):
            checked.append((platform_name, os.path.basename(zip_path)))
            return _ok_result()

        with mock.patch.object(self.gp, "verify_pack_against_platform", record):
            self.gp._run_verify_packs(args)
        return checked

    def _touch(self, name: str) -> None:
        (self.out / name).write_bytes(b"")

    def test_region_opens_the_regional_pack(self):
        import region as region_mod

        regions = region_mod.parse_requested("us")
        tag = self.gp._narrowings("full", regions, None, False, False)[0][0]
        self._touch(f"{self.stem}_BIOS_Pack.zip")
        self._touch(f"{self.stem}{tag}_BIOS_Pack.zip")
        checked = self._run(self._args(regions=regions))
        self.assertEqual(checked, [("retroarch", f"{self.stem}{tag}_BIOS_Pack.zip")])

    def test_unnarrowed_check_ignores_the_regional_pack(self):
        self._touch(f"{self.stem}_AsiaPacific_BIOS_Pack.zip")
        self._touch(f"{self.stem}_BIOS_Pack.zip")
        checked = self._run(self._args())
        self.assertEqual(checked, [("retroarch", f"{self.stem}_BIOS_Pack.zip")])

    def test_named_platform_with_only_a_narrowed_pack_fails(self):
        self._touch(f"{self.stem}_Truth_BIOS_Pack.zip")
        with self.assertRaises(SystemExit) as ctx:
            self._run(self._args())
        self.assertEqual(ctx.exception.code, 1)

    def test_include_archived_reaches_the_archived_pack(self):
        stem = self.gp._platform_pack_stem(["retropie"], "retropie", "platforms")
        self._touch(f"{stem}_BIOS_Pack.zip")
        checked = self._run(
            self._args(platform=None, all=True, include_archived=True)
        )
        self.assertIn(("retropie", f"{stem}_BIOS_Pack.zip"), checked)


class GroupRenameKeepsSystemTag(unittest.TestCase):
    def test_single_system_pack_does_not_take_the_full_name(self):
        import generate_pack as gp

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            built = Path(tmp) / f"RetroArch_x_BIOS_Pack{gp._system_tag(['atari-lynx'])}.zip"

            def fake_generate(*a, **kw):
                built.write_bytes(b"")
                return str(built)

            args = argparse.Namespace(
                all_variants=False, source="full", required_only=False,
                platforms_dir="platforms", target=None, split=False,
                include_extras=False, emulators_dir="emulators", regions=[],
                one_per_slot=False, offline=True, bios_dir="bios",
                output_dir=tmp,
            )
            with mock.patch.object(gp, "generate_pack", fake_generate), \
                    mock.patch.object(gp, "verify_and_finalize_packs", return_value=True):
                gp._run_platform_packs(
                    args, [(["retroarch", "lakka"], "retroarch")], {}, {}, {},
                    {}, {}, ["atari-lynx"],
                )
            names = os.listdir(tmp)
        stem = gp._platform_pack_stem(["retroarch", "lakka"], "retroarch", "platforms")
        self.assertEqual(names, [f"{stem}_BIOS_Pack_Lynx.zip"])


if __name__ == "__main__":
    unittest.main()
