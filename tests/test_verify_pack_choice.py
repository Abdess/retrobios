"""--verify-packs opens the pack the flags name, by its exact file name.

The check took the first sorted *_BIOS_Pack.zip whose name contained the
platform name. With a full and a regional pack side by side, --region us
judged the full pack against the regional expectation and never opened the
regional one. A pack built with --source truth answered SKIP and exit 0.
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
    return (True, 0, 0, [], 1, 1, 1, 1, 0, 0)


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
            ["retroarch"], "retroarch", "platforms"
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
            "all_variants": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _run(self, args) -> list[str]:
        checked: list[str] = []

        def record(zip_path, platform_name, *a, **kw):
            checked.append((platform_name, os.path.basename(zip_path)))
            self.variants.append(
                (kw.get("source", "full"), kw.get("required_only", False))
            )
            return _ok_result()

        self.variants: list[tuple[str, bool]] = []

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

    def test_all_variants_checks_every_variant_as_it_was_built(self):
        """After --all-variants the check opened the full pack only, and then
        said "hashes checked during the build" for the five narrowed packs:
        one missing a file its narrowed list requires passed. Each is now
        held to the platform's list narrowed the same way."""
        names = {}
        for source, required in self.gp.ALL_VARIANTS:
            tags = "".join(
                tag for tag, _ in self.gp._narrowings(source, None, None, False, required)
            )
            names[f"{self.stem}{tags}_BIOS_Pack.zip"] = (source, required)
            self._touch(f"{self.stem}{tags}_BIOS_Pack.zip")
        checked = self._run(self._args(all_variants=True))
        self.assertEqual(
            dict(zip((name for _p, name in checked), self.variants)), names
        )

    def test_a_target_the_platform_lacks_is_refused(self):
        """`--platform bizhawk --target rpi4typo --verify-packs` verified the
        full pack and said `all OK`, where the build refused the target."""
        import contextlib
        import io

        bizhawk = self.gp._platform_pack_stem(["bizhawk"], "bizhawk", "platforms")
        self._touch(f"{bizhawk}_BIOS_Pack.zip")
        self._touch(f"{self.stem}_BIOS_Pack.zip")
        for platform, target in (("bizhawk", "rpi4typo"), ("retroarch", "swich")):
            with self.subTest(platform=platform), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as ctx:
                self._run(self._args(platform=platform, target=target))
            self.assertEqual(ctx.exception.code, 1)
            self.assertEqual(self.variants, [])

    def test_the_run_ends_on_a_summary(self):
        """A failing pack was named only above its own error lines, and the
        log ended on the last platform's OK line."""
        import contextlib
        import io

        pack = f"{self.stem}_BIOS_Pack.zip"
        self._touch(pack)
        out, err = io.StringIO(), io.StringIO()
        failed = (False, 0, 0, ["x: missing"], 1, 0, 1, 1, 0, 0)
        with mock.patch.object(self.gp, "verify_pack_against_platform",
                               return_value=failed), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit):
            self.gp._run_verify_packs(self._args())
        self.assertEqual(
            err.getvalue().strip().splitlines()[-1],
            f"ERROR: packs failed verification: retroarch ({pack})",
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._run(self._args())
        self.assertEqual(out.getvalue().strip().splitlines()[-1], "Verified 1 pack: all OK")

    def test_the_sweep_checks_release_packs_and_a_named_platform_its_own(self):
        """--all checks the packs a release publishes (release_pack): the
        RetroPie pack, archived and served by the installer, is left to a
        check that names it."""
        stem = self.gp._platform_pack_stem(["retropie"], "retropie", "platforms")
        self._touch(f"{stem}_BIOS_Pack.zip")
        self._touch(f"{self.stem}_BIOS_Pack.zip")
        checked = self._run(
            self._args(platform=None, all=True, include_archived=True)
        )
        self.assertIn(("retroarch", f"{self.stem}_BIOS_Pack.zip"), checked)
        self.assertNotIn(("retropie", f"{stem}_BIOS_Pack.zip"), checked)
        checked = self._run(self._args(platform="retropie"))
        self.assertIn(("retropie", f"{stem}_BIOS_Pack.zip"), checked)


class GroupRenameKeepsSystemTag(unittest.TestCase):
    def test_single_system_pack_does_not_take_the_full_name(self):
        import generate_pack as gp

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            def fake_generate(*a, pack_name=None, **kw):
                # The group's name is handed in: nothing is renamed afterwards.
                built = Path(tmp) / (
                    pack_name or f"RetroArch_x_BIOS_Pack{gp._system_tag(['atari-lynx'])}.zip"
                )
                built.write_bytes(b"")
                return str(built)

            args = argparse.Namespace(
                all_variants=False, source="full", required_only=False,
                platforms_dir="platforms", target=None, split=False,
                emulators_dir="emulators", regions=[],
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
