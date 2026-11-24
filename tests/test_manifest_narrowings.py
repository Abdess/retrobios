"""A narrowed manifest run writes no artifact under the default list's name.

standalone/<platform>.json carries no tag. A --required-only run wrote it
beside myminui_required.json from the narrowed list, and with --output-dir
install/ it replaced the layouts every --standalone install reads.
"""

from __future__ import annotations

import tests

import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from packs import manifest as packs_manifest
from packs import manifestrun

REPO_ROOT = Path(__file__).resolve().parent.parent
PLATFORM = "retroarch"

NARROWINGS: dict[str, dict] = {
    "platform source": {"source": "platform"},
    "truth source": {"source": "truth"},
    "region": {"regions": ["north-america"]},
    "target": {"target": "switch"},
    "required only": {"required_only": True},
    "no game data": {"no_game_data": True},
}


def _listed(*_args, **options) -> dict:
    if options.get("build_out") is not None:
        options["build_out"].update(slot_choices={}, profiles={})
    return {
        "files": [], "omitted_files": [], "total_files": 0,
        "total_size": 0, "total_omitted": 0,
    }


def _run(out: str, **flags) -> bool:
    args = argparse.Namespace(
        platforms_dir=str(REPO_ROOT / "platforms"), output_dir=out,
        bios_dir=str(REPO_ROOT / "bios"), emulators_dir=str(REPO_ROOT / "emulators"),
        target=None, offline=True, regions=None, no_game_data=False,
        uncached_trees=None, all_variants=False, source="full", required_only=False,
    )
    for key, value in flags.items():
        setattr(args, key, value)
    tc = {PLATFORM: {"fbneo"}} if args.target else {}
    with (
        mock.patch.object(packs_manifest, "generate_manifest", side_effect=_listed),
        mock.patch.object(packs_manifest, "_mark_truth"),
        mock.patch.object(packs_manifest, "standalone_layouts",
                          return_value={"dolphin": {"files": []}}),
        mock.patch.object(manifestrun, "skip_empty_truth", return_value=False),
        contextlib.redirect_stdout(io.StringIO()),
    ):
        return manifestrun.run_manifest_mode(args, [([PLATFORM], PLATFORM)], {}, {}, {}, tc)


def _written(out: str) -> list[str]:
    return sorted(str(p.relative_to(out)) for p in Path(out).rglob("*.json"))


class NarrowedRunsKeepTheDefaultNames(unittest.TestCase):
    def test_the_default_run_writes_the_list_and_its_layouts(self):
        with tempfile.TemporaryDirectory() as out:
            self.assertTrue(_run(out))
            self.assertEqual(
                _written(out), [f"{PLATFORM}.json", f"standalone/{PLATFORM}.json"]
            )

    def test_no_narrowing_writes_an_untagged_artifact(self):
        for label, flags in NARROWINGS.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as out:
                self.assertTrue(_run(out, **flags))
                written = _written(out)
                self.assertEqual(len(written), 1, written)
                self.assertNotIn("standalone", written[0])
                self.assertNotEqual(written[0], f"{PLATFORM}.json")

    def test_a_narrowed_list_builds_no_layouts(self):
        options = {
            "source": "truth", "regions": ["north-america"], "target_name": "switch",
            "required_only": True, "no_game_data": True, "one_per_slot": True,
        }
        for key, value in options.items():
            with self.subTest(key), mock.patch.object(
                packs_manifest, "generate_manifest", side_effect=_listed
            ), mock.patch.object(packs_manifest, "_mark_truth"), mock.patch.object(
                packs_manifest, "standalone_layouts", return_value={"dolphin": {}}
            ):
                layouts: dict = {}
                result = packs_manifest.generate_install_list(
                    PLATFORM, "p", {}, "b", "r", standalone_out=layouts, **{key: value}
                )
                self.assertEqual(layouts, {})
                self.assertNotIn("standalone_builds", result)


if __name__ == "__main__":
    unittest.main()
