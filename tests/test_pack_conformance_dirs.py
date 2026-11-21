"""The conformance stage reads the directories the run was given.

``run_platform_packs`` called ``verify_and_finalize_packs`` without them, so
packs built from ``--platforms-dir`` and ``--emulators-dir`` were judged
against ``platforms/`` and ``emulators/``, or not matched to any platform at
all and never judged.
"""

from __future__ import annotations

import tests

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from packs import platformrun
from packs import finalize as packs_finalize
from packs import integrity as packverify

REPO_ROOT = Path(__file__).resolve().parents[1]


class ConformanceUsesTheRunDirectories(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _args(self, split: bool) -> argparse.Namespace:
        return argparse.Namespace(
            all_variants=False, source="full", required_only=False,
            platforms_dir="fixture-platforms", target=None, split=split,
            emulators_dir="fixture-emulators", regions=[],
            one_per_slot=False, offline=True, bios_dir="bios",
            output_dir=self.tmp.name, verify_packs=False,
        )

    def test_run_passes_both_directories(self):
        for split in (False, True):
            if split:
                Path(self.tmp.name, "X_Split").mkdir(exist_ok=True)
            with self.subTest(split=split), mock.patch.object(
                platformrun, "verify_and_finalize_packs", return_value=True
            ) as finalize:
                platformrun.run_platform_packs(
                    self._args(split), [], {}, {}, {}, {}, {}, None
                )
            self.assertTrue(finalize.call_args_list)
            for call in finalize.call_args_list:
                self.assertEqual(call.kwargs.get("platforms_dir"), "fixture-platforms")
                self.assertEqual(call.kwargs.get("emulators_dir"), "fixture-emulators")

    def test_finalizer_hands_the_emulators_directory_on(self):
        out = Path(self.tmp.name)
        (out / "Fix_BIOS_Pack.zip").write_bytes(b"")
        seen = {}

        def record(*args, **kwargs):
            seen.update(kwargs)
            return True, 0, 0, [], 0, 0, 0, 0, 0, 0

        with mock.patch.object(packs_finalize, "list_registered_platforms", return_value=["fix"]), \
                mock.patch.object(
                    packs_finalize, "expected_pack_names",
                    return_value={"fix": {"Fix_BIOS_Pack.zip"}},
                ), \
                mock.patch.object(packs_finalize, "pack_archives", return_value=["Fix_BIOS_Pack.zip"]), \
                mock.patch.object(
                    packs_finalize, "verify_pack",
                    return_value=(True, {"summary": {
                        "verified": 0, "total_files": 0, "untracked": 0, "errors": 0,
                    }, "errors": []}),
                ), \
                mock.patch.object(packs_finalize, "inject_manifest"), \
                mock.patch.object(packs_finalize, "_target_cores_for", return_value=None), \
                mock.patch.object(packverify, "verify_pack_against_platform", record):
            packs_finalize.verify_and_finalize_packs(
                str(out), {"files": {}, "indexes": {}},
                platforms_dir="fixture-platforms",
                emulators_dir="fixture-emulators",
            )
        self.assertEqual(seen.get("emulators_dir"), "fixture-emulators")


class TheBuildChecksEachVariantAsVerifyPacksDoes(unittest.TestCase):
    """The build skipped conformance on every narrowed pack while
    --verify-packs held the same pack to its own expectation, so one pack
    had two verdicts."""

    def test_a_narrowed_pack_is_checked_under_its_variant(self):
        seen: list[tuple] = []

        def record(zip_path, platform_name, *args, **kwargs):
            seen.append((Path(zip_path).name, kwargs.get("source"), kwargs.get("required_only")))
            return True, 0, 0, [], 0, 0, 0, 0, 0, 0

        names = ["Fix_BIOS_Pack.zip", "Fix_Required_BIOS_Pack.zip", "Fix_Truth_BIOS_Pack.zip"]
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(packs_finalize, "list_registered_platforms", return_value=["fix"]), \
                mock.patch.object(packs_finalize, "expected_pack_names",
                                  return_value={"fix": set(names)}), \
                mock.patch.object(packs_finalize, "pack_archives", return_value=names), \
                mock.patch.object(
                    packs_finalize, "verify_pack",
                    return_value=(True, {"summary": {
                        "verified": 0, "total_files": 0, "untracked": 0, "errors": 0,
                    }, "errors": []}),
                ), \
                mock.patch.object(packs_finalize, "inject_manifest"), \
                mock.patch.object(packs_finalize, "_target_cores_for", return_value=None), \
                mock.patch.object(packverify, "verify_pack_against_platform", record):
            packs_finalize.verify_and_finalize_packs(
                tmp, {"files": {}, "indexes": {}}, platforms_dir="fixture-platforms",
            )
        self.assertEqual(seen, [
            ("Fix_BIOS_Pack.zip", "full", False),
            ("Fix_Required_BIOS_Pack.zip", "full", True),
            ("Fix_Truth_BIOS_Pack.zip", "truth", False),
        ])

    def test_the_run_names_the_variants_it_built(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            platformrun, "verify_and_finalize_packs", return_value=True
        ) as finalize:
            args = argparse.Namespace(
                all_variants=True, source="full", required_only=False,
                platforms_dir="p", target=None, split=False, emulators_dir="e",
                regions=[], one_per_slot=False, offline=True, bios_dir="bios",
                output_dir=tmp, verify_packs=False,
            )
            platformrun.run_platform_packs(args, [], {}, {}, {}, {}, {}, None)
        self.assertEqual(len(finalize.call_args.kwargs["variants"]), 6)


if __name__ == "__main__":
    unittest.main()
