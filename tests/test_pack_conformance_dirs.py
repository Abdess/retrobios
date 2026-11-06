"""The conformance stage reads the directories the run was given.

``_run_platform_packs`` called ``verify_and_finalize_packs`` without them, so
packs built from ``--platforms-dir`` and ``--emulators-dir`` were judged
against ``platforms/`` and ``emulators/``, or not matched to any platform at
all and never judged.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import argparse
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_pack as gp  # noqa: E402
import packverify  # noqa: E402


class ConformanceUsesTheRunDirectories(unittest.TestCase):
    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
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
                gp, "verify_and_finalize_packs", return_value=True
            ) as finalize:
                gp._run_platform_packs(
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

        with mock.patch.object(gp, "list_registered_platforms", return_value=["fix"]), \
                mock.patch.object(
                    gp, "_expected_pack_names",
                    return_value={"fix": {"Fix_BIOS_Pack.zip"}},
                ), \
                mock.patch.object(gp, "_pack_archives", return_value=["Fix_BIOS_Pack.zip"]), \
                mock.patch.object(
                    gp, "verify_pack",
                    return_value=(True, {"summary": {
                        "verified": 0, "total_files": 0, "untracked": 0, "errors": 0,
                    }, "errors": []}),
                ), \
                mock.patch.object(gp, "inject_manifest"), \
                mock.patch.object(gp, "_target_cores_for", return_value=None), \
                mock.patch.object(gp, "verify_pack_against_platform", record), \
                mock.patch.object(packverify, "verify_pack_against_platform", record):
            gp.verify_and_finalize_packs(
                str(out), {"files": {}, "indexes": {}},
                platforms_dir="fixture-platforms",
                emulators_dir="fixture-emulators",
            )
        self.assertEqual(seen.get("emulators_dir"), "fixture-emulators")


if __name__ == "__main__":
    unittest.main()
