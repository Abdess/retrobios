"""A standalone-only profile does not mark its files standalone.

Per-file mode separates the two builds of a dual profile. ares, clk,
primehack, jgenesis and five Switch emulators repeated `mode: standalone`
on all 226 of their files: the gap analysis skips such a file, so
cross_reference reported 0 undeclared files where verify --standalone
counted 118 for clk alone, and a platform listing the emulator without
standalone_cores dropped them from its pack.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

DUAL_PROFILE = {
    "emulator": "Dual",
    "type": "standalone + libretro",
    "cores": ["dual"],
    "systems": ["sys"],
    "files": [
        {"name": "both.bin"},
        {"name": "standalone.bin", "mode": "standalone"},
        {"name": "libretro.bin", "mode": "libretro"},
    ],
}


class StandaloneProfilesCarryNoFileMode(unittest.TestCase):
    def test_every_profile_follows_it(self):
        offenders = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if document.get("type") != "standalone":
                continue
            marked = sum(
                1 for entry in document.get("files") or []
                if isinstance(entry, dict) and entry.get("mode") == "standalone"
            )
            if marked:
                offenders.append(f"{path.stem}: {marked}")
        self.assertEqual(offenders, [])

    def test_the_schema_refuses_it(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads((REPO_ROOT / "schemas" / "emulator.schema.json").read_text())
        validator = Draft202012Validator(schema)
        profile = {
            "emulator": "X",
            "type": "standalone",
            "systems": ["x"],
            "files": [{"name": "a.bin", "mode": "standalone"}],
        }
        self.assertTrue(list(validator.iter_errors(profile)))
        profile["type"] = "standalone + libretro"
        self.assertEqual(
            [e.message for e in validator.iter_errors(profile) if "mode" in e.message],
            [],
        )


class CrossReferenceReadsTheBuildThePlatformRuns(unittest.TestCase):
    """cross_reference dropped every standalone entry whatever the platform:
    for Recalbox, which runs Dolphin standalone, it reported 12 Dolphin gaps
    where verify and the pack builder found 26."""

    def _gaps(self, standalone_cores):
        import sys

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from cross_reference import cross_reference

        empty_db = {"files": {}, "indexes": {}}
        report = cross_reference(
            {"dual": DUAL_PROFILE}, {}, empty_db, standalone_cores=standalone_cores
        )
        return sorted(g["name"] for g in report["dual"]["gap_details"])

    def test_a_platform_running_it_standalone(self):
        self.assertEqual(self._gaps({"dual"}), ["both.bin", "standalone.bin"])

    def test_a_platform_running_the_core(self):
        self.assertEqual(self._gaps(set()), ["both.bin", "libretro.bin"])


if __name__ == "__main__":
    unittest.main()
