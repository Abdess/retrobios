#!/usr/bin/env python3
"""Native-format exporters.

export_native.py turns the profile data back into each platform's own file:
Recalbox's es_bios.xml, Batocera's systems list, RetroDECK's manifests. The
point is that a platform maintainer can take the output and use it, so the
format has to be theirs, not an approximation of it. None of it was covered.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from exporter import discover_exporters  # noqa: E402
from exporter.base_exporter import BaseExporter  # noqa: E402

TRUTH = {
    "systems": {
        "sony-playstation": {
            "files": [
                {
                    "name": "scph5501.bin",
                    "path": "psx/scph5501.bin",
                    "md5": "490f666e1afb15b7362b406ed1cea246",
                    "required": True,
                },
                {
                    "name": "scph7001.bin",
                    "path": "psx/scph7001.bin",
                    "md5": "1e68c231d0896b7eadcad1d7d8e76129",
                    "required": False,
                },
                # Carries an md5 on purpose: without one it would be dropped
                # for being incomplete, and the placeholder guard would never
                # be the reason it stayed out.
                {
                    "name": "<user-selected>.bin",
                    "path": "psx/PLACEHOLDER-MUST-NOT-SHIP.bin",
                    "md5": "00000000000000000000000000000000",
                    "required": False,
                },
            ],
        },
    },
}


class ExporterRegistry(unittest.TestCase):
    def test_every_exporter_declares_a_platform_and_the_contract(self):
        exporters = discover_exporters()
        self.assertTrue(exporters, "no exporters discovered")
        for platform, cls in exporters.items():
            with self.subTest(platform=platform):
                self.assertTrue(issubclass(cls, BaseExporter))
                self.assertEqual(cls.platform_name(), platform)
                instance = cls()
                self.assertTrue(callable(instance.export))
                self.assertTrue(callable(instance.validate))

    def test_the_registry_covers_the_platforms_it_claims(self):
        for expected in ("recalbox", "batocera", "retrodeck", "romm"):
            self.assertIn(expected, discover_exporters())


class SharedHelpers(unittest.TestCase):
    def test_placeholder_names_are_recognised(self):
        for name in ("<user-selected>.bin", "rom*.bin", "a<b>.rom"):
            self.assertTrue(BaseExporter._is_pattern(name), name)
        for name in ("scph5501.bin", "bios_CD_E.bin"):
            self.assertFalse(BaseExporter._is_pattern(name), name)

    def test_destination_prefers_path_then_destination_then_name(self):
        self.assertEqual(
            BaseExporter._dest({"path": "a", "destination": "b", "name": "c"}), "a"
        )
        self.assertEqual(BaseExporter._dest({"destination": "b", "name": "c"}), "b")
        self.assertEqual(BaseExporter._dest({"name": "c"}), "c")
        self.assertEqual(BaseExporter._dest({}), "")

    def test_a_scraped_display_name_wins_over_the_slug(self):
        self.assertEqual(
            BaseExporter._display_name("sony-playstation", {"name": "PlayStation"}),
            "PlayStation",
        )

    def test_acronyms_stay_upper_case_in_a_derived_name(self):
        derived = BaseExporter._display_name("nes-and-snes")
        self.assertIn("NES", derived)
        self.assertIn("SNES", derived)


class _ExportFixture(unittest.TestCase):
    platform = ""

    def setUp(self):
        if not self.platform:
            self.skipTest("base fixture")
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name) / "out"
        self.exporter = discover_exporters()[self.platform]()

    def tearDown(self):
        if hasattr(self, "_tmp"):
            self._tmp.cleanup()

    def _export(self) -> str:
        self.exporter.export(TRUTH, str(self.out))
        self.assertTrue(self.out.exists(), "exporter wrote nothing")
        return self.out.read_text(encoding="utf-8")


class RecalboxExport(_ExportFixture):
    platform = "recalbox"

    def test_output_is_well_formed_xml_in_recalbox_shape(self):
        root = ET.fromstring(self._export())
        self.assertEqual(root.tag, "biosList")
        systems = root.findall("system")
        self.assertTrue(systems, "no <system> emitted")

    def test_each_declared_file_becomes_a_bios_element_with_its_md5(self):
        root = ET.fromstring(self._export())
        by_path = {
            b.get("path"): b for s in root.findall("system") for b in s.findall("bios")
        }
        self.assertIn("psx/scph5501.bin", by_path)
        self.assertEqual(
            by_path["psx/scph5501.bin"].get("md5"),
            "490f666e1afb15b7362b406ed1cea246",
        )

    def test_a_placeholder_entry_is_not_exported_as_a_file(self):
        """Recalbox would otherwise look for a file nobody can supply.

        The check is on the destination path, not the name: the exporter
        writes path=, so asserting on the name passes whatever the filter
        does.
        """
        exported = self._export()
        self.assertNotIn("PLACEHOLDER-MUST-NOT-SHIP", exported)
        self.assertNotIn("<user-selected>", exported)

    def test_mandatory_is_only_stated_when_it_is_false(self):
        """Recalbox treats a missing attribute as mandatory."""
        root = ET.fromstring(self._export())
        by_path = {
            b.get("path"): b for s in root.findall("system") for b in s.findall("bios")
        }
        self.assertIsNone(by_path["psx/scph5501.bin"].get("mandatory"))
        self.assertEqual(by_path["psx/scph7001.bin"].get("mandatory"), "false")

    def test_the_export_round_trips_through_its_own_validator(self):
        self.exporter.export(TRUTH, str(self.out))
        self.assertEqual(self.exporter.validate(TRUTH, str(self.out)), [])

    def test_a_truncated_export_is_reported_by_the_validator(self):
        self.exporter.export(TRUTH, str(self.out))
        self.out.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n<biosList></biosList>\n',
            encoding="utf-8",
        )
        self.assertTrue(
            self.exporter.validate(TRUTH, str(self.out)),
            "a file missing every entry validated clean",
        )


class EveryExporterProducesSomething(unittest.TestCase):
    """Whatever the format, an exporter must write a non-empty file it accepts."""

    def test_each_exporter_writes_and_validates_its_own_output(self):
        for platform, cls in sorted(discover_exporters().items()):
            with self.subTest(platform=platform):
                with tempfile.TemporaryDirectory() as directory:
                    out = Path(directory) / "out"
                    exporter = cls()
                    try:
                        exporter.export(TRUTH, str(out))
                    except (KeyError, TypeError, ValueError) as exc:
                        self.fail(f"{platform} export raised {exc!r}")
                    self.assertTrue(out.exists(), f"{platform} wrote nothing")
                    self.assertTrue(
                        out.stat().st_size > 0, f"{platform} wrote an empty file"
                    )
                    issues = exporter.validate(TRUTH, str(out))
                    self.assertEqual(
                        issues, [], f"{platform} rejects its own output: {issues[:2]}"
                    )

    def test_no_exporter_emits_a_placeholder_name(self):
        for platform, cls in sorted(discover_exporters().items()):
            with self.subTest(platform=platform):
                with tempfile.TemporaryDirectory() as directory:
                    out = Path(directory) / "out"
                    cls().export(TRUTH, str(out))
                    exported = out.read_text(encoding="utf-8", errors="replace")
                    self.assertNotIn(
                        "PLACEHOLDER-MUST-NOT-SHIP",
                        exported,
                        f"{platform} exported a placeholder as a real file",
                    )
                    self.assertNotIn("<user-selected>", exported)


if __name__ == "__main__":
    unittest.main()
