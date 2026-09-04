"""A MAME romset ref must name the line declaring its own set.

profile_sync follows content, so a drifted ref still anchors wherever the
cited text went. That is drift detection working, and it cannot answer the
only question a MAME ref asks: does this line declare this set. Asking it
found nineteen stale refs in one driver where profile_sync had flagged five.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import mame_ref_audit
from mame_ref_audit import declares


DRIVER = [
    "// a driver file",
    "CONS( 2000, ekara,    0,     0, m, i, s, init, \"Takara\", \"e-kara\", F )",
    "CONS( 2002, ekarag,   ekara, 0, m, i, s, init, \"Takara\", \"e-kara DE\", F )",
    "/* Naomi */ GAME( 1998, naomi, 0, n, n, s, init, ROT0, \"Sega\", \"Naomi\", F )",
    "ROM_START( soundbox )",
]

PROFILE = """emulator: Test
source: "https://github.com/libretro/mame"
source_commit: "pinsha"
files:
  - name: ekara.zip
    category: bios_zip
    source_ref: "src/mame/tvgames/xavix.cpp:99"
  - name: ekarag.zip
    category: bios_zip
    source_ref: "src/mame/tvgames/xavix.cpp:3"
  - name: soundbox.zip
    category: bios_zip
    source_ref: "src/mame/sega/segaai.cpp:1"
"""


class TestDeclares(unittest.TestCase):
    def test_the_set_name_is_argument_one(self):
        self.assertTrue(declares(DRIVER[1], "ekara"))

    def test_a_clone_naming_it_as_parent_is_not_a_declaration(self):
        """ekara is the parent field of ekarag; most of a driver looks so."""
        self.assertFalse(declares(DRIVER[2], "ekara"))
        self.assertTrue(declares(DRIVER[2], "ekarag"))

    def test_a_declaration_behind_a_comment_still_counts(self):
        self.assertTrue(declares(DRIVER[3], "naomi"))

    def test_a_rom_start_is_not_a_machine_declaration(self):
        self.assertFalse(declares(DRIVER[4], "soundbox"))


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        Path(self.dir, "p.yml").write_text(PROFILE, encoding="utf-8")
        self._fetch = mame_ref_audit.upstream.fetch_file
        mame_ref_audit.upstream.fetch_file = (
            lambda repo, sha, path, cache, offline=False:
            DRIVER if path.endswith("xavix.cpp") else ["ROM_START( soundbox )"]
        )

    def tearDown(self):
        mame_ref_audit.upstream.fetch_file = self._fetch
        self.tmp.cleanup()

    def test_a_ref_pointing_elsewhere_is_reported_with_its_declaration(self):
        findings, agreed, unjudged = mame_ref_audit.audit("p", self.dir, ".c", False)
        self.assertEqual(agreed, 1, "ekarag cites its own line")
        self.assertEqual([f.set_name for f in findings], ["ekara"])
        self.assertEqual(findings[0].cited, 99)
        self.assertEqual(findings[0].declared, 2)

    def test_a_set_no_machine_declares_is_left_unjudged(self):
        """A device archive takes its DEFINE_DEVICE_TYPE shortname."""
        _, _, unjudged = mame_ref_audit.audit("p", self.dir, ".c", False)
        self.assertEqual(unjudged, 1)

    def test_rewrite_moves_only_the_entry_that_owns_the_ref(self):
        findings, _, _ = mame_ref_audit.audit("p", self.dir, ".c", False)
        self.assertEqual(mame_ref_audit.rewrite("p", self.dir, findings), 1)
        text = Path(self.dir, "p.yml").read_text(encoding="utf-8")
        self.assertIn('source_ref: "src/mame/tvgames/xavix.cpp:2"', text)
        self.assertIn(
            'source_ref: "src/mame/tvgames/xavix.cpp:3"', text,
            "ekarag's own ref must be untouched",
        )

    def test_a_corrected_profile_reports_nothing(self):
        findings, _, _ = mame_ref_audit.audit("p", self.dir, ".c", False)
        mame_ref_audit.rewrite("p", self.dir, findings)
        again, agreed, _ = mame_ref_audit.audit("p", self.dir, ".c", False)
        self.assertEqual(again, [])
        self.assertEqual(agreed, 2)


class TestCorpusStaysCorrect(unittest.TestCase):
    """The committed profiles agree with their pinned drivers.

    Offline, so it reads the fetch cache: skipped where that is cold rather
    than turning a network absence into a failure.
    """

    def test_every_mame_family_ref_names_its_own_set(self):
        if not (ROOT / ".cache").is_dir():
            self.skipTest("no upstream cache")
        for name in ("mame", "mamearcade", "mamemess", "groovymame"):
            with self.subTest(emulator=name):
                findings, agreed, _ = mame_ref_audit.audit(
                    name, str(ROOT / "emulators"), str(ROOT / ".cache"), True
                )
                if not agreed and not findings:
                    self.skipTest(f"{name}: driver sources not cached")
                self.assertEqual(
                    [f.set_name for f in findings], [],
                    f"{name} has refs that do not declare their own set",
                )
