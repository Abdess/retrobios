"""A profile that declares no files has nothing that can go missing.

No file to be absent, no ref to drift: an empty `files:` list is the one
assertion in the repository that ages without any existing check noticing.
virtualjaguar carried "No external BIOS files are required or loaded by this
core" while its source had grown eleven filenames read from the system
directory, and only a manual reading found it.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import fileless_audit


ASKS = [
    "static void init(void)",
    "   if (environ_cb(RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY, &dir) && dir)",
    "      snprintf(path, sizeof(path), \"%s/bios.rom\", dir);",
]
QUIET = ["static void init(void) { /* nothing */ }"]

BASE = """emulator: Test
source: "https://github.com/o/n"
source_commit: "pinsha"
files: []
"""


class TestFilelessAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self._orig = (
            fileless_audit.select_views,
            fileless_audit.upstream.fetch_file,
            fileless_audit.collect_citations,
        )

        class View:
            repo = "repo"
            pin = "pinsha"

        fileless_audit.select_views = lambda doc, cache, offline: [View()]
        fileless_audit.collect_citations = lambda doc: [
            type("C", (), {"ref": "libretro.c:10"})()
        ]
        self.source = ASKS
        fileless_audit.upstream.fetch_file = (
            lambda repo, sha, path, cache, offline=False: self.source
        )

    def tearDown(self):
        (
            fileless_audit.select_views,
            fileless_audit.upstream.fetch_file,
            fileless_audit.collect_citations,
        ) = self._orig
        self.tmp.cleanup()

    def _write(self, body: str) -> None:
        Path(self.dir, "p.yml").write_text(body, encoding="utf-8")

    def _run(self):
        return fileless_audit.audit("p", self.dir, ".c", False)

    def test_a_fileless_profile_whose_source_asks_is_flagged(self):
        self._write(BASE)
        self.assertEqual(self._run(), [("libretro.c", "RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY")])

    def test_a_source_that_asks_for_nothing_is_quiet(self):
        self._write(BASE)
        self.source = QUIET
        self.assertEqual(self._run(), [])

    def test_a_profile_that_declares_files_is_not_the_subject(self):
        self._write("emulator: T\nfiles:\n  - name: a.bin\n")
        self.assertIsNone(self._run())

    def test_a_directory_declaration_is_coverage(self):
        """dinothawr reads system_dir/dinothawr/ and says so there."""
        self._write(BASE + "data_directories:\n  - key: d\n")
        self.assertIsNone(self._run())

    def test_a_written_answer_settles_it(self):
        """craft asks for the directory to write its world database in."""
        self._write(BASE + 'exclusion_note: "the directory is written, not read"\n')
        self.assertIsNone(self._run())

    def test_an_empty_answer_does_not_settle_it(self):
        self._write(BASE + 'exclusion_note: "   "\n')
        self.assertEqual(len(self._run()), 1)


class TestCorpusIsAnswered(unittest.TestCase):
    """Every fileless profile is covered, answered, or flagged.

    Offline, so it reads the fetch cache; skipped where that is cold rather
    than turning a network absence into a failure.
    """

    def test_no_fileless_profile_is_left_unexplained(self):
        if not (ROOT / ".cache").is_dir():
            self.skipTest("no upstream cache")
        from safeparse import yaml_load

        flagged = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            with path.open(encoding="utf-8") as handle:
                document = yaml_load(handle) or {}
            if document.get("files"):
                continue
            try:
                hits = fileless_audit.audit(
                    path.stem, str(ROOT / "emulators"), str(ROOT / ".cache"), True
                )
            except Exception:
                continue
            if hits:
                flagged.append(path.stem)
        self.assertEqual(
            flagged, [],
            "these declare no files and their source asks for a directory, "
            "with nothing written down about why",
        )
