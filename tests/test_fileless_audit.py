"""A profile that declares no files has nothing that can go missing.

No file to be absent, no ref to drift: an empty `files:` list is the one
assertion in the repository that ages without any existing check noticing.
virtualjaguar carried "No external BIOS files are required or loaded by this
core" while its source had grown eleven filenames read from the system
directory, and only a manual reading found it.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_an_alias_has_no_files_of_its_own(self):
        """eden-nightly is eden under another name, yet it was swept and its
        forge's 403 failed the run."""
        self._write(BASE + "type: alias\nalias_of: other\n")
        self.assertIsNone(self._run())

    def test_an_empty_answer_does_not_settle_it(self):
        self._write(BASE + 'exclusion_note: "   "\n')
        self.assertEqual(len(self._run()), 1)


class TestCommandLine(unittest.TestCase):
    """Named profiles were the only mode, so the documented example printed
    nothing. A misspelt name ended in a traceback and an unreachable source
    left the run green."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        Path(self.tmp.name, "open.yml").write_text(BASE, encoding="utf-8")
        Path(self.tmp.name, "done.yml").write_text(
            "emulator: D\nfiles:\n  - name: a.bin\n", encoding="utf-8"
        )

    def _main(self, *argv, audit=None):
        read = []

        def fake(name, *args):
            read.append(name)
            if audit:
                return audit(name)
            return []

        with mock.patch.object(sys, "argv", ["fileless_audit.py", *argv,
                                             "--emulators-dir", self.tmp.name]), \
                mock.patch.object(fileless_audit, "audit", side_effect=fake), \
                mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            with self.assertRaises(SystemExit) as caught:
                fileless_audit.main()
        return caught.exception.code, read

    def test_all_reads_only_the_profiles_nobody_answered(self):
        code, read = self._main("--all")
        self.assertEqual((code, read), (0, ["open"]))

    def test_a_misspelt_profile_is_named(self):
        code, read = self._main("opne")
        self.assertIn("open", str(code))
        self.assertEqual(read, [])

    def test_an_unreachable_source_fails_the_run(self):
        def unreachable(name):
            raise fileless_audit.upstream.UpstreamError("HTTP 403")

        code, _ = self._main("open", audit=unreachable)
        self.assertEqual(code, 1)


class TestCorpusIsAnswered(unittest.TestCase):
    """Every fileless profile is covered, answered, or flagged.

    Offline, so it reads the fetch cache, and is skipped where that is cold rather
    than turning a network absence into a failure.
    """

    def test_no_fileless_profile_is_left_unexplained(self):
        if not (ROOT / ".cache").is_dir():
            self.skipTest("no upstream cache")
        from safeparse import yaml_load

        fetch = fileless_audit.upstream.fetch_file
        read = []

        def counted(*args, **kwargs):
            # A cold path is unread here, not absent.
            try:
                lines = fetch(*args, **kwargs)
            except fileless_audit.upstream.NotCachedError:
                return None
            if lines is not None:
                read.append(args[2])
            return lines

        flagged = []
        with mock.patch.object(fileless_audit.upstream, "fetch_file", counted):
            for path in sorted((ROOT / "emulators").glob("*.yml")):
                with path.open(encoding="utf-8") as handle:
                    document = yaml_load(handle) or {}
                if document.get("files"):
                    continue
                try:
                    hits = fileless_audit.audit(
                        path.stem, str(ROOT / "emulators"), str(ROOT / ".cache"), True
                    )
                except fileless_audit.upstream.NotCachedError:
                    # A cold branch tip is unread too, not a branch gone.
                    continue
                if hits:
                    flagged.append(path.stem)
        if not read:
            self.skipTest("the upstream cache holds no source a fileless profile cites")
        self.assertEqual(
            flagged, [],
            "these declare no files and their source asks for a directory, "
            "with nothing written down about why",
        )
