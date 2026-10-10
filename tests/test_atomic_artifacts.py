"""Generated artifacts are written whole or not at all.

write_if_changed got the scratch-and-rename treatment, but the install
manifests, the target manifests and release.json were still truncated at
their final name, and restore_large_files copied an asset straight to its
path in bios/: a scan running beside the copy hashed the truncated file.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import artifacts  # noqa: E402


class WholeOrNothing(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_an_interrupted_write_keeps_the_previous_file(self):
        target = self.dir / "manifest.json"
        target.write_text("{}")
        with mock.patch("os.replace", side_effect=OSError("cut")), self.assertRaises(OSError):
            artifacts.write_text_atomic(str(target), "{\"files\": []}")
        self.assertEqual(target.read_text(), "{}")
        self.assertEqual(os.listdir(self.dir), ["manifest.json"])

    def test_an_interrupted_copy_leaves_no_file(self):
        source = self.dir / "asset.bin"
        source.write_bytes(b"x" * 1000)
        target = self.dir / "bios" / "asset.bin"
        target.parent.mkdir()
        with mock.patch("shutil.copy2", side_effect=OSError("cut")), self.assertRaises(OSError):
            artifacts.copy_file_atomic(str(source), str(target))
        self.assertEqual(os.listdir(target.parent), [])


class EveryWriterGoesThroughIt(unittest.TestCase):
    def test_manifests_record_and_restore_use_the_atomic_helpers(self):
        scripts = REPO_ROOT / "scripts"
        for name, helper in (
            ("generate_pack.py", "write_text_atomic("),
            ("release_record.py", "write_text_atomic("),
            ("restore_large_files.py", "copy_file_atomic("),
        ):
            source = (scripts / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                self.assertIn(helper, source)
        pack = (scripts / "generate_pack.py").read_text(encoding="utf-8")
        self.assertNotIn('with open(path, "w") as f:\n        f.write(new_json)', pack)
        self.assertNotIn("json.dump(result, f", pack)
        self.assertNotIn("args.output.write_text(", (scripts / "release_record.py").read_text())
        self.assertNotIn("shutil.copy2(source, path)", (scripts / "restore_large_files.py").read_text())


    def test_scrapers_write_whole_files(self):
        """A streamed yaml.dump into platforms/<x>.yml let a concurrent reader
        parse a valid platform holding a fraction of its systems."""
        import re

        streamed = re.compile(
            r"open\([^)]*['\"](?:w|wb|a)['\"]|\.write_text\(|\.write_bytes\("
        )
        offenders = [
            f"{path.relative_to(REPO_ROOT)}:{number}"
            for path in sorted((REPO_ROOT / "scripts" / "scraper").rglob("*.py"))
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            )
            if streamed.search(line)
        ]
        self.assertEqual(offenders, [])

    def test_the_text_is_utf8_whatever_the_locale(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.yml"
            artifacts.write_text_atomic(str(target), "name: \u00e9mulateur \u2014 \u30d5\n")
            self.assertEqual(
                target.read_bytes().decode("utf-8"), "name: \u00e9mulateur \u2014 \u30d5\n"
            )

if __name__ == "__main__":
    unittest.main()
