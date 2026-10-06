"""The gap report reads the collection the way the resolver does.

Three ways it called held files missing, or a missing file held: system IDs
compared verbatim (sega-megacd against sega-mega-cd), no sha256 in the hash
fallback (rust_dos names its SC-55 ROMs by sha256 alone), and directory names
indexed as files (BasiliskII's required ROM read as held because cpcemu keeps
a directory called ROM).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from cross_reference import (  # noqa: E402
    _build_supplemental_index,
    cross_reference,
    entry_source,
)


def _index(**over) -> dict:
    base = {
        "by_name": {}, "by_name_lower": {}, "by_path_suffix": {}, "by_md5": {},
        "by_sha256": {}, "by_crc32": {}, "db_files": {}, "data_names": set(),
    }
    base.update(over)
    return base


class GapReportSources(unittest.TestCase):
    def test_a_sha256_alone_finds_the_file(self):
        entry = {"name": "wave1.bin", "sha256": "AB" * 32}
        self.assertEqual(entry_source(entry, _index(by_sha256={"ab" * 32: "s"})), "bios")

    def test_a_directory_does_not_stand_for_a_file(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            (Path(tmp) / "bios" / "cpcemu" / "ROM").mkdir(parents=True)
            names = _build_supplemental_index(str(Path(tmp) / "data"), str(Path(tmp) / "bios"))
        self.assertIsNone(entry_source({"name": "ROM"}, _index(data_names=names)))
        directory = {"name": "ROM", "type": "directory"}
        self.assertEqual(entry_source(directory, _index(data_names=names)), "data")

    def test_a_system_spelled_otherwise_is_still_declared(self):
        profiles = {"gpgx": {"emulator": "gpgx", "systems": ["sega-megacd"],
                             "files": [{"name": "bios_CD_U.bin"}]}}
        declared = {"megacd": {"bios_CD_U.bin"}}  # sega-mega-cd, normalized
        db = {"files": {}, "indexes": {}}
        report = cross_reference(profiles, declared, db)
        self.assertEqual(report["gpgx"]["gaps"], 0)


if __name__ == "__main__":
    unittest.main()
