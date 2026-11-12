"""The verify excerpt of wiki/reading-reports.md is written from a run: it
went stale with every file the collection gained."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_report_excerpt  # noqa: E402

RUN = [
    "RetroDECK: 9/10 OK, 1 untested [md5]",
    "  UNTESTED (required): a/x.bin: declared hash contradicted by the local file",
    "  UNTESTED (required): a/y.bin: declared hash contradicted by the local file",
    "  DISCREPANCY: a/z.rom: RetroDECK says OK but core says size mismatch",
    "    core [size]",
    "  DISCREPANCY: a/w.rom: another one",
    "    core [size]",
    "  Core files: 5 in pack, 0 required missing, 1 optional missing (--verbose lists them)",
    "  Game data: 2 in pack, 0 missing",
    "  Ground truth: 1/10 files have emulator validation (10%)",
    "    9 platform-only (no emulator profile)",
]


class TheExcerptIsTheRun(unittest.TestCase):
    def test_one_entry_of_each_shape_then_every_count(self):
        self.assertEqual(generate_report_excerpt.excerpt(RUN), [
            RUN[0], RUN[1], RUN[3], RUN[4], RUN[7], RUN[8], RUN[9], RUN[10]])

    def test_the_page_carries_the_block(self):
        text = generate_report_excerpt.PAGE.read_text(encoding="utf-8")
        self.assertIsNotNone(generate_report_excerpt.BLOCK.search(text))


if __name__ == "__main__":
    unittest.main()
