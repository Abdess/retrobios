"""The verify excerpt of wiki/reading-reports.md is written from a run: it
went stale with every file the collection gained."""

from __future__ import annotations

import tests

import unittest

from sitegen import reportexcerpt

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
        self.assertEqual(reportexcerpt.excerpt(RUN), [
            RUN[0], RUN[1], RUN[3], RUN[4], RUN[7], RUN[8], RUN[9], RUN[10]])

    def test_the_page_carries_the_block(self):
        text = reportexcerpt.PAGE.read_text(encoding="utf-8")
        self.assertIsNotNone(reportexcerpt.BLOCK.search(text))


if __name__ == "__main__":
    unittest.main()
