"""Fixtures shared by the profile_sync test modules."""

from __future__ import annotations

import tests

from unittest import mock

from profiling.reports import (
    CitedSource,
    EntryReport,
    ProfileReport,
)
from profiling.anchoring import PartResult
from model.sourceref import RefPart
from core import upstream
from profiling import versionbasis


def _version_read_as_written(profile, cache_dir, offline, profiles=None, recompute=False):
    """bump_commit reads core_version again at the new pin. These fixtures
    have no forge behind them, so the version reads as written here:
    tests/test_version_basis.py holds the reading and the refusals."""
    stated = versionbasis.declared(profile, "")
    return [versionbasis.Reading("", "file", stated, stated, "fixture", versionbasis.MATCH)]


_VERSION_AS_WRITTEN = mock.patch.object(versionbasis, "check", _version_read_as_written)


def setUpModule():
    _VERSION_AS_WRITTEN.start()


def tearDownModule():
    _VERSION_AS_WRITTEN.stop()


def _sample_report():
    shifted = PartResult(RefPart("a.c", 2, 4), "SHIFTED", None, 10, 12, [])
    changed = PartResult(RefPart("b.c", 5, 5), "CHANGED", None, 7, 7, [])
    return ProfileReport(
        name="demo",
        repo="o/n",
        host="github.com",
        pin="pinsha0000",
        pin_origin="profiled_date 2026-03-29",
        head="headsha000",
        entries=[
            EntryReport("f0.bin", "a.c:2-4", "SHIFTED", [shifted]),
            EntryReport("f1.bin", "b.c:5", "CHANGED", [changed]),
        ],
        counts={"SHIFTED": 1, "CHANGED": 1},
        cited_sources=[
            CitedSource(path, _SAMPLE_REPO, "pinsha0000", "headsha000")
            for path in ("a.c", "b.c")
        ],
    )


_SAMPLE_REPO = upstream.parse_repo("https://github.com/o/n")


SAMPLE = '''emulator: Test
source: "https://github.com/o/n"
profiled_date: "2026-03-29"

notes: >
  A note mentioning profiled_date: "1999-01-01" inside prose.

files:
  - name: "a.bin"
    source_ref: "a.c:10-12"
  - name: "b.bin"
    source_ref: "b.c:5"
'''


PROSE_SAMPLE = '''emulator: Test
source: "https://github.com/o/n"
profiled_date: "2026-03-29"
source_commit: "pin"

notes: |
  The loader appends dc/ to the system directory (a.c:10) and reads
  both ranges (b.c:2,8-9) on boot.

files:
  - name: "a.bin"
    source_ref: "a.c:10-12"
'''
