"""A system pack and verify --system name the same missing files.

The pack registered only loose files as occupants: a destination an earlier
profile's archive or data tree had filled was reported missing even when
the bytes were the same and in the ZIP, and an archive several profiles ask
for was counted once per profile. verify, in turn, never registered archives
or trees and credited a profile's file at a path holding another profile's.
`--system snk-neogeo-mvs` said 113 missing where verify said 51.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*argv: str) -> str:
    result = subprocess.run(
        [sys.executable, *argv], cwd=REPO_ROOT, capture_output=True, text=True,
        timeout=1800,
    )
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


class SystemPackMatchesVerify(unittest.TestCase):
    SYSTEMS = ("snk-neogeo-mvs", "msx")

    def setUp(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        self.out = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.out, True)

    def test_the_same_files_are_missing(self):
        for system in self.SYSTEMS:
            with self.subTest(system=system):
                packed = _run(
                    "scripts/generate_pack.py", "--system", system, "--offline",
                    "--output-dir", str(self.out / system),
                )
                report = json.loads(_run("scripts/verify.py", "--system", system, "--json"))
                # The rest of the line is the name: openMSX's ROM names hold
                # spaces ("Japanese MSX-Write (1986) (Ascii) (J).rom").
                pack_missing = sorted(re.findall(r"^  MISSING: (.+)$", packed, re.M))
                # One per destination, as the pack reports them. An entry the
                # collection cannot hold is counted apart on both sides.
                verify_missing = sorted({
                    (d["destination"], d["name"]) for d in report["details"]
                    if d["status"] == "missing" and not d.get("unsourceable")
                })
                verify_missing = sorted(name for _dest, name in verify_missing)
                # Both sides reported, so an empty list is a finding and not a
                # parse that matched nothing. Requiring missing files instead
                # would fail the day the collection fills them.
                # Data-tree members are counted apart in the summary
                # ("105 files packed, 3730 from data directories, 7 missing").
                summary = re.search(
                    r"(\d+) files packed(?:, \d+ from data directories)?, (\d+) missing",
                    packed,
                )
                self.assertIsNotNone(summary, packed[-500:])
                self.assertGreater(report["total_files"], 0)
                self.assertEqual(int(summary.group(2)), len(pack_missing))
                self.assertEqual(pack_missing, verify_missing)


if __name__ == "__main__":
    unittest.main()
