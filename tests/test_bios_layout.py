"""bios/ is laid out maker, then machine, then files.

QEMU kept 79 files and Roland four at the maker level, so neither had a
machine page. Chihiro was filed under Microsoft and Sega, and the Oric under
Oric and Tangerine: one machine, two folders, two pages.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Files the trees below them address at the maker level, left as they are.
MAKER_LEVEL = {
    "RPG Maker/wildmidi.cfg",
    "ScummVM/scummvm.zip",
}

# The machines filed under one maker only, and that maker.
ONE_MAKER = {"Chihiro": "Sega", "Oric": "Tangerine"}


def _tracked_and_ignored() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "bios"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return [line[len("bios/"):] for line in out.splitlines() if line.startswith("bios/")]


class MakerThenMachine(unittest.TestCase):
    def setUp(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("not a git checkout")
        self.paths = _tracked_and_ignored()
        if not self.paths:
            self.skipTest("bios/ not present")

    def test_no_file_sits_at_the_maker_level(self):
        loose = sorted(
            p for p in self.paths
            if p.count("/") == 1 and p not in MAKER_LEVEL
        )
        self.assertEqual(loose, [])

    def test_one_machine_has_one_maker(self):
        for machine, maker in ONE_MAKER.items():
            makers = sorted({
                p.split("/", 1)[0] for p in self.paths
                if p.count("/") >= 2 and p.split("/")[1] == machine
                and p.split("/", 1)[0] != "Other"
            })
            self.assertEqual(makers, [maker], machine)


if __name__ == "__main__":
    unittest.main()
