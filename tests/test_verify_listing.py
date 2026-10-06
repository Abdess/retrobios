"""verify.py lists what generate_pack.py lists for the same request."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *argv], capture_output=True, text=True, cwd=REPO_ROOT, timeout=300
    )


class ListingsAgree(unittest.TestCase):
    def test_list_systems_honours_platform(self):
        verify = _run("scripts/verify.py", "--list-systems", "--platform", "bizhawk")
        pack = _run("scripts/generate_pack.py", "--list-systems", "--platform", "bizhawk")
        self.assertEqual(verify.returncode, 0)
        self.assertEqual(verify.stdout, pack.stdout)

    def test_listing_refuses_a_narrowing_flag(self):
        result = _run("scripts/verify.py", "--list-emulators", "--region", "us")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
