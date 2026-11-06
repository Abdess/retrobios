"""The post-build check judges only the packs this run would name.

A MiSTer _Custom pack left in the directory by a --from-md5 run was
attached to misterfpga by substring and checked against the full list:
0/81, FAILED, exit code 1, for a run whose own pack was 81/81.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from generate_pack import verify_and_finalize_packs  # noqa: E402


class FinalizeByExactName(unittest.TestCase):
    def test_a_custom_pack_is_not_judged_as_the_platform_pack(self):
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            with zipfile.ZipFile(Path(tmp) / "MiSTer_FPGA_Custom_BIOS_Pack.zip", "w") as zf:
                zf.writestr("README.txt", "custom")
            ok = verify_and_finalize_packs(tmp, {"files": {}, "indexes": {}})
        self.assertTrue(ok)


class APackFromAnotherRunIsLeftAlone(unittest.TestCase):
    """A one-platform build verified, recompressed and gave a new manifest to
    every pack in the directory: MiSTer's lost its pack_systems fields after a
    MinUI run, and a bizhawk run rewrote 52 GB of packs it never built."""

    def test_a_second_platform_does_not_rewrite_the_first(self):
        import json
        import subprocess

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            def build(platform: str) -> str:
                proc = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", "--platform", platform,
                     "--offline", "--output-dir", tmp],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout[-2000:] + proc.stderr[-2000:])
                return proc.stdout

            build("misterfpga")
            (first,) = Path(tmp).glob("MiSTer*_BIOS_Pack.zip")
            before = first.read_bytes()
            output = build("minui")
            self.assertNotIn(first.name, output)
            self.assertEqual(first.read_bytes(), before)
            with zipfile.ZipFile(first) as zf:
                manifest = json.loads(zf.read("manifest.json"))
            self.assertIn("install_list", manifest)


if __name__ == "__main__":
    unittest.main()
