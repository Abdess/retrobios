"""The post-build check judges only the packs this run would name.

A MiSTer _Custom pack left in the directory by a --from-md5 run was
attached to misterfpga by substring and checked against the full list:
0/81, FAILED, exit code 1, for a run whose own pack was 81/81.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class FinalizeByExactName(unittest.TestCase):
    def test_a_custom_pack_is_not_judged_as_the_platform_pack(self):
        from generate_pack import verify_and_finalize_packs

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            with zipfile.ZipFile(Path(tmp) / "MiSTer_FPGA_Custom_BIOS_Pack.zip", "w") as zf:
                zf.writestr("README.txt", "custom")
            ok = verify_and_finalize_packs(tmp, {"files": {}, "indexes": {}})
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
