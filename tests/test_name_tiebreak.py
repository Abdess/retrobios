"""Same-named candidates are ordered by the size the entry declares.

ScummVM declares MT32_PCM.ROM at 524288 bytes; the name step took the 1 MB
CM-32L PCM ROM that sorted first. Ordering rejects nothing, so a size
without `validation: [size]` keeps its informative status.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import _by_affinity  # noqa: E402


class DeclaredSizeOrders(unittest.TestCase):
    def test_the_fitting_size_comes_first(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            big = Path(tmp) / "a" / "pcm.rom"
            small = Path(tmp) / "b" / "pcm.rom"
            for path, size in ((big, 1024), (small, 512)):
                path.parent.mkdir()
                path.write_bytes(b"x" * size)
            ordered = _by_affinity([str(big), str(small)], {"size": 512}, "")
            self.assertEqual(ordered[0], str(small))
            kept = _by_affinity([str(big), str(small)], {}, "")
            self.assertEqual(kept, [str(big), str(small)])



class OwnerOutranksSharedTree(unittest.TestCase):
    def test_the_owners_copy_beats_two_matching_segments(self):
        """armsx2's fxaa.fx lost to NetherSX2's under shaders/common/."""
        from common import _by_affinity  # noqa: PLC0415

        paths = [
            "bios/Other/nethersx2/assets/shaders/common/fxaa.fx",
            "bios/Other/armsx2/fxaa.fx",
        ]
        ordered = _by_affinity(
            paths, {"name": "fxaa.fx", "source_profile": "armsx2"},
            "pcsx2/resources/shaders/common/fxaa.fx",
        )
        self.assertEqual(ordered[0], "bios/Other/armsx2/fxaa.fx")

if __name__ == "__main__":
    unittest.main()
