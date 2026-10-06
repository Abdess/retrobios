"""A pack limited to some systems carries those systems' core extras.

With --platform and --system, the full source emptied the core extras, so
`--source full` and `--source platform` built the same pack under two
names; the split packs, built per system, carried them.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from generate_pack import _extras_for_systems  # noqa: E402


class SystemExtras(unittest.TestCase):
    def test_extras_follow_their_system(self):
        extras = [
            {"name": "a", "source_system": "sony-playstation"},
            {"name": "b", "source_system": "sega-saturn"},
            {"name": "c", "source_systems": ["sony-playstation", "sony-psp"]},
        ]
        picked = [e["name"] for e in _extras_for_systems(extras, ["sony-playstation"])]
        self.assertEqual(picked, ["a", "c"])

    def test_full_source_does_not_empty_them(self):
        source = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertNotIn('elif system_filter and source != "truth":\n          core_files = []', source)


if __name__ == "__main__":
    unittest.main()
