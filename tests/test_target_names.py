"""A hardware target names its artifacts by the name it is filed under.

`switch`, `nx` and `nintendo-switch` are one RetroArch target. The tag came
from the name as typed, so one target gave three pack and manifest names,
and `--verify-packs --target nx` looked for a pack nobody had built.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import canonical_target_name  # noqa: E402


class AliasesResolveToOneName(unittest.TestCase):
    def test_retroarch_switch_aliases(self):
        platforms = str(REPO_ROOT / "platforms")
        for typed in ("switch", "nx", "nintendo-switch"):
            with self.subTest(typed=typed):
                self.assertEqual(
                    canonical_target_name(["retroarch"], typed, platforms),
                    "nintendo-switch",
                )

    def test_an_unknown_name_is_left_for_the_target_check(self):
        self.assertEqual(
            canonical_target_name(["retroarch"], "bogus", str(REPO_ROOT / "platforms")),
            "bogus",
        )


class TheBuilderNamesByTheCanonicalTarget(unittest.TestCase):
    def test_an_alias_writes_the_canonical_manifest(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out:
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform", "retroarch",
                 "--target", "nx", "--manifest", "--offline", "--output-dir", out],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                sorted(p.name for p in Path(out).glob("*.json")),
                ["retroarch_nintendoswitch.json"],
            )


if __name__ == "__main__":
    unittest.main()
