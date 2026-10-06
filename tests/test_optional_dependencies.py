"""The suite runs with only the build dependencies installed.

jsonschema is needed by the schema validator and by CI, nowhere else. Six
tests imported it unguarded, so a contributor with stdlib and pyyaml saw
fifteen errors instead of skipped schema checks.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

HIDE_AND_RUN = """
import io
import sys
import unittest

sys.modules["jsonschema"] = None
names = sys.argv[1:]
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
for test, trace in result.errors + result.failures:
    print(test.id())
    print(trace.strip().splitlines()[-1])
sys.exit(0 if result.wasSuccessful() else 1)
"""


class SuiteWithoutJsonschema(unittest.TestCase):
    def test_every_module_skips_instead_of_erroring(self):
        names = sorted(
            f"tests.{path.stem}"
            for path in (REPO_ROOT / "tests").glob("test_*.py")
            if path.stem != Path(__file__).stem
            and any(
                token in path.read_text(encoding="utf-8")
                for token in ("jsonschema", "validate_schemas")
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", HIDE_AND_RUN, *names],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            text=True,
            timeout=600,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
