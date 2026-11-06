"""``verify.py --all`` lists the platforms of ``--platforms-dir``.

The list came from ``platforms/`` whatever the flag said, while each config
was read from the flag's directory: a platform absent from the copy crashed
the run, and one registered only in the copy was never checked.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class AllReadsTheGivenDirectory(unittest.TestCase):
    def test_only_the_directory_platforms(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            plat = Path(tmp)
            (plat / "_registry.yml").write_text(
                "platforms:\n  solo:\n    config: solo.yml\n"
            )
            (plat / "solo.yml").write_text(
                "platform: Solo\nverification_mode: existence\n"
                "base_destination: system\nsystems: {}\n"
            )
            run = subprocess.run(
                [sys.executable, "scripts/verify.py", "--all",
                 "--platforms-dir", str(plat), "--json"],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        self.assertEqual(list(json.loads(run.stdout)), ["solo"])


if __name__ == "__main__":
    unittest.main()
