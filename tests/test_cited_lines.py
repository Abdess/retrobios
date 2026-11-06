"""Citations corrected by hand land on the code they describe, at the pin.

Each row is a citation that once named a blank line one or two lines above
its target. Read from the upstream cache, offline, and skipped where the cache
does not hold the file.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import upstream  # noqa: E402
from safeparse import yaml_load  # noqa: E402

CACHE = ROOT / ".cache" / "upstream"

# (profile, cited path, cited line, text the line holds)
CITATIONS = [
    (
        "kenji-nx",
        "src/KenjinxAndroid/app/src/main/java/org/kenjinx/android/MainActivity.kt",
        295,
        "AppPath = this.getExternalFilesDir(null)!!.absolutePath",
    ),
]


class CitedLinesHoldTheirCode(unittest.TestCase):
    def test_each_citation_is_in_the_profile_and_on_its_code(self):
        for profile, path, line, text in CITATIONS:
            with self.subTest(profile=profile, path=path):
                raw = (ROOT / "emulators" / f"{profile}.yml").read_text(encoding="utf-8")
                cited = re.escape(path.rsplit("/", 1)[-1]) + rf":(?:[\d,-]+,)?{line}\b"
                self.assertRegex(raw, cited)
                document = yaml_load(raw)
                repo = upstream.parse_repo(str(document["source"]))
                try:
                    lines = upstream.fetch_file(
                        repo, str(document["source_commit"]), path, str(CACHE), True
                    )
                except upstream.NotCachedError:
                    self.skipTest(f"{path} is not in the upstream cache")
                self.assertIsNotNone(lines)
                self.assertIn(text, lines[line - 1])


if __name__ == "__main__":
    unittest.main()
