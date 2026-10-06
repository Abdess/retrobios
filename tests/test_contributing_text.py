"""CONTRIBUTING.md and the site's contributing page say the same thing.

Two generators wrote the page and drifted: four steps to add a platform in
the repository, five on the site, under two different titles.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_readme  # noqa: E402
import generate_site  # noqa: E402


def _normalized(text: str) -> str:
    text = re.sub(r"\]\([^)]*\)", "](link)", text)
    return "\n".join(text.splitlines()[1:]).replace("on this site", "on the documentation site")


class OneContributingText(unittest.TestCase):
    def test_repository_and_site_pages_match(self):
        self.assertEqual(
            _normalized(generate_readme.generate_contributing()),
            _normalized(generate_site.generate_contributing()),
        )



class CoverageReadsTheGivenProfiles(unittest.TestCase):
    """generate_site --emulators-dir changed the emulator pages but not the
    platform coverage, which read ./emulators whatever was given."""

    def test_the_directory_reaches_verify(self):
        from unittest import mock  # noqa: PLC0415

        seen: list[str] = []

        def fake_verify(config, db, emulators_dir, **_kwargs):
            seen.append(emulators_dir)
            return {"status_counts": {}, "total_files": 0, "undeclared_files": [], "details": []}

        with mock.patch.object(generate_readme, "verify_platform", fake_verify), \
                mock.patch.object(generate_readme, "load_emulator_profiles", return_value={}):
            generate_readme.compute_coverage(
                "retroarch", str(REPO_ROOT / "platforms"), {"files": {}}, emulators_dir="elsewhere"
            )
        self.assertEqual(seen, ["elsewhere"])

if __name__ == "__main__":
    unittest.main()
