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


if __name__ == "__main__":
    unittest.main()
