"""A target scraper that cannot read its source writes nothing.

The EmuDeck, RetroPie and RetroArch scrapers turned a failed request (an
anonymous API quota, a moved buildbot directory) into an empty core list
and wrote the file anyway: a target vanished, or kept no cores, and the
packs built for it shrank without an error.
"""

from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.scraper.targets import (  # noqa: E402
    emudeck_targets_scraper,
    retroarch_targets_scraper,
    retropie_targets_scraper,
)


def _refuse(*_args, **_kwargs):
    raise urllib.error.HTTPError("https://api.github.com/x", 403, "rate limited", {}, None)


class FailedRequestsStopTheScrape(unittest.TestCase):
    def test_every_scraper_raises(self):
        for module in (
            emudeck_targets_scraper,
            retropie_targets_scraper,
            retroarch_targets_scraper,
        ):
            with self.subTest(scraper=module.__name__):
                with mock.patch.object(module.urllib.request, "urlopen", _refuse):
                    with self.assertRaises(RuntimeError):
                        module.Scraper().fetch_targets()

    def test_an_empty_listing_is_not_a_target(self):
        class _Empty:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"[]"

        for module in (emudeck_targets_scraper, retropie_targets_scraper):
            with self.subTest(scraper=module.__name__):
                with mock.patch.object(
                    module.urllib.request, "urlopen", lambda *a, **k: _Empty()
                ):
                    with self.assertRaises(RuntimeError):
                        module.Scraper().fetch_targets()


if __name__ == "__main__":
    unittest.main()
