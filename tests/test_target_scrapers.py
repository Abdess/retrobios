"""A target scraper that cannot read its source writes nothing.

The EmuDeck, RetroPie and RetroArch scrapers turned a failed request (an
anonymous API quota, a moved buildbot directory) into an empty core list
and wrote the file anyway: a target vanished, or kept no cores, and the
packs built for it shrank without an error.
"""

from __future__ import annotations

import json
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
            with (
                self.subTest(scraper=module.__name__),
                mock.patch.object(module.urllib.request, "urlopen", _refuse),
                self.assertRaises(RuntimeError),
            ):
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
            with (
                self.subTest(scraper=module.__name__),
                mock.patch.object(module.urllib.request, "urlopen", lambda *_a, **_k: _Empty()),
                self.assertRaises(RuntimeError),
            ):
                module.Scraper().fetch_targets()



class RetroPieModuleFlags(unittest.TestCase):
    """The RetroPie target list read flags as requirements and libretro alone.

    sdl1 and sdl2 are build options, not hardware: read as requirements they
    removed dosbox, atari800 and linapple from every target, and with only
    scriptmodules/libretrocores listed, no standalone package (openmsx,
    xroar, amiberry) reached a targeted pack at all.
    """

    def test_flags_follow_rp_register_module(self):
        available = retropie_targets_scraper._is_available
        cases = {
            ("sdl1 !mali", "rpi4"): True,
            ("!all videocore", "rpi3"): True,
            ("!all videocore", "rpi4"): False,
            ("!armv6 !videocore !:\\$__gcc_version:-lt:9", "rpi3"): False,
            ("!armv6 !videocore !:\\$__gcc_version:-lt:9", "rpi4"): True,
            ("!all x86", "rpi4"): False,
            ("!all x86", "x86_64"): True,
            ("!all arm rpi3 rpi4 rpi5 x86", "rpi1"): True,
        }
        for (flags, platform), expected in cases.items():
            with self.subTest(flags=flags, platform=platform):
                self.assertIs(available(flags, platform), expected)

    def test_standalone_sections_are_listed_and_keep_their_id(self):
        listings = {
            "emulators": [{"name": "dosbox-staging.sh"}, {"name": "dosbox.sh"}],
            "libretrocores": [{"name": "lr-beetle-psx.sh"}, {"name": "lr-dosbox.sh"}],
            "ports": [{"name": "openbor.sh"}],
        }
        modules = {
            "emulators/dosbox-staging.sh": 'rp_module_id="dosbox-staging"\nrp_module_flags="sdl2"',
            "libretrocores/lr-beetle-psx.sh": 'rp_module_id="lr-beetle-psx"',
            "libretrocores/lr-dosbox.sh": 'rp_module_id="lr-dosbox"',
            "emulators/dosbox.sh": 'rp_module_id="dosbox"\nrp_module_flags="sdl1 !mali"',
            "ports/openbor.sh": 'rp_module_id="openbor"\nrp_module_flags="sdl1 !mali !x11"',
        }

        def fake_fetch(url, accept="text/plain"):
            section = url.rstrip("/").rsplit("/", 1)[-1]
            if section in listings:
                return json.dumps(listings[section])
            return modules[url.split("scriptmodules/", 1)[1]]

        with mock.patch.object(retropie_targets_scraper, "_fetch", fake_fetch):
            targets = retropie_targets_scraper.Scraper().fetch_targets()["targets"]
        self.assertEqual(
            targets["rpi4"]["cores"], ["beetle_psx", "dosbox", "dosbox-staging", "openbor"]
        )
        self.assertEqual(targets["x86_64"]["cores"], ["beetle_psx", "dosbox", "dosbox-staging"])


if __name__ == "__main__":
    unittest.main()
