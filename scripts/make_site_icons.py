#!/usr/bin/env python3
"""Write the project's mark: the site's icons and the repository's logos.

The mark is the chip of the project logo drawn as vector shapes: a body,
four pins per side and the pixel glyph on a 4 by 4 grid. Three variants:

- ``logo.svg``: white, the glyph cut out so the header colour shows through.
  It sits on the indigo header in both schemes.
- ``favicon.svg``: indigo chip with a cyan glyph, lighter in a dark browser.
- ``favicon-32.png`` and ``apple-touch-icon.png`` (180 px, opaque): the same
  shapes rasterised by a headless Chromium through Playwright, for browsers
  that take no SVG icon and for home-screen shortcuts.

The files land in ``website/assets/brand/``, which generate_site.py copies into
the site. The site build never runs this script.

The repository's own images come from the same shapes, in ``.github/assets/``:

- ``logo.svg`` and ``logo.png`` (256 px): the chip in colour, as the favicon.
- ``favicon.png`` (32 px).
- ``banner-light.svg`` and ``banner-dark.svg``: the mark and the name as the
  site header shows them, for the README in each scheme.
- ``social-preview.png`` (1280 by 640): the mark and the name in white on the
  sharing cards' indigo, uploaded by hand in the repository settings.

    python scripts/make_site_icons.py
"""

from __future__ import annotations

import argparse

from core.paths import REPO_ROOT
from sitegen.brand import write_brand
from sitegen.chromium import require_playwright


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.parse_args()
    sync_playwright = require_playwright()
    for path in write_brand(sync_playwright):
        print(path.relative_to(REPO_ROOT))


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
