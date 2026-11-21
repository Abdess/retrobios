#!/usr/bin/env python3
"""Download the platform logos and system icons the site shows, once.

The site served these from other hosts: GitHub avatars and files on the
``master`` branch of upstream repositories. A rename upstream broke an image
in silence, and every page view hit third-party hosts. This tool copies them
into ``docs_assets/logos/`` and ``docs_assets/system-icons/``, which are
committed, and records where each came from in a ``sources.json`` beside
them. The site build only reads those copies (``sitegen.diagrams.localize_images``).

Raster logos are normalised to an 80 px square WebP, twice the 40 px they
are shown at, and system icons to a 48 px PNG, so every tile has the same
weight. SVG is minified by svgo, and a raster an SVG embeds is cut to the
tile size.
Normalising needs Pillow. This is a maintenance tool run by hand when a
logo changes, not a build step: the build stays on the standard library
and PyYAML.

    python scripts/fetch_site_images.py              # logos and icons
    python scripts/fetch_site_images.py --only logos
"""

from __future__ import annotations

import argparse

from sitegen.imagefetch import fetch_icons, fetch_logos


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--only", choices=("logos", "icons"), help="fetch one kind only")
    args = parser.parse_args()
    if args.only in (None, "logos"):
        print("Platform logos:")
        for file_name, url in fetch_logos():
            print(f"  {file_name} from {url}")
    if args.only in (None, "icons"):
        print("System icons:")
        for file_name in fetch_icons():
            print(f"  {file_name}")


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
