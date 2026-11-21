#!/usr/bin/env python3
"""Render the sharing cards (Open Graph images) to PNG, once.

Each card is an SVG written by ``sitegen.diagrams.og_card_svg`` from the
registry, rasterised by a headless Chromium through Playwright, then
committed under ``docs_assets/og/``. The site build copies the PNG files and
never runs this script, so it adds nothing to the build's dependencies.
Run it again when a section's wording, the platform count, the list of
platforms or the consoles of a manufacturer change.

    python scripts/make_og_cards.py
    python scripts/make_og_cards.py --only platforms
    python scripts/make_og_cards.py --only systems

A platform page shares a card with its own name (``og/platforms/<id>.png``),
a manufacturer's systems page one with the manufacturer's name and its
consoles (``og/systems/<slug>.png``), the other pages their section's.
"""

from __future__ import annotations

import argparse

from core.paths import REPO_ROOT
from sitegen.chromium import require_playwright
from sitegen.ogcards import card_keys, card_titles, render_cards


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the sharing cards to PNG.",
                                     allow_abbrev=False)
    parser.add_argument("--only", choices=("sections", "platforms", "systems"),
                        help="render one kind of card (default: all)")
    args = parser.parse_args()
    sync_playwright = require_playwright()
    titles = card_titles(args.only)
    for path in render_cards(sync_playwright, card_keys(args.only, titles), titles):
        print(path.relative_to(REPO_ROOT))


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
