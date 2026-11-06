#!/usr/bin/env python3
"""Render the sharing cards (Open Graph images) to PNG, once.

Each card is an SVG written by ``sitediagrams.og_card_svg`` from the
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
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from common import list_registered_platforms, load_platform_config  # noqa: E402
from sitediagrams import OG_SECTIONS, og_card_svg, wrap  # noqa: E402

OUT = ROOT / "docs_assets" / "og"
LOGO = ROOT / "docs_assets" / "brand" / "logo.svg"
PLATFORM_TAGLINE = "Which BIOS files it needs, and where each one goes"
# The tagline's box on the card: og_card_svg wraps it at this width and
# size, and three lines fit above the address.
TAGLINE_WIDTH, TAGLINE_SIZE, TAGLINE_LINES = 1000, 34, 3


def platform_cards() -> dict[str, tuple[str, str]]:
    """Each platform page's card, by its path under og/, with its title."""
    platforms = ROOT / "platforms"
    return {
        f"platforms/{name}": (load_platform_config(name, str(platforms))["platform"],
                              PLATFORM_TAGLINE)
        for name in list_registered_platforms(str(platforms))
    }


def consoles_tagline(consoles: list[str], lead: str = "BIOS files for") -> str:
    """"BIOS files for PlayStation, PlayStation 2 and 5 more": as many
    names as the card's three lines hold, the rest counted."""
    names = sorted(consoles, key=str.casefold)
    for shown in range(len(names), 0, -1):
        rest = len(names) - shown
        listed = names[:shown]
        if rest:
            text = f"{lead} {', '.join(listed)} and {rest} more"
        elif len(listed) > 1:
            text = f"{lead} {', '.join(listed[:-1])} and {listed[-1]}"
        else:
            text = f"{lead} {listed[0]}"
        if len(wrap(text, TAGLINE_WIDTH, TAGLINE_SIZE)) <= TAGLINE_LINES:
            return text
    return f"{lead} {len(names)} sections"


def system_cards() -> dict[str, tuple[str, str]]:
    """Each manufacturer page's card under og/systems/, titled with the
    manufacturer and listing its consoles. Read from the same grouping the
    system pages are written from."""
    from common import GAME_DATA_TOPS, load_database
    from generate_site import _group_by_manufacturer, _slug

    def lead(manufacturer: str) -> str:
        # Other holds one folder per emulator, a game publisher's page its
        # games' data: neither is a list of consoles.
        if manufacturer in GAME_DATA_TOPS:
            return "Game data for"
        return "Files kept for the emulators" if manufacturer == "Other" else "BIOS files for"

    manufacturers = _group_by_manufacturer(load_database(str(ROOT / "database.json")))
    return {
        f"systems/{_slug(manufacturer)}": (
            manufacturer, consoles_tagline(list(consoles), lead(manufacturer)))
        for manufacturer, consoles in sorted(manufacturers.items())
    }


def card_svg(key: str, logo: str, titles: dict[str, tuple[str, str]]) -> str:
    if key in OG_SECTIONS:
        return og_card_svg(key, logo)
    # A page card is a section card with the page's own title and tagline.
    # The tagline is a format string there: braces in a name stay text.
    title, tagline = titles[key]
    OG_SECTIONS[key] = (title, tagline.replace("{", "{{").replace("}", "}}"))
    try:
        return og_card_svg(key, logo)
    finally:
        del OG_SECTIONS[key]


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the sharing cards to PNG.",
                                     allow_abbrev=False)
    parser.add_argument("--only", choices=("sections", "platforms", "systems"),
                        help="render one kind of card (default: all)")
    args = parser.parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright with Chromium is needed: pip install playwright") from exc
    titles: dict[str, tuple[str, str]] = {}
    if args.only in (None, "platforms"):
        titles.update(platform_cards())
    if args.only in (None, "systems"):
        titles.update(system_cards())
    keys = [*(OG_SECTIONS if args.only in (None, "sections") else []), *titles]
    logo = LOGO.read_text(encoding="utf-8")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 630})
        for key in keys:
            page.set_content(
                '<html><body style="margin:0">' + card_svg(key, logo, titles) + "</body></html>"
            )
            path = OUT / f"{key}.png"
            path.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(path), clip={"x": 0, "y": 0, "width": 1200, "height": 630})
            print(path.relative_to(ROOT))
        browser.close()


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
