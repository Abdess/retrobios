"""The sharing cards (Open Graph images): each page's title and tagline, rendered to PNG."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from core.paths import DB_FILE, PLATFORMS_DIR, REPO_ROOT
from core.text import series
from model.collection import group_by_manufacturer, manufacturer_slug
from model.composition import GAME_DATA_TOPS
from model.database import load_database
from model.platforms import load_platform_config
from model.registry import list_registered_platforms
from sitegen.diagrams import OG_SECTIONS, og_card_svg, wrap

OUT = REPO_ROOT / "docs_assets" / "og"
LOGO = REPO_ROOT / "docs_assets" / "brand" / "logo.svg"
PLATFORM_TAGLINE = "Which BIOS files it needs, and where each one goes"
# The tagline's box on the card: og_card_svg wraps it at this width and
# size, and three lines fit above the address.
TAGLINE_WIDTH, TAGLINE_SIZE, TAGLINE_LINES = 1000, 34, 3


def platform_cards() -> dict[str, tuple[str, str]]:
    """Each platform page's card, by its path under og/, with its title."""
    platforms = REPO_ROOT / PLATFORMS_DIR
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
        else:
            text = f"{lead} {series(listed)}"
        if len(wrap(text, TAGLINE_WIDTH, TAGLINE_SIZE)) <= TAGLINE_LINES:
            return text
    return f"{lead} {len(names)} sections"


def _manufacturer_lead(manufacturer: str) -> str:
    # Other holds one folder per emulator, a game publisher's page its
    # games' data: neither is a list of consoles.
    if manufacturer in GAME_DATA_TOPS:
        return "Game data for"
    return "Files kept for the emulators" if manufacturer == "Other" else "BIOS files for"


def system_cards() -> dict[str, tuple[str, str]]:
    """Each manufacturer page's card under og/systems/, titled with the
    manufacturer and listing its consoles. Read from the same grouping the
    system pages are written from."""
    manufacturers = group_by_manufacturer(load_database(str(REPO_ROOT / DB_FILE)))
    return {
        f"systems/{manufacturer_slug(manufacturer)}": (
            manufacturer, consoles_tagline(list(consoles), _manufacturer_lead(manufacturer)))
        for manufacturer, consoles in sorted(manufacturers.items())
    }


def card_titles(only: str | None) -> dict[str, tuple[str, str]]:
    """The page cards of the kind *only* names (every kind when None), by key."""
    titles: dict[str, tuple[str, str]] = {}
    if only in (None, "platforms"):
        titles.update(platform_cards())
    if only in (None, "systems"):
        titles.update(system_cards())
    return titles


def card_keys(only: str | None, titles: dict[str, tuple[str, str]]) -> list[str]:
    """The section cards, unless *only* names another kind, then the page cards."""
    return [*(OG_SECTIONS if only in (None, "sections") else []), *titles]


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


def render_cards(sync_playwright: Any, keys: list[str],
                 titles: dict[str, tuple[str, str]]) -> Iterator[Path]:
    """Each card's PNG as it is written under og/, drawn by a headless Chromium."""
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
            yield path
        browser.close()
