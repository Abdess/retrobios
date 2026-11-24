"""The sharing cards (Open Graph images): each page's title and tagline, rendered to PNG."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from core.paths import DB_FILE, PLATFORMS_DIR, REPO_ROOT
from core.text import series
from model.collection import group_by_manufacturer
from model.manufacturers import manufacturer_slug
from model.composition import GAME_DATA_TOPS
from model.database import load_database
from model.platforms import load_platform_config
from model.registry import list_registered_platforms
from sitegen.diagrams import FONT, setups_named, wrap

OUT = REPO_ROOT / "website" / "assets" / "og"
LOGO = REPO_ROOT / "website" / "assets" / "brand" / "logo.svg"
PLATFORM_TAGLINE = "Which BIOS files it needs, and where each one goes"
# The tagline's box on the card: og_card_svg wraps it at this width and
# size, and three lines fit above the address.
TAGLINE_WIDTH, TAGLINE_SIZE, TAGLINE_LINES = 1000, 34, 3


# Sharing cards: one 1200x630 card per section of the site, rendered to PNG
# once by scripts/make_og_cards.py and committed under website/assets/og/.

OG_SECTIONS: dict[str, tuple[str, str]] = {
    "home": ("BIOS and firmware packs", "Checked file by file, for {frontends}"),
    "start": ("Start here", "What BIOS files are, and how to install them with one command"),
    "setup": ("Setups", "Where the files go on each device and frontend"),
    "explore": ("Systems and emulators", "Which files each console and emulator reads"),
    "reference": ("Reference", "Verification modes, gaps, provenance and the data API"),
    "contribute": ("Contribute", "Adding files, emulator profiles and platforms"),
}


def og_card_svg(section: str, mark_svg: str) -> str:
    """A sharing card. ``mark_svg`` is the site's white mark
    (website/assets/brand/logo.svg), drawn as the header draws it."""
    title, tagline = OG_SECTIONS[section]
    tagline = tagline.format(frontends=setups_named(["RetroArch", "Batocera", "EmuDeck"]))
    mark = mark_svg.strip().replace("<svg ", '<svg x="96" y="88" width="112" height="112" ', 1)
    body = [
        '<rect width="1200" height="630" fill="#2b2e5c"/>',
        '<rect x="0" y="606" width="1200" height="24" fill="#3b3f7a"/>',
        mark,
        '<text x="236" y="164" font-size="48" font-weight="700" fill="#ffffff">RetroBIOS</text>',
        f'<text x="96" y="330" font-size="72" font-weight="700" fill="#ffffff">{escape(title)}</text>',
    ]
    for index, line in enumerate(wrap(tagline, TAGLINE_WIDTH, TAGLINE_SIZE)):
        body.append(
            f'<text x="96" y="{400 + index * 46}" font-size="34" fill="#d4d6ee">{escape(line)}</text>'
        )
    body.append('<text x="96" y="556" font-size="28" fill="#aebcff">abdess.github.io/retrobios</text>')
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" '
        f'font-family="{FONT}">' + "".join(body) + "</svg>"
    )


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
    manufacturers = group_by_manufacturer(load_database(str(REPO_ROOT / DB_FILE))).sections
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
