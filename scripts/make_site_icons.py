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

The files land in ``docs_assets/brand/``, which generate_site.py copies into
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

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs_assets" / "brand"
PROJECT = ROOT / ".github" / "assets"

HEADER = "#3b3f7a"
GLYPH = "#8be0f7"
GLYPH_DIM = "#4fa3c4"
# The site title: the light scheme's accent, the dark scheme's accent.
TITLE = {"light": "#273c8f", "dark": "#aebcff"}
# The mark beside it: the header logo in each scheme (website/src/assets).
MARK = {"light": HEADER, "dark": "#fff"}
# The sharing cards' background (sitediagrams.og_card_svg).
CARD = "#2b2e5c"
FONT = "system-ui, -apple-system, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif"

# (column, row, dim) on the 4 by 4 grid, read from the project logo.
PIXELS = [
    (0, 0, False), (1, 0, False), (2, 0, True),
    (1, 1, False), (3, 1, True),
    (0, 2, False), (3, 2, False),
    (1, 3, True), (2, 3, False), (3, 3, False),
]

BODY = (8, 8, 32, 4)  # x, y, size, corner radius in a 48 unit box
PIN_CENTRES = (13.5, 20.5, 27.5, 34.5)
PIN_WIDTH = 3.4
PIN_LENGTH = 5.5
CELL = 5.0
GAP = 1.6


def _pins(fill: str) -> str:
    half = PIN_WIDTH / 2
    rects = []
    for centre in PIN_CENTRES:
        start = centre - half
        rects += [
            (start, 8 - PIN_LENGTH, PIN_WIDTH, PIN_LENGTH),
            (start, 40, PIN_WIDTH, PIN_LENGTH),
            (8 - PIN_LENGTH, start, PIN_LENGTH, PIN_WIDTH),
            (40, start, PIN_LENGTH, PIN_WIDTH),
        ]
    return "".join(
        f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="0.8" fill="{fill}"/>'
        for x, y, w, h in rects
    )


def _glyph(bright: str, dim: str) -> str:
    span = 4 * CELL + 3 * GAP
    origin = BODY[0] + (BODY[2] - span) / 2
    return "".join(
        f'<rect x="{origin + c * (CELL + GAP):g}" y="{origin + r * (CELL + GAP):g}" '
        f'width="{CELL:g}" height="{CELL:g}" rx="0.6" fill="{dim if is_dim else bright}"/>'
        for c, r, is_dim in PIXELS
    )


def _body(fill: str, extra: str = "") -> str:
    x, y, size, radius = BODY
    return f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="{radius}" fill="{fill}"{extra}/>'


def _mark(fill: str) -> str:
    """The chip in one colour, glyph cut out so what is behind shows through."""
    return ('<mask id="glyph">' + _body("#fff") + _glyph("#000", "#5a5a5a") + "</mask>"
            + _pins(fill) + _body(fill, ' mask="url(#glyph)"'))


def logo_svg() -> str:
    """White chip, glyph cut out: the header colour shows through it."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" '
            'aria-label="RetroBIOS">' + _mark("#fff") + "</svg>")


def project_logo_svg() -> str:
    """The chip in colour, on any background."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" role="img" '
            'aria-label="RetroBIOS">' + _pins(HEADER) + _body(HEADER) + _glyph(GLYPH, GLYPH_DIM)
            + "</svg>")


def banner_svg(scheme: str) -> str:
    """The mark and the name as the site header sets them: system-ui at 600,
    the mark about twice the height of the capitals."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 64" role="img" '
            'aria-label="RetroBIOS"><g transform="scale(1.3333)">' + _mark(MARK[scheme]) + "</g>"
            f'<text x="76" y="44" fill="{TITLE[scheme]}" font-family="{FONT}" font-size="36" '
            'font-weight="600">RetroBIOS</text></svg>')


def social_preview_html() -> str:
    """The white mark and the name on the sharing cards' indigo, centred."""
    return (f'<html><body style="margin:0;width:1280px;height:640px;background:{CARD};'
            'display:flex;align-items:center;justify-content:center;gap:40px">'
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="208" height="208">'
            + _mark("#fff") + "</svg>"
            f'<span style="font-family:{FONT};font-size:128px;font-weight:600;color:#fff">'
            "RetroBIOS</span></body></html>")


def favicon_svg() -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
        "<style>.c{fill:" + HEADER + "}"
        "@media (prefers-color-scheme: dark){.c{fill:#8a8fd6}}</style>"
        + _pins(HEADER).replace(f'fill="{HEADER}"', 'class="c"')
        + _body(HEADER).replace(f'fill="{HEADER}"', 'class="c"')
        + _glyph(GLYPH, GLYPH_DIM) + "</svg>"
    )


def touch_icon_svg() -> str:
    """Opaque square: iOS fills transparency with black."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-6 -6 60 60">'
        f'<rect x="-6" y="-6" width="60" height="60" fill="{HEADER}"/>'
        + logo_svg().split(">", 1)[1].rsplit("</svg>", 1)[0] + "</svg>"
    )


def main() -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright with Chromium is needed: pip install playwright") from exc
    OUT.mkdir(parents=True, exist_ok=True)
    vectors = (
        (OUT / "logo.svg", logo_svg()), (OUT / "favicon.svg", favicon_svg()),
        (PROJECT / "logo.svg", project_logo_svg()),
        (PROJECT / "banner-light.svg", banner_svg("light")),
        (PROJECT / "banner-dark.svg", banner_svg("dark")),
    )
    for path, text in vectors:
        path.write_text(text + "\n", encoding="utf-8")
        print(path.relative_to(ROOT))
    favicon = favicon_svg().replace("@media (prefers-color-scheme: dark)", "@media not all")
    rasters = (
        (OUT / "favicon-32.png", 32, favicon),
        (OUT / "apple-touch-icon.png", 180, touch_icon_svg()),
        (PROJECT / "favicon.png", 32, favicon),
        (PROJECT / "logo.png", 256, project_logo_svg()),
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for path, size, text in rasters:
            page = browser.new_page(viewport={"width": size, "height": size})
            sized = text.replace("<svg ", f'<svg width="{size}" height="{size}" ', 1)
            page.set_content(f'<html><body style="margin:0;background:transparent">{sized}</body></html>')
            page.screenshot(path=str(path), omit_background=True, clip={"x": 0, "y": 0, "width": size, "height": size})
            page.close()
            print(path.relative_to(ROOT))
        page = browser.new_page(viewport={"width": 1280, "height": 640})
        page.set_content(social_preview_html())
        page.screenshot(path=str(PROJECT / "social-preview.png"),
                        clip={"x": 0, "y": 0, "width": 1280, "height": 640})
        print((PROJECT / "social-preview.png").relative_to(ROOT))
        browser.close()


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
