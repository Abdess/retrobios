"""What the install box of Get the files shows under each tab.

Two things per tab, both drawn from data:

- The steps that differ by system, opening a terminal and pasting the line,
  as a drawing: one card per step, a pictogram and a short caption, drawn
  with sitediagrams' primitives and shown as its SVG files, one per layout
  and theme (sitediagrams.pictures). The text steps above it
  (platforms/_guides.yml, terminals) are the one text source: the images
  are alt="", so the page reads the steps once. The files say the same in
  their title and desc, for one opened on its own. The pictograms are
  generic shapes (a menu, a search field, a window, keys, a mouse, the
  power symbol), no vendor's interface or logo.
- The installer demo recorded for that place (scripts/make_demo.py): the
  full-screen interface on a handheld under "On the device", the terminal
  recording under the others but Windows. No Windows recording is
  published (make_demo.py says why), and a curl line recorded in a Linux
  terminal under the PowerShell command would contradict it.
"""

from __future__ import annotations

from dataclasses import dataclass
from xml.sax.saxutils import escape

import sitemarkup as markup
from sitediagrams import (
    MONO_STYLE,
    NARROW,
    STROKE,
    TEXT_SIZE,
    WIDE,
    _badge,
    _badge_side,
    _line,
    _n,
    _rect,
    _text,
    diagram_files,
    pictures,
    svg_document,
    wrap,
)

KEY_SIZE = 11.5
ICON_H = 44.0


@dataclass(frozen=True)
class Step:
    """One card: a pictogram (*icon* and its *word*, the text it shows:
    keys joined by "+", the word typed in a search field) and a caption."""

    icon: str
    caption: str
    word: str = ""


STEPS: dict[str, tuple[str, tuple[Step, ...]]] = {
    "windows": ("Windows: open PowerShell and paste the line", (
        Step("menu", "Open the Start menu"),
        Step("search", "Type PowerShell and press Enter", "PowerShell"),
        Step("copy", "Click Copy, the button by the line"),
        Step("mouse", "Right-click in the window to paste"),
        Step("keys", "Press Enter", "Enter"),
    )),
    "macos": ("macOS: open Terminal and paste the line", (
        Step("keys", "Press Cmd+Space", "Cmd+Space"),
        Step("search", "Type Terminal and press Return", "Terminal"),
        Step("copy", "Click Copy, the button by the line"),
        Step("keys", "Press Cmd+V to paste", "Cmd+V"),
        Step("keys", "Press Return", "Return"),
    )),
    "linux": ("Linux: open a terminal and paste the line", (
        Step("keys", "Open a terminal, often Ctrl+Alt+T", "Ctrl+Alt+T"),
        Step("copy", "Click Copy, the button by the line"),
        Step("keys", "Press Ctrl+Shift+V to paste", "Ctrl+Shift+V"),
        Step("keys", "Press Enter", "Enter"),
    )),
    "steamdeck": ("Steam Deck: open Konsole and paste the line", (
        Step("power", "Hold power, pick Switch to Desktop"),
        Step("window", "Open Konsole"),
        Step("copy", "Click Copy, the button by the line"),
        Step("keys", "Press Ctrl+Shift+V to paste", "Ctrl+Shift+V"),
        Step("keys", "Press Enter", "Enter"),
    )),
}

# The recording each tab shows (docs_assets/demo/demo.json keys), "" for none.
TAB_DEMOS = {"device": "handheld", "windows": ""}
DEFAULT_DEMO = "default"


def demo_variant(tab: str) -> str:
    return TAB_DEMOS.get(tab, DEFAULT_DEMO)


def description(tab: str) -> str:
    """The steps in words: the desc of the SVG files."""
    return " ".join(f"{index}. {step.caption}." for index, step in
                    enumerate(STEPS[tab][1], start=1))


# Pictograms, drawn in a box *w* wide and ICON_H high from (x, y).


def _stroke(d: str, cls: str = "rb-d-line", width: float = 1.5) -> str:
    return f'<path d="{d}" fill="none" stroke="{STROKE}" stroke-width="{_n(width)}" class="{cls}"/>'


def _key_width(label: str) -> float:
    return max(20.0, len(label) * KEY_SIZE * 0.62 + 10)


def _keys(x: float, y: float, w: float, word: str) -> list[str]:
    labels = word.split("+")
    total = sum(_key_width(label) for label in labels) + 4 * (len(labels) - 1)
    left = x + (w - total) / 2
    out = []
    top = y + ICON_H / 2 - 12
    for label in labels:
        width = _key_width(label)
        out.append(_rect(left, top, width, 24, accent=True))
        out.append(
            f'<text x="{_n(left + width / 2)}" y="{_n(top + 16.5)}" font-size="{_n(KEY_SIZE)}" '
            f'text-anchor="middle" fill="currentColor" style="{MONO_STYLE}">{escape(label)}</text>')
        left += width + 4
    return out


def _menu(x: float, y: float, w: float) -> list[str]:
    cx, top = x + w / 2, y + 4
    out = [_rect(cx - 22, top, 44, 36)]
    out += [_stroke(f"M{_n(cx - 14)} {_n(top + 10 + 8 * i)} H{_n(cx + 14)}") for i in range(3)]
    return out


def _search(x: float, y: float, w: float, word: str) -> list[str]:
    width = min(w - 4, len(word) * KEY_SIZE * 0.62 + 34)
    left, top = x + (w - width) / 2, y + ICON_H / 2 - 12
    return [
        _rect(left, top, width, 24, accent=True),
        f'<circle cx="{_n(left + 11)}" cy="{_n(top + 11)}" r="5" fill="none" stroke="{STROKE}" '
        'stroke-width="1.5" class="rb-d-line"/>',
        _stroke(f"M{_n(left + 15)} {_n(top + 15)} L{_n(left + 19)} {_n(top + 19)}"),
        f'<text x="{_n(left + 25)}" y="{_n(top + 16.5)}" font-size="{_n(KEY_SIZE)}" '
        f'fill="currentColor" style="{MONO_STYLE}">{escape(word)}</text>',
    ]


def _window(x: float, y: float, w: float) -> list[str]:
    cx, top = x + w / 2, y + 2
    return [
        _rect(cx - 32, top, 64, 40),
        _stroke(f"M{_n(cx - 32)} {_n(top + 9)} H{_n(cx + 32)}"),
        f'<text x="{_n(cx - 24)}" y="{_n(top + 28)}" font-size="{_n(KEY_SIZE)}" '
        f'fill="currentColor" style="{MONO_STYLE}">&gt;_</text>',
    ]


def _copy(x: float, y: float, w: float) -> list[str]:
    cx, top = x + w / 2, y + 6
    return [_rect(cx - 12, top, 18, 24), _rect(cx - 6, top + 7, 18, 24, accent=True)]


def _mouse(x: float, y: float, w: float) -> list[str]:
    cx, top = x + w / 2, y + 2
    return [
        f'<rect x="{_n(cx - 13)}" y="{_n(top)}" width="26" height="40" rx="12" fill="none" '
        f'stroke="{STROKE}" stroke-width="1.5" class="rb-d-line"/>',
        # The right button, the one to press.
        f'<path d="M{_n(cx + 1)} {_n(top + 1)} A12 12 0 0 1 {_n(cx + 12)} {_n(top + 13)} '
        f'L{_n(cx + 1)} {_n(top + 13)} Z" fill="currentColor" class="rb-d-num"/>',
        _stroke(f"M{_n(cx)} {_n(top)} V{_n(top + 14)} M{_n(cx - 13)} {_n(top + 14)} "
                f"H{_n(cx + 13)}"),
    ]


def _power(x: float, y: float, w: float) -> list[str]:
    cx, cy = x + w / 2, y + ICON_H / 2 + 2
    return [
        _stroke(f"M{_n(cx - 9)} {_n(cy - 11)} A14 14 0 1 0 {_n(cx + 9)} {_n(cy - 11)}", width=2.5),
        _stroke(f"M{_n(cx)} {_n(cy - 18)} V{_n(cy - 2)}", width=2.5),
    ]


def _icon(step: Step, x: float, y: float, w: float) -> list[str]:
    if step.icon == "keys":
        return _keys(x, y, w, step.word)
    if step.icon == "search":
        return _search(x, y, w, step.word)
    return {"menu": _menu, "window": _window, "copy": _copy, "mouse": _mouse,
            "power": _power}[step.icon](x, y, w)


def _wide(steps: tuple[Step, ...]) -> tuple[float, float, list[str]]:
    """The cards in a row, joined by arrows."""
    gap = 14.0
    width = (WIDE - gap * (len(steps) - 1) - 2) / len(steps)
    captions = [wrap(step.caption, width - 12, TEXT_SIZE) for step in steps]
    height = 34 + ICON_H + 10 + max(len(lines) for lines in captions) * 18 + 8
    out: list[str] = []
    for index, (step, lines) in enumerate(zip(steps, captions)):
        x = 1 + index * (width + gap)
        out.append(_rect(x, 1, width, height))
        out += _badge(x + 8, 8, str(index + 1))
        out += _icon(step, x + 4, 30, width - 8)
        y = 30 + ICON_H + 24
        for line in lines:
            out.append(_text(x + width / 2, y, line, anchor="middle"))
            y += 18
        if index < len(steps) - 1:
            mid = 1 + height / 2
            out += _line([(x + width + 1, mid), (x + width + gap - 1, mid)])
    return WIDE, height + 2, out


def _narrow(steps: tuple[Step, ...]) -> tuple[float, float, list[str]]:
    """One card a row: number, pictogram, caption."""
    icon_w, row_gap = 112.0, 8.0
    text_x = 8 + _badge_side("9") + 6 + icon_w + 8
    out: list[str] = []
    y = 1.0
    for index, step in enumerate(steps):
        lines = wrap(step.caption, NARROW - text_x - 8, TEXT_SIZE)
        height = max(ICON_H + 12, len(lines) * 18 + 16)
        out.append(_rect(1, y, NARROW - 2, height))
        out += _badge(8, y + height / 2 - 10, str(index + 1))
        out += _icon(step, 8 + _badge_side("9") + 6, y + (height - ICON_H) / 2, icon_w)
        ty = y + height / 2 - (len(lines) - 1) * 9 + 5
        for line in lines:
            out.append(_text(text_x, ty, line))
            ty += 18
        y += height + row_gap
    return NARROW, y - row_gap + 1, out


def _svg(tab: str, layout: str) -> str:
    title, steps = STEPS[tab]
    width, height, body = (_wide if layout == "wide" else _narrow)(steps)
    return svg_document(width, height, title, description(tab), body, f"rb-steps-{tab}-{layout}")


def _layouts(tab: str) -> dict[str, str]:
    return {layout: _svg(tab, layout) for layout in ("wide", "narrow")}


def stem(tab: str) -> str:
    return f"steps-{tab}"


def steps_files() -> dict[str, str]:
    """Every tab's drawing files, by name under sitediagrams.DIAGRAM_DIR."""
    return {name: text for tab in STEPS for name, text in diagram_files(stem(tab), _layouts(tab)).items()}


def steps_figure(tab: str) -> list[str]:
    """The figure of a tab's steps, both layouts in both themes, or nothing
    for a tab with no drawing. The steps above it say its words."""
    if tab not in STEPS:
        return []
    return [f'<figure class="rb-figure rb-steps" {markup.search_exclude()}>',
            pictures(stem(tab), _layouts(tab)), "</figure>", ""]


def tab_demo(tab: str) -> list[str]:
    """The recording a tab shows, as generate_site writes the component."""
    from generate_site import install_demo  # noqa: PLC0415

    variant = demo_variant(tab)
    return install_demo(variant, tab) if variant else []


def install_box(tabs: tuple[str, ...]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """What terminal_tabs puts under each tab's steps and under its command."""
    return ({tab: steps_figure(tab) for tab in tabs},
            {tab: tab_demo(tab) for tab in tabs})
