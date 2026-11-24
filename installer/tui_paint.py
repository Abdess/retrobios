"""Screen lines: cut to width, styled, and painted with or without colour."""
from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from installer.paths import shown_path
from installer.terminal import COLOUR_ROLES, _apart, painted, status_spans
from installer.text import _char_width, _pad, cell_width, fit, screen_text
from installer.tui_routes import TUI_ROUTES

if TYPE_CHECKING:
    from installer.invocation import Invocation

# How a line is drawn without colour: the screen's title and a headline
# bold, the row in focus reversed, the bar and secondary text dim.
_STYLES = {"title": "\x1b[1m", "head": "\x1b[1m", "focus": "\x1b[7m", "dim": "\x1b[2m",
           "hint": "\x1b[2m"}
# The role each style is drawn in with colour (tui_paint).
_COLOUR_BASES = {"title": "strong", "head": "strong", "focus": "selected", "dim": "muted",
                 "hint": "muted", "refusal": "failure"}
# A count or a size on a headline: "4 files to download, 1.0 MB".
_KEY_NUMBER = re.compile(r"(?<![=\w.])\d[\d,.]*(?: (?:B|KB|MB|GB|TB)\b)?")
_PROGRESS_BAR = re.compile(r"^ *\[(#*)(-*)\]")
_FOLDER_LABEL = "BIOS folder: "


def ascii_text(text: str) -> str:
    """The text in ASCII, accents dropped (Edition) and any other character
    as one ? per cell it took, so the columns stay where they were."""
    if text.isascii():
        return text
    plain = "".join(char for char in unicodedata.normalize("NFKD", text)
                    if not unicodedata.combining(char))
    return "".join(char if char.isascii() else "?" * _char_width(char) for char in plain)


def middle(text: str, width: int) -> str:
    """A long path cut in its middle, its start and its last folders kept."""
    if cell_width(text) <= width:
        return text
    if width <= 3:
        return fit(text, width)
    room = width - 3
    tail = fit(text[::-1], room // 2)[::-1]
    return fit(text, room - cell_width(tail)) + "..." + tail


def _columns(left: str, right: str, width: int) -> str:
    """left, and right against the edge when both fit, else left alone."""
    room = width - cell_width(right) - 2
    if not right or room < 8:
        return fit(left, width)
    return _pad(fit(left, room), room) + "  " + right


# Said under a command a path of which was cut to fit (_command_wrap).
TUI_SHORTENED = "Shortened to fit this window."


class TuiLine(str):
    """A screen line and how it is drawn: "head" (the screen's title),
    "title", "focus", "dim", "hint" (the bar), "refusal" or plain.

    mark is what a click on the line reaches (tui_hits): ("row", index,
    (action, value)) for a row of the list, ("scroll", kind, rows) for the
    line saying which lines are in view, ("bar",) for the bar."""

    style = ""
    mark: tuple | None = None
    # A line of a command, however it was wrapped: the mouse is left to the
    # terminal on a frame showing one (tui_wants_mouse).
    command = False
    # Whether the command it holds is typed into PowerShell, from the
    # Invocation that made it: its line ends follow its words.
    powershell: bool | None = None
    # Shown on the Details screen, not on the screen it explains.
    detail = False
    # A count standing for Details lines: left out where they are shown.
    brief = False


def _styled(text: str, style: str = "") -> TuiLine:
    line = TuiLine(screen_text(text))
    line.style = style
    return line


def _detail(text: str, style: str = "") -> TuiLine:
    """A line of the Details screen: an explanation, a list, a reason."""
    line = _styled(text, style)
    line.detail = True
    return line


def _details(lines: Iterable[str]) -> list[TuiLine]:
    """lines as Details lines, each keeping how it is drawn."""
    marked = []
    for line in lines:
        copy = TuiLine(str(line))
        for name in ("style", "mark", "command", "powershell"):
            if hasattr(line, name):
                setattr(copy, name, getattr(line, name))
        copy.detail = True
        marked.append(copy)
    return marked


def _is_detail(line: object) -> bool:
    return bool(getattr(line, "detail", False))


def _command_line(text: str, hint: Invocation) -> TuiLine:
    """A line holding a command hint made, wrapped with hint's shell."""
    line = _styled(text, "command")
    line.powershell = hint.powershell()
    return line


def _bar_keys() -> set[str]:
    """Every name a key or a button takes on the bar, on every route."""
    keys = {"Enter", "Esc", "Space", "Start", "Select", "Ctrl-C", "?", "/", "X/Space/tap",
            "Space/tap"}
    for route in TUI_ROUTES.values():
        keys.update(route.bar)
        keys.update(name for name in route.bar.values() if name)
    keys.update(name.strip() for pair in _SHORT_KEYS for name in pair)
    keys.update(f"{route.help['page'] or 'PgUp/PgDn'}".split(", ")[0]
                for route in TUI_ROUTES.values())
    return keys


def _bar_spans(text: str, first: str) -> list[tuple[int, int, str]]:
    """The bar's key names faint, the first in first, its actions plain:
    drawn faint, Back and Quit were the hardest words to find on a
    handheld, B being its way back."""
    spans = []
    for number, entry in enumerate(re.finditer(r"\S+(?: \S+)*", text)):
        key = entry.group().split(" ", 1)[0]
        if entry.group().endswith(TUI_ARMED_SHORT):
            # Armed by a first tap: the whole entry stands out, a plain
            # ": tap again" looked like no change at all.
            spans.append((entry.start(), entry.end(), first))
        elif key in _bar_keys() and " " in entry.group():
            spans.append((entry.start(), entry.start() + len(key),
                          first if number == 0 else "muted"))
    return spans


def tui_paint(text: str, style: str, colour: bool) -> str:
    """A drawn line as the terminal gets it: its style, and with colour the
    roles of its words (COLOUR_ROLES). The characters are those of text.

    The title names RetroBIOS in the accent, a headline its counts and
    sizes, the bar the key it names first, a line its status words, the
    plan and the result the BIOS folder in bold.
    """
    if not colour:
        if style == "hint":
            return painted(text, _bar_spans(text, "strong"))
        return _STYLES.get(style, "") + text
    base = _COLOUR_BASES.get(style, "")
    if style == "folder":
        # The rest of a BIOS folder wrapped onto its own line, as bold as
        # its start.
        start = len(text) - len(text.lstrip(" "))
        return painted(text, [(start, len(text.rstrip(" ")), "strong")], base)
    if style not in ("", "head", "title", "hint", "refusal"):
        return painted(text, [], base)
    spans: list[tuple[int, int, str]] = []
    if style == "hint":
        return painted(text, _bar_spans(text, "accent"))
    if style == "head":
        at = text.find("RetroBIOS")
        if at >= 0:
            spans.append((at, at + len("RetroBIOS"), "accent"))
    if style == "title":
        spans += [(match.start(), match.end(), "accent")
                  for match in _KEY_NUMBER.finditer(text)]
    lead = text.lstrip(" ")
    if lead.startswith(_FOLDER_LABEL):
        start = len(text) - len(lead) + len(_FOLDER_LABEL)
        # The folder alone: on Options the bold ran on into --dest.
        end = text.find("  ", start)
        spans.append((start, len(text.rstrip(" ")) if end < 0 else end, "strong"))
    bar = _PROGRESS_BAR.match(text)
    if bar:
        spans += [(bar.start(1), bar.end(1), "accent"), (bar.start(2), bar.end(2), "muted")]
    # On a bold line a status word stays bold.
    spans += [(start, end, f"strong+{role}" if base == "strong"
               and not COLOUR_ROLES[role].startswith("1;") else role)
              for start, end, role in status_spans(text)]
    return painted(text, _apart(spans), base)


def _short_path(path: Path | None, home: Path) -> str:
    if path is None:
        return ""
    text = str(path)
    home_text = str(home)
    if home_text not in ("", "/", ".") and (text == home_text
                                           or text.startswith(home_text + os.sep)):
        return "~" + text[len(home_text):]
    return shown_path(text)


# What a check run tells the screen, kept whole when Choose systems widens a
# --system plan: Back with the same ticks gives that plan back.
_CHECK_FIELDS = ("check", "files", "systems", "choices", "set_aside", "found", "scanned",
                 "unreadable", "saves", "unplaced_why", "check_summary", "checked_flags", "cli_systems",
                 "facts", "ticked", "version", "board", "checked_dests", "games",
                 "games_unavailable")

TUI_ARMED_SHORT = "tap again"

# Shorter key names for a narrow bar: at 40 columns "X/Space Tick" was cut,
# and nothing said how to tick with a controller.
_SHORT_KEYS = (("A/Enter/tap ", "A/tap "), ("A/Enter ", "A "), ("B/Esc ", "B "),
               ("X/Space/tap ", "X/tap "),
               ("X/Space ", "X "), ("Y/o ", "Y "), ("Left/Right ", "<> "), ("Up/Down ", "^v "))
