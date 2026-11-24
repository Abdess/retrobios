"""The help screen, and the view that picks which screen to draw."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from installer.outcome import _SHORT_DEFINITIONS
from installer.paths import shown_path
from installer.terminal import TUI_MIN_COLS, TUI_MIN_ROWS
from installer.text import _pad, cell_width, fit
from installer.tui_frame import (
    TUI_LONG_LIST,
    _ROW_VERBS,
    _armed_hint,
    _back_hint,
    _compose,
    _hint,
    _route_hint,
    _tap_hint,
    _text_lines,
)
from installer.tui_paint import _styled
from installer.tui_plan_view import _screen_definition
from installer.tui_routes import TUI_PAD_ROUTES, TUI_ROUTES
from installer.tui_rows import _CHECKLISTS, _PAGERS, tui_rows
from installer.tui_screens import _TUI_VIEWS, _only_match
from installer.tui_state import TUI_MAX_WIDTH

if TYPE_CHECKING:
    from installer.tui_state import TuiState


def _route_extras(state: TuiState) -> list[tuple[str, str]]:
    """What a route's own buttons do that no key of the table says."""
    if state.pad == "muxterm":
        return [("Select", "Keyboard on or off"), ("Menu", "Close the terminal")]
    if state.pad == "miyoo":
        return [("B", "Sends no key here")]
    return []


def _help_list_keys(state: TuiState, names: dict[str, str]) -> list[tuple[str, str]]:
    """The keys a screen's own list adds to the help: ticks, filters, order."""
    screen = state.screen
    keys: list[tuple[str, str]] = []
    if screen in ("systems", "cores"):
        keys.append(("a, n", "All, none"))
    elif screen in ("regions", "emulators"):
        keys.append(("n", "None"))
    if screen == "platforms":
        keys.append(("/", "Filter by setup or device name"))
    elif screen in _CHECKLISTS:
        keys.append(("/", "Filter"))
    if screen in ("platforms", *_CHECKLISTS) and state.filters.get(screen):
        keys.append((names["esc"], "Clear the filter"))
    if screen == "regions":
        keys.append(("Left/Right", "Move a region up or down the order"))
    if screen == "options":
        keys.append(("Left/Right", "Change a value"))
    if screen in ("plan", "systems", "confirm"):
        keys.append((names["options"], "Change"))
    if screen in ("plan", "confirm"):
        keys.append(("d", "Details"))
    elif screen == "result" and not tui_rows(state):
        keys.append((f"{names['options']}, d" if names["options"] else "d", "Details"))
    return keys


def _help_lines(state: TuiState) -> list[tuple[str, str]]:
    screen = state.screen
    names = {action: name or "" for action, name in
             TUI_ROUTES.get(state.pad, TUI_ROUTES["both"]).help.items()}
    # gptokeyb's kill: Start pressed first also chooses the row in focus.
    kill = ([(names["kill"], "Quit at once")]
            if state.pad in ("gptokeyb", "gptokeyb_muxterm") else [])
    if screen == "installing":
        return [(names["stop"], "Stop: what is done stays done"),
                *([(names["kill"], "Stop")] if names["kill"] else []),
                *_route_extras(state), *_help_key(state)]
    if state.editing:
        # Typing a filter: Space, a, n and q type there, and the help listed
        # them as ticks, all, none and quit.
        return [("Enter", "Done"), ("Esc", "Clear the filter"),
                ("Backspace", "Delete a character"), ("Ctrl-U", "Clear"), ("Ctrl-C", "Quit"),
                *_route_extras(state)]
    if screen == "path":
        return [(names["enter"], "Use this folder"), ("Backspace", "Delete a character"),
                ("Ctrl-U", "Clear"), (names["esc"], "Back"), ("Ctrl-C", "Quit"),
                *_route_extras(state)]
    keys = [(names["move"], "Move")]
    if len(tui_rows(state)) > TUI_LONG_LIST or screen in _PAGERS:
        keys += [*([(names["page"], "Page")] if names["page"] else []),
                 *([("Home/End, g/G", "First, last")] if state.pad in ("both", "keys")
                   else [])]
    primary = _primary(state) or _TUI_VIEWS[screen](state, 80, 24)[2][0]
    ok = names["ok"]
    if primary.startswith("A/"):
        # A bar that offers no A (Confirm while it counts) names none here.
        keys.append((ok, primary.split(" ", 1)[-1]))
    if screen in _CHECKLISTS:
        keys.append((names["tick"], "Tick, untick"))
    # How a tap acts, before what the list says elsewhere: last, it was the
    # line a 40x12 help cut.
    keys += _tap_help(state)
    keys += _help_list_keys(state, names)
    # The result's bar calls B Exit: the help called it Quit.
    back = "Exit" if screen == "result" else "Quit" if len(state.stack) == 1 else "Back"
    keys += [(names["back"], back), ("q, Ctrl-C", "Quit"), *kill, *_route_extras(state),
             *_help_key(state)]
    return keys


def _tap_help(state: TuiState) -> list[tuple[str, str]]:
    """How a tap acts on this screen, where the terminal reports clicks."""
    if not state.mouse:
        return []
    if state.screen in (*_CHECKLISTS, "regions"):
        # One rule for the three lists of ticks: A ticks, a tap as A.
        return [("Tap", "Tick or untick a row, as A")]
    if state.screen in _PAGERS and not tui_rows(state):
        return [("Tap", "A bottom line entry presses its key"),
                *([("Shift+drag", "Select text to copy")] if state.screen == "result"
                  and state.os_type != "android" and state.pad not in TUI_PAD_ROUTES
                  else [])]
    # Said at every size, 40x12 included: Install below waits for a second
    # tap, and the help is where a reader looks when nothing happened.
    armed = [row.action for row in tui_rows(state) if row.action in ("install", "addapp")]
    if state.screen == "plan" and "install" in armed:
        return [("Tap", "A row or Install: click or tap twice")]
    if state.screen == "result" and armed:
        return [("Tap", "A row or Put it on the card: tap twice")]
    return [("Tap", "A row: tap twice to open it")]


def _help_key(state: TuiState) -> list[tuple[str, str]]:
    """? and F1, named only where a keyboard may send them: no pad route
    maps a button to either."""
    return [("?, F1", "This help")] if state.pad in ("both", "keys") else []


def _primary(state: TuiState) -> str | None:
    """What A does on the row in focus, for the first entry of the bar."""
    rows = tui_rows(state)
    if not rows:
        return None
    row = rows[max(0, min(state.focus.get(state.screen, 0), len(rows) - 1))]
    verb = _ROW_VERBS.get(row.action)
    if row.action == "filter" and _only_match(state) is not None:
        verb = "Choose"
    if row.action == "zip" and state.browse_for == "pack":
        verb = "Use this pack"
    return f"A/Enter {verb}" if verb else None


def _view_help(state: TuiState, width: int, height: int) -> tuple:
    keys = _help_lines(state)
    column = min(22, max(cell_width(key) for key, _what in keys) + 2)

    def drawn(entries: list[tuple[str, str]]) -> list[str]:
        # Two spaces at least: a key as wide as the column touched its text
        # ("Select Keyboard on or off" on muxterm).
        lines = []
        for key, what in entries:
            if cell_width(key) > column - 2:
                lines.append(f"{key}  {what}")
                continue
            # Wrapped under its own column: wrapped by the screen, a long text
            # ran back to the left edge ("/ Filter (Esc clears)" at 40x12).
            words = textwrap.wrap(what, max(8, width - column)) or [""]
            lines.append(f"{_pad(key, column)}{words[0]}")
            lines += [" " * column + word for word in words[1:]]
        return lines

    extra = []
    if state.screen in ("setup", "plan", "browse", "folder") and state.dest is not None:
        extra = ["", f"BIOS folder: {shown_path(state.dest)}"]
    more = ["", state.status_more] if state.status_more else []
    # What the plan's kinds are: at 40 columns the plan has no room for the
    # sentence, and the game data row was a choice nothing explained
    # Said before the keys a list also says elsewhere.
    words = _screen_definition(state)
    defined = ["", *textwrap.wrap(words, width)] if words else []
    # Cut from its end at 40x12, the help lost Quit and This help with no
    # sign: what a list's keys also say elsewhere goes first.
    for spare in ("First, last", "All, none", "extra", "Filter by setup or device name",
                  "Filter", "Change", "Details", "This help", "gap", "definitions"):
        if (len(drawn(keys)) + len(extra) + len(defined)
                + len(_text_lines(more, width)) <= height):
            break
        if spare == "extra":
            extra = []
        elif spare == "gap":
            # The blank line before the definitions, before a definition
            # is shortened: the Tap line that says Install takes a second
            # tap is kept at every size.
            defined = defined[1:] if defined[:1] == [""] else defined
        elif spare == "definitions":
            # The short form at 40x12, whole: the long one was cut in the
            # middle of its second sentence.
            short = [brief for long_form, brief in _SHORT_DEFINITIONS if long_form in words]
            room = height - len(drawn(keys)) - len(extra) - len(_text_lines(more, width))
            # Still too long: a definition left out whole, never cut in a
            # sentence.
            while len(short) > 1 and len(textwrap.wrap(" ".join(short), width)) > room:
                short.pop()
            defined = textwrap.wrap(" ".join(short), width) if short else []
        else:
            keys = [entry for entry in keys if entry[1] != spare]
    return ("Keys", _compose(state, width, height, drawn(keys) + defined + extra + more, []),
            ("Any key or a tap closes this help" if state.mouse
             else "Any key closes this help",))


def tui_view(state: TuiState, cols: int, rows: int) -> list[str]:
    """The screen as rows lines of at most cols cells, from the state alone."""
    if cols < TUI_MIN_COLS or rows < TUI_MIN_ROWS:
        # How large, and how large it is now: "larger" alone left the
        # reader resizing by guess.
        lines: list[str] = [_styled("")] * rows
        said = [fit(text, cols) for text in (
            "Make the window larger:",
            f"{TUI_MIN_COLS}x{TUI_MIN_ROWS} or more, now {cols}x{rows}")][:rows]
        top = max(0, (rows - len(said)) // 2)
        for index, text in enumerate(said):
            lines[top + index] = _styled(" " * max(0, (cols - cell_width(text)) // 2) + text)
        return lines
    width = min(cols, TUI_MAX_WIDTH) - 2
    height = rows - 3
    view = _view_help if state.help else _TUI_VIEWS[state.screen]
    title, body, hint = view(state, width, height)
    primary = _primary(state) if not state.help and hint[0].startswith("A/Enter") else None
    if primary:
        hint = (primary, *hint[1:])
    if state.editing == state.screen and not state.help:
        # Typing: Space and ? go into the filter, so the bar names the two
        # keys that end it, not Tick and Help.
        hint = ("Enter Done", "Esc Clear")
    routed = _route_hint(state, _back_hint(state, hint), width)
    tapped = _tap_hint(state, routed)
    if (tapped != routed and "? Help" in _hint(width, *routed)
            and "? Help" not in _hint(width, *tapped)):
        # At 40 columns "/tap" pushed "? Help" off the bar: the help, which
        # says how a tap acts, keeps its entry.
        tapped = routed
    hint = _armed_hint(state, tapped, width)
    lines = [_styled(fit(f" RetroBIOS: {title}", cols), "head"), _styled("")]
    # A long line is drawn whole, the terminal folding it into the rows
    # after it (_text_lines): cut to the width, a copied path lost its end.
    for line in body[:height]:
        drawn = _styled(" " + line if line.style == "long" else fit(" " + line, cols),
                        line.style)
        drawn.mark = line.mark
        drawn.command = getattr(line, "command", False)
        lines.append(drawn)
    lines += [_styled("")] * (rows - 1 - len(lines))
    # Never the last cell of the screen: a terminal may scroll when it is written.
    bar = _styled(fit(" " + _hint(width, *hint), cols - 1), "hint")
    bar.mark = ("bar",)
    lines.append(bar)
    return lines
