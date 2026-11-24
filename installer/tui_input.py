"""Keys, taps and the wheel turned into a new state, and what a click reaches on a frame."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple

from installer.host_fs import closed_folder
from installer.terminal import TUI_MIN_COLS, TUI_MIN_ROWS
from installer.text import cell_width
from installer.tui_actions import _activate, _checklist, _option, _tick, _toggle_region
from installer.tui_commands import _tui_standalone_fits
from installer.tui_folder_actions import _card_refusal, _choose_card, _closed_status, typed_path
from installer.tui_frame import _armed, _bar_click, _bar_commits, _pager_starts
from installer.tui_help import tui_view
from installer.tui_keys import TuiKey, TuiMouse
from installer.tui_rows import TUI_TICK_ROWS, _CHECKLISTS, _PAGERS, _first_item, tui_rows
from installer.tui_screens import _only_match, _pager_items
from installer.tui_state import TUI_MAX_WIDTH
from installer.tui_steps import _back, _open_details, _push, _start_run, tui_interrupt, tui_quit

if TYPE_CHECKING:
    from installer.tui_state import TuiRow, TuiState


def _move_region(state: TuiState, name: str, step: int) -> None:
    """Left and Right: the region's rank, its row staying where it is."""
    if name not in state.regions:
        return
    index = state.regions.index(name)
    target = max(0, min(len(state.regions) - 1, index + step))
    state.regions.insert(target, state.regions.pop(index))
    rows = tui_rows(state)
    state.focus["regions"] = next((i for i, row in enumerate(rows) if row.value == name), 0)


def _edit_text(text: str, key: TuiKey, selected: bool = False) -> str | None:
    """The field after a key, None when the key is not an edit. A selected
    text is replaced by what is typed or pasted, and cleared by Backspace."""
    if key.name in ("char", "paste"):
        return key.text if selected else text + key.text
    if key.name in ("backspace", "delete"):
        return "" if selected else text[:-1]
    if key.name == "ctrl-u":
        return ""
    return None


def _filter_key(state: TuiState, key: TuiKey) -> list[tuple]:
    """Typing in a list's filter. It never ticks or unticks anything, and
    focus never lands on All or None: the next A or X there undid a choice."""
    screen = state.screen
    edited = _edit_text(state.filters.get(screen, ""), key)
    rows = tui_rows(state)
    filter_row = next((i for i, row in enumerate(rows) if row.action == "filter"), 0)
    if edited is not None:
        state.filters[screen] = edited
        state.focus[screen] = filter_row
        return []
    if key.name == "esc":
        state.filters[screen] = ""
    state.editing = ""
    rows = tui_rows(state)
    only = _only_match(state)
    if key.name == "enter" and only is not None:
        return _activate(state, only)
    if key.name in ("enter", "down") and len(rows) > filter_row + 1:
        state.focus[screen] = filter_row + 1
    else:
        state.focus[screen] = filter_row
    return []


def _path_key(state: TuiState, key: TuiKey) -> list[tuple]:
    edited = _edit_text(state.path_text, key, state.path_selected)
    if edited is not None:
        state.path_text, state.path_selected = edited, False
        return []
    if key.name == "esc":
        return _back(state)
    if key.name == "enter":
        path = typed_path(state.path_text)
        if path is None:
            state.status = "Type a folder first."
            return []
        closed = closed_folder(path)
        if closed is not None:
            state.status = _closed_status(state, closed)
            return []
        if _card_refusal(state, path):
            return []
        state.stack.pop()
        return _choose_card(state, path)
    return []


def _page_step(state: TuiState) -> int:
    """The rows the current screen draws, measured on its view at the
    window's size: its intro wraps to more lines on a narrow window."""
    state.page_rows = 0
    tui_view(state, state.cols, state.rows)
    return state.page_rows or max(1, state.rows - 6)


def _pager_key(state: TuiState, key: TuiKey) -> list[tuple]:
    screen = state.screen
    top = state.focus.get(screen, 0)
    page = max(1, state.rows - 5)
    name, char = key.name, key.text if key.name == "char" else ""
    if name == "up" or char == "k":
        top -= 1
    elif name == "down" or char == "j":
        top += 1
    elif name == "pgup":
        top -= page
    elif name == "pgdn":
        top += page
    elif name == "home" or char == "g":
        top = 0
    elif name == "end" or char == "G":
        top = 1 << 30
    elif name in ("enter", "esc", "backspace") or char == " ":
        if screen == "result":
            return tui_quit(state)
        if screen == "details":
            # Never _back: a run counting under the plan goes on.
            state.stack.pop()
            return []
        return _back(state)
    state.focus[screen] = max(0, min(top, _pager_last(state, _pager_items(state))))
    return []


def _pager_last(state: TuiState, items: list) -> int:
    """The first line shown when the end of a pager is in view: the view's
    own height (tui_view), less the line that counts."""
    total = _pager_starts(state, items, min(state.cols, TUI_MAX_WIDTH) - 2)[-1]
    height = state.rows - 3
    return 0 if total <= height else max(0, total - max(1, height - 1))


def tui_update(state: TuiState, key: TuiKey | TuiMouse) -> list[tuple]:
    """What a key does on the current screen, and the work it starts. A
    choice that --standalone cannot sit beside turns it off, said once."""
    effects = _tui_key(state, key)
    if state.standalone and state.emulators and not _tui_standalone_fits(state):
        state.standalone = False
        state.status = TUI_STANDALONE_OFF
    return effects


# Said when a choice of regions, cores or systems turns Standalone off.
TUI_STANDALONE_OFF = ("Standalone version off: the build is installed whole, which "
                      "regions, cores and systems do not narrow.")


def _tui_pad_key(state: TuiState, key: TuiKey) -> TuiKey:
    """The key a handheld's buttons mean on this screen."""
    if state.pad == "miyoo":
        key = _miyoo_key(state, key)
    if (state.pad in _NO_PAGE_PADS and key.name in ("left", "right")
            and state.screen not in ("regions", "options")):
        # muxterm keeps PgUp and PgDn for its scrollback: the D-pad's Left
        # and Right page instead (X or Y still ticks). One system of 66 took
        # about 60 Down presses.
        key = TuiKey("pgup" if key.name == "left" else "pgdn")
    return key


def _tui_run_screen_key(state: TuiState, key: TuiKey, char: str) -> list[tuple]:
    """A key while a check or an install runs."""
    if state.screen == "checking":
        if char == "q":
            return tui_quit(state)
        return _back(state) if key.name in ("esc", "backspace") else []
    # B, Esc and q are the stops a controller or a plain keyboard has.
    if key.name in ("esc", "backspace") or char == "q":
        return tui_interrupt(state)
    return []


def _tui_focus_move(state: TuiState, key: TuiKey, char: str, rows: list[TuiRow],
                    focus: int, wrap: bool) -> tuple[int, list[TuiRow]] | None:
    """The focus a move takes the list to, and its rows, None for a key that
    moves nothing."""
    screen = state.screen
    last = len(rows) - 1
    page = _page_step(state) if key.name in ("pgup", "pgdn") else 1
    name = key.name
    if name == "up" or char == "k":
        return (last if wrap and focus == 0 else max(0, focus - 1)), rows
    if name == "down" or char == "j":
        return (0 if wrap and focus == last else min(last, focus + 1)), rows
    if name == "pgup":
        return max(0, focus - page), rows
    if name == "pgdn":
        return min(last, focus + page), rows
    if name == "home" or char == "g":
        return 0, rows
    if name == "end" or char == "G":
        return last, rows
    if name in ("esc", "backspace") and state.filters.get(screen):
        # The filter goes first, the screen with the second press, and the
        # row in focus stays in focus.
        row = rows[focus]
        state.filters[screen] = ""
        rows = tui_rows(state)
        return next((i for i, item in enumerate(rows)
                     if item.action == row.action and item.value == row.value), focus), rows
    return None


def _tui_list_action(state: TuiState, key: TuiKey, char: str, rows: list[TuiRow],
                     row: TuiRow) -> list[tuple] | None:
    """What a key does on a list of ticks or on the options, None for none."""
    screen, name = state.screen, key.name
    if screen == "regions" and char == " " and row.action == "region":
        return _activate(state, row)
    if screen == "regions" and name in ("left", "shift-up", "right", "shift-down"):
        _move_region(state, str(row.value), -1 if name in ("left", "shift-up") else 1)
        return []
    if screen in _CHECKLISTS and row.action in ("system", "core", "emulator") and (
            char == " " or name in ("right", "left")):
        _tick(state, row, None if char == " " else name == "right")
        return []
    if screen in (*_CHECKLISTS, "regions") and char == " ":
        # X on All, None, Done or the filter: only A, an explicit choice,
        # acts there.
        return []
    if screen in (*_CHECKLISTS, "regions") and char in ("a", "n"):
        # All and None by name, at the end of a list of 189 rows.
        named = [item for item in rows if item.action == ("all" if char == "a" else "none")]
        return _checklist(state, named[0]) if named else []
    if screen == "options" and name in ("left", "right"):
        return _option(state, row.action, 1 if name == "right" else -1) \
            if row.action in ("game_data", "installed", "jobs", "addapp", "offline") \
            or (row.action == "from" and name == "left") else []
    return None


def _tui_row_action(state: TuiState, key: TuiKey, char: str, rows: list[TuiRow],
                    row: TuiRow) -> list[tuple] | None:
    """What a key that moves no focus does on a list, None for nothing."""
    screen, name = state.screen, key.name
    if name in ("esc", "backspace"):
        return tui_quit(state) if screen == "result" else _back(state)
    if (name == "tab" or char == "o") and screen in ("plan", "systems", "confirm"):
        _push(state, "options")
        state.focus["options"] = _first_item(state)
        return []
    if char == "/" and any(item.action == "filter" for item in rows):
        # The focus goes to the field typed into: it stayed on None, and the
        # bar named None's keys while letters went into the filter.
        state.editing = screen
        state.focus[screen] = next(i for i, item in enumerate(rows) if item.action == "filter")
        return []
    listed = _tui_list_action(state, key, char, rows, row)
    if listed is not None:
        return listed
    if char == " ":
        return _space(state, row)
    if name == "enter":
        return _activate(state, row)
    return None


def _tui_past_heading(state: TuiState, key: TuiKey, char: str, rows: list[TuiRow],
                      focus: int, last: int, wrap: bool) -> int:
    """The row a move lands on instead of a heading."""
    name = key.name
    # A heading names the rows under it and is never in focus: the
    # move goes on to the next row its way, else stays where it was.
    step = -1 if name in ("up", "pgup", "end") or char in ("k", "G") else 1
    moved = name in ("up", "down") or char in ("k", "j")
    if not moved and focus in (0, last):
        # A page or Home clamped to an end: the first row from that end.
        step = 1 if focus == 0 else -1
    order = list(range(focus, -1, -1) if step < 0 else range(focus, len(rows)))
    if wrap and moved:
        order += range(last, focus, -1) if step < 0 else range(focus)
    return next((index for index in order if rows[index].action != "heading"),
                max(0, min(state.focus.get(state.screen, 0), last)))


def _tui_row_key(state: TuiState, key: TuiKey, char: str, rows: list[TuiRow]) -> list[tuple]:
    """A key on a screen that lists rows."""
    screen = state.screen
    focus = max(0, min(state.focus.get(screen, 0), len(rows) - 1))
    row = rows[focus]
    last = len(rows) - 1
    # A list of ticks wraps at any length: None and Done, at its end, are
    # a few presses up from its first item on a pad.
    wrap = len(rows) < 10 or screen in (*_CHECKLISTS, "regions")
    moved = _tui_focus_move(state, key, char, rows, focus, wrap)
    if moved is None:
        acted = _tui_row_action(state, key, char, rows, row)
        if acted is not None:
            return acted
    else:
        focus, rows = moved
    if rows[focus].action == "heading":
        focus = _tui_past_heading(state, key, char, rows, focus, last, wrap)
    state.focus[screen] = focus
    return []


def _tui_screen_key(state: TuiState, key: TuiKey) -> list[tuple]:
    """A key on the current screen, once no field takes it."""
    screen = state.screen
    char = key.text if key.name == "char" else ""
    if key.name == "f1" or char == "?":
        state.help = True
        return []
    if screen in ("checking", "installing"):
        return _tui_run_screen_key(state, key, char)
    if char == "q":
        return tui_quit(state)
    rows = tui_rows(state)
    if screen == "error" and key.name in ("pgup", "pgdn"):
        # The message scrolls, the rows stay (_view_error).
        step = max(1, state.rows - len(rows) - 5)
        state.focus["error_text"] = max(0, state.focus.get("error_text", 0)
                                        + (step if key.name == "pgdn" else -step))
        return []
    if (char == "d" and screen in ("plan", "confirm", "result") and not (
            screen == "confirm" and (state.running or state.dry is None))) or (
            screen == "result" and not rows and (char == "o" or key.name == "tab")):
        return _open_details(state)
    if screen in _PAGERS and not rows:
        return _pager_key(state, key)
    if not rows:
        return _back(state) if key.name in ("esc", "backspace") else []
    return _tui_row_key(state, key, char, rows)


def _tui_key(state: TuiState, key: TuiKey | TuiMouse) -> list[tuple]:
    """tui_update for one key."""
    if isinstance(key, TuiMouse):
        return tui_mouse(state, key)
    # A key moves the focus its own way: the next tap focuses again.
    state.tapped = None
    if key.name in ("ctrl-c", "ctrl-d"):
        return tui_interrupt(state)
    if state.cols < TUI_MIN_COLS or state.rows < TUI_MIN_ROWS:
        return []
    if state.help:
        state.help = False
        return []
    if state.app_running:
        # The app is being written to the card: it finishes first.
        return []
    if state.screen == "path" and key.name == "f1":
        # ? is typed into the path there: F1 opens the help, which says the
        # refusal in full. "? says more" could not be followed on this screen.
        state.help = True
        return []
    if not (key.name == "f1" or (key.name == "char" and key.text == "?")
            and state.screen != "path"):
        # The help says it in full: the status is the short form.
        state.status_more = ""
    state.status = ""
    if state.screen == "path":
        return _path_key(state, key)
    if state.editing and key.name == "f1":
        # ? is typed into the filter, F1 opens the help: it ended the typing
        # and opened nothing. The typing goes on once the help closes.
        state.help = True
        return []
    if state.editing:
        return _filter_key(state, key)
    return _tui_screen_key(state, _tui_pad_key(state, key))


# Lines one notch of the wheel moves.
TUI_WHEEL_LINES = 3

# Seconds after a screen is drawn during which a press is taken for the
# second tap of a double tap made on the screen before, and dropped. A
# double click is two presses at most 400 ms (GTK, GNOME) to 500 ms
# (Windows, macOS) apart, and the new screen is drawn on the first release,
# about 100 ms after the first press: 0.4 s after the draw covers both. A
# deliberate tap comes later, a reader taking longer than that to find it.
TUI_TAP_SETTLE = 0.4


def _tui_tap_done(state: TuiState, event: TuiMouse, hits: TuiHits, target: tuple | None) -> bool:
    """Whether event ends a tap made on target, a press kept for its release."""
    button = event.button & 3
    # A tap is a press and a release on one target of one frame: a release
    # on a frame drawn after its press is dropped, and so is a press within
    # TUI_TAP_SETTLE of a new screen, so the second tap of a double tap that
    # changed the screen does nothing on the new one.
    seen_on = (hits.frame, state.screen, len(state.stack), state.help, target)
    if not event.release:
        settled = state.now - hits.shown >= TUI_TAP_SETTLE
        state.pressed = seen_on if button == 0 and settled else None
        return False
    pressed, state.pressed = state.pressed, None
    if button not in (0, 3) or pressed != seen_on:
        return False
    if state.help:
        # Any key closes the help, a tap too.
        state.help = False
        return False
    return True


def _tui_tap_row(state: TuiState, target: tuple) -> list[tuple]:
    """A tap on a row of the list."""
    rows = tui_rows(state)
    index = target[1]
    if index >= len(rows) or (rows[index].action, rows[index].value) != target[2]:
        return []
    screen = state.screen
    row = rows[index]
    seen = (screen, len(state.stack), row.action, row.value)
    if row.action == "heading":
        return []
    if state.editing:
        state.editing = ""
    elif row.action in TUI_TICK_ROWS:
        state.status = state.status_more = ""
        state.focus[screen] = index
        state.tapped = seen
        if screen == "regions":
            _toggle_region(state, row.value)
        else:
            _tick(state, row, None)
        return []
    elif (max(0, min(state.focus.get(screen, 0), len(rows) - 1)) == index
          and (state.tapped == seen or _armed(state) is not None)):
        # A second tap, on the row or on the bar entry that armed it.
        state.tapped = None
        return tui_update(state, TuiKey("enter"))
    state.status = state.status_more = ""
    state.focus[screen] = index
    state.tapped = seen
    return []


def tui_mouse(state: TuiState, event: TuiMouse) -> list[tuple]:
    """What a click, a tap or the wheel does, read against the frame on
    screen when it came (state.hits): a frame drawn for another screen, or
    a row no longer where it was drawn, does nothing.

    A tap acts when the button goes up, on the target it went down on: a
    swipe that ends elsewhere does nothing. What it does follows the row's
    kind. A tick (a system, a core, a region) is ticked or unticked, as
    Space does: a tap that unticks a box elsewhere continued here, and the
    next one installed every file. A choice is focused, and opened by a
    second tap on the row this screen saw tapped: one terminal row is far
    smaller than a finger, and the row a screen opens on (Install on
    Confirm) is never chosen by one tap. On a bar entry it presses that
    entry's key. The right and middle buttons do nothing, nor a click with
    Shift, Meta or Ctrl held, which the terminal keeps for its own
    selection and links.
    """
    hits = state.hits
    if (event.button & 32 or hits is None or hits.screen != state.screen
            or hits.help != state.help or hits.size != (state.cols, state.rows)
            or hits.depth != len(state.stack)
            or state.cols < TUI_MIN_COLS or state.rows < TUI_MIN_ROWS or state.app_running):
        state.pressed = None
        return []
    target = hits.at(event.col - 1, event.row - 1)
    if event.button & 64:
        if event.release or event.button & 3 > 1 or state.help:
            return []
        return _wheel(state, hits, 1 if event.button & 1 else -1)
    if event.button & 28:
        state.pressed = None
        return []
    if not _tui_tap_done(state, event, hits, target) or target is None:
        return []
    if target[0] == "key":
        return _bar_tap(state, target[1])
    if target[0] == "scroll":
        return _scroll_tap(state, target[1])
    return _tui_tap_row(state, target)


def _bar_tap(state: TuiState, key: TuiKey) -> list[tuple]:
    """A tap on a bar entry. One that writes files (_bar_commits) is drawn
    armed by the first tap and pressed by the second on the same screen,
    on the bar or on the row it acts on."""
    if key.name == "ctrl-c":
        if state.run == "install" and state.running:
            return tui_interrupt(state)
        # A quit chosen with a finger is a quit chosen: QUIT_CODE, never
        # the code of an interrupted run.
        return tui_quit(state)
    if not _bar_commits(state, key):
        return tui_update(state, key)
    if _armed(state) != key:
        state.tapped = ("bar", state.screen, len(state.stack), key)
        return []
    state.tapped = None
    return tui_update(state, key)


def _wheel(state: TuiState, hits: TuiHits, step: int) -> list[tuple]:
    """A notch of the wheel: the list, the message or the text moves, and
    the focus moves only when it would leave the rows in view."""
    screen = state.screen
    lines = step * TUI_WHEEL_LINES
    if hits.listing is not None:
        first, shown, total = hits.listing
        top = max(0, min(first + lines, total - shown))
        state.list_top[screen] = top
        rows = tui_rows(state)
        focus = max(0, min(state.focus.get(screen, 0), len(rows) - 1))
        focus = max(top, min(focus, top + shown - 1))
        if rows and rows[focus].action == "heading":
            # Never on a heading: the row under it, else the one above.
            below = focus + 1 < min(len(rows), top + shown)
            focus = focus + 1 if below or focus == 0 else focus - 1
        state.focus[screen] = focus
    elif hits.scroll == "error":
        state.focus["error_text"] = max(0, state.focus.get("error_text", 0) + lines)
    elif hits.scroll == "pager":
        last = _pager_last(state, _pager_items(state))
        state.focus[screen] = max(0, min(state.focus.get(screen, 0) + lines, last))
    return []


def _scroll_tap(state: TuiState, kind: str) -> list[tuple]:
    """A tap on the line saying which lines are in view: the next page,
    and from the last one the first."""
    before = (dict(state.focus), dict(state.list_top))
    effects = tui_update(state, TuiKey("pgdn"))
    # The view keeps a scroll inside the text: measured, not guessed.
    tui_view(state, state.cols, state.rows)
    if (dict(state.focus), dict(state.list_top)) != before:
        return effects
    if kind == "error":
        state.focus["error_text"] = 0
        return effects
    return effects + tui_update(state, TuiKey("home"))


# The routes inside muxterm, where no button sends PgUp or PgDn.
_NO_PAGE_PADS = ("muxterm", "gptokeyb_muxterm")


# A Miyoo's L1 and R1 are the keys E and T (codes 18 and 20).
_MIYOO_PAGES = {"e": "pgup", "t": "pgdn"}


def _miyoo_key(state: TuiState, key: TuiKey) -> TuiKey:
    """A Miyoo's buttons as the keys they stand for, outside a text field:
    its A is Space, the button that chooses, so it acts as Enter but where
    it ticks a system or a core."""
    if key.name != "char":
        return key
    if key.text in _MIYOO_PAGES:
        return TuiKey(_MIYOO_PAGES[key.text])
    if key.text != " ":
        return key
    if state.screen in _CHECKLISTS:
        rows = tui_rows(state)
        row = rows[max(0, min(state.focus.get(state.screen, 0), len(rows) - 1))] \
            if rows else None
        if row is not None and row.action in ("system", "core"):
            return key
    return TuiKey("enter")


# Rows Space leaves alone: it is X (tick) on PortMaster and Y on muxterm, a
# key pressed for something else, and these end the run or write.
_SPACE_INERT = ("install", "close", "quit", "exit", "addapp")


def _space(state: TuiState, row: TuiRow) -> list[tuple]:
    """Space opens what a row leads to, and never installs by itself: on
    the plan's Install it opens the confirm screen, where A installs."""
    if row.action == "install" and state.screen == "plan":
        if state.systems and not state.ticked:
            state.status = "No system is ticked: tick one, or choose All."
            return []
        state.must_confirm = True
        _push(state, "confirm")
        return _start_run(state, "confirm")
    if row.action in _SPACE_INERT:
        return []
    return _activate(state, row)


class TuiHits(NamedTuple):
    """What a click reaches on one drawn frame (tui_hits): each target is
    (line, first column, column past the last, what it does), lines and
    columns counted from 0. listing is (first row shown, rows shown, rows)
    for a list taller than its room, scroll "pager" or "error" for a text
    that scrolls."""

    screen: str
    help: bool
    size: tuple[int, int]
    targets: tuple
    listing: tuple | None = None
    scroll: str = ""
    # How many screens deep the frame was drawn, and its number: a frame
    # whose targets differ from the one before it is another frame.
    depth: int = 0
    frame: int = 0
    # When this screen was first drawn (state.now): a press sooner than
    # TUI_TAP_SETTLE after it belongs to a tap made on the screen before.
    shown: float = 0.0

    def at(self, col: int, line: int) -> tuple | None:
        return next((target for row, first, end, target in self.targets
                     if row == line and first <= col < end), None)


_BAR_ENTRY = re.compile(r"\S+(?: \S+)*")


def tui_hits(state: TuiState, lines: list[str]) -> TuiHits:
    """The targets of the frame tui_view drew: a row of the list across
    the whole width, its text or not, each entry of the bar that names a
    key, and the line saying which lines are in view."""
    cols = max([state.cols, *(cell_width(str(line)) for line in lines)])
    targets: list[tuple] = []
    shown: list[int] = []
    listed = None
    scroll = ""
    for number, line in enumerate(lines):
        mark = getattr(line, "mark", None)
        if not mark:
            continue
        if mark[0] == "row":
            targets.append((number, 0, cols, mark))
            shown.append(mark[1])
        elif mark[0] == "scroll":
            targets.append((number, 0, cols, mark))
            if mark[1] == "list":
                listed = mark[2]
            else:
                scroll = mark[1]
        elif mark[0] == "bar" and not state.help:
            for entry in _BAR_ENTRY.finditer(str(line)):
                key = _bar_click(state, entry.group().split(" ", 1)[0])
                if key is not None:
                    targets.append((number, entry.start(), entry.end(), ("key", key)))
    rows = (min(shown), len(shown), listed) if listed is not None and shown else None
    hits = TuiHits(state.screen, state.help, (state.cols, state.rows), tuple(targets),
                   rows, scroll, len(state.stack))
    before = state.hits
    if before is None:
        return hits._replace(frame=0, shown=state.now)
    same = before[:7] == hits[:7]
    # Another screen, its help or its size: what a finger aimed at was
    # elsewhere, and the settle time starts again.
    moved = (before.screen, before.help, before.size, before.depth) != (
        hits.screen, hits.help, hits.size, hits.depth)
    return hits._replace(frame=before.frame if same else before.frame + 1,
                         shown=state.now if moved else before.shown)
