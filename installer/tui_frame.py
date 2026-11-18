"""How a screen is laid out: its text, its rows, the pager and the key bar."""
from __future__ import annotations

import bisect
from collections.abc import Iterable
from typing import TYPE_CHECKING

from installer.text import _pad, _wrap, cell_width, fit
from installer.tui_commands import tui_flags
from installer.tui_keys import TuiKey
from installer.tui_paint import TUI_ARMED_SHORT, TUI_SHORTENED, _FOLDER_LABEL, _SHORT_KEYS, _columns, _styled, middle
from installer.tui_routes import TUI_ROUTES
from installer.tui_rows import TUI_TICK_ROWS, _CHECKLISTS, tui_rows

if TYPE_CHECKING:
    from installer.tui_paint import TuiLine
    from installer.tui_state import TuiRow, TuiState


def _bar_commits(state: TuiState, key: TuiKey) -> bool:
    """Whether a bar entry's key writes files with no screen after it to
    look first: the plan's Install when it installs at once, and Put it on
    the card. Those take a second tap. Anything else, Quit, Close, Continue
    and Install on Confirm (itself the look before the install) included,
    acts on one: TUI_TAP_SETTLE already keeps a double tap from reaching
    the next screen."""
    if key.name != "enter":
        return False
    rows = tui_rows(state)
    if not rows:
        return False
    row = rows[max(0, min(state.focus.get(state.screen, 0), len(rows) - 1))]
    if state.screen == "plan" and row.action == "install":
        # Counted again first when the options changed: Confirm comes next.
        return bool(state.ticked or not state.systems) and \
            tui_flags(state) == state.checked_flags
    return state.screen == "result" and row.action == "addapp"


def _tapped_row(state: TuiState) -> tuple:
    """What a tap on the row in focus records (tui_mouse)."""
    rows = tui_rows(state)
    if not rows:
        return ()
    row = rows[max(0, min(state.focus.get(state.screen, 0), len(rows) - 1))]
    return (state.screen, len(state.stack), row.action, row.value)


def _armed(state: TuiState) -> TuiKey | None:
    """The key a first tap armed on this screen, a second tap pressing it:
    a bar entry that writes files, or the row in focus a tap chose. A tap
    on the focused Install row was counted and drawn nowhere
, and one on any other focused row too: the row a
    beginner taps first gave no sign the tap was seen.
    A tick is no choice: a tap ticks it at once."""
    tapped = state.tapped
    if state.help or not tapped:
        return None
    if tapped[0] == "bar":
        armed = (tapped[1] == state.screen and tapped[2] == len(state.stack)
                 and _bar_commits(state, tapped[3]))
        return tapped[3] if armed else None
    enter = TuiKey("enter")
    return (enter if tapped == _tapped_row(state) and tapped[2] not in TUI_TICK_ROWS
            and not state.editing else None)


def armed_words(state: TuiState, width: int) -> str:
    """What a first tap says on the row and on the bar alike: "tap again" on
    a phone, where nothing clicks, and where the bar is short, "click or
    tap again" else. The row said one and the bar the other."""
    if state.os_type == "android" or width < TUI_LONG_BAR_WIDTH:
        return TUI_ARMED_SHORT
    return TUI_ARMED


def _armed_label(state: TuiState, row: TuiRow, width: int) -> TuiRow:
    """The row in focus drawn armed as its bar entry is, in the longest
    words that fit the row. A row that names a choice (a setup, a folder)
    keeps its name where the words do not fit beside it, the bar saying
    them: "Continue: tap again" in its place hid which setup was tapped."""
    verb = _ROW_VERBS.get(row.action, row.label)
    said = armed_words(state, width)
    label = f"{row.label}: {said}"
    if cell_width(f"> {label}") <= width:
        return row._replace(label=label)
    if row.action not in ("install", "addapp"):
        return row
    return row._replace(label=f"{verb}: {said}")


# What an armed bar entry adds to its name, drawn in the accent: a mouse
# clicks and a finger taps, and the screen cannot tell which it was. The
# short form where the long one does not fit.
TUI_ARMED = "click or tap again"


def _back_hint(state: TuiState, parts: tuple) -> tuple:
    """The bar's B/Esc entry as Esc acts on this screen: a filter typed or
    set is cleared first, and the first screen quits. Two first screens
    said Back and quit, and while a filter was typed the bar said Quit."""
    if state.help:
        return parts
    screen = state.screen
    if state.editing == screen:
        word = "Esc Clear"
    elif state.filters.get(screen):
        word = "B/Esc Clear"
    elif len(state.stack) == 1:
        word = "B/Esc Quit"
    else:
        return parts
    return tuple(word if part in ("B/Esc Back", "B/Esc Quit") else part for part in parts)


def _route_hint(state: TuiState, parts: tuple, width: int | None = None) -> tuple:
    """The bar's entries named as the run's input names them. On Android
    with no pad route named (Termux on a phone), a bar too narrow for both
    names keeps the key's: it said "A Continue" where a phone has an Enter
    key and no A button, and the a key does nothing.
    The help still names both."""
    pad = ("keys" if state.pad == "both" and state.os_type == "android"
           and width is not None and width < TUI_LONG_BAR_WIDTH else state.pad)
    route = TUI_ROUTES.get(pad)
    if route is None or state.help:
        return parts
    names = route.bar
    named = []
    for part in parts:
        key, sep, what = part.partition(" ")
        if key in names:
            mine = names[key]
            if mine is None:
                continue
            key = mine
        named.append(key + sep + what)
    if state.pad == "muxterm" and state.screen == "path":
        named.append("Select Keyboard")
    return tuple(named)


def _tap_hint(state: TuiState, parts: tuple) -> tuple:
    """The bar's tick entry naming the tap that ticks too, on a list of
    ticks where the terminal reports clicks: X/Space Tick said nothing of
    a finger, which went to the row and continued."""
    if not state.mouse or state.help or state.screen not in (*_CHECKLISTS, "regions"):
        return parts
    keys = ("A/Enter", "A", "Enter", "Start")
    return tuple(f"{part.split(' ', 1)[0]}/tap {part.split(' ', 1)[1]}"
                 if part.endswith(" Tick") and part.split(" ", 1)[0] in keys
                 else part for part in parts)


# Shorter verbs for a narrow bar, tried before an entry is dropped.
_SHORT_VERBS = ((" Untick all", " None"), (" Tick all", " All"))


# Below this many columns of text the bar always uses the short key names.
TUI_LONG_BAR_WIDTH = 52


def _hint(width: int, *parts: str) -> str:
    """The keys that matter now, short names first given up, then whole
    entries from the right."""
    full = "  ".join(parts)
    # One rule for every screen of a width: at 40 columns the plan read
    # "A Install" and the next screen "A/Enter Install".
    if cell_width(full) <= width and width >= TUI_LONG_BAR_WIDTH:
        return full
    short = []
    for part in parts:
        for long_name, short_name in _SHORT_KEYS:
            if part.startswith(long_name):
                part = short_name + part[len(long_name):]
        short.append(part)
    if cell_width("  ".join(short)) > width:
        # A verb shortened before an entry is given up: Back went first.
        for verb, brief in _SHORT_VERBS:
            short = [part.replace(verb, brief) for part in short]
    text = ""
    for part in short:
        longer = f"{text}  {part}" if text else part
        if cell_width(longer) > width:
            break
        text = longer
    return text or fit(short[0], width)


# What A does on each kind of row: the bar names it for the row in focus.
_ROW_VERBS = {
    "install": "Install", "close": "Close", "quit": "Quit", "systems": "Open",
    "options": "Open", "setup": "Continue", "another": "Open", "platform": "Choose",
    "default": "Use this folder", "browse": "Browse", "type": "Type a path",
    "use": "Use this folder", "up": "Go up", "dir": "Open", "create": "Create",
    "other": "Choose another", "cardroot": "Use the root", "all": "Tick all",
    "none": "Untick all", "filter": "Filter", "system": "Tick", "core": "Tick",
    "region": "Tick", "done": "Done", "regions": "Open", "cores": "Open", "command": "Open",
    "preview": "Open", "folder": "Choose", "game_data": "Change", "installed": "Change",
    "slot": "Change", "standalone": "Change",
    "jobs": "Change", "retry": "Try again", "back": "Back", "stay": "Stay",
    "fromcard": "Choose", "from": "Add a folder", "misplaced": "Show", "zip": "Copy from it",
    "unreadable": "Show", "exit": "Exit", "addapp": "Put it on the card",
    "cardsystem": "Choose", "rescan": "Look again", "elsewhere": "Choose", "drive": "Choose",
    "recheck": "Check again", "gamedata": "Change", "share": "Choose", "morecores": "Show",
    "games": "Change", "startonly": "Change", "gameslist": "Show", "details": "Show",
    "device": "Open", "emulators": "Open", "emulator": "Tick", "board": "Choose",
    "pack": "Choose", "offline": "Change", "more": "Open", "remove": "Open",
    "backups": "Open", "putback": "Open", "dropbackup": "Open", "rmall": "Choose",
    "rmsystem": "Choose", "rmmisplaced": "Choose", "rmgo": "Remove", "rmbackup": "Change", "backup": "Choose",
    "bkrestore": "Put back", "bkdelete": "Delete", "actgo": "Confirm",
    "packmake": "Open", "packgo": "Make", "packwhere": "Change",
}


# The widest a row's two columns spread: at 120 columns a system's size sat
# 85 columns from its name.
TUI_ROW_SPREAD = 78


def _row_line(row: TuiRow, focused: bool, width: int) -> TuiLine:
    if row.action == "heading":
        # Flush left of the rows it names, never in focus.
        return _styled(fit(row.label, width), row.style)
    left = ("> " if focused else "  ") + row.label
    if row.align and (row.right or row.narrow or row.cut):
        # One column for the list: the longest form that fits after it, a
        # single device's name cut before nothing.
        room = min(width, TUI_ROW_SPREAD) - row.align
        right = next((form for form in (row.right, *row.narrow)
                      if form and cell_width(form) <= room), "")
        if not right and row.cut and room >= 9:
            right = fit(row.cut, room - 3).rstrip() + "..."
        return _styled(_pad(left, row.align) + right if right else left,
                       "focus" if focused else row.style)
    if row.right:
        width = min(width, max(TUI_ROW_SPREAD, cell_width(left) + 2 + cell_width(row.right)))
    if row.keep_right and row.right:
        whole = width - cell_width(left) - 2
        forms = (row.right, *row.narrow)
        right = next((form for form in forms if cell_width(form) <= whole), "")
        if not right:
            right = forms[-1]
            room = width - cell_width(right) - 2
            if room >= 8:
                left = fit(left, room - 3).rstrip() + "..."
        return _styled(_columns(left, right, width), "focus" if focused else row.style)
    if row.narrow or row.cut:
        # The name first: the longest right-hand form that leaves it whole,
        # else none at all when that is what keeps it whole. Nintendo Game
        # Boy, Game Boy Advance and Game Boy Color read alike once cut. A
        # device name cut comes before a count of devices.
        whole = width - cell_width(left) - 2
        counted = row.narrow[-1:] if row.cut and len(row.narrow) > 1 else ()
        named = (row.right, *row.narrow[:len(row.narrow) - len(counted)])
        right = next((form for form in named if cell_width(form) <= whole), "")
        if not right and row.cut and whole >= 9:
            right = fit(row.cut, whole - 3).rstrip() + "..."
        if not right:
            right = next((form for form in counted if cell_width(form) <= whole), "")
        if not right and cell_width(left) > width and row.narrow:
            right = row.narrow[-1]
        text = _columns(left, right, width)
    else:
        right = middle(row.right, max(12, width // 2)) if row.right else ""
        text = _columns(left, right, width)
    return _styled(text, "focus" if focused else row.style)


def _text_lines(items: list, width: int, whole: bool = False) -> list[TuiLine]:
    """Items as screen lines. whole keeps every word, path and command
    whole (_wrap): a line wider than width is drawn as it is, the terminal
    folding it, with the rows it takes after it left to it ("cont")."""
    lines: list[TuiLine] = []
    for item in items:
        style = getattr(item, "style", "")
        if getattr(item, "mark", None) is not None:
            # A line saying which lines are in view keeps what a click on it does.
            line = _styled(fit(str(item), width), style)
            line.mark = item.mark
            lines.append(line)
            continue
        if style == "path" and not whole:
            # One line, cut in its middle: the end of a path tells it apart.
            lines.append(_styled(middle(str(item), width)))
            continue
        # A command is wrapped between its shell words on every screen: the
        # plan's root command was cut inside its URL.
        command = style == "command" or getattr(item, "command", False)
        kind = "command" if command else "text" if whole else ""
        folder = str(item).lstrip(" ").startswith(_FOLDER_LABEL)
        # A folder on its own line wraps at its own indent.
        pieces = _wrap(str(item), width, "" if style == "path" and str(item).startswith("  ")
                       else "  ", whole=kind, powershell=getattr(item, "powershell", None))
        if command and "..." in "".join(pieces) and "..." not in str(item):
            # Its path cut to fit: said under it, never as part of it.
            pieces.append(TUI_SHORTENED)
        for number, piece in enumerate(pieces):
            if piece is TUI_SHORTENED:
                lines.append(_styled(fit(piece, width), "dim"))
                continue
            if cell_width(piece) <= width:
                # The rest of a BIOS folder's line keeps its weight.
                line = _styled(fit(piece, width), "folder" if folder and number
                               else "" if style in ("path", "command") else style)
                line.command = command
                lines.append(line)
                continue
            line = _styled(piece, "long")
            line.command = command
            lines.append(line)
            lines += [_styled("", "cont")] * (-(-cell_width(piece) // width) - 1)
    return lines


def _whole_words(state: TuiState) -> bool:
    """Whether a pager keeps paths and commands whole: the result and the
    command line, the screens a person copies from."""
    return state.screen in ("result", "command")


def _scrolled(lines: list[TuiLine], first: int, height: int, lead: int = 0,
              count: int | None = None) -> list[TuiLine]:
    """height lines of a longer list from first, the last one saying where.
    The lead rows (a Filter) are not counted among the entries, nor what
    follows the count entries (All, None and Done)."""
    if len(lines) <= height:
        return lines
    shown = max(1, height - 1)
    first = max(0, min(first, len(lines) - shown))
    end = first + shown
    count = len(lines) - lead if count is None else count
    start = min(count, max(1, first + 1 - lead))
    where = f"{start}-{max(start, min(count, end - lead))} of {count}"
    return lines[first:end] + [_styled(where, "dim")]


# The rows a screen keeps for its list under pinned lines.
TUI_PINNED_ROWS = 4
# A list longer than this opens its systems on None, and its help names a
# page key.
TUI_LONG_LIST = 9


def _compose(
    state: TuiState, width: int, height: int, before: list, rows: list[TuiRow],
    after: Iterable = (), footer: Iterable = (), pinned: Iterable = (),
) -> list[TuiLine]:
    """Text, then the rows, then more text, in height lines. The rows are
    always shown, scrolled around the focus when they do not fit. pinned
    comes first and stays when the rows fill the screen, leaving them
    TUI_PINNED_ROWS lines at least."""
    footer_lines = _text_lines(list(footer), width)
    room = max(1, height - len(footer_lines))
    top_lines = _text_lines(list(pinned), width)[:max(0, room - TUI_PINNED_ROWS)]
    if top_lines:
        top_lines.append(_styled(""))
        room -= len(top_lines)
        return top_lines + _compose(state, width, room, before, rows, after) + footer_lines
    focus = max(0, min(state.focus.get(state.screen, 0), len(rows) - 1)) if rows else 0
    armed = bool(rows) and _armed(state) is not None
    row_lines = [_row_line(_armed_label(state, row, width) if armed and index == focus else row,
                           index == focus, width) for index, row in enumerate(rows)]
    for index, (row, line) in enumerate(zip(rows, row_lines)):
        line.mark = ("row", index, (row.action, row.value))
    # What L1/R1 move by: the rows drawn. Six fewer than the window's height
    # skipped rows the intro left no room for at 40x12, muOS among them.
    state.page_rows = max(1, min(len(row_lines), room - 1))
    if len(row_lines) >= room:
        first = focus - (room - 1) // 2
        # Scrolled by the wheel, the list stays where it was put while the
        # focus is in view: centred again, the row under the pointer moved.
        kept = state.list_top.get(state.screen)
        if kept is not None and kept <= focus < kept + max(1, room - 1):
            first = kept
        else:
            state.list_top.pop(state.screen, None)
        ticks = [i for i, row in enumerate(rows) if row.action in TUI_TICK_ROWS]
        lead = ticks[0] if ticks else next(
            (i for i, row in enumerate(rows) if row.action not in ("all", "none", "filter")), 0)
        # A list of ticks counts its items: the Filter above them and All,
        # None and Done below are no entries of it.
        body = _scrolled(row_lines, first, room, lead, len(ticks) if ticks else None)
        if len(row_lines) > room:
            body[-1].mark = ("scroll", "list", len(rows))
    else:
        budget = room - len(row_lines)
        top: list[TuiLine] = []
        for index, item in enumerate(before):
            lines = _text_lines([item], width)
            if str(item).rstrip().endswith(":") and index + 1 < len(before):
                # A line that leads into the next one gives way with it, the
                # rest of a wrapped folder included: the save line ended on
                # "under:" at 60x20, its folder cut.
                led = [before[index + 1]]
                for more in before[index + 2:]:
                    if not str(more).startswith("  "):
                        break
                    led.append(more)
                if len(top) + len(lines) + len(_text_lines(led, width)) > budget:
                    break
                top += lines
                continue
            if len(top) + len(lines) > budget:
                break
            top += lines
        budget -= len(top)
        gap = [_styled("")] if top and row_lines and budget > 0 else []
        budget -= len(gap)
        # Whole items only: cut to the room left, a note ended in the
        # middle of its sentence at 40x12.
        tail: list[TuiLine] = []
        for item in after:
            lines = _text_lines([item], width)
            if 1 + len(tail) + len(lines) > budget:
                break
            tail += lines
        bottom = [_styled(""), *tail] if tail else []
        body = top + gap + row_lines + bottom
    body += [_styled("")] * (room - len(body))
    return body + footer_lines


def _pager(
    state: TuiState, width: int, height: int, items: list, lead: int = 0,
) -> list[TuiLine]:
    """The lines in view, scrolled line by line, the last one saying which
    lines these are. The lead items (a count above a list) are not counted.

    It scrolled by item and counted items: at 40x12 the result read
    "1-2 of 5" over eight lines, its last paragraph cut, and a paragraph
    longer than the screen could never be read to its end. Only the items
    in view are wrapped: the 8,000 lines of a full preview were wrapped
    again at every key.
    """
    starts = _pager_starts(state, items, width)
    total = starts[-1]
    whole = _whole_words(state)
    if total <= height:
        return _text_lines(items, width, whole)
    room = max(1, height - 1)
    first = max(0, min(state.focus.get(state.screen, 0), total - room))
    index = bisect.bisect_right(starts, first) - 1
    offset = first - starts[index]
    lines: list[TuiLine] = []
    while index < len(items) and starts[index] < first + room:
        lines += _text_lines([items[index]], width, whole)
        index += 1
    skip = starts[lead] if lead else 0
    start = max(1, first + 1 - skip)
    end = max(start, first + room - skip)
    where = _styled(f"{start}-{end} of {total - skip}", "dim")
    where.mark = ("scroll", "pager", total)
    return lines[offset:offset + room] + [where]


def _pager_starts(state: TuiState, items: list, width: int) -> list[int]:
    """The line each item starts on once wrapped at width, and the total
    last, kept while the items stay the same. An item that fits is one line
    without being wrapped."""
    whole = _whole_words(state)
    key = (width, whole, [(str(item), getattr(item, "style", "")) for item in items])
    if state.pager_cache is not None and state.pager_cache[0] == key:
        return state.pager_cache[1]
    starts = [0]
    for item in items:
        fits = ((getattr(item, "style", "") == "path" and not whole)
                or cell_width(str(item)) <= width)
        starts.append(starts[-1] + (1 if fits else len(_text_lines([item], width, whole))))
    state.pager_cache = (key, starts)
    return starts


def _fitted_compose(state: TuiState, width: int, height: int, core: list,
                    notes: list, rows: list[TuiRow], after: list, pinned: list) -> list:
    """_compose with the text core always shown whole above the rows: the
    notes go first, the last one first, then the lines before the core,
    then a folder that does not fit its lines is drawn on one, cut in its
    middle. At 40x12 a note took the room and the folder Use this folder
    takes went with it."""
    def shown(body: list, before: list) -> bool:
        top = _text_lines(list(pinned), width)
        wanted = len(_text_lines(before, width)) + (len(top) + 1 if top else 0)
        drawn = next((index for index, line in enumerate(body)
                      if (getattr(line, "mark", None) or ("",))[0] == "row"), len(body))
        return drawn >= wanted
    candidates = [core + notes[:keep] for keep in range(len(notes), -1, -1)]
    candidates.append(list(core))
    if core:
        candidates.append([*core[:-1], _styled(str(core[-1]), "path")])
    for before in candidates:
        body = _compose(state, width, height, before, rows, after, pinned=pinned)
        if shown(body, before):
            return body
    return body


def _status_after(state: TuiState) -> list[str]:
    """The status under a screen's rows, its full form after it."""
    if not state.status:
        return []
    if not state.status_more:
        return [state.status]
    # Said once: the full form repeated the short one under it. The help
    # holds it, and a pad, with no button for the help, reads it here.
    if state.pad in ("both", "keys"):
        return [_styled(f"{state.status} {'F1' if state.screen == 'path' else '?'} says more.",
                        getattr(state.status, "style", ""))]
    return [state.status, state.status_more]


def _middle_label(row: TuiRow, room: int) -> TuiRow:
    """A row naming a folder, the folder cut in its middle to fit."""
    name, _sep, value = row.label.partition(": ")
    return row._replace(label=f"{name}: " + middle(value, room - len(name) - 2), style="")


# The bar of the three lists of ticks, one wording.
_CHECKLIST_BAR = ("A/Enter Tick", "B/Esc Done", "? Help")


def _status_footer(state: TuiState) -> list:
    return [_styled(str(state.status), "refusal")] if state.status else []


_STATE_WORDS = {"missing": "missing", "wrong_hash": "wrong copy"}


def _bar(share: float, width: int) -> str:
    room = max(4, width - 7)
    filled = int(share * room)
    return f"[{'#' * filled}{'-' * (room - filled)}] {int(share * 100):3d}%"


def _armed_hint(state: TuiState, parts: tuple, width: int) -> tuple:
    """The bar with the entry a first tap armed saying that a second one
    presses it, in the longest words the bar keeps whole: at 40 columns
    "click or tap again" was cut inside its last word, and the bar's B
    went with it."""
    key = _armed(state)
    if key is None:
        return parts
    at = next((index for index, part in enumerate(parts) if " " in part
               and _bar_click(state, part.split(" ", 1)[0]) == key), None)
    if at is None:
        return parts
    part = parts[at]
    verb = part.split(" ", 1)[1]
    said = armed_words(state, width)
    forms = (f"{part}: {said}",
             f"{part.split(' ', 1)[0]} {' '.join(verb.split()[:3])}: {said}")
    # Every entry kept first, then every one but the help, then the armed
    # one whole: on a phone at 40 columns Esc Quit went first.
    for keep in (len(parts), len([p for p in parts if not p.startswith("? ")]), 1):
        for form in forms:
            armed = (*parts[:at], form, *parts[at + 1:])
            drawn = _hint(width, *armed)
            if form.split(" ", 1)[1] in drawn and len(drawn.split("  ")) >= keep:
                return armed
    return (*parts[:at], forms[-1], *parts[at + 1:])


# The keys the bar's entries name, as a click on the entry presses them. A
# pair of keys (Left/Right, PgUp/PgDn) is no button: which one is meant
# cannot be told.
_BAR_CLICKS = {
    "A/Enter": TuiKey("enter"), "A": TuiKey("enter"), "Enter": TuiKey("enter"),
    "Start": TuiKey("enter"), "B/Esc": TuiKey("esc"), "B": TuiKey("esc"),
    "Esc": TuiKey("esc"), "X/Space": TuiKey("char", " "), "X": TuiKey("char", " "),
    "Space": TuiKey("char", " "), "Y/o": TuiKey("char", "o"), "Y": TuiKey("char", "o"),
    "o": TuiKey("char", "o"), "/": TuiKey("char", "/"), "Ctrl-U": TuiKey("ctrl-u"),
    "X/Space/tap": TuiKey("char", " "), "X/tap": TuiKey("char", " "),
    "Space/tap": TuiKey("char", " "), "A/Enter/tap": TuiKey("enter"), "A/tap": TuiKey("enter"),
    "Ctrl-C": TuiKey("ctrl-c"),
    # F1 and not ?, which the path screen types into the path.
    "?": TuiKey("f1"),
}


def _bar_click(state: TuiState, name: str) -> TuiKey | None:
    """The key a bar entry's name stands for, on the route the bar names."""
    route = TUI_ROUTES.get(state.pad)
    if route is not None and name not in _BAR_CLICKS:
        name = next((key for key, mine in route.bar.items() if mine == name), name)
    return _BAR_CLICKS.get(name)
