"""Each screen drawn from the state."""
from __future__ import annotations

import bisect
import re
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

from installer.app import NO_PYTHON_CARDS, app_lines, no_python_words
from installer.cards import _last_name, card_where
from installer.constants import CARD_PLATFORMS, GAME_DATA, OTHER_SYSTEMS
from installer.detect_os import detected_os, detected_shown
from installer.embedded import (
    _GAMES_PART_CARDS,
    _a,
    _mounted_cards,
    card_setup,
    card_system,
    display_name,
    setup_bios_folder,
    shown_path,
)
from installer.from_folders import MAX_SCANNED_FILES, sources_line
from installer.invocation import Invocation
from installer.line_ui import (
    CANNOT_WRITE,
    _pad,
    cannot_write_words,
    core_count_words,
    drives_left_out,
    game_data_only,
    game_data_only_words,
    share_words,
    side_name,
    space_words,
    unavailable_lines,
    unlisted_saves_words,
    unproven_words,
)
from installer.local_files import _retroarch_config_at, save_where_words
from installer.offline import LOCAL, offline_named, offline_undo
from installer.outcome import (
    EVERYTHING_IN_PLACE,
    NEXT_ON_CARD,
    NEXT_ON_DEVICE,
    ROMM_SCAN_WORDS,
    TUI_CHOOSE_TITLE,
    TUI_FOLDER_TITLE,
    TUI_FOUND_TITLE,
    _offline_failure,
    _offline_only,
    _offline_remedy,
    _retry_words,
    needed_absent_words,
    write_remedy,
)
from installer.pack import pack_lacks_words
from installer.pack_source import NOT_KEPT, NOT_WRITABLE
from installer.record import record_changes, record_says, system_title
from installer.removal import _kept_words, kept_line
from installer.run import _FOLDER_LABEL
from installer.setups import TuiRow, _setup_label, android_hint
from installer.tally import installed_words, kinds_definition, left_out_words, parts_words, tally
from installer.terminal import format_duration
from installer.text import _plural, _wrap, agree, cell_width, fit, format_size
from installer.tui_rows import (
    OTHER_HELP,
    TUI_TICK_ROWS,
    _CHECKLISTS,
    _choice_entries,
    _choice_in_place,
    _choice_line,
    _counts_predate_options,
    _emptied_words,
    _needed,
    _no_setup_reads,
    _on_its_card,
    _plan_data,
    _plan_fetch,
    _plan_folder,
    _plan_rows,
    _shared_needed,
    _ticked_estimate,
    _ticked_files,
    _ticked_held,
    _tui_card_bound,
    _tui_categories,
    _tui_estimating,
    _tui_found_elsewhere,
    _tui_misplaced,
    _tui_pack_trees,
    _tui_tally,
    games_pager_lines,
    games_plan_words,
    games_where,
    tui_rows,
    tui_systems,
    tui_verbose,
)
from installer.tui_state import (
    TUI_PAD_ROUTES,
    TUI_ROUTES,
    TuiState,
    _core_base,
    _removing_misplaced,
    _tui_card,
    _tui_installed,
    tui_command,
    tui_core_flags,
    tui_flags,
    tui_hint,
    tui_record_kept,
)
from installer.tui_text import (
    TUI_ARMED_SHORT,
    TUI_SHORTENED,
    _SHORT_KEYS,
    TuiKey,
    TuiLine,
    _columns,
    _command_line,
    _detail,
    _details,
    _is_detail,
    _short_path,
    _styled,
    middle,
)

# The narrowest column of devices the setup list aligns them in: below it
# they stand against the right edge, one edge for every row.
TUI_DEVICE_ROOM = 12


def _aligned_devices(rows: list[TuiRow], width: int) -> list[TuiRow]:
    """The setup list's devices starting at one column, two cells after the
    longest setup name, where that leaves them room: at 80 columns they
    began anywhere from column 20 to 70."""
    named = [row for row in rows if row.action in ("platform", "cardsystem")]
    if not named:
        return rows
    column = 2 + max(cell_width(row.label) for row in named) + 2
    if min(width, TUI_ROW_SPREAD) - column < TUI_DEVICE_ROOM:
        return rows
    return [row._replace(align=column) if row in named else row for row in rows]


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


def _scan_lines(state: TuiState) -> list[str]:
    """What the reading of the --from folders left out, one line each."""
    lines: list = []
    for scan in state.scanned:
        if scan["truncated"]:
            lines.append(_detail(f"Read the first {MAX_SCANNED_FILES:,} files of "
                                 f"{scan['folder']}."))
        lines += [f"{drive} is another drive: add it to copy from it too."
                  for drive in scan["other_drives"]]
    # The count, which line mode always says, stays where no row names
    # these files: the plan's Show row does.
    if state.unreadable and any(row.action == "unreadable" for row in _plan_rows(state)):
        lines += _details(_unreadable_count(state))
    elif state.unreadable:
        lines += _unreadable_count(state)
    return lines


def _unreadable_count(state: TuiState) -> list[str]:
    """How many files the --from folders hold that could not be read."""
    lines = []
    if state.unreadable:
        count = len(state.unreadable)
        # Named as it was given: "your old card" was said of a folder.
        where = ", ".join(_last_name(folder) for folder in
                          dict.fromkeys(event["folder"] for event in state.unreadable))
        lines.append(f"{_plural(count, 'file')} in {where} could not be read.")
    return lines


class _PlanFigures(NamedTuple):
    """The counts and sizes one plan's lines are written from."""
    need: int
    data: int
    dry: bool
    fetch: int
    fetch_bytes: int
    data_bytes: int
    copied: list
    lacking: list
    sizes: dict
    elsewhere: dict
    offline: bool


def _plan_figures(check: dict, state: TuiState) -> _PlanFigures:
    need = _needed(check)
    data = check.get("data_missing", 0)
    dry = check is state.dry and check is not state.check
    fetch, fetched, copied, lacking, sizes = _plan_fetch(state, check)
    fetch_bytes = fetched - (check.get("data_bytes", 0) if data else 0)
    elsewhere = (_tui_found_elsewhere(state, set(copied) if dry else None)
                 if check is state.check or dry else {})
    offline = _offline_only()
    # The data files are files to fetch like the others: one count and one
    # size, the kinds apart on the line under the folder. "8358 files and
    # 2636 data files" read as two kinds of one thing.
    data_bytes = check.get("data_bytes", 0) if data else 0
    return _PlanFigures(need, data, dry, fetch, fetch_bytes, data_bytes, copied, lacking,
                        sizes, elsewhere, offline)


def _plan_needed_headline(check: dict, fig: _PlanFigures) -> str:
    """The headline of a plan with files to install."""
    need, data, fetch, copied = fig.need, fig.data, fig.fetch, fig.copied
    if fig.elsewhere:
        # The folder by its last name: the whole path pushed the BIOS
        # folder off a 40x15 screen. The Options row spells it out. The
        # data files are among those to fetch: one count.
        where = ", ".join(f"{len(events)} found in {_last_name(folder)}"
                          for folder, events in fig.elsewhere.items())
        rest = fetch + data
        return (f"{where}, {agree(rest, 'needs', 'need')} the internet ({offline_named()})"
                if rest and fig.offline
                else f"{where}, {rest} to download "
                f"({format_size(fig.fetch_bytes + fig.data_bytes)})"
                if rest else f"{where}, nothing to download")
    if need and fetch and fig.offline:
        return (f"{agree(fetch + data, 'file needs', 'files need')} the "
                f"internet, which {offline_named()} does not use")
    if need and fetch and LOCAL.pack is not None and copied:
        # One count: "21 files to install from the pack" above "23 to
        # install", and the result said 23 came from the pack, then 21.
        held = check["bytes_needed"] - sum(fig.sizes[dest_] for dest_ in fig.lacking)
        return (f"{_plural(need - len(fig.lacking) + data, 'file')} to install, "
                f"{format_size(held + fig.data_bytes)}")
    if need and fetch and LOCAL.pack is not None:
        # Nothing comes from the network: "to download" on a handheld with
        # no Wi-Fi read as a failure on its way.
        return (f"{_plural(fetch + data, 'file')} to install from the pack, "
                f"{format_size(fig.fetch_bytes + fig.data_bytes)}")
    if need and fetch:
        return (f"{_plural(fetch + data, 'file')} to download, "
                f"{format_size(fig.fetch_bytes + fig.data_bytes)}")
    if need and data:
        copied_bytes = sum(fig.sizes[dest_] for dest_ in copied)
        return (f"{_plural(len(copied) + data, 'file')} to install, "
                f"{format_size(copied_bytes + fig.data_bytes)}")
    return f"{_plural(len(copied), 'file')} to copy from this machine"


def _plan_headline(check: dict, state: TuiState, fig: _PlanFigures) -> str:
    data = fig.data
    # The data trees' size comes from their own event: "2636 data files"
    # beside "6.6 GB" said nothing of what they weigh.
    data_size = (f" ({format_size(check['data_bytes'])})" if data and "data_bytes" in check
                 else "")
    if not fig.need:
        return (f"{_plural(data, 'data file')} to fetch{data_size}" if data
                else EVERYTHING_IN_PLACE.rstrip("."))
    if fig.lacking and not fig.fetch and not fig.copied:
        # The data files too, when the pack holds none of them: "8252
        # files" said nothing of the 2636 it cannot give either.
        lacked = len(fig.lacking) + (data if data and not _tui_pack_trees(state) else 0)
        return pack_lacks_words(lacked, lacked)
    return _plan_needed_headline(check, fig)


def _plan_backups(check: dict, state: TuiState, fig: _PlanFigures) -> int:
    """How many wrong copies the plan replaces, the old ones kept."""
    # The wrong copies something replaces: offline, those a folder copied
    # from holds, else those the network or the pack brings too. "The 1
    # wrong copy is replaced" stood over a copy no folder held, which the
    # result then said was left.
    wrong_dests = [event["dest"] for event in (state.dry_files if fig.dry else state.files)
                   if event.get("state") == "wrong_hash"]
    return (sum(1 for dest_ in wrong_dests if dest_ in fig.copied) if fig.offline
            else sum(1 for dest_ in wrong_dests
                     if dest_ in fig.copied or dest_ not in fig.lacking)
            if wrong_dests else check["wrong_hash"])


def _misplaced_line(misplaced: list) -> TuiLine:
    return _detail(
        f"{_plural(len(misplaced), 'file')} "
        f"{'is' if len(misplaced) == 1 else 'are'} in the wrong place, "
        f"{'it' if len(misplaced) == 1 else 'they'} will be copied where the "
        "emulators read "
        f"{'it' if len(misplaced) == 1 else 'them'}, the "
        f"{'copy' if len(misplaced) == 1 else 'copies'} left as "
        f"{'it is' if len(misplaced) == 1 else 'they are'}.")


def _backup_line(backup: int, wrong: int) -> TuiLine:
    # With its subject: "They are replaced" sat lines under the count.
    # Not where nothing can be installed: nothing is replaced then.
    return _detail(
        (f"The {_plural(wrong, 'wrong copy')} " if backup == wrong
         else f"{backup} of the {_plural(wrong, 'wrong copy')} ")
        + f"{'is' if backup == 1 else 'are'} replaced, the old "
        f"{'one' if backup == 1 else 'ones'} kept in a backup folder.")


def _plan_split_line(fig: _PlanFigures) -> list[TuiLine]:
    """The pack and copy split under the counts."""
    if fig.copied and fig.fetch and LOCAL.pack is not None:
        return [_detail(f"{fig.fetch} from the pack, {len(fig.copied)} copied from this "
                        "machine")]
    if fig.copied and fig.fetch and not fig.offline:
        # 47 to download above 49 missing and 1 wrong copy: the 3 found on
        # this machine are the difference, on a line of its own ("0 wrong
        # copies: 2 of them" read as two of the zero). Offline the headline
        # says it: "3 downloaded" sat under "3 need the internet".
        return [_detail(f"{fig.need} to install: {len(fig.copied)} copied from this machine, "
                        f"{fig.fetch} downloaded")]
    return []


def _plan_from_lines(state: TuiState, fig: _PlanFigures, offline_lines: list) -> list:
    """What the plan says of the folders copied from."""
    # A folder copied from that holds none of them: the plan came back
    # the same, still saying to copy from a folder.
    held = {Path(folder).absolute() for folder in fig.elsewhere}
    empty = [_last_name(str(folder)) for folder in state.from_folders
             if Path(folder).absolute() not in held]
    if empty and not fig.need:
        # Every file is in place: "packx holds none of these files" read
        # as an empty card, where it holds all 22.
        return [f"Nothing to copy from {', '.join(empty)}: every file is in "
                "place."]
    if empty and offline_lines and len(empty) == len(state.from_folders):
        # Said once: "USBSTICK holds none of these files" was followed
        # by "They are not in USBSTICK".
        return [f"{', '.join(empty)} {'holds' if len(empty) == 1 else 'hold'} "
                "none of these files: run the installer again with a pack "
                f"(--from-pack) or {offline_undo()}."]
    return [f"{name} holds none of these files." for name in empty] + offline_lines


def _plan_check_lines(check: dict, state: TuiState) -> list:
    """The lines a plan adds from the check's own events."""
    lines: list = []
    if check is state.check:
        lines += _scan_lines(state)
    if check.get("not_installable"):
        lines += _unavailable_brief(state) + _details(_unavailable_lines(state))
    if check is state.check:
        lines += _unplaced_lines(_choice_summary(state), state,
                                 "Choose it in Change, Save folder (--save-dir).")
    if check is state.check:
        lines += _found_lines(state)
    return lines


def _plan_lines(check: dict, dest: Path | None, state: TuiState) -> list:
    fig = _plan_figures(check, state)
    data, fetch = fig.data, fig.fetch
    headline = _plan_headline(check, state, fig)
    wrong = check["wrong_hash"]
    # Where some were found, the plan names the rest by kind ("Not in old:
    # 10 BIOS files and 6 game data files.", _view_plan), and the remedy
    # follows it: "They" sat under a split of all 22.
    offline_lines = ([_offline_remedy([_last_name(str(folder))
                                       for folder in state.from_folders],
                                      named=bool(fig.elsewhere) and not fig.dry)]
                     if fig.offline and fetch else [])
    # The folder comes second: on a 40x12 screen it is what is left once
    # the rows are drawn, and nothing is written before it is seen.
    lines: list = [
        _styled(headline, "title"),
        _styled(f"BIOS folder: {_short_path(_plan_folder(state, dest), state.home)}", "path"),
    ]
    found_in = _retroarch_config_at(dest) if dest is not None else None
    if found_in:
        # Right under the folder it names: after the save lines it read as
        # naming them.
        lines.append(_detail(f"Named by {_short_path(Path(found_in[0]), state.home)}", "path"))
    if state.facts.get("writable") is False and dest is not None:
        # The remedy itself comes below, after the counts.
        lines += cannot_write_words(dest, state.platform, tui_hint(state),
                                    state.pad not in TUI_PAD_ROUTES, _on_its_card(state),
                                    screen=True, remedy=False)
    # Said again where it is the BIOS folder: the browser said it, and the
    # plan named ~ alone.
    lines += filter(None, [_no_setup_reads(state, dest)])
    # The data files missing among the missing: the headline counts them,
    # and "10888 need the internet" sat over "8252 missing".
    counts = (f"{check['present']} in place, {check['missing'] + data} missing, "
              f"{_plural(wrong, 'wrong copy')}")
    # A first install's missing files are its normal state, not a warning.
    lines.append(_detail(counts, "quiet" if not check["present"] and not wrong else ""))
    # The backup line goes right under the count it explains, before the
    # pack and copy split: at 40x12 and 40x15 it came after it, and was cut.
    count_at = len(lines)
    lines += _plan_split_line(fig)
    after_counts = len(lines)
    saves = (_choice_saves(state) if check is state.check
             else state.dry_saves if check is state.dry else None)
    saves_lines = _saves_lines(state, saves)
    lines += [_detail(line, "path" if index else "") for index, line in enumerate(saves_lines)]
    free = state.facts.get("free")
    if free is not None:
        lines.append(_detail(f"Free space: {format_size(free)}"))
        if check["bytes_needed"] > free:
            lines.append(space_words(check["bytes_needed"], free, _on_its_card(state)))
    backup = _plan_backups(check, state, fig)
    misplaced = _tui_misplaced(state) if check is state.check else []
    if misplaced:
        lines.insert(after_counts, _misplaced_line(misplaced))
    if backup:
        lines.insert(count_at, _backup_line(backup, wrong))
    if state.facts.get("writable") is False and dest is not None:
        lines += _commands(state, write_remedy(dest, state.platform, tui_hint(state),
                                               state.pad not in TUI_PAD_ROUTES))
    lines += _plan_check_lines(check, state)
    if check is state.check and state.from_folders:
        offline_lines = _plan_from_lines(state, fig, offline_lines)
    if fig.lacking and (fetch or fig.copied):
        offline_lines.insert(0, pack_lacks_words(len(fig.lacking), len(fig.lacking) + fetch))
    # On Confirm the remedy comes right after the headline: at 40x12 it was
    # what got cut, Back left alone below it. On the plan it comes after the
    # folder and what named it: between them, Named by sat lines under its
    # folder.
    at = 1 if check is state.dry else 3 if found_in else 2
    return lines[:at] + offline_lines + lines[at:]


def _choice_saves(state: TuiState) -> dict | None:
    """The check's saves event, counted again over the systems ticked while
    the plan estimates them: one ticked system without a save file kept
    the line of the whole list."""
    if not _tui_estimating(state) or not state.saves:
        return state.saves
    count = _choice_save_count(state)
    return {**state.saves, "files": count} if count else None


def _choice_summary(state: TuiState) -> dict | None:
    """The check's summary, its save files left out counted over the
    systems ticked while the plan estimates them."""
    summary = state.check_summary
    if not _tui_estimating(state) or not summary:
        return summary
    count = _choice_save_count(state)
    skipped = [group if group.get("reason") != "no_save_directory"
               else {**group, "files": count} for group in summary.get("skipped") or []]
    return {**summary, "skipped": skipped}


def _choice_save_count(state: TuiState) -> int:
    """The files of the choice read from the frontend's save directory,
    game data left out when it is."""
    return sum(1 for entry in _choice_entries(state) if entry.get("root") == "save"
               and not (state.no_game_data and entry.get("category") == GAME_DATA))


def _commands(state: TuiState, lines: list[str]) -> list[str]:
    """Lines holding a command the user may run, drawn as commands: wrapped
    between shell words, and the mouse left to the terminal over them."""
    hint = tui_hint(state)
    launchers = (hint.launcher(), hint.launcher(True))
    return [_command_line(line, hint) if any(launcher in line for launcher in launchers)
            else line for line in lines]


def _saves_lines(state: TuiState, saves: dict | None, whole: bool = False) -> list[str]:
    """Where the files read from the frontend's save directory go: a second
    folder this run writes to, named before anything is written. saves is
    the event of the run the screen shows. whole spells the folder in full,
    as the result names its other folders."""
    if not saves or not saves.get("files"):
        return []
    name = display_name(state.platform) if state.platform else "the frontend"
    count = saves["files"]
    words, folder = save_where_words(saves["folder"])
    # The folder alone is cut in the middle: cut with the sentence, it
    # lost "directory goes to" even at 80 columns.
    # The folder on its own line at the BIOS folder's indent: at the
    # label's, the two folders of a plan sat at two.
    return [f"{_plural(count, 'file')} read from {name}'s save directory "
            f"{'goes' if count == 1 else 'go'} to{' ' + words if words else ''}:",
            "  " + (shown_path(folder) if whole else _short_path(Path(folder), state.home))]


def _unplaced_lines(summary: dict | None, state: TuiState,
                    remedy: str = "") -> list[str]:
    """The files read from the frontend's save directory that the run left
    out, that directory being unknown: said, never silent."""
    count = sum(group.get("files", 0) for group in (summary or {}).get("skipped") or []
                if group.get("reason") == "no_save_directory")
    if not count:
        return []
    name = display_name(state.platform) if state.platform else "the frontend"
    left = f"{_plural(count, 'file')} read from {name}'s save directory left out"
    if state.manifest and not state.manifest.get("save_directory"):
        return [f"{left}.", _detail(f"{unlisted_saves_words(name)}.")]
    return [f"{left}. {remedy or TUI_SAVE_REMEDY}", _detail("Its place is not known.")]


# Said when ES-DE is found, and in fewer words where the long form would
# give way: at 40x12 it ended in the middle of its sentence.
TUI_ESDE_NOTE = "ES-DE found: its BIOS files go to each emulator, not to ES-DE itself."
TUI_ESDE_SHORT = "ES-DE: files go to each emulator."


def _view_setup(state: TuiState, width: int, height: int) -> tuple:
    rows = tui_rows(state)
    focus = rows[min(state.focus.get("setup", 0), len(rows) - 1)]
    after = ([f"BIOS folder: {shown_path(setup_bios_folder(*state.setups[focus.value][:2]))}"]
             if focus.action == "setup" else [])
    before = ["Found on this machine:" if state.setups
              else "A drive here could be either of these:" if state.doubts
              else "Nothing was found here."]
    status = [state.status] if state.status else []
    body = _compose(state, width, height, before, rows, after + status + state.notes,
                    pinned=state.refused)
    if TUI_ESDE_NOTE in state.notes and not any(
            str(line).strip().startswith("ES-DE found") for line in body):
        # The note gave way whole: its short form, where it fits.
        notes = [TUI_ESDE_SHORT if note == TUI_ESDE_NOTE else note for note in state.notes]
        body = _compose(state, width, height, before, rows, after + status + notes,
                        pinned=state.refused)
    return (TUI_FOUND_TITLE, body, ("A/Enter Continue", "B/Esc Quit", "? Help"))


def _view_platforms(state: TuiState, width: int, height: int) -> tuple:
    rows = tui_rows(state)
    if state.dest_given is not None:
        title = "Whose files go there?"
        before = [f"Choose the setup that reads {_short_path(state.dest_given, state.home)}."]
    else:
        title = TUI_CHOOSE_TITLE
        before = ["Choose the setup that will use the BIOS files."]
    pinned = list(state.refused)
    if state.dest_given is None and not state.setups and len(state.stack) == 1:
        # The first screen when nothing was found: at 40x15 its 18 rows
        # left no line to say so, or what to do.
        # A handheld's owner knows its device, not its system's name: the
        # filter finds it, and a pad that cannot type finds the cards right
        # after RetroArch (_cards_first).
        pinned.append("Nothing was found here. Choose the setup, or type the device's "
                      "name (/)." if state.pad in ("both", "keys") else
                      "Nothing was found here. Choose the setup: handhelds come after "
                      "RetroArch.")
        before = []
    needle = state.filters.get("platforms", "")
    after = ([f"No setup matches '{needle}'.", *filter(None, [android_hint(
        needle, state.os_type)])] if len(rows) == 1 and needle else [])
    after += [state.status] if state.status else []
    # The first screen quits on B, as its help says: the bar said Back.
    back = "B/Esc Quit" if len(state.stack) == 1 else "B/Esc Back"
    return (title, _compose(state, width, height, before, _aligned_devices(rows, width), after,
                            pinned=pinned),
            ("A/Enter Choose", back, "/ Filter", "? Help"))


def _view_folder(state: TuiState, width: int, height: int) -> tuple:
    name = display_name(state.platform)
    bound = _tui_card_bound(state)
    if bound and state.folder_default is not None and state.folder_kind == "found":
        # On the device itself: its own folder, which is no card to look for.
        title = TUI_FOLDER_TITLE
        before = [f"{bound[0]} reads its BIOS files from:", str(state.folder_default)]
    elif bound:
        title = "Where is the SD card?"
        setup = card_setup(bound[0], state.platform)
        top = ("that drive's top folder" if bound[0] in _GAMES_PART_CARDS
               else "the card's top folder")
        before = [f"{bound[0]} keeps its BIOS files {card_where(*bound)}. Choose {top}"
                  + (", the one holding .system." if state.platform in CARD_PLATFORMS
                     else ".")]
        known = setup is None or setup.known()
        if not known:
            # Its own files are on a part of the card a computer does not
            # open: the drives no other system claims are offered.
            before.append(f"RetroBIOS cannot tell {_a(bound[0])} card by its files: "
                          "check that it is the right card.")
        if state.folder_default is not None:
            # Use this folder takes it: named, not left to guess.
            before += [f"The BIOS folder chosen for {bound[0]}:", str(state.folder_default)]
        if any(row.action == "rescan" for row in tui_rows(state)):
            before.append((f"No {bound[0]} card is mounted." if known
                           else "No card or drive is mounted.")
                          + " Insert it, then choose Look again.")
    elif state.folder_kind == "share":
        title = TUI_FOLDER_TITLE
        before = [share_words(state.platform)]
    elif state.folder_default is not None:
        title = TUI_FOLDER_TITLE
        lead = {"found": f"{name} reads its BIOS files from:",
                "chosen": f"The BIOS folder chosen for {name}:"}.get(
                    state.folder_kind,
                    f"{side_name(state.os_type, state.platform)} usually reads its BIOS "
                    "files from:")
        before = [lead, str(state.folder_default)]
    elif state.folder_kind == "closed":
        title = TUI_FOLDER_TITLE
        before = [f"Choose another folder for {name}: browse for it or type it."]
    else:
        title = TUI_FOLDER_TITLE
        before = [f"No usual {name} folder here: browse for it or type it."]
    notes: list = []
    if not bound and state.folder_kind != "share":
        notes = [note for note in (drives_left_out(state.platform), unproven_words()) if note]
    body = _fitted_compose(state, width, height, before, notes,
                           tui_rows(state), _status_after(state), state.refused)
    return (title, body, ("A/Enter Choose", "B/Esc Back", "? Help"))


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


def _view_browse(state: TuiState, width: int, height: int) -> tuple:
    # Under WSL a drive is E:\ on every screen: the title said /mnt/e.
    where = "Drives" if state.browse_dir is None else middle(shown_path(state.browse_dir), width)
    hint: list = []
    if state.browse_for == "from":
        # Two lines at 40 columns: the long form was cut after "copied,".
        whole = ("Choose the old card, a backup folder or a ZIP: its BIOS files are "
                 "copied, each one checked, nothing on it is changed.")
        hint = [whole if len(_wrap(whole, width)) <= 2
                else "Choose the old card, a backup folder or a ZIP."]
    elif state.browse_for == "save":
        hint = [f"Choose {display_name(state.platform)}'s save directory: some "
                "cores read files there."]
    elif state.browse_for == "pack":
        hint = ["Choose the pack ZIP downloaded before: nothing is downloaded then."]
    elif state.browse_for == "packto":
        hint = ["Choose the folder the pack goes in."]
    # The hint is kept whole under the list, which scrolls: three folders at
    # 40x12 cut it to "Choose the old card, a backup folder".
    return ("Copy from" if state.browse_for == "from"
            else "Save folder" if state.browse_for == "save"
            else "From a pack" if state.browse_for == "pack"
            else "Pack folder" if state.browse_for == "packto" else "Browse for a folder",
            _compose(state, width, height, [where], tui_rows(state), _status_after(state),
                     hint),
            ("A/Enter Open", "B/Esc Back", "? Help"))


def _view_path(state: TuiState, width: int, height: int) -> tuple:
    text = state.path_text + "_"
    if cell_width(text) > width - 2:
        text = "..." + fit(text[::-1], width - 5)[::-1]
    bound = _tui_card_bound(state)
    # Read as the card's top folder, and said so: "The folder for
    # RetroArch" asked for Onion's card.
    prompt = (f"The top folder of the {bound[0]} SD card:"
              if bound is not None and state.folder_kind != "found"
              else f"The folder for {display_name(state.platform)}:")
    lines = [prompt, _styled(f"> {text}", "focus"), ""]
    if state.status:
        # Said before the hint, which it replaces: at 40x12 the refusal
        # was drawn below the last line and Enter seemed to do nothing.
        lines += _status_after(state)
    else:
        lines.append(("Typing or pasting replaces it. " if state.path_selected else "")
                     + "Ctrl-U clears. Quotes are removed, ~ and variables are expanded.")
    return ("Type a path", _compose(state, width, height, lines, []),
            ("Enter Use this folder", "Esc Back", "Ctrl-U Clear"))


def _view_create(state: TuiState, width: int, height: int) -> tuple:
    # Pushed by _choose once the folder is set.
    assert state.dest is not None
    before = [f"{shown_path(state.dest)} does not exist.",
              f"The nearest folder that does: {state.facts.get('nearest', '')}"]
    if state.facts.get("risky"):
        before.append("Every folder of this path would be made: check its start before "
                      "creating it.")
    if state.card_note:
        before.append(state.card_note)
    return ("Create the folder?", _compose(state, width, height, before, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back"))


def _view_cardroot(state: TuiState, width: int, height: int) -> tuple:
    name = display_name(state.facts.get("card", ""))
    # Pushed by _choose once the folder is set.
    assert state.dest is not None
    before = [f"{shown_path(state.dest)} is inside {_a(name)} card. {name} reads its BIOS "
              f"files under the card's root: {shown_path(state.facts.get('card_root', ''))}"]
    return ("Use the card root?", _compose(state, width, height, before, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back"))


def _view_checking(state: TuiState, width: int, height: int) -> tuple:
    # Titled as the plan is: ArkOS's card was "RetroArch:" here, "ArkOS
    # (RetroArch files)" one screen on.
    lines = [f"{_setup_label(state.platform, state.dest)}: "
             f"{_short_path(_plan_folder(state, state.dest), state.home)}", ""]
    elapsed = format_duration(max(0.0, state.now - state.started))
    if state.manifest is None:
        lines.append(f"Getting the file list... {elapsed}")
    else:
        # Not its count: the check counts the files it checks, which the
        # plan then gives (8179 after "File list: 8169 files").
        lines += ["File list received.", _reading_line(state, elapsed)]
    # Back first: a double tap on the Continue before it pressed the Quit
    # drawn in the same cell.
    return ("Checking", _compose(state, width, height, lines, []),
            ("B/Esc Back", "Ctrl-C Quit"))


def _reading_line(state: TuiState, elapsed: str) -> str:
    if state.games_reading and not state.reading:
        done, total = state.games_reading
        return f"Reading the games: {done} of {total}"
    if state.reading:
        done, total = state.reading
        return f"Reading the files already in the folder: {done} of {total}"
    return f"Reading the files already in the folder... {elapsed}"


def _estimated_head(state: TuiState, check: dict, lines: list, data: int) -> list:
    """The plan's lines under an estimate for the systems ticked."""
    # The headline counts the systems ticked, as the list just did: at
    # 40x12 the line below it was dropped, and the plan showed the
    # total of all of them. Their data files too, as line mode's head.
    # One total, the data files in it, the kinds under the folder
    # adding up to it.
    count, size = _ticked_estimate(state)
    lines[0] = _styled(f"About {_plural(count, 'file')}, {format_size(size)}"
                       f", for {len(state.ticked)} of {len(state.systems)} systems", "title")
    if _offline_only():
        # Offline, what the folders copied from hold of the systems
        # ticked: the plan counted the whole list beside "For your 1 of
        # 11 systems".
        held = _ticked_held(state)
        rest = len(_ticked_files(state)) - len(held) + data
        # Nothing at hand: the head the whole list's plan says, for the
        # systems ticked. "About 0 files, 0 B" stood over 20 files the
        # internet would bring.
        lines[0] = _styled(
            f"{agree(rest, 'file needs', 'files need')} the internet, which "
            f"{offline_named()} does not use, for {len(state.ticked)} of "
            f"{len(state.systems)} systems", "title") if not held else _styled(
            f"About {_plural(count, 'file')}, "
            f"{format_size(size)}, for {len(state.ticked)} of "
            f"{len(state.systems)} systems"
            + (f", {agree(rest, 'needs', 'need')} the internet "
               f"({offline_named()})" if rest else ""), "title")
        if not rest:
            # The remedy was for files of the whole list: none of the
            # choice needs the internet.
            names = [_last_name(str(folder)) for folder in state.from_folders]
            remedies = {_offline_remedy(names), _offline_remedy(names, named=True)}
            lines = [line for line in lines if str(line) not in remedies]
    # The in place and missing counts are the whole list's: under an
    # estimate for some systems they read as its own.
    whole = (f"{check['present']} in place, "
             f"{check['missing'] + check.get('data_missing', 0)} missing, "
             f"{check['wrong_hash']} wrong ")
    return [line for line in lines if not str(line).startswith(whole)]


def _plan_named(state: TuiState) -> str:
    """The choice named on the command line, in line mode's words."""
    games_count = (state.games or {}).get("games") if state.for_games else None
    named = [*([f"for the {_plural(games_count, 'game')} {games_where(state)}"
                + (", only what starts" if state.required_only else "")
                + (" (--for-games)" if state.games_choice == "cli" else "")]
               if games_count else []),
             *([f"for {len(state.systems)} of {len(tui_systems(state))} systems (--system)"]
                if state.cli_systems and state.systems else []),
             # Named as line mode names it, out of how many, the flag after
             # the words where the command line gave it: "--core" said
             # nothing of the count, and "--region." stood alone.
             *([core_count_words(state.cores, _core_base(state))
                + (" (--core)" if state.cores == state.cli_cores else "")]
               if tui_core_flags(state) else []),
             *(["regions ranked" + (" (--region)" if state.regions == state.cli_regions
                                    else "")] if state.regions else [])]
    said = ", ".join(named)
    if said and not said.startswith("for "):
        said = f"for this choice: {said}"
    return said


def _record_said(state: TuiState, said: str) -> tuple[str, list]:
    """The choice said and the changes since, where a record is kept."""
    since: list = []
    if tui_record_kept(state) and not state.cli_choice and state.record is not None:
        # The record's systems by name, its row saying whose choice it is:
        # nobody typed --system. The games and the other options are said
        # as the plan says them.
        what = record_says(state.record, state.manifest)
        if what == "every file":
            said = ""
        elif what not in ("the games", "the options chosen"):
            said = f"for {what}"
        updated, new = record_changes(state.record, [
            entry for entry in (state.manifest or {}).get("files") or []
            if entry.get("dest") in state.checked_dests])
        changes = [*([f"{_plural(updated, 'file')} updated in the list"] if updated else []),
                   *([f"{new} new"] if new else [])]
        if changes:
            since = [_detail(f"Since then: {', '.join(changes)}.")]
    return said, since


def _plan_kinds(state: TuiState, check: dict, estimating: bool, data: int,
                data_size: int | None) -> tuple[str, str]:
    """The split by kind under the folder and the definition it needs."""
    # Of the files the headline counts, by kind: those ticked when it
    # estimates them, those to install otherwise. Under the folder, never
    # above it: inserted second, it pushed the folder off a 40x12 plan.
    kinds_of = (_ticked_files(state) if estimating else
                [event for event in state.files if event["state"] != "present"])
    found = (_tui_found_elsewhere(state) if not estimating and _offline_only()
             and state.check is check else {})
    if found:
        # Some were found in a folder: the kinds split those the headline
        # says need the internet, named as such.
        took = {event["dest"] for events in found.values() for event in events}
        outside = [event for event in kinds_of if event["dest"] not in took]
        if outside or data:
            kinds_of = outside
        else:
            # Every file found: the kinds are those of the files copied,
            # and game data is defined as the pack's plan defines it. The
            # --from plan said neither.
            found = {}
    parts, defined = _kinds_lines(state, kinds_of, data, data_size, whole=bool(found))
    if _choice_in_place(state) or (state.emptied and state.systems and not state.ticked):
        # Nothing of the choice is left to install: a split of the whole
        # list under its headline counted files it does not hold.
        parts = defined = ""
    if found and parts:
        parts = (f"Not in {', '.join(_last_name(str(folder)) for folder in found)}: "
                 f"{parts}")
    return parts, defined


def _plan_tail_notes(state: TuiState, lines: list, defined: str) -> None:
    """The version, board, status and definition lines, each where it goes."""
    if state.version:
        # Before the free space, which gives way first: appended last, the
        # note was cut from the 40x12 plan with no sign.
        free = next((index for index, line in enumerate(lines)
                     if str(line).startswith("Free space:")), len(lines))
        lines.insert(free, state.version)
    if state.board:
        free = next((index for index, line in enumerate(lines)
                     if str(line).startswith("Free space:")), len(lines))
        lines.insert(free, _detail(state.board))
    if state.status:
        lines.append(state.status)
    if defined:
        # Once, after the counts and before the save line: last, it was
        # the first line to give way at 80 columns, where the counts named
        # data files nothing defined. The help says it
        # where the screen has no room.
        saves = next((index for index, line in enumerate(lines)
                      if "'s save directory" in str(line)), len(lines))
        lines.insert(saves, _detail(defined))


def _plan_text(state: TuiState) -> list:
    """Every line of the plan, the Details lines among them."""
    check = state.check or {}
    lines = _plan_lines(check, state.dest, state)
    choice = _choice_line(state)
    estimating = _tui_estimating(state)
    data, data_size = _plan_data(state, check)
    if state.emptied and state.systems and not state.ticked:
        lines = [_styled(_emptied_words(state), "title"), *lines[1:2]]
        estimating = False
    elif _choice_in_place(state):
        lines = [_styled(_choice_in_place(state), "title"), *lines[1:2]]
        choice = []
        estimating = False
    elif estimating:
        lines = _estimated_head(state, check, lines, data)
    # Under the folder and what named it, in this order: the card's note,
    # the choice named on the command line, the choice made here.
    at = next((index + 1 for index, line in enumerate(lines)
               if str(line).startswith("BIOS folder:")), 1)
    if at < len(lines) and str(lines[at]).startswith("Named by "):
        at += 1
    said, since = _record_said(state, _plan_named(state))
    # A system --system named that --no-game-data left empty, in line mode's
    # words.
    listed = {row["system"] for row in state.systems}
    emptied_named = game_data_only_words([
        system_title(system, state.manifest) for system in game_data_only(
            [name for name in state.cli_systems if name not in listed],
            (state.manifest or {}).get("files") or [])]) if state.no_game_data else ""
    # Named on the command line: said in line mode's words, and widened by
    # Choose systems. --core and --region were said in line mode alone
    parts, defined = _plan_kinds(state, check, estimating, data, data_size)
    lines[at:at] = [*([_detail(state.card_note)] if state.card_note
                      and state.card_note != state.status else []),
                    *([f"{said[0].upper()}{said[1:]}."] if said else []), *since,
                    *([emptied_named] if emptied_named else []), *choice,
                    *([_detail(parts)] if parts else []), *games_plan_words(state)]
    _plan_tail_notes(state, lines, defined)
    return lines


def _shown(state: TuiState, lines: list) -> list:
    """The lines a screen shows: with --verbose every line but the counts
    standing for them, else every line but Details."""
    if tui_verbose(state):
        return [line for line in lines if not getattr(line, "brief", False)]
    return [line for line in lines if not _is_detail(line)]


def _view_plan(state: TuiState, width: int, height: int) -> tuple:
    check = state.check or {}
    lines = _shown(state, _plan_text(state))
    # A folder that does not fit is wrapped, as the first screen wraps it:
    # cut in its middle, the plan hid the part being checked before Install.
    # At 40 columns too, broken after a separator: cut there, it was spelled
    # one way on the plan and another on the result.
    lines = [piece for line in lines for piece in (
        [_styled(part, "folder" if index and str(line).startswith(_FOLDER_LABEL)
                 else "") for index, part in enumerate(_wrap(
                     str(line), width, "" if str(line).startswith("  ") else "  "))]
        if getattr(line, "style", "") == "path" and cell_width(str(line)) > width
        else [line])]
    rows = tui_rows(state)
    if width < 54:
        rows = [row._replace(label="Copy from an old card or a folder")
                if row.action == "fromcard" else row for row in rows]
        # One line: in two, a 40x12 plan dropped it, "1 wrong copy" left
        # alone to say a file would be replaced.
        wrong = check.get("wrong_hash", 0)
        long_form = f"The {_plural(wrong, 'wrong copy')} "
        lines = [_styled(f"{_plural(wrong, 'wrong copy')}: backed up, "
                         "replaced.") if str(line).startswith(long_form) else line
                 for line in lines]
        # Above the count it explains, which gives way first: the folder
        # spelled whole takes two lines at 40 columns.
        counted = f"{check.get('present', 0)} in place, "
        at = next((index for index, line in enumerate(lines)
                   if str(line).startswith(counted)), None)
        if at is not None and at + 1 < len(lines) and "backed up, replaced" in str(lines[at + 1]):
            lines[at], lines[at + 1] = lines[at + 1], lines[at]
    # A muOS card gets RetroArch's files: the title says both.
    system = detected_shown(state.platform, state.dest) if state.dest is not None else ""
    name = display_name(state.platform, state.manifest)
    return (f"{system} ({name} files)" if system and system != name else name,
            _plan_body(state, width, height, lines, rows),
            ("A/Enter Install", "B/Esc Back", "Y/o Change", "? Help"))


def _plan_body(state: TuiState, width: int, height: int, lines: list,
               rows: list[TuiRow], short: bool = False) -> list[TuiLine]:
    """The plan's text and rows. Where both do not fit, the headline, the
    whole BIOS folder and the version note stay and the rows scroll under
    them: at 40x12 the plan named ~/.var/app/ as the folder, and dropped the
    note that the list is for another version. With
    no room for its sentences the note is said in one line (short): at
    40x12 the RetroBat note was still dropped."""
    body = _compose(state, width, height, lines, rows)
    at = next((index for index, line in enumerate(lines)
               if str(line).startswith(_FOLDER_LABEL.rstrip())), None)
    kept = list(lines[:1])
    if at is not None:
        # The folder line and the rest of the folder wrapped after it.
        end = at + 1
        while end < len(lines) and getattr(lines[end], "style", "") == "folder":
            end += 1
        kept += lines[at:end]
    kept += [line for line in lines if state.version
             and str(line) in (state.version, state.version_short)]
    # Why the folder rows are offered, before Install anyway: at 40x12 the
    # plan offered Choose another folder and Install anyway and no word of
    # why.
    kept += [line for line in lines if str(line).startswith(CANNOT_WRITE)]
    # A file in place that the install replaces, said whatever the rows: the
    # More row every plan holds pushed it out of a 40x12 plan.
    kept += [line for line in lines if "backed up, replaced" in str(line)]
    top = _text_lines(kept, width)
    drawn = [str(line).strip() for line in body]
    # Three lines at least for the rows: two of them and where the list is,
    # the blank line above them given up first.
    if all(str(line).strip() in drawn for line in top):
        return body
    if len(top) + min(len(rows), 3) > height:
        if not short and state.version_short and state.version in map(str, lines):
            return _plan_body(state, width, height, [
                _styled(state.version_short) if str(line) == state.version else line
                for line in lines], rows, True)
        return body
    gap = [_styled("")] if len(top) + 1 + min(len(rows), 3) <= height else []
    return top + gap + _compose(state, width, height - len(top) - len(gap), [], rows)


def _kinds_lines(state: TuiState, events: list[dict], data: int,
                 data_size: int | None, whole: bool = False) -> tuple[str, str]:
    """The plan's files by kind (parts_words) and what each kind is: the
    same words as line mode's head, game data left out counted over the
    choice. whole: the kinds are said even when there is one."""
    categories = _tui_categories(state)
    categorized = bool(categories)
    if state.no_game_data:
        # Counted apart as left out, never also among the files installed.
        events = [event for event in events if categories.get(event["dest"]) != GAME_DATA]
    counts = (_tui_tally(state, events) if categorized
              else tally({"size": event["size"]} for event in events))
    left = 0
    if categorized and state.no_game_data:
        left = sum(1 for entry in _choice_entries(state) if entry.get("category") == GAME_DATA)
    parts = parts_words(counts, data, data_size, left)
    if whole and not parts and counts.files:
        parts = f"{_plural(counts.files, 'file')} ({format_size(counts.size)})"
    # Game data named as missing is defined too, on its own line: the
    # definition was spliced into that sentence.
    missing = any(entry.get("category") == GAME_DATA for entry in _unavailable(state)[0])
    defined = kinds_definition(categorized and bool(counts.games or left or missing),
                               bool(data))
    return (f"{parts}." if parts else ""), defined


def _screen_definition(state: TuiState) -> str:
    """What the kinds the plan or Confirm counts are, as their screen says
    it where there is room (kinds_definition), "" elsewhere."""
    if state.screen == "plan" and state.check:
        estimating = _tui_estimating(state)
        return _kinds_lines(state, _ticked_files(state) if estimating else [
            event for event in state.files if event["state"] != "present"],
            *_plan_data(state, state.check))[1]
    if state.screen == "confirm" and state.dry and not state.running:
        data = state.dry.get("data_missing", 0)
        return _kinds_lines(state, state.dry_files, data,
                            state.dry.get("data_bytes") if data else None)[1]
    return ""


def _view_systems(state: TuiState, width: int, height: int) -> tuple:
    rows = tui_rows(state)
    whole_rows = rows
    if width < 60:
        # The name first: the size alone stays beside it, the count is in
        # the total below.
        rows = [row._replace(right=re.sub(r"^\d+ files?, ", "", row.right)) for row in rows]
    elif width >= 78:
        # The id --system takes, beside a name that does not show it.
        # Only where it fits whole: a cut id ("maker26-co") said nothing.
        rows = [row._replace(label=f"{row.label}  {row.value}")
                if row.action == "system" and str(row.value) not in row.label
                and cell_width(f"> {row.label}  {row.value}  {row.right}") + 2 <= width
                else row for row in rows]
    chosen = _ticked_files(state)
    total = (f"{len(state.ticked)} of {len(state.systems)} systems: "
             f"{_plural(len(chosen), 'file')}, {format_size(sum(e['size'] for e in chosen))}"
             + (" before the options" if _counts_predate_options(state) else ""))
    footer: list[TuiLine | str] = [_styled(total, "title")]
    focused = rows[min(state.focus.get("systems", 0), len(rows) - 1)]
    drawn = str(_row_line(focused, True, width))
    if focused.action == "system" and not (
            f"> {focused.label}" in drawn
            and any(form and drawn.endswith(form) for form in (focused.right, *focused.narrow))):
        # A long name kept whole leaves no room for its size, and a name
        # longer than the screen is cut: both are spelled out below.
        whole = whole_rows[min(state.focus.get("systems", 0), len(whole_rows) - 1)]
        footer.insert(0, f"{whole.label[4:]}: {whole.right}")
    if focused.value == OTHER_SYSTEMS:
        footer.insert(0, OTHER_HELP)
    elif "shared" in focused.right:
        count = _shared_needed(state)[focused.value][0]
        # "+19" read as 19 more on top of a system whose 19 are all shared.
        footer.insert(0, f"+{count} shared: counted once" if "all shared" not in focused.right
                      else "Shared, counted once" if count == 1
                      else f"All {count} shared, counted once")
    elif _shared_needed(state):
        # Its line kept when the focus leaves a shared system: the page
        # held 4, 3 and 5 systems as the note came and went.
        footer.insert(0, " ")
    needle = state.filters.get("systems", "")
    if needle and not any(row.action == "system" for row in rows):
        footer.insert(0, f"No system matches '{needle}'.")
    # In the lines the rows leave on every length of list: below the rows
    # it was dropped once they filled the screen.
    if state.status:
        footer.insert(0, _styled(str(state.status), "refusal"))
    return ("Choose systems",
            _compose(state, width, height, [], rows, (), footer),
            _CHECKLIST_BAR)


def _view_options(state: TuiState, width: int, height: int) -> tuple:
    rows = tui_rows(state)
    # The headings say what each group decides, the flags on the right
    # which option of the command line each row is.
    after: list = []
    if width < 60:
        # A value cut to make room for its flag said nothing: the flag of
        # the focused row is named below instead.
        focus = rows[min(state.focus.get("options", 0), len(rows) - 1)]
        after = [f"Sets {focus.right}"] if focus.right else []
        rows = [row._replace(right="") for row in rows]
    # A folder is cut in its middle, its last levels being what tells it apart.
    room = width - 4 - (0 if width < 60 else 2 + max(cell_width(r.right) for r in rows))
    rows = [_middle_label(row, room) if row.style == "path" else row for row in rows]
    # In the lines the rows leave: below them it went once they filled
    # the screen.
    return ("Change", _compose(state, width, height, [], rows, after, _status_footer(state)),
            ("A/Enter Change", "B/Esc Back", "Left/Right Set", "? Help"))


def _view_device(state: TuiState, width: int, height: int) -> tuple:
    # "Board" is the list's word, glossed once: a beginner knows the device.
    pinned = ["Choose the board, the chip of the device the games run on. "
              "Every board fits any device."]
    rows = tui_rows(state)
    if state.targets_problem:
        after = [state.targets_problem]
    elif state.targets_for != state.platform:
        after = ["Reading the board list..."]
    elif not rows:
        after = [f"{display_name(state.platform)} publishes no board list: every "
                 "board's files are installed."]
    else:
        after = []
    return ("Device", _compose(state, width, height, [], rows, after,
                               _status_footer(state), pinned),
            ("A/Enter Choose", "B/Esc Back", "? Help") if rows else ("B/Esc Back", "? Help"))


def _view_emulators(state: TuiState, width: int, height: int) -> tuple:
    pinned = ["Tick the emulators to install for. With none ticked, every "
              "emulator's files are installed."]
    return ("Emulators", _compose(state, width, height, [], tui_rows(state), [],
                                  _status_footer(state), pinned),
            _CHECKLIST_BAR)


def _middle_label(row: TuiRow, room: int) -> TuiRow:
    """A row naming a folder, the folder cut in its middle to fit."""
    name, _sep, value = row.label.partition(": ")
    return row._replace(label=f"{name}: " + middle(value, room - len(name) - 2), style="")


def _view_regions(state: TuiState, width: int, height: int) -> tuple:
    # An order, not a set: ticked all, it would rank regions nobody ranked.
    # None ticked keeps every region, said so.
    before = ["Tick the regions to keep, best first. Where a system has one BIOS "
              "per region, the best one found is installed. With none ticked, every "
              "region's BIOS is kept."]
    return ("Preferred regions",
            _compose(state, width, height, [], tui_rows(state), (), _status_footer(state),
                     before),
            (*_CHECKLIST_BAR[:2], "Left/Right Order", "? Help"))


# The bar of the three lists of ticks, one wording.
_CHECKLIST_BAR = ("A/Enter Tick", "B/Esc Done", "? Help")


def _status_footer(state: TuiState) -> list:
    return [_styled(str(state.status), "refusal")] if state.status else []


def _view_cores(state: TuiState, width: int, height: int) -> tuple:
    # Kept above a list that scrolls: dropped once the rows filled the
    # screen, 189 cores never said what unticking does.
    pinned = ["Untick the cores not in use: the platform's own files are always kept, "
              "and a core with no extra file reads only those."]
    return ("Cores", _compose(state, width, height, [], tui_rows(state), (),
                              _status_footer(state), pinned),
            _CHECKLIST_BAR)


_STATE_WORDS = {"missing": "missing", "wrong_hash": "wrong copy"}


def _pager_items(state: TuiState) -> list:
    """The text of a screen that scrolls, the same for its view and its keys."""
    if state.screen == "misplaced":
        return ["They are copied where the emulators read them. The copies found stay where "
                "they are.", ""] + [f"{event['dest']}: {event['reason']}"
                                    for event in _tui_misplaced(state)]
    if state.screen == "unreadable":
        return [f"{event['path']}" + (f", {event['member']}" if event["member"] else "")
                + f": {event['reason']}" for event in state.unreadable]
    if state.screen == "games":
        return games_pager_lines(state)
    if state.screen == "result":
        return _shown(state, tui_outcome(state)[1])
    if state.screen == "details":
        return details_lines(state)
    if state.screen == "command":
        return ["The same choice without questions:", "",
                _command_line(tui_command(state), tui_hint(state))]
    if state.running:
        items = ["Counting the files for these choices..."]
    elif state.dry is None:
        items = state.tail or ["The preview did not finish."]
    else:
        # From a pack nothing is downloaded, as the plan says.
        verb = "to install from the pack" if LOCAL.pack is not None else "to download"
        items = [f"{_plural(_needed(state.dry), 'file')} {verb}, "
                 f"{format_size(state.dry['bytes_needed'])}. Nothing is written.", ""]
        items += [f"{_STATE_WORDS.get(event['state'], event['state']):<10} "
                  f"{format_size(event['size']):>9}  {event['dest']}"
                  for event in state.dry_files]
        for kept in (state.dry_summary or {}).get("kept") or []:
            items.append(f"Replaced files would be kept in {kept['folder']}")
    return items


def _scroll(state: TuiState, items: list, width: int, height: int) -> tuple:
    """The bar's Scroll entry, only for a text taller than the screen: it
    was named over nine lines that fit, Down pressed 13 times doing nothing."""
    return ("Up/Down Scroll",) if _pager_starts(state, items, width)[-1] > height else ()


def _view_preview(state: TuiState, width: int, height: int) -> tuple:
    # The count and the blank line above the files are not among them.
    lead = 2 if state.dry is not None and not state.running else 0
    items = _pager_items(state)
    return ("Preview", _pager(state, width, height, items, lead),
            ("A/Enter Back", *_scroll(state, items, width, height)))


def _view_unreadable(state: TuiState, width: int, height: int) -> tuple:
    items = _pager_items(state)
    return ("Files that could not be read", _pager(state, width, height, items),
            ("A/Enter Back", *_scroll(state, items, width, height)))


def _view_games(state: TuiState, width: int, height: int) -> tuple:
    items = _pager_items(state)
    return (f"Games {games_where(state)}", _pager(state, width, height, items, 2),
            ("A/Enter Back", *_scroll(state, items, width, height)))


def _view_misplaced(state: TuiState, width: int, height: int) -> tuple:
    items = _pager_items(state)
    return ("Files in the wrong place", _pager(state, width, height, items, 2),
            ("A/Enter Back", *_scroll(state, items, width, height)))


def _view_command(state: TuiState, width: int, height: int) -> tuple:
    return ("Command line", _pager(state, width, height, _pager_items(state)),
            ("A/Enter Back",))


def _view_confirm(state: TuiState, width: int, height: int) -> tuple:
    if state.running or state.dry is None:
        # Nothing to install yet: "A/Enter Install" sat over a press that
        # did nothing, then a screen with Back alone.
        return ("Confirm", _compose(state, width, height,
                                    ["Counting the files for these choices..."], []),
                ("B/Esc Back", "? Help"))
    else:
        # Why this screen: the numbers above are counted again for the
        # systems and options chosen, the last look before anything is
        # written.
        lines = _shown(state, _confirm_text(state))
    if not any(row.action == "install" for row in tui_rows(state)) and state.dry is not None:
        # Back alone: one Back on the bar, and no word of an Install. Titled
        # for what it is: "Confirm" over nothing to confirm.
        return ("Nothing to install", _compose(state, width, height, lines, tui_rows(state)),
                ("A/Enter Back", "B/Esc Back", "? Help")
                if tui_rows(state)[0].action == "close" else ("A/Enter Back", "? Help"))
    return ("Confirm", _compose(state, width, height, lines, tui_rows(state)),
            ("A/Enter Install", "B/Esc Back", "? Help"))


def _confirm_text(state: TuiState) -> list:
    """Every line of Confirm, the Details lines among them."""
    lines = _plan_lines(state.dry or {}, state.dest, state)
    # The kinds apart, as the plan counts them, under the folder.
    data = (state.dry or {}).get("data_missing", 0)
    parts, _defined = _kinds_lines(state, state.dry_files, data,
                                   (state.dry or {}).get("data_bytes") if data else None)
    if parts:
        at = next((index + 1 for index, line in enumerate(lines)
                   if str(line).startswith(_FOLDER_LABEL)), len(lines))
        lines.insert(at, _detail(parts))
    if any(row.action == "install" for row in tui_rows(state)):
        lines.insert(0, "Counted again for these choices.")
        lines.insert(1, _detail("Nothing is written before Install."))
    return lines


def _bar(share: float, width: int) -> str:
    room = max(4, width - 7)
    filled = int(share * room)
    return f"[{'#' * filled}{'-' * (room - filled)}] {int(share * 100):3d}%"


def _view_installing(state: TuiState, width: int, height: int) -> tuple:
    lines: list = []
    if state.download is None:
        elapsed = format_duration(max(0.0, state.now - state.started))
        lines.append(_reading_line(state, elapsed))
    else:
        total = state.download["bytes"]
        progress = state.progress or {}
        done = progress.get("bytes_done", 0)
        lines.append(_bar(min(done / total, 1.0) if total else 1.0, width))
        lines.append(f"{format_size(done)} of {format_size(total)}")
        window = [sample for sample in state.samples if sample[0] >= state.now - 5]
        start, base = window[0] if window else (state.now, state.network)
        seconds = state.now - start
        speed = (state.network - base) / seconds if seconds >= 1 else 0
        if speed > 0:
            lines.append(f"{format_size(int(speed))}/s, "
                         f"{format_duration((total - done) / speed)} left")
        files_done = progress.get("files_done", 0)
        lines.append(f"{files_done} of {_plural(state.download['files'], 'file')}")
        if files_done >= state.download["files"] and state.summary is None:
            lines.append("Finishing...")
    stops = TUI_ROUTES.get(state.pad, TUI_ROUTES["both"]).stop
    # Plain: how to stop is no aside.
    lines.append(f"Stopping, finishing the files in flight. Press {stops[0]} "
                 "again to stop now." if state.stopping
                 else f"{stops[1]} stops. What is done stays done.")
    room = height - len(lines) - 1
    failed = [item for item in reversed(state.finished) if not item[1]]
    good = [item for item in reversed(state.finished) if item[1]] if tui_verbose(state) else []
    shown = (failed + good)[:max(0, room)]
    if shown:
        lines.append("")
        lines += [f"{'ok    ' if ok else 'FAILED'} {dest}" + (f" ({reason})" if reason else "")
                  for dest, ok, reason in shown]
    return ("Installing", _compose(state, width, height, lines, []),
            ("B/Esc Stop", "? Help"))


_SPACE_NEEDED = re.compile(r"Needed: (\S+ \S+)\. Free: (\S+ \S+)\.")


def _space_stop(state: TuiState) -> re.Match | None:
    """Needed and free, when the run stopped for lack of space."""
    return next(filter(None, (_SPACE_NEEDED.search(line) for line in state.tail)), None)


def _space_words(state: TuiState) -> str:
    """The run's stop for lack of space, in words, "" for another stop."""
    match = _space_stop(state)
    if match is None:
        return ""
    dest = (state.dest or Path(".")).absolute()
    card = any((mount == dest or mount in dest.parents) and card_system(mount)
               for mount in _mounted_cards())
    return f"The {'card' if card else 'drive'} is full: {match[1]} needed, {match[2]} free."


def _tui_sources(state: TuiState, installed: int, missing: int, wrong: int = 0,
                 failed: int = 0) -> str:
    """Where the installed files came from, as the line mode says it:
    "6 files copied from /media/me/OLD, 42 downloaded, 2 still missing." """
    ok = {dest for dest, good, _why in state.finished if good}
    folders: dict[str, int] = {}
    fixed = 0
    for dest, (folder, reason) in state.local_dests.items():
        if dest not in ok:
            continue
        if reason:
            fixed += 1
        else:
            # By its name, as the plan said "6 found in old card".
            name = _last_name(folder)
            folders[name] = folders.get(name, 0) + 1
    copied = fixed + sum(folders.values())
    return sources_line(list(folders.items()), fixed, max(0, installed - copied), missing,
                        "from the pack" if LOCAL.pack is not None else "downloaded",
                        wrong=wrong, failed=failed)


def _unavailable(state: TuiState) -> tuple[list[dict], int]:
    """The list's files RetroBIOS cannot supply for the systems chosen: the
    ones an emulator needs to start, and how many others."""
    listed = {row["system"] for row in state.systems}
    chosen = state.ticked if state.systems else None
    needed, others = [], 0
    for entry in (state.manifest or {}).get("omitted_files") or []:
        system = entry.get("system") if entry.get("system") in listed else OTHER_SYSTEMS
        if chosen is not None and system not in chosen:
            continue
        if state.no_game_data and entry.get("category") == "game_data":
            continue
        if entry.get("required"):
            needed.append(entry)
        else:
            others += 1
    return needed, others


def _found_lines(state: TuiState) -> list[TuiLine]:
    """What the setups screen said of this machine, on a plan that opened
    in its place: the setup found by its label, and the notes (ES-DE found,
    what detection printed) on Details, one line on the plan saying so."""
    if not state.opened_on_plan or not state.setups:
        return []
    lines = _details([f"Found here: {state.setups[0][2]}.", *state.notes])
    if state.notes:
        brief = _styled(f"{_plural(len(state.notes), 'note')} on this machine: Details.")
        brief.brief = True
        lines.insert(0, brief)
    return lines


def _unavailable_brief(state: TuiState) -> list[TuiLine]:
    """The count of the files an emulator needs that cannot be supplied, on
    the screen itself: their names are on Details, and in place with
    --verbose, where the count is not said again."""
    needed, _others = _unavailable(state)
    if not needed:
        return []
    line = _styled(needed_absent_words(len(needed), "Details"))
    line.brief = True
    return [line]


def _unavailable_lines(state: TuiState) -> list[str]:
    """The files that cannot be supplied and stop an emulator, by name and
    system: "1 file ... an emulator needs it" named neither."""
    needed, _others = _unavailable(state)
    return unavailable_lines(needed, state.manifest, state.dest,
                             (state.manifest or {}).get("files") or [])


class _OutcomeCounts(NamedTuple):
    """What an install run reported, as its result counts it."""
    summary: dict
    installed: int
    failed: list
    offline_failed: list
    left: int
    up_to_date: int
    total: int
    space: str
    errors: str


def _outcome_counts(state: TuiState) -> _OutcomeCounts:
    summary = state.summary or {}
    # Killed by the second Ctrl-C, the child wrote no summary: what it
    # reported finished is what is installed.
    installed = summary.get("installed", sum(1 for _dest, ok, _why in state.finished if ok))
    failed = summary.get("failed") or []
    # Left out by --offline: missing, never failed, as line mode says it.
    # The engine counts them in pending and no longer in failed (a file was
    # both): pending holds the real failures too, which are taken out.
    offline_failed = [failure for failure in failed if _offline_failure(failure["reason"])]
    failed = [failure for failure in failed if not _offline_failure(failure["reason"])]
    left = len(offline_failed) + (max(0, summary.get("pending", 0) - len(failed))
                                  if _offline_only() and not offline_failed else 0)
    up_to_date = summary.get("up_to_date", 0)
    total = (state.download or {}).get("files", 0)
    space = "" if summary else _space_words(state)
    errors = f", {len(failed)} failed" if failed else ""
    return _OutcomeCounts(summary, installed, failed, offline_failed, left, up_to_date, total,
                          space, errors)


def _done_head(state: TuiState, counts: _OutcomeCounts) -> str:
    installed = counts.installed
    # With the sources line below, the count alone: "23 installed from
    # the pack" sat above "21 from the pack".
    source = (" from the pack" if LOCAL.pack is not None
              and not _tui_sources(state, installed, 0) else "")
    # The plan said the wrong copies are replaced: the result counts them.
    replaced = sum(kept.get("files", 0) for kept in counts.summary.get("kept") or [])
    # One kind is named in the count, not on a line of its own: "78
    # files installed" above "Installed: 78 BIOS files".
    word = "BIOS file" if _one_kind(state, installed) else "file"
    head = (f"{_plural(installed, word)} installed{source}"
            + (f", {replaced} of them replaced" if replaced else "") + ".")
    if counts.up_to_date:
        head += f" {_plural(counts.up_to_date, 'file')} already in place."
    return head


def _outcome_head(state: TuiState, counts: _OutcomeCounts) -> tuple[str, str]:
    """The result's title and its first line."""
    summary, installed, failed, left = (counts.summary, counts.installed, counts.failed,
                                        counts.left)
    errors, total = counts.errors, counts.total
    if summary.get("interrupted") or state.code == 130:
        return "Stopped", (f"Stopped: {installed} of {total} installed, run again to finish."
                           if total
                           else "Stopped. Run again to carry on: what is done stays done.")
    if left and installed:
        return ("Finished with files missing",
                f"{installed} installed, {left} not fetched ({offline_named()}){errors}.")
    if left:
        return ("Nothing installed",
                f"Nothing was installed: {_plural(left, 'file')} not fetched "
                f"({offline_named()}){errors}.")
    if failed and installed:
        return "Finished with errors", f"{installed} installed, {len(failed)} failed."
    if failed:
        return "Nothing installed", f"Nothing was installed: {_plural(len(failed), 'file')} failed."
    if not summary and counts.space:
        return "Not enough space", counts.space
    if not summary:
        return "Stopped", f"The installer stopped with code {state.code}."
    if installed:
        return "Done", _done_head(state, counts)
    return "Done", EVERYTHING_IN_PLACE


def _outcome_counted(state: TuiState, counts: _OutcomeCounts, title: str,
                     head: str) -> list[str]:
    """The head, then where the files came from and what is still missing."""
    installed, failed, left = counts.installed, counts.failed, counts.left
    lines = [head]
    ok_dests = {dest for dest, good, _why in state.finished if good}
    missing = ([failure["dest"] for failure in counts.offline_failed]
               or [event["dest"] for event in state.files
                   if event["dest"] not in ok_dests][:left]) if left else []
    # A wrong copy left in place is no missing file: --check counts it apart,
    # and the result said "1 still missing" of it.
    wrong_dests = {event["dest"] for event in state.files if event.get("state") == "wrong_hash"}
    wrong_left = sum(1 for dest in missing if dest in wrong_dests)
    sources = _tui_sources(state, installed, left - wrong_left, wrong_left, len(failed))
    if (left or failed) and installed and sources:
        # One count, then the remedy, as line mode says it: the count came
        # twice, the remedy between them.
        lines[0] = sources
        sources = ""
    elif title == "Done" and sources and "," not in sources and not counts.summary.get("kept"):
        # Every file from one place: "22 files installed." over "22 files
        # copied from packx." said one count twice.
        lines[0] = sources + head[head.index(".") + 1:]
        sources = ""
    if sources:
        lines.append(sources)
    if left:
        # What is still missing by kind, as the copies are counted: 6 of the
        # 16 were game data, and the old card's result said 16 files.
        apart = _tui_tally(state, [{"dest": dest, "size": 0} for dest in missing
                                   if dest not in wrong_dests])
        if _tui_categories(state) and apart.bios and apart.games:
            lines.append(_detail(f"Still missing: {installed_words(apart.bios, apart.games)}."))
        # Each folder spelled in full, as the result names its others.
        lines.append(_offline_remedy([shown_path(folder) for folder in state.from_folders]))
    return lines


def _outcome_placed(state: TuiState, counts: _OutcomeCounts, title: str) -> list[str]:
    """What was installed by kind, the BIOS folder and what goes with it."""
    installed, up_to_date = counts.installed, counts.up_to_date
    lines: list[str] = []
    ok = {dest for dest, good, _why in state.finished if good}
    if any(reason and dest in ok for dest, (_folder, reason) in state.local_dests.items()):
        # A fix copies: the misplaced files are the user's, never moved.
        lines.append(_detail("The copies in the wrong place were left as they are."))
    if _tui_categories(state) and title != "Stopped" and installed:
        # As the plan counted them, and as line mode ends, on every result:
        # the old card's said "6 files copied" and no kind. The data tree
        # files are the installed ones no file event names.
        done = _tui_tally(state, [{"dest": dest, "size": 0}
                                  for dest, good, _why in state.finished if good])
        if done.files and not (title == "Done" and _one_kind(state, installed)):
            lines.append(_detail("Installed: " + installed_words(
                done.bios, done.games, max(0, installed - done.files)) + "."))
    # The folder the plan named: MinUI's Bios, not the card's root.
    lines.append(f"BIOS folder: {shown_path(str(_plan_folder(state, state.dest)))}")
    if installed + up_to_date:
        # Spelled as the BIOS folder above it is, whole: "~/" beside a full
        # path was two spellings on one screen.
        lines += _details(_saves_lines(state, state.done_saves, whole=True))
    if state.version:
        # Said again with the result, as line mode ends: the system's own
        # BIOS check may mark the files just put in place.
        lines.append(state.version)
    if state.platform == "romm" and installed:
        lines.append(ROMM_SCAN_WORDS)
    fallback = (state.games or {}).get("fallback") or [] if state.for_games else []
    if fallback:
        # Named with the result, as line mode ends: they got every BIOS of
        # their system, so that they start.
        names = ", ".join(str(item.get("name")) for item in fallback[:3])
        more = f" and {len(fallback) - 3} more" if len(fallback) > 3 else ""
        their = "its" if len(fallback) == 1 else "their"
        lines.append(_detail(f"Not recognised, every BIOS of {their} system kept: "
                             f"{names}{more}."))
    if counts.space:
        lines.append("Free some space on the card, then run again." if _on_its_card(state)
                     else "Free some space, or run again and choose another folder.")
    return lines


def _failure_lines(failed: list) -> list[str]:
    """Each file that failed with its reason, a reason shared by many said once."""
    lines: list[str] = []
    causes: dict[str, list[str]] = {}
    for failure in failed:
        causes.setdefault(failure["reason"], []).append(failure["dest"])
    shown = 0
    for reason, dests in causes.items():
        if len(dests) > 3:
            # A read-only folder fails every file alike: said once.
            lines.append(f"  {len(dests)} files failed, all for one reason: "
                         f"{reason or 'none given'}.")
            continue
        for dest in dests:
            if shown < 20:
                lines.append(f"  failed: {dest}" + (f" ({reason})" if reason else ""))
            shown += 1
    if shown > 20:
        lines.append(f"  ... and {shown - 20} more")
    return lines


def _retry_lines(failed: list) -> list[str]:
    # What a rerun does, as line mode and the first install page say
    # it: the screen never did.
    pairs = [(failure["dest"], failure["reason"]) for failure in failed]
    retry = _retry_words(pairs)
    if retry:
        return [retry]
    if not all(str(reason).startswith(NOT_KEPT) for _dest, reason in pairs):
        return ["Run it again to retry only those."]
    return []


def _outcome_unfinished(state: TuiState, counts: _OutcomeCounts, title: str) -> list[str]:
    """The data files not installed, the remedy for a folder not written,
    and the log of a run that died."""
    summary, installed, failed = counts.summary, counts.installed, counts.failed
    lines: list[str] = []
    expected = (state.dry if state.dry is not None else state.check or {}).get(
        "data_missing", 0)
    landed = max(0, installed - sum(1 for _dest, good, _why in state.finished if good))
    if expected > landed and not counts.left and title != "Stopped" and summary:
        # The data files the plan counted, never named on a result that
        # counted the BIOS files alone.
        lines.append(_detail(f"{_plural(expected - landed, 'data file')} not installed"
                             + (f": not in {LOCAL.pack.name}." if LOCAL.pack is not None
                                else ".")))
    if state.dest is not None and any(failure["reason"] == NOT_WRITABLE
                                      for failure in failed):
        # The plan's own advice: the result offered nothing after 22 files
        # failed on a read-only card.
        lines += _commands(state, write_remedy(state.dest, state.platform, tui_hint(state),
                                               state.pad not in TUI_PAD_ROUTES))
    if not summary and not counts.space and state.code != 130:
        # A stop asked for (Ctrl-C, Select+Start, the window closed) is said
        # by the line above: the log's last lines are for a run that died.
        lines += [f"  {line}" for line in state.tail[-8:]]
    return lines


def _outcome_closing(state: TuiState, counts: _OutcomeCounts, title: str) -> list[str]:
    """The backups, the files left out, the next step and the command."""
    summary, installed = counts.summary, counts.installed
    lines: list[str] = []
    run = Invocation()
    run.os_type = state.os_type
    # A controller cannot type a command: on a pad route none is printed,
    # the result of a muOS install ended on four lines of shell.
    typed = state.pad not in TUI_PAD_ROUTES
    for kept in summary.get("kept") or []:
        lines.append(f"The files it replaced are kept in {kept['folder']}")
        if typed:
            # Broken between its words only, never inside one (_wrap).
            lines += _details([_command_line(f"To put them back: {run.launcher()} --restore "
                                             f"{run.word(str(kept['folder']))}", run)])
    if summary and not summary.get("interrupted") and installed + counts.up_to_date:
        lines += _unavailable_brief(state) + _details(_unavailable_lines(state))
    for group in summary.get("left_out") or []:
        lines.append(_detail(f"{left_out_words(group)}."))
    lines += _unplaced_lines(summary, state)
    lines += _tui_app_lines(state)
    if title == "Done" and not (state.platform == "romm" and installed):
        # Last of what the result says by default: RomM's scan is its step.
        lines.append(tui_next_words(state))
    if typed:
        lines += _details(["Same choice without questions:",
                           _command_line(f"  {tui_command(state)}", tui_hint(state))])
    if tui_keeps_log(state):
        lines.append(f"Log: {state.log}")
    if state.mouse and typed:
        # A drag over the command selected nothing: the terminal sends the
        # press as a report. Said where it is read.
        lines.append(_detail(TUI_RESULT_AGAIN if state.os_type == "android"
                             else TUI_RESULT_COPY, "dim"))
    return lines


def tui_outcome(state: TuiState) -> tuple[str, list[str]]:
    """The result in words, first what happened, then where and what next."""
    counts = _outcome_counts(state)
    if state.dest_error is not None:
        return _dest_error_outcome(state, counts.installed)
    title, head = _outcome_head(state, counts)
    lines = _outcome_counted(state, counts, title, head)
    lines += _outcome_placed(state, counts, title)
    lines += _failure_lines(counts.failed)
    if title == "Finished with errors":
        lines += _retry_lines(counts.failed)
    lines += _outcome_unfinished(state, counts, title)
    lines += _outcome_closing(state, counts, title)
    return title, lines


def tui_next_words(state: TuiState) -> str:
    """The step after an install the result says went well."""
    if _on_its_card(state):
        return NEXT_ON_CARD
    if state.dest is not None and detected_os(state.platform, state.dest):
        return NEXT_ON_DEVICE
    return f"Next: start {display_name(state.platform, state.manifest)} and play."


def _dest_error_outcome(state: TuiState, installed: int) -> tuple[str, list[str]]:
    """The result of a run whose BIOS folder could not be created: that
    reason for every file, and its remedy. It said "22 files not fetched
    (RETROBIOS_INSTALL_OFFLINE=1)" and sent the user for a pack holding all
    22."""
    message = str((state.dest_error or {}).get("message", ""))
    folder = shown_path(str(_plan_folder(state, state.dest)))
    _where, _sep, why = message.rpartition(": ")
    head = (f"Nothing was installed: {folder} cannot be created ({why.lower() or 'no reason'})."
            if not installed else f"{installed} installed, then {folder} could not be "
            f"created ({why.lower() or 'no reason'}).")
    lines = [head]
    remedy = (write_remedy(state.dest, state.platform, tui_hint(state),
                           state.pad not in TUI_PAD_ROUTES) if state.dest is not None else [])
    if not remedy or str(remedy[0]).startswith("Or "):
        lines.append("Run it again and choose another folder.")
    lines += _commands(state, remedy)
    if state.pad not in TUI_PAD_ROUTES:
        lines += _details(["Same choice without questions:",
                           _command_line(f"  {tui_command(state)}", tui_hint(state))])
    if tui_keeps_log(state):
        lines.append(f"Log: {state.log}")
    return ("Nothing installed" if not installed else "Finished with errors"), lines


# How to copy from the result, under its command while the mouse is on.
# Termux has no Shift key under a finger: there the second sentence alone.
TUI_RESULT_AGAIN = "All of this is shown again in the terminal after Exit."
TUI_RESULT_COPY = f"Shift and a drag select text. {TUI_RESULT_AGAIN}"


def _one_kind(state: TuiState, installed: int) -> bool:
    """Whether every file a run installed is a BIOS file of a list that
    marks its kinds: the count then names the kind."""
    if not _tui_categories(state):
        return False
    done = _tui_tally(state, [{"dest": dest, "size": 0}
                              for dest, good, _why in state.finished if good])
    return bool(done.files) and done.files == installed and not done.games


def _tui_app_lines(state: TuiState) -> list[str]:
    """What became of the RetroBIOS app on the card, once the install finished."""
    card = _tui_card(state)
    if card is None:
        return []
    if state.app_running:
        return ["Putting RetroBIOS on the card..."]
    if state.app is not None:
        return app_lines(card, state.app)
    if card.place is None and card.system in NO_PYTHON_CARDS and _tui_installed(state):
        return [no_python_words(card.system)]
    return []


def tui_keeps_log(state: TuiState) -> bool:
    """Whether the run's log is kept: when a failure names it, and only then.
    57 folders of logs from stopped and finished runs were left in /tmp."""
    if state.screen == "crashed":
        return True
    # A full card is said in words on the screen: its log adds nothing.
    return (bool(state.log) and state.code not in (0, 130, None)
            and _space_stop(state) is None)


def details_lines(state: TuiState) -> list:
    """What the screen under Details leaves out: its explanations, lists
    and reasons."""
    if len(state.stack) < 2:
        return ["Nothing more to say here."]
    # Read as the screen under it reads itself: its rows, its words.
    top = state.stack.pop()
    try:
        under = state.screen
        lines = (_plan_text(state) if under == "plan"
                 else _confirm_text(state) if under == "confirm"
                 else _removal_text(state) if under == "removal"
                 else tui_action_outcome(state) if under == "actdone"
                 else tui_outcome(state)[1] if under == "result" else [])
    finally:
        state.stack.append(top)
    return [line for line in lines if _is_detail(line)] or ["Nothing more to say here."]


def _removal_text(state: TuiState) -> list:
    """The removal plan: what goes and the space freed, where, what stays
    and why, the files themselves behind Details."""
    plan = state.removal or {}
    folder = _short_path(state.dest, state.home)
    if not plan.get("files"):
        lines: list = ["No copy in the wrong place." if _removing_misplaced(state)
                       else "Nothing here can be removed."]
    elif _removing_misplaced(state):
        lines = [f"{_plural(plan['files'], 'copy')} in the wrong place go, "
                 f"{format_size(plan['bytes'])} freed. The files where the cores read "
                 "them stay."]
    elif state.removal_backup:
        lines = [f"{_plural(plan['files'], 'file')} to a backup, "
                 f"{format_size(plan['bytes'])}."]
    else:
        lines = [f"{_plural(plan['files'], 'file')} go, {format_size(plan['bytes'])} freed."]
    lines.append(_styled(f"{_FOLDER_LABEL}{folder}", "path"))
    kept = plan.get("kept") or []
    if kept:
        lines.append(f"{agree(len(kept), 'file stays', 'files stay')}: "
                     f"{_kept_words([{**item, 'what': ''} for item in kept])}.")
    if not plan.get("files") and plan.get("message") and not kept:
        lines.append(_detail(str(plan["message"])))
    lines += _details(["", "Removed:"] + [f"  {dest}" for dest in plan.get("dests") or []]
                      if plan.get("dests") else [])
    lines += _details(["", "Left as they are:"] + [
        f"  {kept_line({**item, 'what': ''})}" for item in kept] if kept else [])
    return lines


def tui_action_outcome(state: TuiState) -> list:
    """What a More action did, in one line, then where."""
    events = state.action_events
    done = [event for event in events if event.get("ok", True)]
    failed = [event for event in events if not event.get("ok", True)]
    size = format_size(sum(int(event.get("size") or 0) for event in done))
    if state.action == "remove" and state.removal_backup:
        lines: list = [f"Moved {_plural(len(done), 'file')} to a backup, {size}."]
    elif state.action == "remove":
        lines = [f"Removed {_plural(len(done), 'file')}, {size} freed."]
    elif state.action == "restore":
        lines = [f"Put back {_plural(len(done), 'file')}, {size}."]
    else:
        gone = next((event for event in events if event.get("status") == "deleted"), None)
        lines = ([f"Deleted the backup, {format_size(int(gone['bytes']))} freed."]
                 if gone is not None else ["The backup was not deleted."])
    if failed:
        lines.append(_styled(f"{_plural(len(failed), 'file')} failed.", "failure"))
        lines += _details([f"  {event.get('dest') or event.get('path')}: {event['reason']}"
                           for event in failed])
    lines.append(_styled(f"{_FOLDER_LABEL}{_short_path(state.dest, state.home)}", "path"))
    return lines


# The result's remedy for the save files left out, as the terminal says it
# once the screen is gone: Options are not there to choose from
# Line mode's words.
TUI_SAVE_REMEDY = "Choose it in Change, Save folder (--save-dir), next time."
