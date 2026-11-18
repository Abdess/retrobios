"""Keys, taps and the events of a child run, turned into a new state."""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from installer.detect_os import detect_board
from installer.embedded import display_name
from installer.line_ui import TUI_MIN_COLS
from installer.removal import list_backups
from installer.run import TUI_MIN_ROWS
from installer.setups import TuiRow
from installer.tui_actions import (
    _activate,
    _checklist,
    _device_focus,
    _filter_key,
    _install_now,
    _known_choice,
    _move_region,
    _option,
    _page_step,
    _pager_key,
    _pager_last,
    _path_key,
    _same_plan,
    _tick,
    _toggle_region,
    _tui_folder_facts,
    tui_interrupt,
    tui_quit,
)
from installer.tui_results import _action_ended, _fail, _open_details, _take_action_event, tui_view
from installer.tui_rows import (
    TUI_TICK_ROWS,
    _CHECKLISTS,
    _PAGERS,
    _back,
    _first_item,
    _focus_plan,
    _needed,
    _push,
    _replace,
    _start_check,
    _start_run,
    tui_rows,
)
from installer.tui_state import TUI_ACTION_RUNS, TuiState, _tui_standalone_fits
from installer.tui_text import TuiKey, TuiMouse, _styled
from installer.tui_view import _armed, _bar_commits, _pager_items

if TYPE_CHECKING:
    from installer.tui_session import TuiHits


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


def _take_scan_event(state: TuiState, kind: str | None, event: dict) -> bool:
    """A check run's reading of the folder: games, files found, choices."""
    if kind == "games":
        state.games = event
    elif kind == "games_unavailable":
        state.games_unavailable = event
    elif kind == "found":
        state.found.append(event)
    elif kind == "scanned":
        state.scanned.append(event)
    elif kind == "unreadable":
        state.unreadable.append(event)
    elif kind == "choices":
        state.choices = list(event["systems"])
    elif kind == "set_aside":
        state.set_aside = set(event["dests"])
    else:
        return False
    return True


def _take_check_event(state: TuiState, kind: str | None, event: dict) -> None:
    if _take_scan_event(state, kind, event):
        return
    if kind == "board":
        state.board = str(event["message"])
        # Read on the device itself, or named by the card in a reader: a
        # computer preparing a card has no board of its own.
        state.board_seen = (state.platform, state.dest, str(event["board"]),
                            bool(event["applied"]), detect_board(state.platform) is not None)
    elif kind == "version":
        state.version = str(event["message"])
        state.version_short = (f"List for {display_name(state.platform, state.manifest)} "
                               f"{event['list_version']}, this is "
                               f"{event['installed_version']}.")
    elif kind == "saves":
        state.saves = event
    elif kind == "data" and state.check is not None:
        state.check["data_bytes"] = event["bytes"]
    elif kind == "check":
        state.check = event
    elif kind == "file":
        state.checked_dests.add(event.get("dest"))
        if event.get("state") != "present":
            state.files.append(event)
    elif kind == "system":
        state.systems.append(event)
    elif kind == "summary":
        state.check_summary = event


def _take_dry_event(state: TuiState, kind: str | None, event: dict) -> None:
    if kind == "saves":
        state.dry_saves = event
    elif kind == "data" and state.dry is not None:
        state.dry["data_bytes"] = event["bytes"]
    elif kind == "check":
        state.dry = event
    elif kind == "file" and event.get("state") != "present":
        state.dry_files.append(event)
    elif kind == "summary":
        state.dry_summary = event


def _take_install_event(state: TuiState, kind: str | None, event: dict) -> None:
    if kind == "app":
        state.app = event
    elif kind == "error" and event.get("stage") == "dest":
        # The BIOS folder could not be created: every file fails for that
        # one reason, said as it happened.
        state.dest_error = event
    elif kind == "saves":
        state.done_saves = event
    elif kind == "found":
        state.local_dests[event["dest"]] = (event["folder"], event["reason"])
    elif kind == "download":
        state.download = event
    elif kind == "transfer":
        state.network = event["bytes_network"]
        state.samples = [sample for sample in state.samples
                         if sample[0] >= state.now - 10] + [(state.now, state.network)]
    elif kind in ("progress", "downloaded"):
        state.progress = event
        if kind == "downloaded":
            state.finished.append((event["dest"], event["ok"], event["reason"]))
    elif kind == "summary":
        state.summary = event


def _take_event(state: TuiState, event: dict) -> None:
    if _take_action_event(state, event):
        return
    kind = event.get("event")
    if kind == "checking" and state.run in ("check", "install"):
        state.reading = (event["files_done"], event["files_total"])
    elif kind == "games_reading" and state.run in ("check", "install"):
        state.games_reading = (event["files_done"], event["files_total"])
    elif state.run == "check":
        _take_check_event(state, kind, event)
    elif state.run in ("confirm", "preview"):
        _take_dry_event(state, kind, event)
    elif state.run == "install":
        _take_install_event(state, kind, event)


def _receive_games_here(state: TuiState, message: tuple) -> list[tuple]:
    _kind, plat, dest, count = message
    if plat == state.platform and dest == state.dest:
        state.games_probed = (plat, dest)
        if state.games_choice not in ("user", "cli", "record"):
            state.games_here = count or 0
            state.for_games, state.games_choice = bool(count), "probe"
    return []


def _receive_manifest(state: TuiState, message: tuple) -> list[tuple]:
    _kind, plat, manifest = message
    if plat != state.platform or state.screen != "checking":
        return []
    state.manifest, state.manifest_for = manifest, plat
    _known_choice(state, plat, manifest)
    if state.games_probed is None:
        state.games_probed = (plat, state.dest)
    return _start_run(state, "check")


def _receive_targets(state: TuiState, message: tuple) -> list[tuple]:
    _kind, plat, targets, problem = message
    if plat == state.platform:
        # Held only once read: a list that could not be read is fetched
        # again the next time Device opens.
        state.targets, state.targets_problem = targets, problem
        state.targets_for = plat if targets is not None else ""
        if state.screen == "device":
            state.focus["device"] = _device_focus(state)
    return []


def _receive_pack_opened(state: TuiState, message: tuple) -> list[tuple]:
    _kind, path, pack, problem = message
    if state.screen != "browse" or state.browse_for != "pack":
        # Left before it opened: never read, closed.
        return [("close_pack", pack)] if pack is not None else []
    if problem:
        state.status = _styled(problem, "refusal")
        return []
    # The pack's own list, as --from-pack reads it: the list fetched
    # before is fetched again from the pack.
    state.packs = [path]
    state.browse_for = "dest"
    state.manifest, state.manifest_for = None, ""
    if not state.manifest_given:
        state.manifest_path = None
    state.targets_for = ""
    return [("use_pack", pack), *_start_check(state)]


def _receive_app(state: TuiState, message: tuple) -> list[tuple]:
    # Put from the result screen, in this process.
    state.app, state.app_running = message[1], False
    if not state.app["ok"] and state.code == 0:
        state.code = 1
    return []


def _receive_manifest_failed(state: TuiState, message: tuple) -> list[tuple]:
    _kind, plat, title, lines, code = message
    if plat != state.platform or state.screen != "checking":
        return []
    _fail(state, lines, code)
    state.error_title = title
    return []


_TUI_RECEIVERS: dict[str, Callable[[TuiState, tuple], list[tuple]]] = {
    "games_here": _receive_games_here,
    "manifest": _receive_manifest,
    "targets": _receive_targets,
    "pack_opened": _receive_pack_opened,
    "app": _receive_app,
    "manifest_failed": _receive_manifest_failed,
}


def _check_ended(state: TuiState, code: int, tail: list[str]) -> list[tuple]:
    if state.check is None:
        return _fail(state, tail, code)
    state.ticked = {row["system"] for row in state.systems if _needed(row)}
    state.emptied = []
    state.hidden_ticks = set()
    if state.keep_ticked is not None:
        listed = {row["system"] for row in state.systems}
        state.ticked = state.keep_ticked & listed
        state.hidden_ticks = state.keep_ticked - listed
        if state.keep_ticked and not state.ticked:
            # Every system chosen holds nothing under these options:
            # said, never taken as every system.
            state.emptied = sorted(state.ticked_names.get(name, name)
                                   for name in state.keep_ticked)
        state.keep_ticked = None
    state.facts = _tui_folder_facts(state)
    state.has_backups = state.dest is not None and bool(list_backups(state.dest))
    _replace(state, "plan")
    refocus, state.refocus = state.refocus, ""
    _focus_plan(state, refocus)
    if state.widen:
        state.widen = False
        plan = tui_rows(state)
        row = next((row for row in plan if row.action == "systems"), None)
        if row is not None:
            return _activate(state, row)
    return []


def tui_receive(state: TuiState, message: tuple) -> list[tuple]:
    """What the file list fetch and the child runs report back."""
    kind = message[0]
    receiver = _TUI_RECEIVERS.get(kind)
    if receiver is not None:
        return receiver(state, message)
    _kind, run_id, *rest = message
    if run_id != state.run_id:
        return []
    if kind == "event":
        _take_event(state, rest[0])
        return []
    code, tail = rest
    state.running = False
    state.tail = [line for line in tail if not line.startswith("RetroBIOS ")]
    tail = state.tail
    if state.run in TUI_ACTION_RUNS:
        return _action_ended(state, code, tail)
    if state.run == "check":
        return _check_ended(state, code, tail)
    if state.run == "confirm" and state.screen == "confirm":
        if state.dry is None:
            return _fail(state, tail, code)
        if _same_plan(state.check, state.dry) and not state.must_confirm:
            state.stack.pop()
            return _install_now(state)
    elif state.run == "install":
        state.code = 130 if state.stopping and code < 0 else code if code >= 0 else 128 - code
        _replace(state, "result")
    return []
