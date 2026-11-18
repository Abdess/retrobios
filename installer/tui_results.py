"""The result, removal, pack and help screens, and the view that draws every screen."""
from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

from installer.embedded import display_name, shown_path
from installer.line_ui import TUI_MIN_COLS, _pad
from installer.outcome import _SHORT_DEFINITIONS
from installer.removal import backup_words
from installer.run import TUI_MAX_WIDTH, TUI_MIN_ROWS
from installer.setups import TuiRow
from installer.text import _plural, _wrap, cell_width, fit, format_size
from installer.tui_rows import _CHECKLISTS, _PAGERS, _push, _replace, tui_rows
from installer.tui_state import TUI_PAD_ROUTES, TUI_ROUTES, TuiState, _removing_misplaced
from installer.tui_text import TuiKey, _details, _short_path, _styled
from installer.tui_view import (
    TUI_LONG_LIST,
    _ROW_VERBS,
    _armed,
    _back_hint,
    _compose,
    _hint,
    _pager,
    _pager_items,
    _removal_text,
    _route_hint,
    _screen_definition,
    _scroll,
    _scrolled,
    _shown,
    _status_footer,
    _tap_hint,
    _text_lines,
    _view_browse,
    _view_cardroot,
    _view_checking,
    _view_command,
    _view_confirm,
    _view_cores,
    _view_create,
    _view_device,
    _view_emulators,
    _view_folder,
    _view_games,
    _view_installing,
    _view_misplaced,
    _view_options,
    _view_path,
    _view_plan,
    _view_platforms,
    _view_preview,
    _view_regions,
    _view_setup,
    _view_systems,
    _view_unreadable,
    armed_words,
    tui_action_outcome,
    tui_outcome,
)


def _fail(state: TuiState, lines: list[str], code: int) -> list[tuple]:
    state.error_title = ""
    state.error = [line for line in lines if line.strip()] or [
        f"The installer stopped with code {code} and said nothing."]
    state.error_code = code or 1
    state.running = False
    _replace(state, "error")
    return []


def _only_match(state: TuiState) -> TuiRow | None:
    """The one setup the filter leaves, when it leaves one."""
    if state.screen != "platforms" or not state.filters.get("platforms"):
        return None
    rows = [row for row in tui_rows(state) if row.action != "filter"]
    return rows[0] if len(rows) == 1 else None


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


def _view_result(state: TuiState, width: int, height: int) -> tuple:
    title, lines = tui_outcome(state)
    lines = _shown(state, lines)
    # The outcome in bold, its counts in their roles: it led a list of
    # lines drawn alike.
    lines[0] = _styled(lines[0], "title")
    rows = tui_rows(state)
    if rows:
        focused = rows[max(0, min(state.focus.get(state.screen, 0), len(rows) - 1))]
        # Exit in focus: A says it, and B saying it again named one action
        # twice.
        return (title, _compose(state, width, height, lines, rows),
                ("A/Enter Choose",) if focused.action == "exit"
                else ("A/Enter Choose", "B/Esc Exit"))
    if state.app_running:
        return (title, _pager(state, width, height, lines), ("Writing to the card...",))
    return (title, _pager(state, width, height, lines),
            ("A/Enter Exit", "Y/o Details", *_scroll(state, lines, width, height)))


def _view_error(state: TuiState, width: int, height: int) -> tuple:
    """The message and its rows. A message longer than the room the rows
    leave scrolls, with a line saying which lines are in view: at 40x12 the
    offline screen dropped its remedy without a word."""
    rows = tui_rows(state)
    text = _text_lines(list(state.error), width)
    room = height - len(rows) - (1 if rows else 0)
    hint: tuple = ("A/Enter Choose", "B/Esc Back")
    if len(text) > room >= 2:
        first = max(0, min(state.focus.get("error_text", 0), len(text) - (room - 1)))
        state.focus["error_text"] = first
        text = _scrolled(text, first, room)
        text[-1].mark = ("scroll", "error", 0)
        page = (TUI_ROUTES.get(state.pad, TUI_ROUTES["both"]).help["page"]
                or "PgUp/PgDn").split(", ")[0]
        hint += (f"{page} Scroll",)
    return (state.error_title or "Something went wrong",
            _compose(state, width, height, text, rows), hint)


def _view_quit(state: TuiState, width: int, height: int) -> tuple:
    rows = tui_rows(state)
    focus = max(0, min(state.focus.get("quit", 0), len(rows) - 1))
    # On Stay, A says Stay: a second "B/Esc Stay" beside it named one choice
    # twice.
    hint = (("A/Enter Choose",) if rows[focus].action == "stay"
            else ("A/Enter Choose", "B/Esc Stay"))
    return ("Quit?",
            _compose(state, width, height, ["Quit without installing? Nothing was written."],
                     rows), hint)


def _view_details(state: TuiState, width: int, height: int) -> tuple:
    items = _pager_items(state)
    return ("Details", _pager(state, width, height, items),
            ("A/Enter Back", *_scroll(state, items, width, height)))


def _open_details(state: TuiState) -> list[tuple]:
    if state.screen == "result":
        # Looked at, they are said again in the terminal after Exit.
        state.details_seen = True
    return _push(state, "details")


def _take_action_event(state: TuiState, event: dict) -> bool:
    """An event of a More run, kept for its screen: whether it was one."""
    kind = event.get("event")
    if kind == "pack" and state.run == "pack_plan":
        state.pack_plan = event
    elif kind == "pack" and state.run == "pack":
        state.pack_done = event
    elif kind in ("progress", "downloaded") and state.run == "pack":
        state.pack_fetched = (int(event["files_done"]), int(event["files_total"]))
    elif kind == "removal_plan" and state.run in ("removal_plan", "remove"):
        state.removal = event
    elif kind == "backup" and state.run == "backups":
        state.backups = [*(state.backups or []), event]
    elif kind in ("removed", "restored", "backup") and state.run in (
            "remove", "restore", "delete_backup"):
        state.action_events.append(event)
    else:
        return False
    return True


def _action_ended(state: TuiState, code: int, tail: list[str]) -> list[tuple]:
    """A More run's end: the plan, the list, or what the action did."""
    if state.run == "pack_plan":
        return _fail(state, tail, code) if state.pack_plan is None else []
    if state.run == "pack":
        state.pack_code = code if code >= 0 else 128 - code
        return []
    if state.run == "removal_plan":
        if state.removal is None:
            return _fail(state, tail, code)
        return []
    if state.run == "backups":
        if state.backups is None and code:
            return _fail(state, tail, code)
        state.backups = state.backups or []
        return []
    state.action_code = code if code >= 0 else 128 - code
    return []


def _view_more(state: TuiState, width: int, height: int) -> tuple:
    return ("More", _compose(state, width, height, [], tui_rows(state),
                             [], _status_footer(state)),
            ("A/Enter Open", "B/Esc Back", "? Help"))


def _view_remove(state: TuiState, width: int, height: int) -> tuple:
    if state.record is None:
        before = ["No install record here: no file is known to be the installer's, so "
                  "nothing is removed."]
    else:
        before = ["Choose what to remove. A file changed or added by hand stays."]
    return ("Remove files", _compose(state, width, height, before, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


def _view_removal(state: TuiState, width: int, height: int) -> tuple:
    if state.running or state.removal is None:
        return ("Remove files", _compose(state, width, height,
                                         ["Reading what can be removed..."], []),
                ("B/Esc Back", "? Help"))
    lines = _shown(state, _removal_text(state))
    lines = [piece for line in lines for piece in (
        [_styled(part, "folder" if index else "") for index, part in enumerate(
            _wrap(str(line), width, "  "))]
        if getattr(line, "style", "") == "path" and cell_width(str(line)) > width
        else [line])]
    return ("Remove files", _compose(state, width, height, lines, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


def _view_backups(state: TuiState, width: int, height: int) -> tuple:
    if state.running or state.backups is None:
        return ("Backups", _compose(state, width, height, ["Reading the backups..."], []),
                ("B/Esc Back", "? Help"))
    if not state.backups:
        before = ["No backup of this folder."]
    else:
        before = [{"look": "Newest first.", "restore": "Choose the backup to put back.",
                   "delete_backup": "Choose the backup to delete."}[state.backups_for]]
    return ("Backups", _compose(state, width, height, before, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


def _view_backup(state: TuiState, width: int, height: int) -> tuple:
    item = state.backup_chosen or {}
    lines = [f"{backup_words(str(item.get('date', '')))}: "
             f"{_plural(int(item.get('files', 0)), 'file')}, "
             f"{format_size(int(item.get('bytes', 0)))}."]
    return ("Backup", _compose(state, width, height, lines, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


def _confirm_action_text(state: TuiState) -> list[str]:
    if state.action == "remove":
        plan = state.removal or {}
        if _removing_misplaced(state):
            return [f"Remove {_plural(plan.get('files', 0), 'copy')} in the wrong place for "
                    f"good? {format_size(plan.get('bytes', 0))} is freed. The files where "
                    "the cores read them stay."]
        if state.removal_backup:
            return [f"Move {_plural(plan.get('files', 0), 'file')} to a backup? The space "
                    "is freed once the backup is deleted."]
        return [f"Remove {_plural(plan.get('files', 0), 'file')} for good? "
                f"{format_size(plan.get('bytes', 0))} is freed."]
    item = state.backup_chosen or {}
    when = backup_words(str(item.get("date", "")))
    if state.action == "restore":
        return [f"Put back the {_plural(int(item.get('files', 0)), 'file')} of {when}? "
                "Each one replaces the file at its place."]
    return [f"Delete the backup of {when} for good? "
            f"{format_size(int(item.get('bytes', 0)))} is freed."]


def _view_actconfirm(state: TuiState, width: int, height: int) -> tuple:
    return ("Confirm", _compose(state, width, height, _confirm_action_text(state),
                                tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


def tui_pack_text(state: TuiState) -> list:
    """The pack's plan: what goes in and its size, where, how many parts,
    the part files behind Details."""
    plan = state.pack_plan or {}
    if plan.get("status") != "planned":
        return [str(plan.get("message") or "No pack can be made of this choice.")]
    parts = list(plan.get("parts") or [])
    lines: list = [f"{_plural(int(plan['files']), 'file')}, "
                   f"{format_size(int(plan['bytes']))}, for "
                   f"{display_name(state.platform, state.manifest)}."]
    shown = Path(str(parts[0] if parts else plan["path"]))
    lines.append(_styled(f"Pack: {_short_path(shown, state.home)}", "path"))
    lines.append(str(plan.get("message") or "")
                 if len(parts) > 1 else "One ZIP, installed with --from-pack.")
    if len(parts) > 1:
        lines += _details(["", "Parts:"] + [f"  {Path(part).name}" for part in parts])
    return lines


def tui_pack_outcome(state: TuiState) -> list:
    """What making the pack did, in one line, then where."""
    done = state.pack_done or {}
    if done.get("status") != "written":
        lines: list = [_styled("No pack was made.", "failure")]
        if done.get("message"):
            lines.append(str(done["message"]))
        lines += _details(list(state.tail))
        return lines
    parts = list(done.get("parts") or [])
    lines = [f"Pack made: {_plural(int(done['files']), 'file')}, "
             f"{format_size(int(done['size']))}"
             + (f", in {len(parts)} parts." if len(parts) > 1 else ".")]
    shown = Path(str(parts[0] if parts else done["path"]))
    lines.append(_styled(f"Pack: {_short_path(shown, state.home)}", "path"))
    lines.append("On the other device, install from it with --from-pack.")
    if len(parts) > 1:
        lines += _details(["", "Parts:"] + [f"  {Path(part).name}" for part in parts])
    return lines


def _wrapped_paths(lines: list, width: int) -> list:
    """A path line too wide for the screen, folded over the next lines."""
    return [piece for line in lines for piece in (
        [_styled(part, "folder" if index else "") for index, part in enumerate(
            _wrap(str(line), width, "  "))]
        if getattr(line, "style", "") == "path" and cell_width(str(line)) > width
        else [line])]


def _view_packplan(state: TuiState, width: int, height: int) -> tuple:
    if state.running or state.pack_plan is None:
        return ("Make a pack", _compose(state, width, height,
                                        ["Reading what goes into the pack..."], []),
                ("B/Esc Back", "? Help"))
    lines = _wrapped_paths(_shown(state, tui_pack_text(state)), width)
    return ("Make a pack", _compose(state, width, height, lines, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


def _view_packdone(state: TuiState, width: int, height: int) -> tuple:
    if state.running:
        fetched = state.pack_fetched
        words = (f"Making the pack: {fetched[0]} of {fetched[1]} files."
                 if fetched else "Making the pack...")
        return ("Working", _compose(state, width, height, [words], []), ("B/Esc Stop",))
    lines = _wrapped_paths(_shown(state, tui_pack_outcome(state)), width)
    lines[0] = _styled(str(lines[0]), "title")
    return ("Done" if state.pack_code == 0 else "Not done",
            _compose(state, width, height, lines, tui_rows(state)),
            ("A/Enter Close", "B/Esc Back", "? Help"))


def _view_actdone(state: TuiState, width: int, height: int) -> tuple:
    if state.running:
        words = {"remove": "Removing the files...", "restore": "Putting the files back...",
                 "delete_backup": "Deleting the backup..."}[state.action]
        return ("Working", _compose(state, width, height, [words], []), ("B/Esc Stop",))
    lines = _shown(state, tui_action_outcome(state))
    lines[0] = _styled(str(lines[0]), "title")
    return ("Done" if state.action_code == 0 else "Not done",
            _compose(state, width, height, lines, tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


_TUI_VIEWS: dict[str, Callable[[TuiState, int, int], tuple]] = {
    "setup": _view_setup, "platforms": _view_platforms, "folder": _view_folder,
    "browse": _view_browse, "path": _view_path, "create": _view_create,
    "checking": _view_checking, "plan": _view_plan, "systems": _view_systems,
    "options": _view_options, "regions": _view_regions, "cores": _view_cores,
    "preview": _view_preview, "command": _view_command, "confirm": _view_confirm,
    "installing": _view_installing, "result": _view_result, "error": _view_error,
    "quit": _view_quit, "cardroot": _view_cardroot, "misplaced": _view_misplaced,
    "unreadable": _view_unreadable, "games": _view_games, "details": _view_details,
    "device": _view_device, "emulators": _view_emulators, "more": _view_more,
    "remove": _view_remove, "removal": _view_removal, "backups": _view_backups,
    "backup": _view_backup, "actconfirm": _view_actconfirm, "actdone": _view_actdone,
    "packplan": _view_packplan, "packdone": _view_packdone,
}


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
