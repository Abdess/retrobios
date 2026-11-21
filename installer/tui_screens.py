"""Each screen drawn from the state, the help, and the view that picks the screen."""
from __future__ import annotations

import re
import textwrap
from collections.abc import Callable
from typing import TYPE_CHECKING

from installer.cards import _GAMES_PART_CARDS, card_setup, setup_bios_folder
from installer.destination import card_where
from installer.detect_os import detected_shown
from installer.embedded import CARD_PLATFORMS, _a
from installer.line_folder import share_words, side_name
from installer.manifest import OTHER_SYSTEMS
from installer.offline import LOCAL
from installer.outcome import _SHORT_DEFINITIONS
from installer.paths import shown_path
from installer.platforms import display_name
from installer.removal import backup_words
from installer.setups import _setup_label, android_hint
from installer.terminal import TUI_MIN_COLS, TUI_MIN_ROWS
from installer.text import _pad, _plural, _wrap, cell_width, fit, format_duration, format_size
from installer.tui_choice import (
    _counts_predate_options,
    _needed,
    _plan_folder,
    _shared_needed,
    _ticked_files,
    _tui_card_bound,
    _tui_misplaced,
    games_pager_lines,
    games_where,
    tui_verbose,
)
from installer.tui_commands import tui_command, tui_hint
from installer.tui_frame import (
    TUI_LONG_LIST,
    TUI_ROW_SPREAD,
    _CHECKLIST_BAR,
    _ROW_VERBS,
    _STATE_WORDS,
    _armed_hint,
    _back_hint,
    _bar,
    _compose,
    _fitted_compose,
    _hint,
    _middle_label,
    _pager,
    _pager_starts,
    _route_hint,
    _row_line,
    _scrolled,
    _status_after,
    _status_footer,
    _tap_hint,
    _text_lines,
)
from installer.tui_outcome import (
    _confirm_action_text,
    _removal_text,
    _wrapped_paths,
    tui_action_outcome,
    tui_outcome,
    tui_pack_outcome,
    tui_pack_text,
)
from installer.tui_paint import _FOLDER_LABEL, _command_line, _is_detail, _short_path, _styled, middle
from installer.tui_plan_view import (
    TUI_ESDE_NOTE,
    TUI_ESDE_SHORT,
    _confirm_text,
    _plan_body,
    _plan_text,
    _reading_line,
    _screen_definition,
    _shown,
)
from installer.tui_routes import TUI_PAD_ROUTES, TUI_ROUTES
from installer.tui_rows import OTHER_HELP, _CHECKLISTS, _PAGERS, tui_rows
from installer.tui_state import TUI_MAX_WIDTH

if TYPE_CHECKING:
    from installer.tui_paint import TuiLine
    from installer.tui_state import TuiRow, TuiState

# The first screen's title: a setup found here, or none, and the list.
# which-pack names them from here.
TUI_FOUND_TITLE = "Where to install?"
TUI_CHOOSE_TITLE = "Which setup?"
# Asked after Which setup? where nothing was found, and on a card.
TUI_FOLDER_TITLE = "Which folder?"


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
        notes = list(state.folder_scan.notes) if state.folder_scan else []
    body = _fitted_compose(state, width, height, before, notes,
                           tui_rows(state), _status_after(state), state.refused)
    return (title, body, ("A/Enter Choose", "B/Esc Back", "? Help"))


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


def _view_cores(state: TuiState, width: int, height: int) -> tuple:
    # Kept above a list that scrolls: dropped once the rows filled the
    # screen, 189 cores never said what unticking does.
    pinned = ["Untick the cores not in use: the platform's own files are always kept, "
              "and a core with no extra file reads only those."]
    return ("Cores", _compose(state, width, height, [], tui_rows(state), (),
                              _status_footer(state), pinned),
            _CHECKLIST_BAR)


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


def _only_match(state: TuiState) -> TuiRow | None:
    """The one setup the filter leaves, when it leaves one."""
    if state.screen != "platforms" or not state.filters.get("platforms"):
        return None
    rows = [row for row in tui_rows(state) if row.action != "filter"]
    return rows[0] if len(rows) == 1 else None


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


def _view_actconfirm(state: TuiState, width: int, height: int) -> tuple:
    return ("Confirm", _compose(state, width, height, _confirm_action_text(state),
                                tui_rows(state)),
            ("A/Enter Choose", "B/Esc Back", "? Help"))


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
