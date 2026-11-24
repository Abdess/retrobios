"""The screens that choose the setup, the platform, the card and the folder."""

from __future__ import annotations

from typing import TYPE_CHECKING

from installer.cards import _GAMES_PART_CARDS, card_setup
from installer.destination import card_where
from installer.embedded import CARD_PLATFORMS, _a
from installer.line_folder import share_words, side_name
from installer.paths import shown_path
from installer.platforms import display_name
from installer.setups import android_hint
from installer.text import _wrap, cell_width, fit
from installer.tui_choice import _tui_card_bound
from installer.tui_frame import TUI_ROW_SPREAD, _compose, _fitted_compose, _status_after
from installer.tui_paint import _short_path, _styled, middle
from installer.tui_plan_view import TUI_ESDE_NOTE, TUI_ESDE_SHORT
from installer.tui_rows import tui_rows

if TYPE_CHECKING:
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
    after = []
    if focus.action == "setup":
        plat, path, _label = state.setups[focus.value]
        after.append(f"BIOS folder: {shown_path(state.setup_folders[plat, path])}")
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
