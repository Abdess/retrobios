"""What choosing a setup, a platform, a card or a folder does."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from installer.cards import (
    _card_boundary,
    _mount_name,
    _mount_points,
    _mounted_cards,
    card_bound,
    card_platform,
    card_setup,
    card_system,
)
from installer.choices import emulator_names
from installer.console import _typed_folder
from installer.cores import CORE_PLATFORMS, core_dirs, installed_cores
from installer.destination import (
    _card_is,
    card_choice,
    card_root_above,
    copy_source_refusal,
    dest_drive,
    missing_folder,
    mounted_cards_of,
    on_its_card,
)
from installer.detect_os import _DETECTED_OS, _FROM_CARD, detected_os, detected_shown
from installer.embedded import CARD_PLATFORMS, _a
from installer.frontend_folders import _retroarch_config_at
from installer.host_fs import _exists, _folder_writable, _is_dir, _nearest_folder, closed_folder
from installer.lists import local_targets
from installer.offline import LOCAL
from installer.paths import shown_path
from installer.platforms import display_name
from installer.setups import setup_folder
from installer.tui_choice import _short_of_space, _tui_card_bound
from installer.tui_commands import tui_record_kept
from installer.tui_folder_scan import card_mounts, scan_folder
from installer.tui_paint import _short_path, _styled
from installer.tui_rows import _platform_rows, tui_rows
from installer.tui_state import TuiRow
from installer.tui_steps import _back, _browse_to, _push, _start_check, _start_run, _tui_record_trim

if TYPE_CHECKING:
    from installer.destination import CardChoice
    from installer.tui_paint import TuiLine
    from installer.tui_state import TuiState


def _closed_status(state: TuiState, closed: tuple[Path, str]) -> TuiLine:
    folder = _short_path(closed[0], state.home)
    return _styled(f"This user cannot open {folder} ({closed[1]}): choose another folder, "
                   "or give this user access to it.", "refusal")


def _set_platform(state: TuiState, plat: str) -> None:
    """Another setup chosen: its list names other boards and emulators, so
    the ones chosen for the setup before are not carried over."""
    if state.platform and plat != state.platform:
        state.target, state.every_board, state.emulators = "", False, []
        state.targets, state.targets_for, state.targets_problem = None, "", ""
    state.platform = plat


def _known_choice(state: TuiState, plat: str, manifest: dict) -> None:
    """The emulators and the board chosen, kept to those the list now read
    names, the others left out and said in one line: a pack's list can
    lack what the network's held, and the check then failed."""
    if tui_record_kept(state):
        _tui_record_trim(state, plat, manifest)
    names = emulator_names(manifest, manifest.get("files") or [],
                           manifest.get("omitted_files") or [])
    gone = [f"--emulator {name}" for name in state.emulators if name not in names]
    state.emulators = [name for name in state.emulators if name in names]
    boards = state.targets if state.targets_for == plat else None
    if LOCAL.manifest is not None or LOCAL.pack is not None:
        try:
            boards = local_targets(plat)
        except SystemExit:
            # A board list beside the list that is no list: the check says so.
            boards = None
    if state.target and boards is not None and state.target not in boards:
        gone.append(f"--target {state.target}")
        state.target = ""
    if gone:
        state.status = f"Left out, not in this list: {', '.join(gone)}."


def _choose(state: TuiState, plat: str, dest: Path, proposed: bool = False) -> list[tuple]:
    """dest taken for plat. proposed is a folder the installer offered (its
    usual or detected folder, a share drive's bios): created without the
    guard a typed path gets, which Enter on it met as Choose another folder,
    and Enter there brought the same two screens back."""
    state.card_note = ""
    closed = closed_folder(dest)
    if closed is not None:
        # Nothing can be checked or written there: the folder is asked
        # again, on the screen that chose it when it can say why.
        _set_platform(state, plat)
        state.status = _closed_status(state, closed)
        if state.stack and state.screen in ("folder", "browse", "path"):
            return []
        # The folder found here is the one the frontend reads: the built-in
        # default beside it is one it does not, offered as "reads its BIOS
        # files from" and filled with Enter.
        state.folder_default, state.folder_kind = None, "closed"
        state.folder_scan = scan_folder(state)
        return _push(state, "folder")
    card = card_system(dest)
    if card and card[0] == plat and card[1] != dest:
        # A muOS or KNULLI card's root: that system reads a folder below it.
        dest = card[1]
    _set_platform(state, plat)
    state.dest = dest
    if plat in CARD_PLATFORMS and card_platform(dest) is None:
        # The engine refuses a folder inside the card, the list writing
        # Bios/<TAG>/ below the root: the root is offered instead.
        for parent in list(dest.absolute().parents)[:2]:
            holder = card_platform(parent)
            if holder:
                state.facts = {"card_root": parent, "card": holder}
                return _push(state, "cardroot")
    root = _own_card_root(dest)
    if root is not None and not _exists(dest) and _is_dir(dest.parent):
        # The card's own files name it, so its folder is known: created as
        # line mode creates it, and said on the plan, not asked.
        state.card_note = (f"{dest.name} is created on {_mount_name(root)}, where "
                           f"{detected_shown(plat, dest) or display_name(plat)} reads it.")
        return _start_check(state)
    if proposed and not _exists(dest):
        # Where no setup is there yet, nothing reads it: said as it is.
        reads = (f", where {detected_shown(plat, dest) or display_name(plat)} reads it"
                 if _is_dir(dest.parent) else ", a folder that does not exist yet")
        state.card_note = (f"{dest.name} is created in "
                           f"{_short_path(dest.parent, state.home)}{reads}.")
        return _start_check(state)
    found = missing_folder(dest)
    if found is None:
        return _start_check(state)
    if found.verdict == "create":
        # One level is a BIOS folder not made yet: line mode makes it and
        # says so, the plan says so here.
        state.card_note = f"{dest.name} is created in {_short_path(dest.parent, state.home)}."
        return _start_check(state)
    # Asked with no as the answer, as line mode asks. A path whose start
    # was mistyped would be created from the root: said on the screen.
    state.facts = {"nearest": found.nearest, "risky": found.nearest.parent == found.nearest}
    return _push(state, "create", 1)


def _card_folder(state: TuiState, folder: Path) -> CardChoice | None:
    """What a folder chosen for a setup that runs from its SD card resolves
    to, as a card root typed in line mode does: None when no card is asked
    for, on the device itself, whose folder is taken as typed (a KNULLI got
    bios added to it), or when the folder is inside a MinUI card, whose
    root _choose offers."""
    bound = _tui_card_bound(state)
    if bound is None and state.platform:
        # Read as line mode reads a folder typed (ask_platform_folder): a
        # Batocera SHARE drive's root goes to its bios folder, another
        # system's drive is refused, a card's root is said.
        return card_choice(state.platform, state.platform, folder)
    if bound is None or (state.platform in CARD_PLATFORMS and card_root_above(folder)):
        return None
    if state.folder_kind == "found" and state.folder_default is not None:
        return None
    return card_choice(bound[0], state.platform, folder)


def _card_status(state: TuiState, choice: CardChoice, given: bool = False) -> None:
    """Say why a folder is not the card: one short sentence first, which a
    40-column screen shows whole, the folder and what was looked for on it
    after, shown where there is room and in the help. given is a folder
    --dest names, which no choice here can change."""
    if given:
        # --dest is fixed for this run: only another system's card gets
        # "choose another setup". A folder inside a card, or one that is no
        # card, is named again in the command.
        then = (f"Run it again with --dest {shown_path(choice.root)}." if choice.root
                else "--dest names it: choose another setup." if choice.other
                else "Run it again with the card's top folder.")
        short = choice.short or choice.refused + "."
    elif choice.other:
        # The top folder of a card, only another system's: "Choose the
        # card's top folder" sent the user back to the same one.
        bound = _tui_card_bound(state)
        kind = "SHARE drive" if "SHARE drive" in choice.short else "card"
        then = (f"Choose the {display_name(state.platform)} SHARE drive, or go back and "
                f"choose {choice.other}." if kind != "card" and not bound else
                f"Insert the {bound[0] if bound else 'right'} card, or go back and choose "
                f"{choice.other}.")
        short = f"That is {_a(choice.other)} {kind}."
    else:
        then = "Choose the card's top folder."
        short = choice.short or choice.refused + "."
    state.status = _styled(f"{short} {then}", "refusal")
    state.status_more = f"{choice.refused}." + (f" {choice.detail}." if choice.detail else "")


def _card_refusal(state: TuiState, folder: Path) -> bool:
    """Whether folder is refused as the card the chosen setup runs from,
    said in the status when it is."""
    choice = _card_folder(state, folder)
    if choice is None or not choice.refused:
        return False
    _card_status(state, choice)
    return True


def _choose_card(state: TuiState, folder: Path) -> list[tuple]:
    """_choose for a folder picked on the folder, browse or path screen: for
    a setup that runs from its SD card, the card's own BIOS folder, and a
    folder that is not its card refused in words."""
    choice = _card_folder(state, folder)
    if choice is None:
        return _choose(state, state.platform, folder)
    if choice.refused:
        _card_status(state, choice)
        if state.stack and state.screen in ("folder", "browse", "path"):
            return []
        state.folder_default, state.folder_kind = None, "usual"
        state.folder_scan = scan_folder(state)
        return _push(state, "folder")
    return _take_card(state, choice, folder)


def _own_card_root(folder: Path) -> Path | None:
    """The root of the card whose own files name folder as its BIOS folder,
    or None: an Onion card's BIOS, a muOS card's MUOS/bios. No folder above
    a mount point is read, as _card_above reads none: it is another drive."""
    points = _mount_points()
    below = folder
    for parent in list(folder.parents)[:2]:
        if _card_boundary(below, points):
            return None
        below = parent
        card = card_system(parent)
        if card and card[1] == folder:
            return parent
    return None


def _take_card(state: TuiState, choice: CardChoice, root: Path) -> list[tuple]:
    """_choose for the folder card_choice gave root, its note kept on the
    screens up to the plan: --dest, the setup list with --dest and a folder
    picked here said nothing of a stick no file names, where line mode did."""
    card = card_system(root)
    if card and card[1] == choice.folder:
        # Titled as the same card found by itself: "Onion (RetroArch files)".
        _DETECTED_OS.setdefault((choice.plat, choice.folder), card[2])
        _FROM_CARD.add((choice.plat, choice.folder))
    elif state.card_bound:
        # A card no file names, chosen as ArkOS's: titled ArkOS, not RetroArch.
        _DETECTED_OS.setdefault((choice.plat, choice.folder), state.card_bound[0])
    # The system's folder below a card that exists is made as line mode
    # makes it (_missing_dest, one level): the screen asked Create the
    # folder? for KNULLI's bios on a blank stick, line mode did not.
    below = choice.folder != root and _is_dir(choice.folder.parent)
    effects = _choose(state, choice.plat, choice.folder, proposed=below)
    # Said once: a note that names the folder already says where the files go.
    named = bool(choice.note) and shown_path(choice.folder) in choice.note
    state.card_note = choice.note if named else " ".join(filter(None, (choice.note,
                                                                       state.card_note)))
    return effects


def _open_folder_screen(state: TuiState, default: Path | None,
                        kind: str = "usual", rebind: bool = False) -> list[tuple]:
    """The folder screen for the chosen setup. rebind is another folder
    asked for from the plan: a card setup found mounted (an Onion card) is
    asked for its card again, never for any folder. A folder off the card
    is one Onion does not read, and the screen said RetroArch."""
    state.folder_default, state.folder_kind = default, kind
    # On the device itself its folder is no card in a reader.
    system = (detected_os(state.platform, state.dest)
              if rebind and state.dest is not None and dest_drive(state.dest) is not None
              else "")
    if system and not state.card_bound and card_bound(system, state.platform):
        state.card_bound = card_bound(system, state.platform)
    # The drives are looked for when the screen opens and on Look again: a
    # card inserted meanwhile moved the rows under the focus.
    state.folder_scan = scan_folder(state)
    refused = kind == "chosen" and (state.facts.get("writable") is False
                                    or _short_of_space(state, state.check or {}))
    # A folder just refused as full or read-only: Browse, not Use this
    # folder, is under A, or A, A came back to the same warning.
    _push(state, "folder")
    if refused and default is not None:
        state.focus["folder"] = next((index for index, row in enumerate(tui_rows(state))
                                      if row.action == "browse"), 1)
    return []


def typed_path(text: str) -> Path | None:
    """A folder typed or pasted: quotes off, ~ and variables expanded."""
    if not text.strip().strip("\"'").strip():
        return None
    return _typed_folder(text)


def _tui_folder_facts(state: TuiState) -> dict:
    """Free space, whether the folder takes files, and the cores found."""
    dest = state.dest
    assert dest is not None
    probe = _nearest_folder(dest)
    try:
        free: int | None = shutil.disk_usage(probe).free
    except OSError:
        free = None
    cores = (installed_cores(core_dirs(state.platform, dest))
             if state.platform in CORE_PLATFORMS else [])
    # The retroarch.cfg that names dest, said under it on the plan. Whether
    # dest is the card of its system is read here with the rest, never by
    # a frame: a card pulled out moved the plan rows under the focus.
    return {"free": free, "writable": _folder_writable(dest), "cores": cores,
            "config": _retroarch_config_at(dest),
            "on_card": on_its_card(state.platform, dest,
                                   state.card_bound[0] if state.card_bound else "")}


def _row_folder(row: TuiRow) -> Path:
    """The folder or archive a row names."""
    value = row.value
    assert isinstance(value, Path)
    return value


def _activate_setup(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on a setup found here, a drive two systems fit, or Another."""
    if row.action == "another":
        return _push(state, "platforms", _platform_focus(state, "retroarch"))
    if row.action == "doubt":
        # Taken as the system chosen, as --platform with --dest takes it.
        value = row.value
        assert isinstance(value, tuple)
        plat, mount = value
        state.card_bound = card_bound(plat, plat)
        _set_platform(state, plat)
        choice = card_choice(plat, plat, mount)
        if choice.refused:
            _card_status(state, choice)
            return []
        return _take_card(state, choice, mount)
    assert isinstance(row.value, int)
    plat, path, _label = state.setups[row.value]
    # A setup found here is its folder: a card looked at and backed
    # out of described the RetroArch chosen next as that card.
    state.card_bound = None
    return _choose(state, plat, path, proposed=True)


def _activate_platforms(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on a setup of the list of every setup."""
    value = row.value
    if row.action == "cardsystem":
        assert isinstance(value, tuple)
        plat, system = value
    else:
        assert isinstance(value, str)
        plat, system = value, value
    _set_platform(state, plat)
    state.card_bound = card_bound(system, plat)
    if state.dest_given is not None:
        # Read as --platform with --dest reads it, for the same folder:
        # ROCKNIX's row added roms/bios to a --dest the line mode kept.
        choice = card_choice(system, plat, state.dest_given)
        if choice.refused:
            _card_status(state, choice, given=True)
            state.platform, state.card_bound = "", None
            return []
        return _take_card(state, choice, state.dest_given)
    return _open_folder_screen(state, *setup_folder(
        state.os_type, state.setups, state.mounted_setups, plat, system))


def _rescan_cards(state: TuiState) -> list[tuple]:
    """Look again for the cards of the setup chosen."""
    bound = _tui_card_bound(state)
    assert bound is not None
    state.folder_scan = scan_folder(state)
    mounts = card_mounts(state.folder_scan)
    cards = [index for index, item in enumerate(tui_rows(state))
             if item.action == "card" and item.value in mounts]
    state.focus["folder"] = cards[0] if cards else state.focus.get("folder", 0)
    state.status = ("" if cards else f"Still no {bound[0]} card "
                    "is mounted.")
    return []


def _browse_for_dest(state: TuiState) -> list[tuple]:
    """Browse for a folder, from the folder screen."""
    state.browse_for = "dest"
    _push(state, "browse")
    _browse_to(state, _nearest_folder(state.folder_default or state.home))
    bound = _tui_card_bound(state)
    if bound and state.folder_kind != "found":
        # A card is asked for: the drives come first, and the home
        # folder's "go back to type a path" sent the user away from
        # the cards listed under it.
        # Its own cards first: the muOS card listed first was focused
        # for Onion.
        own = mounted_cards_of(bound[0], state.platform)
        setup = card_setup(bound[0], state.platform)
        # Another system's card is never focused for this one: the
        # muOS card was, under "Choose the Onion card below".
        free = [mount for mount in _mounted_cards()
                if setup is None or _card_is(setup, mount)[0] != "other"]
        drives = ([index for index, item in enumerate(state.browse_rows)
                   if item.action == "dir" and item.value in own]
                  or [index for index, item in enumerate(state.browse_rows)
                      if item.action == "dir" and item.value in free])
        if drives:
            state.focus["browse"] = drives[0]
        state.status = (f"Choose the {bound[0]} card below." if own
                        else f"No {bound[0]} card is mounted: insert it, or open "
                        "its top folder.")
    return []


def _activate_folder(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on a row of the BIOS folder question."""
    action = row.action
    if action == "default":
        assert state.folder_default is not None
        return _choose(state, state.platform, state.folder_default, proposed=True)
    if action in ("share", "drive"):
        return _choose(state, state.platform, _row_folder(row), proposed=True)
    if action == "rescan":
        return _rescan_cards(state)
    if action == "card":
        return _choose_card(state, _row_folder(row))
    if action == "browse":
        return _browse_for_dest(state)
    state.path_text = str(state.folder_default or "")
    state.path_selected = bool(state.path_text)
    return _push(state, "path")


def _use_from_folder(state: TuiState, row: TuiRow) -> list[tuple]:
    """A folder or archive to copy BIOS files from, chosen in the browser."""
    chosen = state.browse_dir if row.action == "use" else _row_folder(row)
    refused = copy_source_refusal(chosen, state.dest)
    if refused:
        state.status = _styled(refused, "refusal")
        return []
    if chosen not in state.from_folders:
        state.from_folders.append(chosen)
    state.browse_for = "dest"
    # The check runs again with it: the plan then says what it holds.
    return _start_check(state)


def _activate_browse(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on a row of the folder browser."""
    action = row.action
    if action == "zip" and state.browse_for == "pack":
        # Opened in this process (perform), which answers pack_opened.
        return [("pack", row.value)]
    if action == "use" and state.browse_for == "packto":
        state.pack_dir = state.browse_dir
        state.browse_for = "dest"
        state.stack.pop()
        state.pack_plan = None
        return _start_run(state, "pack_plan")
    if action == "use" and state.browse_for == "save":
        state.passthrough = [flag for flag in state.passthrough
                             if flag[0] != "--save-dir"]
        state.passthrough.append(("--save-dir", str(state.browse_dir)))
        state.browse_for = "dest"
        return _start_check(state)
    if action in ("use", "zip") and state.browse_for == "from":
        return _use_from_folder(state, row)
    if action == "use":
        assert state.browse_dir is not None
        return _choose_card(state, state.browse_dir)
    if action == "up" and state.browse_dir is not None:
        if row.value == state.browse_dir:
            _browse_to(state, None if os.name == "nt" else state.browse_dir)
        else:
            _browse_to(state, _row_folder(row), came_from=state.browse_dir)
        return []
    _browse_to(state, _row_folder(row))
    return []


def _activate_create(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on Create the folder?."""
    if row.action == "create":
        state.stack.pop()
        return _start_check(state)
    if len(state.stack) == 1:
        # The folder came from --dest: nothing is under this screen, and
        # Back asked Quit? with Quit in focus. The
        # folder screen takes its place, as the plan's row opens it.
        state.stack.pop()
        return _open_folder_screen(state, state.dest, "chosen", rebind=True)
    return _back(state)


def _activate_cardroot(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on the card root question."""
    if row.action == "cardroot":
        state.stack.pop()
        return _choose(state, state.platform, state.facts["card_root"])
    return _back(state)


def _platform_focus(state: TuiState, plat: str) -> int:
    """The platform list's row for plat, below its filter row."""
    rows = _platform_rows(state)
    return next((index for index, row in enumerate(rows)
                 if row.action == "platform" and row.value == plat), 1)
