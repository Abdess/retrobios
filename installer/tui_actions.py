"""What choosing a row does on each screen, and the moves between screens."""
from __future__ import annotations

import os
import shutil
from collections.abc import Callable
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
from installer.choices import emulator_names, known_regions, trim_recorded
from installer.console import QUIT_CODE, _typed_folder
from installer.cores import CORE_PLATFORMS, core_dirs, installed_cores
from installer.destination import (
    _card_is,
    _last_name,
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
from installer.games import games_probe
from installer.host_fs import _exists, _folder_writable, _is_dir, _nearest_folder, closed_folder
from installer.install_record import (
    RECORD_NARROWING,
    _RECORD_SAID,
    choice_words,
    options_without,
    record_options,
    setup_record,
    take_recorded_choice,
)
from installer.lists import local_targets
from installer.offline import LOCAL
from installer.pack import _listed
from installer.pack_source import PackSource
from installer.paths import shown_path
from installer.platforms import _tui_system_label, display_name
from installer.regions import resolve_regions
from installer.setups import setup_folder
from installer.tui_choice import (
    _board_seen,
    _choice_in_place,
    _cores_dir_given,
    _counts_predate_options,
    _dest_card,
    _device_choice,
    _needed,
    _no_setup_reads,
    _none_ticked,
    _save_dir_given,
    _short_of_space,
    _system_titles,
    _tui_card_bound,
    core_ticked,
    tui_choices,
)
from installer.tui_commands import _tui_card, tui_flags, tui_pack_dir, tui_record_kept
from installer.tui_folder_scan import card_mounts, scan_folder
from installer.tui_paint import _CHECK_FIELDS, _short_path, _styled
from installer.tui_rows import (
    TUI_TICK_ROWS,
    _ACTION_SCREENS,
    _CHECKLISTS,
    _browse_rows,
    _device_rows,
    _first_item,
    _os_folder,
    _platform_rows,
    tui_rows,
)
from installer.tui_screens import _only_match
from installer.tui_state import TuiRow

if TYPE_CHECKING:
    from installer.destination import CardChoice
    from installer.tui_paint import TuiLine
    from installer.tui_state import TuiState


def _choose_board(state: TuiState, name: str) -> list[tuple]:
    """A board chosen on Device, back on Change. The board the run reads
    itself is no option: the command stays the one with nothing chosen.
    Every board is always said, the run otherwise reading a board itself
    (one started with --target or --every-board read none)."""
    seen = _board_seen(state)
    read = seen[0] if seen is not None and seen[1] else ""
    state.every_board = not name
    state.target = "" if not name or name == read else name
    return _back(state)


def _focus_plan(state: TuiState, action: str) -> None:
    """The plan's focus on the row doing action. A plan that keeps no file,
    a choice emptied or already in place, opens on Choose systems: the
    focus kept its index, and Enter opened Options."""
    actions = [row.action for row in tui_rows(state)]
    keeps_none = _choice_in_place(state) or (state.emptied and state.systems
                                             and not state.ticked)
    if action in actions:
        state.focus["plan"] = actions.index(action)
    elif keeps_none and "systems" in actions:
        state.focus["plan"] = actions.index("systems")


def _push(state: TuiState, screen: str, focus: int = 0) -> list[tuple]:
    state.stack.append(screen)
    state.focus[screen] = focus
    return []


def _replace(state: TuiState, screen: str) -> None:
    state.stack[-1] = screen
    state.focus[screen] = 0


def _back(state: TuiState) -> list[tuple]:
    if state.screen == "packdone" and not state.running and "more" in state.stack:
        # Made or not, its plan is spent: back to More.
        del state.stack[state.stack.index("more") + 1:]
        return []
    if state.screen == "actdone" and not state.running:
        # Done: what was planned is gone, and the plan is counted again.
        return _activate_action(state, TuiRow("recheck", ""))
    effects = [("kill",)] if state.running else []
    if state.running:
        # What the stopped run still reports belongs to no screen.
        state.running = False
        state.run_id += 1
    if len(state.stack) == 1:
        state.stack.append("quit")
        state.focus["quit"] = 0
        return effects
    refused = _none_ticked(state)
    if refused:
        # Done and B leave a list of ticks alike, never with nothing
        # ticked: said on every length of list, in the line the rows
        # leave.
        state.status = refused
        return effects
    chose = state.screen == "systems" and state.ticked != (state.ticked_before or set())
    if state.screen == "systems" and state.widened_from is not None:
        before, state.widened_from = state.widened_from, None
        if state.ticked == {row["system"] for row in before["systems"]}:
            # The systems --system named, ticked again: the exact plan of
            # their own check, not an estimate over every system.
            for field, value in before.items():
                setattr(state, field, value)
            chose = False
    if state.screen == "regions":
        state.region_order = []
    state.stack.pop()
    if chose and state.screen == "plan":
        # The systems chosen, the next press is Install: Back left the focus
        # on Choose systems.
        _focus_plan(state, "install")
    if state.screen == "checking" and not state.running:
        # Stay after Esc on a check started from the command line: a
        # Checking screen nothing feeds counted seconds forever.
        return effects + _start_check(state)
    if state.screen == "plan" and _counts_predate_options(state):
        # The plan's numbers were read under the options before: they are
        # read again, the systems ticked kept.
        return effects + _start_check(state)
    return effects


def _keep_choice(state: TuiState) -> None:
    """The systems ticked, kept for the next check of the same platform's
    list when they are not every system to install: one choice for the
    whole run, whatever is changed on the way (game data, an option, a
    folder, a folder to copy from). A choice already set aside (widening a
    --system) is left as it is."""
    if (state.keep_ticked is not None or not state.systems
            or state.manifest_for != state.platform):
        return
    if state.emptied and not state.ticked:
        # Still the choice the options emptied: the same systems again.
        state.keep_ticked = set(state.ticked_names)
        return
    needed = {row["system"] for row in state.systems if _needed(row)}
    state.keep_ticked = (None if needed <= state.ticked and not state.hidden_ticks
                         else state.ticked | state.hidden_ticks)
    titles = _system_titles(state)
    state.ticked_names = {
        **{name: label for name, label in state.ticked_names.items()
           if name in state.hidden_ticks},
        **{row["system"]: _tui_system_label(row, titles)
           for row in state.systems if row["system"] in state.ticked}}


def _start_run(state: TuiState, run: str) -> list[tuple]:
    state.run = run
    state.running = True
    state.run_id += 1
    state.started = state.now
    if run == "check":
        # The systems of an earlier check go first: ticks read against them
        # dropped the --system the command line gave.
        state.check, state.files, state.systems, state.reading = None, [], [], None
        state.checked_dests = set()
        state.choices = state.set_aside = None
        state.found, state.scanned, state.unreadable = [], [], []
        state.check_summary = state.saves = None
        state.unplaced_why = {}
        state.version = state.version_short = state.board = ""
        state.games = state.games_reading = state.games_unavailable = None
        state.checked_flags = tui_flags(state)
    elif run in ("confirm", "preview"):
        state.dry, state.dry_files, state.dry_summary = None, [], None
        state.dry_saves = None
    else:
        state.done_saves = state.dest_error = None
        state.download = state.progress = state.reading = state.games_reading = None
        state.samples, state.local_dests, state.network = [], {}, 0
        state.finished, state.summary, state.code, state.stopping = [], None, None, False
    return [("run", run)]


def _tui_record_take(state: TuiState) -> None:
    """The recorded choice made the screen's, as its options would make it."""
    setup = state.record or {}
    taken = take_recorded_choice(setup.get("choice") or [])
    if taken is None:
        state.status = "The install record names options this installer lacks, so it is ignored."
        state.record = None
        return
    parsed = taken.parsed
    left_out, choice = list(taken.left_out), taken.choice
    recorded_regions = list(parsed.region or [])
    regions = known_regions(recorded_regions)
    if regions != recorded_regions:
        # One region at a time, as line mode keeps them: a known region
        # beside an unknown one stays.
        left_out.append("--region (a region this installer does not know)")
        choice = choice_words(options_without(record_options(choice), "--region", regions))
    if left_out:
        # What the run takes, as line mode keeps it: the plan reads as the
        # record's own choice again.
        setup = state.record = {**setup, "choice": choice}
        state.status = f"Left out of the recorded choice: {', '.join(left_out)}."
    state.cli_systems = list(parsed.system or [])
    state.cores = [token.strip() for value in parsed.core or [] for token in value.split(",")
                   if token.strip()]
    state.regions = resolve_regions(regions) if regions else []
    state.no_game_data = bool(parsed.no_game_data)
    state.installed_only = bool(parsed.installed_cores)
    state.for_games = parsed.for_games is not None
    state.games_folder = parsed.for_games if isinstance(parsed.for_games, Path) else None
    state.required_only = bool(parsed.required_only) and state.for_games
    state.games_choice = "record"
    # Device and Emulators show these: a choice no row showed was kept apart.
    state.target = str(parsed.target or "")
    state.every_board = bool(parsed.every_board)
    state.emulators = list(parsed.emulator or [])
    state.record_flags = [(flag, value) for flag, value in record_options(setup["choice"])
                          if flag == "--declared-only"]
    if state.manifest is not None and state.manifest_for == state.platform:
        _tui_record_trim(state, state.platform, state.manifest)


def _tui_record_trim(state: TuiState, plat: str, manifest: dict) -> None:
    """The systems, cores, regions and emulators of the recorded choice
    that this list cannot take, left out by the rule line mode follows
    (trim_recorded) and said on the status line."""
    if state.record is None:
        return
    asked = {"--system": list(state.cli_systems), "--core": list(state.cores),
             "--region": list(state.regions), "--emulator": list(state.emulators)}
    parts = trim_recorded(asked, plat, manifest, manifest.get("files") or [],
                          manifest.get("omitted_files") or [])
    if not parts:
        return
    choice = record_options(state.record["choice"])
    for part in parts:
        if part.flag == "--system":
            state.cli_systems = list(part.keep)
        elif part.flag == "--core":
            state.cores = list(part.keep)
        elif part.flag == "--region":
            state.regions = list(part.keep)
        else:
            state.emulators = list(part.keep)
        choice = options_without(choice, part.flag, part.keep)
    state.record = {**state.record, "choice": choice_words(choice)}
    words = ", ".join(f"{part.flag} ({part.why})" for part in parts)
    state.status = f"Left out of the recorded choice: {words}."


def _tui_record_drop(state: TuiState) -> None:
    """The recorded choice given up: the choice nothing narrows."""
    state.cli_systems, state.cores, state.regions, state.record_flags = [], [], [], []
    state.no_game_data = state.installed_only = state.required_only = False
    state.target, state.every_board, state.emulators = "", False, []
    state.for_games, state.games_folder, state.games_choice = None, None, ""
    # The systems of the recorded check go, and with them its ticks.
    state.systems, state.ticked, state.keep_ticked, state.widened_from = [], set(), None, None


def _tui_record_load(state: TuiState) -> None:
    """Read the record of the setup and folder chosen, once for each, and
    take its choice where nothing chose: the command line, or the screen
    for an earlier folder."""
    key = (state.platform, state.dest)
    if state.dest is None or state.record_for == key:
        return
    taken = tui_record_kept(state)
    state.record_for = key
    setup, path, problem = setup_record(state.platform, state.dest)
    if problem and str(path) not in _RECORD_SAID:
        _RECORD_SAID.add(str(path))
        state.status = f"{problem}, so it is ignored."
    if taken:
        _tui_record_drop(state)
    # Games read on a card are what the plan found, not a choice.
    found = ("--for-games", "--required-only") if state.games_choice in ("", "probe") else ()
    state.record = None
    untouched = not any(flag in RECORD_NARROWING and flag not in found
                        for flag, _value in tui_flags(state))
    state.record = setup
    if setup is not None and not state.cli_choice and untouched:
        _tui_record_take(state)


def _start_check(state: TuiState) -> list[tuple]:
    """Check the chosen folder, after fetching the file list once, the
    systems ticked kept (_keep_choice)."""
    _tui_record_load(state)
    _keep_choice(state)
    _games_look(state)
    state.refocus = ""
    if "plan" in state.stack:
        del state.stack[state.stack.index("plan"):]
    while state.stack and state.stack[-1] in ("checking", "error", "create"):
        state.stack.pop()
    state.stack.append("checking")
    state.facts, state.ticked = {}, set()
    if state.manifest is not None and state.manifest_for == state.platform:
        return _start_run(state, "check")
    state.manifest = None
    state.run, state.run_id = "check", state.run_id + 1
    state.started = state.now
    return [("fetch", state.platform)]


def _games_look(state: TuiState) -> None:
    """For a folder chosen once a card was looked at for games, the new one
    looked at too, from what this run already read (no network): its games
    make "For the games on this card" the choice, unless the user or the
    command line decided."""
    if (state.games_choice in ("user", "cli", "record") or state.games_probed is None
            or state.dest is None or state.games_probed == (state.platform, state.dest)):
        return
    count = games_probe(state.platform, state.dest, network=False, os_type=state.os_type)
    state.games_probed = (state.platform, state.dest)
    state.games_here = count or 0
    state.for_games, state.games_choice = bool(count), "probe"


def _browse_to(state: TuiState, folder: Path | None, came_from: Path | None = None) -> None:
    state.browse_dir = folder
    copying = state.browse_for == "from"
    state.browse_rows, state.status = _browse_rows(folder, copying or state.browse_for == "pack",
                                                   _dest_card(state) if copying else None)
    if state.browse_for == "pack":
        # A pack is a ZIP, never a folder.
        state.browse_rows = [row for row in state.browse_rows if row.action != "use"]
    focus = 0
    if (folder is not None and state.browse_for not in ("from", "pack", "packto")
            and folder in (state.home, Path(folder.anchor))):
        # No frontend reads its BIOS files from HOME or a drive's root: A
        # pressed through the screens installed into ~. A goes into a
        # visible subfolder there, never a card or drive listed first (A
        # then took /mnt/d, the Windows D: drive, for the BIOS folder) nor
        # .cache. With none, Use this folder keeps the focus and says where.
        focus = next((index for index, row in enumerate(state.browse_rows)
                      if row.action == "dir" and isinstance(row.value, Path)
                      and row.label == f"{row.value.name}/"
                      and not _os_folder(row.value, folder)), 0)
        if not focus and not state.status:
            state.status = _no_setup_reads(state, folder)
            # Never on the row the sentence warns against: A, A, A put a
            # BizHawk install into the home folder. The first folder below
            # it, hidden ones too, else the folder above.
            focus = next((index for index, row in enumerate(state.browse_rows)
                          if row.action == "dir" and isinstance(row.value, Path)
                          and row.label == f"{row.value.name}/"), 0) or next(
                (index for index, row in enumerate(state.browse_rows)
                 if row.action == "up"), 0)
    if (folder is not None and state.browse_for == "from" and came_from is None
            and folder in (state.home, Path(folder.anchor))):
        # The old card is most often a mounted one: the docs say the copy
        # browser opens on them, and A on Use this folder read all of HOME.
        # Not the card being installed to: it was focused first, and taken.
        mounts = [mount for mount in _mounted_cards() if mount != _dest_card(state)]
        focus = next((index for index, row in enumerate(state.browse_rows)
                      if row.action == "dir" and row.value in mounts), focus)
    for index, row in enumerate(state.browse_rows):
        if came_from is not None and row.action == "dir" and row.value == came_from:
            focus = index
    state.focus["browse"] = focus


def _open_backups(state: TuiState, purpose: str) -> list[tuple]:
    """The backups of the folder, read by a child: to look at them, or to
    put one back or delete one."""
    state.backups_for, state.backups = purpose, None
    _push(state, "backups")
    return _start_run(state, "backups")


def _activate_pack_action(state: TuiState, row: TuiRow) -> list[tuple] | None:
    """A and Enter on the pack screens, None on another row."""
    screen, action = state.screen, row.action
    if screen == "more" and action == "packmake":
        state.pack_plan = None
        _push(state, "packplan")
        return _start_run(state, "pack_plan")
    if screen == "packplan" and action == "packwhere":
        state.browse_for = "packto"
        _push(state, "browse")
        _browse_to(state, _nearest_folder(tui_pack_dir(state)))
        return []
    if screen == "packplan" and action == "packgo":
        state.pack_done, state.pack_code, state.pack_fetched = None, None, None
        _push(state, "packdone")
        return _start_run(state, "pack")
    if screen == "packdone" and action == "close":
        state.exit_code = state.pack_code if state.pack_code is not None else 1
        return []
    return None


def _activate_removal_action(state: TuiState, row: TuiRow) -> list[tuple] | None:
    """A and Enter on More and the removal screens, None on another row."""
    screen, action = state.screen, row.action
    if screen == "more" and action == "remove":
        return _push(state, "remove")
    if screen == "more":
        return _open_backups(state, {"backups": "look", "putback": "restore",
                                     "dropbackup": "delete_backup"}[action])
    if screen == "remove":
        state.removal_scope = ([("--system", str(row.value))] if action == "rmsystem"
                               else [("--misplaced", "")] if action == "rmmisplaced"
                               else [])
        state.removal = None
        _push(state, "removal")
        return _start_run(state, "removal_plan")
    if screen == "removal" and action == "rmbackup":
        state.removal_backup = not state.removal_backup
        return []
    if screen == "removal" and action == "rmgo":
        state.action = "remove"
        return _push(state, "actconfirm")
    return None


def _activate_backup_action(state: TuiState, row: TuiRow) -> list[tuple] | None:
    """A and Enter on the backup and action screens, None on another row."""
    screen, action = state.screen, row.action
    if screen == "backups" and action == "backup":
        state.backup_chosen = (state.backups or [])[int(str(row.value))]
        if state.backups_for == "look":
            return _push(state, "backup")
        state.action = state.backups_for
        return _push(state, "actconfirm")
    if screen == "backup":
        state.action = "restore" if action == "bkrestore" else "delete_backup"
        return _push(state, "actconfirm")
    if screen == "actconfirm" and action == "actgo":
        state.action_events, state.action_code = [], None
        _replace(state, "actdone")
        return _start_run(state, state.action)
    if screen == "actdone" and action == "close":
        state.exit_code = state.action_code if state.action_code is not None else 1
        return []
    if screen == "actdone" and action == "recheck":
        # The record changed with the folder: read again, with its choice.
        state.record_for = None
        del state.stack[1:]
        state.stack.append("checking")
        return _start_check(state)
    return None


def _activate_action(state: TuiState, row: TuiRow) -> list[tuple]:
    """A and Enter on the More screens."""
    if row.action == "back":
        return _back(state)
    for activate in (_activate_pack_action, _activate_removal_action, _activate_backup_action):
        effects = activate(state, row)
        if effects is not None:
            return effects
    return []


def _open_details(state: TuiState) -> list[tuple]:
    if state.screen == "result":
        # Looked at, they are said again in the terminal after Exit.
        state.details_seen = True
    return _push(state, "details")


def tui_quit(state: TuiState, code: int | None = None, asked: bool = True) -> list[tuple]:
    """Leave now: with the install's own code once it ran, else QUIT_CODE
    for a quit the user chose (q, Quit) and 130 for Ctrl-C. asked is a quit
    the user chose, said as one: it read "stopped", the word of an
    interrupted run."""
    state.quit_asked = asked
    if code is None:
        code = QUIT_CODE if asked else 130
    if state.screen == "result":
        code = state.code if state.code is not None else 1
    elif state.screen == "error":
        code = state.error_code
    state.exit_code = code
    return [("kill",)] if state.running else []


def tui_interrupt(state: TuiState) -> list[tuple]:
    """Ctrl-C: an install stops and says what it did, anything else ends."""
    if state.run == "install" and state.running:
        if state.stopping:
            return [("kill",)]
        state.stopping = True
        return [("stop",)]
    return tui_quit(state, asked=False)


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


def _plan_close(state: TuiState, row: TuiRow) -> list[tuple]:
    """Close on the plan: every file in place."""
    state.exit_code = 0
    return []


def _plan_where(state: TuiState, row: TuiRow) -> list[tuple]:
    """Change where: back to the setups, a run in progress stopped."""
    effects = [("kill",)] if state.running else []
    state.running, state.run_id = False, state.run_id + 1
    del state.stack[1:]
    return effects


def _plan_record(state: TuiState, row: TuiRow) -> list[tuple]:
    """Same choice as last time, toggled."""
    # No: the choice nothing narrows, the card's games when it holds
    # some. Yes: the recorded choice again. Counted again either way.
    if tui_record_kept(state):
        _tui_record_drop(state)
        if state.dest is not None:
            count = games_probe(state.platform, state.dest, network=False,
                                os_type=state.os_type)
            state.games_probed = (state.platform, state.dest)
            state.games_here = count or 0
            state.for_games, state.games_choice = bool(count), "probe"
    else:
        _tui_record_drop(state)
        _tui_record_take(state)
    effects = _start_check(state)
    state.refocus = "record"
    return effects


def _plan_games(state: TuiState, row: TuiRow) -> list[tuple]:
    """For the games or Start files only, toggled."""
    action = row.action
    # One press, then counted again: the games decide the systems,
    # so the ticks start again from every system they need.
    if action == "games":
        state.for_games, state.games_choice = not state.for_games, "user"
    else:
        state.required_only = not state.required_only
    state.ticked = {row["system"] for row in state.systems if _needed(row)}
    state.hidden_ticks = set()
    effects = _start_check(state)
    state.refocus = action
    return effects


def _plan_game_data(state: TuiState, row: TuiRow) -> list[tuple]:
    """Game data, toggled."""
    # One press, then counted again, as Back from Options counts,
    # the systems ticked kept: the check set them back to every
    # system, and the install wrote all eight.
    state.no_game_data = not state.no_game_data
    effects = _start_check(state)
    state.refocus = "gamedata"
    return effects


def _plan_open(state: TuiState, row: TuiRow) -> list[tuple]:
    """A row of the plan that opens its own screen."""
    action = row.action
    if action == "systems" and state.cli_systems:
        # The check read only what --system named: it is read again for
        # every system, those named ticked. Its exact plan is kept, to
        # come back to when the ticks do not change (_back).
        state.widened_from = {field: getattr(state, field) for field in _CHECK_FIELDS}
        state.keep_ticked = {row["system"] for row in state.systems}
        state.cli_systems, state.widen = [], True
        return _start_check(state)
    if action == "systems":
        state.ticked_before = set(state.ticked)
    # On the first system, A ticking it: Choose systems opened on None,
    # and A there unticked every system.
    _push(state, action)
    state.focus[action] = _first_item(state)
    return []


_PLAN_ACTIONS: dict[str, Callable[[TuiState, TuiRow], list[tuple]]] = {
    "install": lambda state, row: _begin_install(state),
    "close": _plan_close,
    "quit": lambda state, row: tui_quit(state),
    "folder": lambda state, row: _open_folder_screen(state, state.dest, "chosen",
                                                     rebind=True),
    "fromcard": lambda state, row: _open_from_browser(state),
    "misplaced": lambda state, row: _push(state, row.action),
    "unreadable": lambda state, row: _push(state, row.action),
    "more": lambda state, row: _push(state, row.action),
    "recheck": lambda state, row: _start_check(state),
    "where": _plan_where,
    "record": _plan_record,
    "games": _plan_games,
    "startonly": _plan_games,
    "gameslist": lambda state, row: _push(state, "games"),
    "gamedata": _plan_game_data,
}


def _activate_plan(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on a row of the plan."""
    return _PLAN_ACTIONS.get(row.action, _plan_open)(state, row)


def _activate_confirm(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on the confirm screen."""
    if row.action == "install":
        state.stack.pop()
        return _install_now(state)
    if row.action == "close":
        state.exit_code = 0
        return []
    return _back(state)


def _activate_error(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on the error screen."""
    if row.action == "retry":
        return _start_check(state)
    if row.action == "quit":
        return tui_quit(state, state.error_code)
    return _back(state)


def _activate_quit(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on the quit question."""
    if row.action == "quit":
        return tui_quit(state)
    return _back(state)


def _activate_result(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on the result."""
    if row.action == "addapp":
        state.add_app = state.app_running = True
        return [("app", _tui_card(state))]
    return tui_quit(state)


def _activate_device(state: TuiState, row: TuiRow) -> list[tuple]:
    """A on Device: a board chosen."""
    if row.action == "board":
        return _choose_board(state, str(row.value))
    return []


_ACTIVATE_SCREENS: dict[str, Callable[[TuiState, TuiRow], list[tuple]]] = {
    "setup": _activate_setup,
    "platforms": _activate_platforms,
    "folder": _activate_folder,
    "browse": _activate_browse,
    "create": _activate_create,
    "cardroot": _activate_cardroot,
    "plan": _activate_plan,
    **dict.fromkeys((*_CHECKLISTS, "regions"), lambda state, row: _checklist(state, row)),
    "options": lambda state, row: _option(state, row.action, 0),
    "device": _activate_device,
    "confirm": _activate_confirm,
    "error": _activate_error,
    "quit": _activate_quit,
    "result": _activate_result,
}


def _activate(state: TuiState, row: TuiRow) -> list[tuple]:
    screen, action = state.screen, row.action
    if action == "details":
        return _open_details(state)
    if action == "filter":
        only = _only_match(state)
        if only is not None:
            # One setup matches: A chooses it, a second press found nothing
            # more to do.
            return _activate(state, only)
        state.editing = screen
        return []
    if screen in _ACTION_SCREENS:
        return _activate_action(state, row)
    activate = _ACTIVATE_SCREENS.get(screen)
    return activate(state, row) if activate else []


def _checklist(state: TuiState, row: TuiRow) -> list[tuple]:
    """A and Enter on Choose systems, Cores and Preferred regions, one rule
    for the three: an item is ticked or unticked, All and None set every
    box, Done leaves as B does (_back), refused while nothing is ticked."""
    screen, action = state.screen, row.action
    if action == "done":
        return _back(state)
    if action == "morecores":
        state.cores_all = True
        return []
    if action == "region":
        _toggle_region(state, str(row.value))
    elif action in TUI_TICK_ROWS:
        _tick(state, row, None)
    elif action == "all" and screen == "systems":
        state.ticked = {item["system"] for item in state.systems}
    elif action == "all":
        state.cores, state.no_cores = [], False
    elif action == "none" and screen == "regions":
        state.regions = []
    elif action == "none" and screen == "emulators":
        # None ticked installs for every emulator, as Preferred regions keeps
        # every region with none ticked.
        state.emulators = []
    elif action == "none":
        if screen == "systems":
            state.ticked = set()
        else:
            state.cores, state.no_cores = [], True
        # On the first item: the next A ticks the one in focus alone.
        state.focus[screen] = _first_item(state)
    return []


def _platform_focus(state: TuiState, plat: str) -> int:
    """The platform list's row for plat, below its filter row."""
    rows = _platform_rows(state)
    return next((index for index, row in enumerate(rows)
                 if row.action == "platform" and row.value == plat), 1)


def _option_flag(state: TuiState, action: str, step: int) -> bool:
    """A yes or no of the options, or the jobs, set: whether action is one."""
    if action == "game_data":
        state.no_game_data = step > 0 if step else not state.no_game_data
    elif action == "slot":
        state.one_per_slot = step > 0 if step else not state.one_per_slot
    elif action == "standalone":
        state.standalone = step > 0 if step else not state.standalone
    elif action == "installed" and not _cores_dir_given(state):
        state.installed_only = step > 0 if step else not state.installed_only
    elif action == "jobs":
        state.jobs = max(1, min(32, state.jobs + (step or 1)))
    elif action == "addapp":
        state.add_app = step > 0 if step else not state.add_app
    else:
        return False
    return True


def _option_offline(state: TuiState, step: int) -> list[tuple]:
    """Without the internet, turned on or off."""
    on = step > 0 if step else not state.offline
    if (on and state.target and not state.manifest_given and not state.packs
            and not (state.targets_for == state.platform and state.targets)):
        # The run reads the board list beside the file list it is
        # given, written only once Device has read it: refused before
        # a check that would stop on it.
        state.status = _styled("Open Device once first: without the internet the "
                               "board list has to be read already.", "refusal")
        return []
    # The screens read state.offline. The effect carries the choice to
    # this process's own fetches and to the runs started next.
    state.offline = on
    return [("offline", on)]


def _option_device(state: TuiState) -> list[tuple]:
    """Device opened, its board list asked for once per setup."""
    _push(state, "device")
    state.focus["device"] = _device_focus(state)
    if state.targets_for != state.platform:
        state.targets, state.targets_problem = None, ""
        return [("targets", state.platform)]
    return []


def _option_regions(state: TuiState) -> list[tuple]:
    """Preferred regions opened, in the order drawn now."""
    state.region_order = []
    _push(state, "regions")
    state.region_order = [str(row.value) for row in tui_rows(state) if row.action == "region"]
    state.focus["regions"] = _first_item(state)
    return []


def _option_from_dropped(state: TuiState) -> list[tuple]:
    """The last folder to copy from, no longer copied from."""
    # Said, and the screen stays: Back to the plan counts again.
    if state.from_folders:
        removed = state.from_folders.pop()
        state.status = f"No longer copying from {_last_name(str(removed))}."
    return []


def _option(state: TuiState, action: str, step: int) -> list[tuple]:
    """A row of the options: step 0 is Enter, -1 and 1 are Left and Right."""
    if _option_flag(state, action, step):
        return []
    if action == "offline" and LOCAL.pack is None:
        return _option_offline(state, step)
    if action == "device":
        return _option_device(state)
    if action == "emulators":
        _push(state, action)
        state.focus[action] = _first_item(state)
    elif action == "pack":
        return _open_pack_browser(state)
    elif action == "cores":
        # On the first core: the filter row under A opened a field a
        # controller cannot type into.
        _push(state, action)
        state.focus[action] = _first_item(state)
    elif action == "regions":
        return _option_regions(state)
    elif action == "command":
        return _push(state, action)
    elif action == "folder":
        return _open_folder_screen(state, state.dest, "chosen", rebind=True)
    elif action == "from":
        return _option_from_dropped(state) if step < 0 else _open_from_browser(state)
    elif action == "savedir":
        state.browse_for = "save"
        _push(state, "browse")
        _browse_to(state, _nearest_folder(_save_dir_given(state) or state.home))
    elif action == "preview":
        _push(state, "preview")
        return _start_run(state, "preview")
    return []


def _device_focus(state: TuiState) -> int:
    """Device opens on the board chosen: the one read here or named by
    the card when nothing else was."""
    rows = _device_rows(state)
    chosen = _device_choice(state)
    return next((index for index, row in enumerate(rows) if row.value == chosen), 0)


def _open_pack_browser(state: TuiState) -> list[tuple]:
    """The browser, to name a pack downloaded before: it opens where a
    download lands."""
    state.browse_for = "pack"
    _push(state, "browse")
    downloads = state.home / "Downloads"
    start = (state.packs[0].parent if state.packs
             else downloads if _is_dir(downloads) else state.home)
    _browse_to(state, _nearest_folder(start))
    return []


def open_tui_pack(path: Path, plat: str) -> tuple[PackSource | None, str]:
    """The pack the screen chose, opened as --from-pack opens it, and why
    it is refused, "" when it is not. The run reads it only once the screen
    takes it (use_tui_pack): a Back before then leaves the run as it was."""
    try:
        pack = PackSource([path])
    except ValueError as exc:
        return None, str(exc)
    spelled = pack.platforms()
    if spelled and plat not in spelled:
        pack.close()
        return None, (f"{pack.name} is a pack for "
                      f"{' and '.join(display_name(name) for name in spelled)}, "
                      f"not {display_name(plat)}.")
    return pack, ""


def use_tui_pack(pack: PackSource) -> None:
    """The pack the screen took, read by this run in place of the network."""
    if LOCAL.pack is not None and LOCAL.pack is not pack:
        LOCAL.pack.close()
    LOCAL.pack = pack


def _open_from_browser(state: TuiState) -> list[tuple]:
    """The browser, to name an old card, a backup or a ZIP to copy from."""
    state.browse_for = "from"
    _push(state, "browse")
    start = state.from_folders[-1].parent if state.from_folders else state.home
    downloads = state.home / "Downloads"
    if not state.from_folders and _is_dir(downloads) and any(
            name.lower().endswith(".zip") for name in _listed(downloads)):
        # A pack or a backup ZIP is most often there: 18 presses from the
        # first screen reached it through HOME, past every mounted drive.
        start = downloads
    _browse_to(state, _nearest_folder(start))
    return []


def _toggle_region(state: TuiState, name: str) -> None:
    if name in state.regions:
        state.regions.remove(name)
    else:
        state.regions.append(name)
    rows = tui_rows(state)
    state.focus["regions"] = next((i for i, row in enumerate(rows) if row.value == name), 0)


def _begin_install(state: TuiState) -> list[tuple]:
    if state.systems and not state.ticked:
        state.status = "No system is ticked: tick one, or choose All."
        return []
    state.must_confirm = False
    if tui_flags(state) != state.checked_flags:
        _push(state, "confirm")
        return _start_run(state, "confirm")
    return _install_now(state)


def _install_now(state: TuiState) -> list[tuple]:
    _push(state, "installing")
    return _start_run(state, "install")


def _same_plan(one: dict | None, other: dict | None) -> bool:
    keys = ("missing", "wrong_hash", "bytes_needed", "data_missing")
    if not one or not other:
        return False
    return all(one[k] == other[k] for k in keys)


def _tick(state: TuiState, row: TuiRow, on: bool | None) -> None:
    if state.screen == "systems" and row.action == "system":
        chosen = state.ticked
    elif state.screen == "cores" and row.action == "core":
        chosen = {name for name in tui_choices(state)["cores"] if core_ticked(state, name)}
    elif state.screen == "emulators" and row.action == "emulator":
        chosen = set(state.emulators)
    else:
        return
    value = row.value
    want = (value not in chosen) if on is None else on
    if state.screen == "emulators":
        if want and value not in state.emulators:
            state.emulators.append(str(value))
        elif not want and value in state.emulators:
            state.emulators.remove(str(value))
        return
    if state.screen == "systems":
        if want:
            state.ticked.add(value)
        else:
            state.ticked.discard(value)
    elif want:
        if value not in state.cores:
            state.cores.append(value)
        state.no_cores = False
        if set(tui_choices(state)["cores"]) <= set(state.cores):
            # Every core ticked again: no narrowing, as before.
            state.cores = []
    elif not state.cores and not state.no_cores:
        # Every core was ticked, those of the other systems too: one
        # untick keeps every other one ticked. Kept to the systems chosen,
        # it cleared the other systems' cores drawn ticked.
        state.cores = [name for name in tui_choices(state)["cores"] if name != value]
        state.no_cores = not state.cores
    elif value in state.cores:
        state.cores.remove(value)
        state.no_cores = not state.cores
