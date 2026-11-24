"""Moves between screens: opening and leaving them, starting a check or a run, the action menus."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from installer.cards import _mounted_cards
from installer.choices import known_regions, trim_recorded
from installer.console import QUIT_CODE
from installer.games import games_probe
from installer.host_fs import _nearest_folder
from installer.install_record import (
    RECORD_NARROWING,
    _RECORD_SAID,
    choice_words,
    options_without,
    record_options,
    setup_record,
    take_recorded_choice,
)
from installer.platforms import _tui_system_label
from installer.regions import resolve_regions
from installer.tui_choice import (
    _board_seen,
    _choice_in_place,
    _counts_predate_options,
    _dest_card,
    _needed,
    _no_setup_reads,
    _none_ticked,
    _system_titles,
)
from installer.tui_commands import tui_flags, tui_pack_dir, tui_record_kept
from installer.tui_rows import _browse_rows, _os_folder, tui_rows
from installer.tui_state import TuiRow

if TYPE_CHECKING:
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
