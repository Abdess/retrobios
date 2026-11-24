"""What choosing a row does on the plan, option, checklist and closing screens, by screen."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from installer.destination import (
    _last_name,
)
from installer.games import games_probe
from installer.host_fs import _is_dir, _nearest_folder
from installer.offline import LOCAL
from installer.pack import _listed
from installer.pack_source import PackSource
from installer.platforms import display_name
from installer.tui_choice import (
    _cores_dir_given,
    _device_choice,
    _needed,
    _save_dir_given,
    core_ticked,
    tui_choices,
)
from installer.tui_commands import _tui_card, tui_flags, tui_record_kept
from installer.tui_paint import _CHECK_FIELDS, _styled
from installer.tui_rows import (
    TUI_TICK_ROWS,
    _ACTION_SCREENS,
    _CHECKLISTS,
    _device_rows,
    _first_item,
    tui_rows,
)
from installer.tui_screens import _only_match
from installer.tui_state import TuiRow

if TYPE_CHECKING:
    from installer.tui_state import TuiState
from installer.tui_folder_actions import (
    _activate_browse,
    _activate_cardroot,
    _activate_create,
    _activate_folder,
    _activate_platforms,
    _activate_setup,
    _open_folder_screen,
)
from installer.tui_steps import (
    _activate_action,
    _back,
    _browse_to,
    _choose_board,
    _open_details,
    _push,
    _start_check,
    _start_run,
    _tui_record_drop,
    _tui_record_take,
    tui_quit,
)


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
