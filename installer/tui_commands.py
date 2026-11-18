"""The child runs the screens start: their options, environment and the command they stand for."""
from __future__ import annotations

import argparse
import os
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from installer.choices import choosable_cores, emulator_names
from installer.handheld_app import card_app
from installer.host_fs import _is_dir
from installer.install_record import RECORD_NARROWING, record_argv, record_options
from installer.invocation import OFFLINE_VARIABLE, Invocation, offline_option
from installer.offline import LOCAL, OFFLINE_FLAG_VALUE
from installer.tally import leave_out_game_data
from installer.tui_routes import TUI_LIST_ENV, TUI_RECORD_ENV

if TYPE_CHECKING:
    from installer.handheld_app import CardApp
    from installer.tui_state import TuiState


def _tui_passthrough(args: argparse.Namespace) -> list[tuple[str, str | None]]:
    """Options the screens do not change, handed to every run unchanged."""
    flags: list[tuple[str, str | None]] = []
    if args.romm_firmware is not None:
        flags.append(("--romm-firmware", str(args.romm_firmware)))
    for flag in ("--save-dir", "--cores-dir"):
        value = getattr(args, flag[2:].replace("-", "_"))
        if value is not None:
            flags.append((flag, str(Path(value).absolute())))
    flags.extend((flag, None) for flag in ("--standalone-copies", "--verbose")
                 if getattr(args, flag[2:].replace("-", "_")))
    return flags


def _tui_system_flags(state: TuiState) -> list[tuple[str, str | None]]:
    """The --system the screen's ticks stand for."""
    needed = {row["system"] for row in state.systems
              if row["missing"] + row["wrong_hash"] > 0}
    if state.systems and not needed <= state.ticked:
        return [("--system", name) for name in sorted(state.ticked)]
    return [("--system", name) for name in state.cli_systems]


def tui_flags(state: TuiState) -> list[tuple[str, str | None]]:
    """The options that carry the choices made on screen, CLI ones included."""
    flags = list(state.passthrough)
    if state.target:
        flags.append(("--target", state.target))
    if state.every_board:
        flags.append(("--every-board", None))
    flags += [("--emulator", name) for name in state.emulators]
    flags += [("--from-pack", str(pack)) for pack in state.packs]
    flags += _tui_system_flags(state)
    flags += [("--core", name) for name in tui_core_flags(state)]
    if state.regions:
        flags.append(("--region", ",".join(state.regions)))
    if state.for_games:
        flags.append(("--for-games", str(state.games_folder) if state.games_folder else None))
        if state.required_only:
            flags.append(("--required-only", None))
    if state.no_game_data:
        flags.append(("--no-game-data", None))
    if state.standalone and _tui_standalone_offered(state):
        flags.append(("--standalone", None))
    if state.one_per_slot and _tui_slot_offered(state, flags):
        flags.append(("--one-per-slot", None))
    if state.installed_only and not any(flag == "--cores-dir" for flag, _v in flags):
        flags.append(("--installed-cores", None))
    if state.jobs != 8:
        flags.append(("--jobs", str(state.jobs)))
    flags += state.record_flags
    if (state.record is not None and not state.for_games
            and not any(flag in RECORD_NARROWING for flag, _value in flags)):
        # The whole list, chosen over a recorded narrower one: said so to
        # the runs, whose own reading of the record would narrow it again.
        flags.append(("--all-files", None))
    flags += [("--from", str(folder)) for folder in state.from_folders]
    if (os.environ.get(OFFLINE_VARIABLE) == OFFLINE_FLAG_VALUE
            and not any(flag == "--offline" for flag, _v in flags)):
        # Given as --offline: said so in the command. Set as the variable,
        # the runs inherit it and the words name it.
        flags.append(("--offline", None))
    return flags


_TUI_MODES = {
    "check": ["--check", "--events"],
    "confirm": ["--dry-run", "--events"],
    "preview": ["--dry-run", "--events"],
    "install": ["--events", "--yes"],
}


def tui_argv(state: TuiState, run: str, python: str, script: str) -> list[str]:
    """The child that does what the screen decided."""
    if run in TUI_ACTION_RUNS:
        return tui_action_argv(state, run, python, script)
    # --dest=VALUE: a folder typed as -x would otherwise be read as an option.
    argv = [python, script, f"--platform={state.platform}", f"--dest={state.dest}"]
    if state.manifest_path is not None:
        argv.append(f"--manifest={state.manifest_path}")
    argv += [flag if value is None else f"{flag}={value}" for flag, value in tui_flags(state)]
    if run == "install" and state.add_app and _tui_app_ready(state):
        # Only the install writes: --check and --dry-run refuse it.
        argv.append("--add-app")
    return argv + _TUI_MODES[run]


def tui_run_env(state: TuiState, own_list: bool) -> dict | None:
    """The environment of a child run: None for this one's own, else with
    the markers the run reads (TUI_LIST_ENV, TUI_RECORD_ENV)."""
    marks = {TUI_LIST_ENV: "1"} if own_list else {}
    if tui_record_kept(state):
        marks[TUI_RECORD_ENV] = "1"
    if not marks and TUI_RECORD_ENV not in os.environ:
        return None
    env = {key: value for key, value in os.environ.items() if key != TUI_RECORD_ENV}
    env.update(marks)
    return env


def tui_hint(state: TuiState) -> Invocation:
    """The command the screen's choices make, every option of the run in
    it: what "Same choice without questions" and the sudo advice give."""
    hint = Invocation()
    hint.os_type = state.os_type
    hint.options = ([("--manifest", str(state.manifest_path))]
                    if state.manifest_given and state.manifest_path else [])
    hint.options += tui_flags(state)
    if state.add_app and _tui_app_ready(state):
        hint.options.append(("--add-app", None))
    # The runs inherit the variable, a command shown to the user does not.
    if offline_option(False) and ("--offline", None) not in hint.options:
        hint.options.append(("--offline", None))
    return hint


def tui_command(state: TuiState) -> str:
    """The same choice as one command, in the form the run was started with."""
    return tui_hint(state).command(state.platform, state.dest)


def _tui_card(state: TuiState) -> CardApp | None:
    """The card the BIOS folder is on, read once for each folder."""
    if state.dest is None:
        return None
    if state.card_for != state.dest:
        state.card_for, state.card = state.dest, card_app(state.dest)
    return state.card


def _tui_app_ready(state: TuiState) -> bool:
    """Whether the RetroBIOS app can go on this card: its system has one,
    and the run may use the network to fetch it."""
    card = _tui_card(state)
    return card is not None and card.place is not None and not LOCAL.offline


def _tui_installed(state: TuiState) -> bool:
    """An install that finished with every file in place."""
    summary = state.summary or {}
    return bool(summary) and not summary.get("interrupted") and not summary.get("failed") \
        and state.code == 0


def _app_offer(state: TuiState) -> bool:
    """The result offers the app: the install finished, the card can take
    it, and it was neither asked for nor put already."""
    return (state.screen == "result" and state.app is None and not state.app_running
            and _tui_installed(state) and _tui_app_ready(state))


def tui_run_files(state: TuiState) -> tuple[list[dict], list[dict]]:
    """The files and omissions the run chooses among, as the check counted
    them: the list without what it set aside before any choice (the save
    entries of a save directory it cannot place), the game data left out
    when the plan leaves it out. Line mode chooses among the same (bare)."""
    manifest = state.manifest or {}
    key = (id(state.manifest), frozenset(state.set_aside or ()), state.no_game_data)
    if state.run_files_cache is not None and state.run_files_cache[0] == key:
        return state.run_files_cache[1]
    aside = state.set_aside or set()
    files = [entry for entry in manifest.get("files") or [] if entry.get("dest") not in aside]
    omitted = list(manifest.get("omitted_files") or [])
    if state.no_game_data:
        files, omitted = leave_out_game_data(files, omitted)[:2]
    state.run_files_cache = (key, (files, omitted))
    return files, omitted


def _core_base(state: TuiState) -> list[str]:
    """The cores a choice on Cores is made among: those of the systems
    chosen, every core the run accepts else (choosable_cores, as line
    mode counts them)."""
    return choosable_cores(*tui_run_files(state), _tui_systems_chosen(state))


def tui_core_flags(state: TuiState) -> list[str]:
    """The --core the run is given: the cores ticked, none when every core
    of the systems chosen is (the run keeps the same files)."""
    if not state.cores or set(_core_base(state)) <= set(state.cores):
        return []
    return list(state.cores)


def _tui_systems_chosen(state: TuiState) -> list[str]:
    """The systems the run is narrowed to, [] for every system."""
    return [value for _flag, value in _tui_system_flags(state) if value]


def _tui_standalone_offered(state: TuiState) -> bool:
    """Whether Change offers --standalone: emulators are chosen, the list
    records a standalone build for each of them, and no region, core or
    system choice narrows the run, which the option refuses beside it."""
    manifest = state.manifest or {}
    layouts = manifest.get("standalone_builds") or []
    if not state.emulators or not layouts or not _tui_standalone_fits(state):
        return False
    names = emulator_names(manifest, *tui_run_files(state))
    return all(names.get(name) in layouts for name in state.emulators)


def _tui_standalone_fits(state: TuiState) -> bool:
    """No region, core or system choice: --standalone takes none."""
    return not (state.regions or tui_core_flags(state) or _tui_system_flags(state))


def _tui_slot_offered(state: TuiState, flags: list[tuple[str, str | None]]) -> bool:
    """Whether Change offers --one-per-slot: the list records its slots and
    the choice is the whole list, as the pack builder decides slots over it
    (no system, emulator or game choice narrows it first)."""
    return bool((state.manifest or {}).get("slot_fields")) and not any(
        flag in ("--system", "--emulator", "--for-games", "--declared-only")
        for flag, _value in flags)


def _record_key(options: Iterable[tuple[str, str | None]]) -> list:
    """A choice in a form two spellings of it share: one name per --system
    and --core, in any order."""
    pairs = record_options(record_argv(options))
    return sorted((flag, name.strip()) for flag, value in pairs
                  for name in ((value or "").split(",") if flag in ("--system", "--core")
                               else [value or ""]) if name.strip() or value is None)


def tui_record_kept(state: TuiState) -> bool:
    """Whether the plan's choice is the one the record keeps."""
    if state.record is None:
        return False
    return _record_key(tui_flags(state)) == _record_key(
        record_options(state.record["choice"]))


# The runs More starts, each a child as an install is: what --remove would
# take (removal_plan), the removal, the backups listed, one put back and
# one deleted.
TUI_ACTION_RUNS = ("removal_plan", "remove", "backups", "restore", "delete_backup",
                   "pack_plan", "pack")
# The plan's options a pack's run leaves out: each reads or writes the BIOS
# folder of this machine, which --pack refuses.
TUI_PACK_DROPPED = ("--dest", "--installed-cores", "--cores-dir", "--save-dir",
                    "--standalone-copies", "--add-app", "--romm-firmware", "--for-games",
                    "--required-only")


def tui_pack_dir(state: TuiState) -> Path:
    """The folder the pack goes in: the one chosen, else Downloads where
    there is one, else the home folder."""
    if state.pack_dir is not None:
        return state.pack_dir
    downloads = state.home / "Downloads"
    return downloads if _is_dir(downloads) else state.home


def tui_pack_argv(state: TuiState, run: str, python: str, script: str) -> list[str]:
    """The child that makes the pack, or lists it (pack_plan): the plan's
    choice, none of the options of this machine's folder. The games of a
    folder named stay a choice, the card's own are not read for a pack."""
    argv = [python, script, f"--platform={state.platform}"]
    if state.manifest_path is not None:
        argv.append(f"--manifest={state.manifest_path}")
    flags = [flag for flag in tui_flags(state) if flag[0] not in TUI_PACK_DROPPED]
    if state.for_games and state.games_folder:
        flags.append(("--for-games", str(state.games_folder)))
        if state.required_only:
            flags.append(("--required-only", None))
    argv += [flag if value is None else f"{flag}={value}" for flag, value in flags]
    argv.append(f"--pack={tui_pack_dir(state)}{os.sep}")
    return argv + (["--dry-run", "--events"] if run == "pack_plan" else ["--events", "--yes"])


def tui_action_argv(state: TuiState, run: str, python: str, script: str) -> list[str]:
    """The child of a More action: its own options and none of the plan's,
    whose --system is an install's choice, not what to remove. A pack
    takes the plan's choice."""
    if run in ("pack_plan", "pack"):
        return tui_pack_argv(state, run, python, script)
    if run in ("restore", "delete_backup"):
        folder = str((state.backup_chosen or {}).get("folder", ""))
        flag = "--restore" if run == "restore" else "--delete-backup"
        return [python, script, f"{flag}={folder}", "--events",
                *(["--yes"] if run == "delete_backup" else [])]
    argv = [python, script, f"--platform={state.platform}", f"--dest={state.dest}"]
    if run == "backups":
        return argv + ["--backups", "--events"]
    if state.manifest_path is not None:
        argv.append(f"--manifest={state.manifest_path}")
    argv += ["--remove", *(f"{flag}={value}" if value else flag
                           for flag, value in state.removal_scope)]
    if state.removal_backup and not _removing_misplaced(state):
        argv.append("--backup")
    return argv + (["--dry-run", "--events"] if run == "removal_plan" else ["--events", "--yes"])


def _removing_misplaced(state: TuiState) -> bool:
    """Whether the removal is of the copies in the wrong place, which are
    deleted: they were never a setup's, so no backup gives them back."""
    return ("--misplaced", "") in state.removal_scope
