"""What the file list fetch and the child runs report back, turned into a new state."""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from installer.device import detect_board
from installer.platforms import display_name
from installer.removal import list_backups
from installer.tui_actions import (
    _activate,
    _device_focus,
    _focus_plan,
    _install_now,
    _known_choice,
    _replace,
    _same_plan,
    _start_check,
    _start_run,
    _tui_folder_facts,
)
from installer.tui_choice import _needed
from installer.tui_commands import TUI_ACTION_RUNS
from installer.tui_outcome import full_drive_words
from installer.tui_paint import _styled
from installer.tui_rows import tui_rows

if TYPE_CHECKING:
    from installer.tui_state import TuiState


def _fail(state: TuiState, lines: list[str], code: int) -> list[tuple]:
    state.error_title = ""
    state.error = [line for line in lines if line.strip()] or [
        f"The installer stopped with code {code} and said nothing."]
    state.error_code = code or 1
    state.running = False
    _replace(state, "error")
    return []


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
    elif kind in ("removed", "restored", "restore", "backup") and state.run in (
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
    elif kind == "unplaced":
        state.unplaced_why[str(event["root"])] = str(event["why"])
    elif kind == "data" and state.check is not None:
        state.check["data_bytes"] = event["bytes"]
    elif kind == "space" and state.check is not None:
        state.check["space_bytes"] = event["bytes"]
    elif kind == "fetch_plan" and state.check is not None:
        state.check["fetch_plan"] = event
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
    elif kind == "space" and state.dry is not None:
        state.dry["space_bytes"] = event["bytes"]
    elif kind == "fetch_plan" and state.dry is not None:
        state.dry["fetch_plan"] = event
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
    elif kind == "failures":
        state.failures = event["failed"]
    elif kind == "summary":
        state.summary = event


def _take_event(state: TuiState, event: dict) -> None:
    if _take_action_event(state, event):
        return
    kind = event.get("event")
    if kind == "no_space":
        state.no_space = (event["bytes_needed"], event["bytes_free"])
        return
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
    state.full_drive = full_drive_words(state)
    state.no_space = None
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
