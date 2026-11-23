"""The result screen: what an install, a pack or a More action did, in words."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from installer.cards import _mounted_cards, card_system
from installer.destination import _last_name
from installer.detect_os import detected_os
from installer.failure_causes import (
    Failure,
    event_records,
    failure_records,
    failure_remedies,
    retry_helps,
    retry_words,
    split_offline,
)
from installer.from_folders import sources_line
from installer.handheld_app import NO_PYTHON_CARDS, app_lines, no_python_words
from installer.invocation import Invocation
from installer.offline import LOCAL, offline_named
from installer.outcome import (
    EVERYTHING_IN_PLACE,
    NEXT_ON_CARD,
    NEXT_ON_DEVICE,
    _offline_remedy,
    write_remedy,
)
from installer.paths import shown_path
from installer.platforms import display_name
from installer.removal import _kept_words, backup_words, kept_line
from installer.romm import ROMM_SCAN_WORDS
from installer.tally import installed_words, left_out_words
from installer.text import _plural, _wrap, agree, cell_width, format_size
from installer.tui_choice import _on_its_card, _plan_folder, _tui_categories, _tui_tally
from installer.tui_commands import _removing_misplaced, _tui_card, _tui_installed, tui_command, tui_hint
from installer.tui_paint import _FOLDER_LABEL, _command_line, _detail, _details, _short_path, _styled
from installer.tui_plan_view import _commands, _saves_lines, _unavailable_brief, _unavailable_lines, _unplaced_lines
from installer.tui_routes import TUI_PAD_ROUTES
from installer.tui_state import tui_offline_only

if TYPE_CHECKING:
    from installer.tui_state import TuiState

def full_drive_words(state: TuiState) -> str:
    """The run's stop for lack of space (its no_space event), in words, ""
    for another stop: read once, when the run ends."""
    if state.no_space is None:
        return ""
    needed, free = state.no_space
    dest = (state.dest or Path(".")).absolute()
    card = any((mount == dest or mount in dest.parents) and card_system(mount)
               for mount in _mounted_cards())
    return (f"The {'card' if card else 'drive'} is full: {format_size(needed)} needed, "
            f"{format_size(free)} free.")


def _tui_sources(state: TuiState, installed: int, missing: int, wrong: int = 0,
                 failed: int = 0) -> str:
    """Where the installed files came from, as the line mode says it:
    "6 files copied from /media/me/OLD, 42 downloaded, 2 still missing." """
    ok = {dest for dest, good, _why in state.finished if good}
    folders: dict[str, int] = {}
    fixed = 0
    for dest, (folder, reason) in state.local_dests.items():
        if dest not in ok:
            continue
        if reason:
            fixed += 1
        else:
            # By its name, as the plan said "6 found in old card".
            name = _last_name(folder)
            folders[name] = folders.get(name, 0) + 1
    copied = fixed + sum(folders.values())
    return sources_line(list(folders.items()), fixed, max(0, installed - copied), missing,
                        "from the pack" if LOCAL.pack is not None else "downloaded",
                        wrong=wrong, failed=failed)


class _OutcomeCounts(NamedTuple):
    """What an install run reported, as its result counts it."""
    summary: dict
    installed: int
    failed: list[Failure]
    offline_failed: list[Failure]
    left: int
    up_to_date: int
    total: int
    space: str
    errors: str


def _outcome_counts(state: TuiState) -> _OutcomeCounts:
    summary = state.summary or {}
    # Killed by the second Ctrl-C, the child wrote no summary: what it
    # reported finished is what is installed.
    installed = summary.get("installed", sum(1 for _dest, ok, _why in state.finished if ok))
    # Each with its cause, from the failures event the summary follows:
    # without it, the cause its words name.
    records = (event_records(state.failures) if summary.get("failed") and state.failures
               else failure_records((failure["dest"], failure["reason"])
                                    for failure in summary.get("failed") or []))
    # Left out by --offline: missing, never failed, as line mode says it.
    # The engine counts them in pending and no longer in failed (a file was
    # both): pending holds the real failures too, which are taken out.
    failed, offline_failed = split_offline(records)
    left = len(offline_failed) + (max(0, summary.get("pending", 0) - len(failed))
                                  if tui_offline_only(state) and not offline_failed else 0)
    up_to_date = summary.get("up_to_date", 0)
    total = (state.download or {}).get("files", 0)
    space = "" if summary else state.full_drive
    errors = f", {len(failed)} failed" if failed else ""
    return _OutcomeCounts(summary, installed, failed, offline_failed, left, up_to_date, total,
                          space, errors)


def _done_head(state: TuiState, counts: _OutcomeCounts) -> str:
    installed = counts.installed
    # With the sources line below, the count alone: "23 installed from
    # the pack" sat above "21 from the pack".
    source = (" from the pack" if LOCAL.pack is not None
              and not _tui_sources(state, installed, 0) else "")
    # The plan said the wrong copies are replaced: the result counts them.
    replaced = sum(kept.get("files", 0) for kept in counts.summary.get("kept") or [])
    # One kind is named in the count, not on a line of its own: "78
    # files installed" above "Installed: 78 BIOS files".
    word = "BIOS file" if _one_kind(state, installed) else "file"
    head = (f"{_plural(installed, word)} installed{source}"
            + (f", {replaced} of them replaced" if replaced else "") + ".")
    if counts.up_to_date:
        head += f" {_plural(counts.up_to_date, 'file')} already in place."
    return head


def _outcome_head(state: TuiState, counts: _OutcomeCounts) -> tuple[str, str]:
    """The result's title and its first line."""
    summary, installed, failed, left = (counts.summary, counts.installed, counts.failed,
                                        counts.left)
    errors, total = counts.errors, counts.total
    if summary.get("interrupted") or state.code == 130:
        return "Stopped", (f"Stopped: {installed} of {total} installed, run again to finish."
                           if total
                           else "Stopped. Run again to carry on: what is done stays done.")
    if left and installed:
        return ("Finished with files missing",
                f"{installed} installed, {left} not fetched ({offline_named()}){errors}.")
    if left:
        return ("Nothing installed",
                f"Nothing was installed: {_plural(left, 'file')} not fetched "
                f"({offline_named()}){errors}.")
    if failed and installed:
        return "Finished with errors", f"{installed} installed, {len(failed)} failed."
    if failed:
        return "Nothing installed", f"Nothing was installed: {_plural(len(failed), 'file')} failed."
    if not summary and counts.space:
        return "Not enough space", counts.space
    if not summary:
        return "Stopped", f"The installer stopped with code {state.code}."
    if installed:
        return "Done", _done_head(state, counts)
    return "Done", EVERYTHING_IN_PLACE


def _outcome_counted(state: TuiState, counts: _OutcomeCounts, title: str,
                     head: str) -> list[str]:
    """The head, then where the files came from and what is still missing."""
    installed, failed, left = counts.installed, counts.failed, counts.left
    lines = [head]
    ok_dests = {dest for dest, good, _why in state.finished if good}
    missing = ([failure.dest for failure in counts.offline_failed]
               or [event["dest"] for event in state.files
                   if event["dest"] not in ok_dests][:left]) if left else []
    # A wrong copy left in place is no missing file: --check counts it apart,
    # and the result said "1 still missing" of it.
    wrong_dests = {event["dest"] for event in state.files if event.get("state") == "wrong_hash"}
    wrong_left = sum(1 for dest in missing if dest in wrong_dests)
    sources = _tui_sources(state, installed, left - wrong_left, wrong_left, len(failed))
    if (left or failed) and installed and sources:
        # One count, then the remedy, as line mode says it: the count came
        # twice, the remedy between them.
        lines[0] = sources
        sources = ""
    elif title == "Done" and sources and "," not in sources and not counts.summary.get("kept"):
        # Every file from one place: "22 files installed." over "22 files
        # copied from packx." said one count twice.
        lines[0] = sources + head[head.index(".") + 1:]
        sources = ""
    if sources:
        lines.append(sources)
    if left:
        # What is still missing by kind, as the copies are counted: 6 of the
        # 16 were game data, and the old card's result said 16 files.
        apart = _tui_tally(state, [{"dest": dest, "size": 0} for dest in missing
                                   if dest not in wrong_dests])
        if _tui_categories(state) and apart.bios and apart.games:
            lines.append(_detail(f"Still missing: {installed_words(apart.bios, apart.games)}."))
        # Each folder spelled in full, as the result names its others.
        lines.append(_offline_remedy([shown_path(folder) for folder in state.from_folders]))
    return lines


def _outcome_placed(state: TuiState, counts: _OutcomeCounts, title: str) -> list[str]:
    """What was installed by kind, the BIOS folder and what goes with it."""
    installed, up_to_date = counts.installed, counts.up_to_date
    lines: list[str] = []
    ok = {dest for dest, good, _why in state.finished if good}
    if any(reason and dest in ok for dest, (_folder, reason) in state.local_dests.items()):
        # A fix copies: the misplaced files are the user's, never moved.
        lines.append(_detail("The copies in the wrong place were left as they are."))
    if _tui_categories(state) and title != "Stopped" and installed:
        # As the plan counted them, and as line mode ends, on every result:
        # the old card's said "6 files copied" and no kind. The data tree
        # files are the installed ones no file event names.
        done = _tui_tally(state, [{"dest": dest, "size": 0}
                                  for dest, good, _why in state.finished if good])
        if done.files and not (title == "Done" and _one_kind(state, installed)):
            lines.append(_detail("Installed: " + installed_words(
                done.bios, done.games, max(0, installed - done.files)) + "."))
    # The folder the plan named: MinUI's Bios, not the card's root.
    lines.append(f"BIOS folder: {shown_path(str(_plan_folder(state, state.dest)))}")
    if installed + up_to_date:
        # Spelled as the BIOS folder above it is, whole: "~/" beside a full
        # path was two spellings on one screen.
        lines += _details(_saves_lines(state, state.done_saves, whole=True))
    if state.version:
        # Said again with the result, as line mode ends: the system's own
        # BIOS check may mark the files just put in place.
        lines.append(state.version)
    if state.platform == "romm" and installed:
        lines.append(ROMM_SCAN_WORDS)
    fallback = (state.games or {}).get("fallback") or [] if state.for_games else []
    if fallback:
        # Named with the result, as line mode ends: they got every BIOS of
        # their system, so that they start.
        names = ", ".join(str(item.get("name")) for item in fallback[:3])
        more = f" and {len(fallback) - 3} more" if len(fallback) > 3 else ""
        their = "its" if len(fallback) == 1 else "their"
        lines.append(_detail(f"Not recognised, every BIOS of {their} system kept: "
                             f"{names}{more}."))
    if counts.space:
        lines.append("Free some space on the card, then run again." if _on_its_card(state)
                     else "Free some space, or run again and choose another folder.")
    return lines


def _failure_lines(failed: list[Failure]) -> list[str]:
    """Each file that failed with its reason, a reason shared by many said once."""
    lines: list[str] = []
    causes: dict[str, list[str]] = {}
    for failure in failed:
        causes.setdefault(failure.reason, []).append(failure.dest)
    shown = 0
    for reason, dests in causes.items():
        if len(dests) > 3:
            # A read-only folder fails every file alike: said once.
            lines.append(f"  {len(dests)} files failed, all for one reason: "
                         f"{reason or 'none given'}.")
            continue
        for dest in dests:
            if shown < 20:
                lines.append(f"  failed: {dest}" + (f" ({reason})" if reason else ""))
            shown += 1
    if shown > 20:
        lines.append(f"  ... and {shown - 20} more")
    return lines


def _remedy_lines(state: TuiState, failed: list[Failure]) -> list[str]:
    """What to do about each cause, the words line mode gives: the screen
    ended a mirror's 404 or a proxy's refusal on "Run it again"."""
    where = shown_path(str(_plan_folder(state, state.dest))) if state.dest else "the folder"
    return [line.strip() for advice in failure_remedies(failed, where)
            for line in advice.split("\n")]


def _retry_lines(failed: list[Failure]) -> list[str]:
    # What a rerun does, as line mode and the first install page say
    # it: the screen never did.
    retry = retry_words(failed)
    if retry:
        return [retry]
    if retry_helps(failed):
        return ["Run it again to retry only those."]
    return []


def _outcome_unfinished(state: TuiState, counts: _OutcomeCounts, title: str) -> list[str]:
    """The data files not installed, the remedy for a folder not written,
    and the log of a run that died."""
    summary, installed, failed = counts.summary, counts.installed, counts.failed
    lines: list[str] = []
    expected = (state.dry if state.dry is not None else state.check or {}).get(
        "data_missing", 0)
    landed = max(0, installed - sum(1 for _dest, good, _why in state.finished if good))
    if expected > landed and not counts.left and title != "Stopped" and summary:
        # The data files the plan counted, never named on a result that
        # counted the BIOS files alone.
        lines.append(_detail(f"{_plural(expected - landed, 'data file')} not installed"
                             + (f": not in {LOCAL.pack.name}." if LOCAL.pack is not None
                                else ".")))
    if state.dest is not None and any(failure.kind == "not_writable" for failure in failed):
        # The plan's own advice: the result offered nothing after 22 files
        # failed on a read-only card.
        lines += _commands(state, write_remedy(state.dest, state.platform, tui_hint(state),
                                               state.pad not in TUI_PAD_ROUTES))
    if not summary and not counts.space and state.code != 130:
        # A stop asked for (Ctrl-C, Select+Start, the window closed) is said
        # by the line above: the log's last lines are for a run that died.
        lines += [f"  {line}" for line in state.tail[-8:]]
    return lines


def _outcome_closing(state: TuiState, counts: _OutcomeCounts, title: str) -> list[str]:
    """The backups, the files left out, the next step and the command."""
    summary, installed = counts.summary, counts.installed
    lines: list[str] = []
    run = Invocation()
    run.os_type = state.os_type
    # A controller cannot type a command: on a pad route none is printed,
    # the result of a muOS install ended on four lines of shell.
    typed = state.pad not in TUI_PAD_ROUTES
    for kept in summary.get("kept") or []:
        lines.append(f"The files it replaced are kept in {kept['folder']}")
        if typed:
            # Broken between its words only, never inside one (_wrap).
            lines += _details([_command_line(f"To put them back: {run.launcher()} --restore "
                                             f"{run.word(str(kept['folder']))}", run)])
    if summary and not summary.get("interrupted") and installed + counts.up_to_date:
        lines += _unavailable_brief(state) + _details(_unavailable_lines(state))
    for group in summary.get("left_out") or []:
        lines.append(_detail(f"{left_out_words(group)}."))
    lines += _unplaced_lines(summary, state)
    lines += _tui_app_lines(state)
    if title == "Done" and not (state.platform == "romm" and installed):
        # Last of what the result says by default: RomM's scan is its step.
        lines.append(tui_next_words(state))
    if typed:
        lines += _details(["Same choice without questions:",
                           _command_line(f"  {tui_command(state)}", tui_hint(state))])
    if tui_keeps_log(state):
        lines.append(f"Log: {state.log}")
    if state.mouse and typed:
        # A drag over the command selected nothing: the terminal sends the
        # press as a report. Said where it is read.
        lines.append(_detail(TUI_RESULT_AGAIN if state.os_type == "android"
                             else TUI_RESULT_COPY, "dim"))
    return lines


def tui_outcome(state: TuiState) -> tuple[str, list[str]]:
    """The result in words, first what happened, then where and what next."""
    counts = _outcome_counts(state)
    if state.dest_error is not None:
        return _dest_error_outcome(state, counts.installed)
    title, head = _outcome_head(state, counts)
    lines = _outcome_counted(state, counts, title, head)
    lines += _outcome_placed(state, counts, title)
    lines += _failure_lines(counts.failed)
    lines += _remedy_lines(state, counts.failed)
    if title == "Finished with errors":
        lines += _retry_lines(counts.failed)
    lines += _outcome_unfinished(state, counts, title)
    lines += _outcome_closing(state, counts, title)
    return title, lines


def tui_next_words(state: TuiState) -> str:
    """The step after an install the result says went well."""
    if _on_its_card(state):
        return NEXT_ON_CARD
    if state.dest is not None and detected_os(state.platform, state.dest):
        return NEXT_ON_DEVICE
    return f"Next: start {display_name(state.platform, state.manifest)} and play."


def _dest_error_outcome(state: TuiState, installed: int) -> tuple[str, list[str]]:
    """The result of a run whose BIOS folder could not be created: that
    reason for every file, and its remedy. It said "22 files not fetched
    (RETROBIOS_INSTALL_OFFLINE=1)" and sent the user for a pack holding all
    22."""
    message = str((state.dest_error or {}).get("message", ""))
    folder = shown_path(str(_plan_folder(state, state.dest)))
    _where, _sep, why = message.rpartition(": ")
    head = (f"Nothing was installed: {folder} cannot be created ({why.lower() or 'no reason'})."
            if not installed else f"{installed} installed, then {folder} could not be "
            f"created ({why.lower() or 'no reason'}).")
    lines = [head]
    remedy = (write_remedy(state.dest, state.platform, tui_hint(state),
                           state.pad not in TUI_PAD_ROUTES) if state.dest is not None else [])
    if not remedy or str(remedy[0]).startswith("Or "):
        lines.append("Run it again and choose another folder.")
    lines += _commands(state, remedy)
    if state.pad not in TUI_PAD_ROUTES:
        lines += _details(["Same choice without questions:",
                           _command_line(f"  {tui_command(state)}", tui_hint(state))])
    if tui_keeps_log(state):
        lines.append(f"Log: {state.log}")
    return ("Nothing installed" if not installed else "Finished with errors"), lines


# How to copy from the result, under its command while the mouse is on.
# Termux has no Shift key under a finger: there the second sentence alone.
TUI_RESULT_AGAIN = "All of this is shown again in the terminal after Exit."
TUI_RESULT_COPY = f"Shift and a drag select text. {TUI_RESULT_AGAIN}"


def _one_kind(state: TuiState, installed: int) -> bool:
    """Whether every file a run installed is a BIOS file of a list that
    marks its kinds: the count then names the kind."""
    if not _tui_categories(state):
        return False
    done = _tui_tally(state, [{"dest": dest, "size": 0}
                              for dest, good, _why in state.finished if good])
    return bool(done.files) and done.files == installed and not done.games


def _tui_app_lines(state: TuiState) -> list[str]:
    """What became of the RetroBIOS app on the card, once the install finished."""
    card = _tui_card(state)
    if card is None:
        return []
    if state.app_running:
        return ["Putting RetroBIOS on the card..."]
    if state.app is not None:
        return app_lines(card, state.app)
    if card.place is None and card.system in NO_PYTHON_CARDS and _tui_installed(state):
        return [no_python_words(card.system)]
    return []


def tui_keeps_log(state: TuiState) -> bool:
    """Whether the run's log is kept: when a failure names it, and only then.
    57 folders of logs from stopped and finished runs were left in /tmp."""
    if state.screen == "crashed":
        return True
    # A full card is said in words on the screen: its log adds nothing.
    return (bool(state.log) and state.code not in (0, 130, None)
            and not state.full_drive)


def _removal_text(state: TuiState) -> list:
    """The removal plan: what goes and the space freed, where, what stays
    and why, the files themselves behind Details."""
    plan = state.removal or {}
    folder = _short_path(state.dest, state.home)
    if not plan.get("files"):
        lines: list = ["No copy in the wrong place." if _removing_misplaced(state)
                       else "Nothing here can be removed."]
    elif _removing_misplaced(state):
        lines = [f"{_plural(plan['files'], 'copy')} in the wrong place go, "
                 f"{format_size(plan['bytes'])} freed. The files where the cores read "
                 "them stay."]
    elif state.removal_backup:
        lines = [f"{_plural(plan['files'], 'file')} to a backup, "
                 f"{format_size(plan['bytes'])}."]
    else:
        lines = [f"{_plural(plan['files'], 'file')} go, {format_size(plan['bytes'])} freed."]
    lines.append(_styled(f"{_FOLDER_LABEL}{folder}", "path"))
    kept = plan.get("kept") or []
    if kept:
        lines.append(f"{agree(len(kept), 'file stays', 'files stay')}: "
                     f"{_kept_words([{**item, 'what': ''} for item in kept])}.")
    if not plan.get("files") and plan.get("message") and not kept:
        lines.append(_detail(str(plan["message"])))
    lines += _details(["", "Removed:"] + [f"  {dest}" for dest in plan.get("dests") or []]
                      if plan.get("dests") else [])
    lines += _details(["", "Left as they are:"] + [
        f"  {kept_line({**item, 'what': ''})}" for item in kept] if kept else [])
    return lines


def tui_action_outcome(state: TuiState) -> list:
    """What a More action did, in one line, then where."""
    end = next((event for event in state.action_events if event.get("event") == "restore"),
               None)
    events = [event for event in state.action_events if event.get("event") != "restore"]
    done = [event for event in events if event.get("ok", True)]
    failed = [event for event in events if not event.get("ok", True)]
    size = format_size(sum(int(event.get("size") or 0) for event in done))
    if state.action == "remove" and state.removal_backup:
        lines: list = [f"Moved {_plural(len(done), 'file')} to a backup, {size}."]
    elif state.action == "remove":
        lines = [f"Removed {_plural(len(done), 'file')}, {size} freed."]
    elif state.action == "restore":
        lines = [f"Put back {_plural(len(done), 'file')}, {size}."]
    else:
        gone = next((event for event in events if event.get("status") == "deleted"), None)
        lines = ([f"Deleted the backup, {format_size(int(gone['bytes']))} freed."]
                 if gone is not None else ["The backup was not deleted."])
    if failed:
        lines.append(_styled(f"{_plural(len(failed), 'file')} failed.", "failure"))
        lines += _details([f"  {event.get('dest') or event.get('path')}: {event['reason']}"
                           for event in failed])
    lines += _restore_end_lines(end)
    lines.append(_styled(f"{_FOLDER_LABEL}{_short_path(state.dest, state.home)}", "path"))
    return lines


def _restore_end_lines(end: dict | None) -> list:
    """What a restore's end event adds to its outcome: why nothing went
    back, where the files at their places were kept, and why the install
    record was not updated."""
    if end is None:
        return []
    message = str(end.get("message") or "")
    lines: list = [_styled(message, "failure") if end.get("status") == "not_backup"
                   else message] if message else []
    lines += [f"Kept {_plural(int(item['files']), 'file')} that were in their place "
              f"({format_size(int(item['bytes']))}) in {item['folder']}"
              for item in end.get("kept") or []]
    if end.get("problem"):
        lines.append(_styled(f"The install record could not be updated ({end['problem']}).",
                             "failure"))
    return lines


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
