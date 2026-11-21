"""The plan and Confirm screens: every line they say."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from installer.destination import _last_name
from installer.from_folders import MAX_SCANNED_FILES
from installer.frontend_folders import save_where_words
from installer.install_record import record_changes, record_says
from installer.manifest import GAME_DATA, OTHER_SYSTEMS
from installer.offline import LOCAL, _offline_only, offline_named, offline_undo
from installer.outcome import EVERYTHING_IN_PLACE, _offline_remedy, write_remedy
from installer.pack_source import pack_lacks_words
from installer.paths import shown_path
from installer.plan_words import (
    CANNOT_WRITE,
    cannot_write_words,
    core_count_words,
    game_data_only,
    game_data_only_words,
    space_words,
    unavailable_lines,
    unlisted_saves_words,
)
from installer.platforms import display_name, system_title
from installer.tally import kinds_definition, needed_absent_words, parts_words, tally
from installer.text import _plural, agree, format_size
from installer.tui_choice import (
    _choice_entries,
    _choice_in_place,
    _choice_line,
    _emptied_words,
    _needed,
    _no_setup_reads,
    _on_its_card,
    _plan_data,
    _plan_fetch,
    _plan_folder,
    _ticked_estimate,
    _ticked_files,
    _ticked_held,
    _tui_categories,
    _tui_estimating,
    _tui_found_elsewhere,
    _tui_misplaced,
    _tui_pack_trees,
    _tui_tally,
    games_plan_words,
    games_where,
    space_needed,
    tui_systems,
    tui_verbose,
)
from installer.tui_commands import _core_base, tui_core_flags, tui_hint, tui_record_kept
from installer.tui_frame import _compose, _text_lines
from installer.tui_paint import _FOLDER_LABEL, _command_line, _detail, _details, _is_detail, _short_path, _styled
from installer.tui_routes import TUI_PAD_ROUTES
from installer.tui_rows import _plan_rows, tui_rows

if TYPE_CHECKING:
    from installer.tui_paint import TuiLine
    from installer.tui_state import TuiRow, TuiState


def _scan_lines(state: TuiState) -> list[str]:
    """What the reading of the --from folders left out, one line each."""
    lines: list = []
    for scan in state.scanned:
        if scan["truncated"]:
            lines.append(_detail(f"Read the first {MAX_SCANNED_FILES:,} files of "
                                 f"{scan['folder']}."))
        lines += [f"{drive} is another drive: add it to copy from it too."
                  for drive in scan["other_drives"]]
    # The count, which line mode always says, stays where no row names
    # these files: the plan's Show row does.
    if state.unreadable and any(row.action == "unreadable" for row in _plan_rows(state)):
        lines += _details(_unreadable_count(state))
    elif state.unreadable:
        lines += _unreadable_count(state)
    return lines


def _unreadable_count(state: TuiState) -> list[str]:
    """How many files the --from folders hold that could not be read."""
    lines = []
    if state.unreadable:
        count = len(state.unreadable)
        # Named as it was given: "your old card" was said of a folder.
        where = ", ".join(_last_name(folder) for folder in
                          dict.fromkeys(event["folder"] for event in state.unreadable))
        lines.append(f"{_plural(count, 'file')} in {where} could not be read.")
    return lines


class _PlanFigures(NamedTuple):
    """The counts and sizes one plan's lines are written from."""
    need: int
    data: int
    dry: bool
    fetch: int
    fetch_bytes: int
    data_bytes: int
    copied: list
    lacking: list
    sizes: dict
    elsewhere: dict
    offline: bool


def _plan_figures(check: dict, state: TuiState) -> _PlanFigures:
    need = _needed(check)
    data = check.get("data_missing", 0)
    dry = check is state.dry and check is not state.check
    fetch, fetched, copied, lacking, sizes = _plan_fetch(state, check)
    fetch_bytes = fetched - (check.get("data_bytes", 0) if data else 0)
    elsewhere = (_tui_found_elsewhere(state, set(copied) if dry else None)
                 if check is state.check or dry else {})
    offline = _offline_only()
    # The data files are files to fetch like the others: one count and one
    # size, the kinds apart on the line under the folder. "8358 files and
    # 2636 data files" read as two kinds of one thing.
    data_bytes = check.get("data_bytes", 0) if data else 0
    return _PlanFigures(need, data, dry, fetch, fetch_bytes, data_bytes, copied, lacking,
                        sizes, elsewhere, offline)


def _plan_needed_headline(check: dict, fig: _PlanFigures) -> str:
    """The headline of a plan with files to install."""
    need, data, fetch, copied = fig.need, fig.data, fig.fetch, fig.copied
    if fig.elsewhere:
        # The folder by its last name: the whole path pushed the BIOS
        # folder off a 40x15 screen. The Options row spells it out. The
        # data files are among those to fetch: one count.
        where = ", ".join(f"{len(events)} found in {_last_name(folder)}"
                          for folder, events in fig.elsewhere.items())
        rest = fetch + data
        return (f"{where}, {agree(rest, 'needs', 'need')} the internet ({offline_named()})"
                if rest and fig.offline
                else f"{where}, {rest} to download "
                f"({format_size(fig.fetch_bytes + fig.data_bytes)})"
                if rest else f"{where}, nothing to download")
    if need and fetch and fig.offline:
        return (f"{agree(fetch + data, 'file needs', 'files need')} the "
                f"internet, which {offline_named()} does not use")
    if need and fetch and LOCAL.pack is not None and copied:
        # One count: "21 files to install from the pack" above "23 to
        # install", and the result said 23 came from the pack, then 21.
        held = check["bytes_needed"] - sum(fig.sizes[dest_] for dest_ in fig.lacking)
        return (f"{_plural(need - len(fig.lacking) + data, 'file')} to install, "
                f"{format_size(held + fig.data_bytes)}")
    if need and fetch and LOCAL.pack is not None:
        # Nothing comes from the network: "to download" on a handheld with
        # no Wi-Fi read as a failure on its way.
        return (f"{_plural(fetch + data, 'file')} to install from the pack, "
                f"{format_size(fig.fetch_bytes + fig.data_bytes)}")
    if need and fetch:
        return (f"{_plural(fetch + data, 'file')} to download, "
                f"{format_size(fig.fetch_bytes + fig.data_bytes)}")
    if need and data:
        copied_bytes = sum(fig.sizes[dest_] for dest_ in copied)
        return (f"{_plural(len(copied) + data, 'file')} to install, "
                f"{format_size(copied_bytes + fig.data_bytes)}")
    return f"{_plural(len(copied), 'file')} to copy from this machine"


def _plan_headline(check: dict, state: TuiState, fig: _PlanFigures) -> str:
    data = fig.data
    # The data trees' size comes from their own event: "2636 data files"
    # beside "6.6 GB" said nothing of what they weigh.
    data_size = (f" ({format_size(check['data_bytes'])})" if data and "data_bytes" in check
                 else "")
    if not fig.need:
        return (f"{_plural(data, 'data file')} to fetch{data_size}" if data
                else EVERYTHING_IN_PLACE.rstrip("."))
    if fig.lacking and not fig.fetch and not fig.copied:
        # The data files too, when the pack holds none of them: "8252
        # files" said nothing of the 2636 it cannot give either.
        lacked = len(fig.lacking) + (data if data and not _tui_pack_trees(state) else 0)
        return pack_lacks_words(lacked, lacked)
    return _plan_needed_headline(check, fig)


def _plan_backups(check: dict, state: TuiState, fig: _PlanFigures) -> int:
    """How many wrong copies the plan replaces, the old ones kept."""
    # The wrong copies something replaces: offline, those a folder copied
    # from holds, else those the network or the pack brings too. "The 1
    # wrong copy is replaced" stood over a copy no folder held, which the
    # result then said was left.
    wrong_dests = [event["dest"] for event in (state.dry_files if fig.dry else state.files)
                   if event.get("state") == "wrong_hash"]
    return (sum(1 for dest_ in wrong_dests if dest_ in fig.copied) if fig.offline
            else sum(1 for dest_ in wrong_dests
                     if dest_ in fig.copied or dest_ not in fig.lacking)
            if wrong_dests else check["wrong_hash"])


def _misplaced_line(misplaced: list) -> TuiLine:
    return _detail(
        f"{_plural(len(misplaced), 'file')} "
        f"{'is' if len(misplaced) == 1 else 'are'} in the wrong place, "
        f"{'it' if len(misplaced) == 1 else 'they'} will be copied where the "
        "emulators read "
        f"{'it' if len(misplaced) == 1 else 'them'}, the "
        f"{'copy' if len(misplaced) == 1 else 'copies'} left as "
        f"{'it is' if len(misplaced) == 1 else 'they are'}.")


def _backup_line(backup: int, wrong: int) -> TuiLine:
    # With its subject: "They are replaced" sat lines under the count.
    # Not where nothing can be installed: nothing is replaced then.
    return _detail(
        (f"The {_plural(wrong, 'wrong copy')} " if backup == wrong
         else f"{backup} of the {_plural(wrong, 'wrong copy')} ")
        + f"{'is' if backup == 1 else 'are'} replaced, the old "
        f"{'one' if backup == 1 else 'ones'} kept in a backup folder.")


def _plan_split_line(fig: _PlanFigures) -> list[TuiLine]:
    """The pack and copy split under the counts."""
    if fig.copied and fig.fetch and LOCAL.pack is not None:
        return [_detail(f"{fig.fetch} from the pack, {len(fig.copied)} copied from this "
                        "machine")]
    if fig.copied and fig.fetch and not fig.offline:
        # 47 to download above 49 missing and 1 wrong copy: the 3 found on
        # this machine are the difference, on a line of its own ("0 wrong
        # copies: 2 of them" read as two of the zero). Offline the headline
        # says it: "3 downloaded" sat under "3 need the internet".
        return [_detail(f"{fig.need} to install: {len(fig.copied)} copied from this machine, "
                        f"{fig.fetch} downloaded")]
    return []


def _plan_from_lines(state: TuiState, fig: _PlanFigures, offline_lines: list) -> list:
    """What the plan says of the folders copied from."""
    # A folder copied from that holds none of them: the plan came back
    # the same, still saying to copy from a folder.
    held = {Path(folder).absolute() for folder in fig.elsewhere}
    empty = [_last_name(str(folder)) for folder in state.from_folders
             if Path(folder).absolute() not in held]
    if empty and not fig.need:
        # Every file is in place: "packx holds none of these files" read
        # as an empty card, where it holds all 22.
        return [f"Nothing to copy from {', '.join(empty)}: every file is in "
                "place."]
    if empty and offline_lines and len(empty) == len(state.from_folders):
        # Said once: "USBSTICK holds none of these files" was followed
        # by "They are not in USBSTICK".
        return [f"{', '.join(empty)} {'holds' if len(empty) == 1 else 'hold'} "
                "none of these files: run the installer again with a pack "
                f"(--from-pack) or {offline_undo()}."]
    return [f"{name} holds none of these files." for name in empty] + offline_lines


def _plan_check_lines(check: dict, state: TuiState) -> list:
    """The lines a plan adds from the check's own events."""
    lines: list = []
    if check is state.check:
        lines += _scan_lines(state)
    if check.get("not_installable"):
        lines += _unavailable_brief(state) + _details(_unavailable_lines(state))
    if check is state.check:
        lines += _unplaced_lines(_choice_summary(state), state,
                                 "Choose it in Change, Save folder (--save-dir).")
    if check is state.check:
        lines += _found_lines(state)
    return lines


def _plan_lines(check: dict, dest: Path | None, state: TuiState) -> list:
    fig = _plan_figures(check, state)
    data, fetch = fig.data, fig.fetch
    headline = _plan_headline(check, state, fig)
    wrong = check["wrong_hash"]
    # Where some were found, the plan names the rest by kind ("Not in old:
    # 10 BIOS files and 6 game data files.", _view_plan), and the remedy
    # follows it: "They" sat under a split of all 22.
    offline_lines = ([_offline_remedy([_last_name(str(folder))
                                       for folder in state.from_folders],
                                      named=bool(fig.elsewhere) and not fig.dry)]
                     if fig.offline and fetch else [])
    # The folder comes second: on a 40x12 screen it is what is left once
    # the rows are drawn, and nothing is written before it is seen.
    lines: list = [
        _styled(headline, "title"),
        _styled(f"BIOS folder: {_short_path(_plan_folder(state, dest), state.home)}", "path"),
    ]
    found_in = state.facts.get("config") if dest is not None else None
    if found_in:
        # Right under the folder it names: after the save lines it read as
        # naming them.
        lines.append(_detail(f"Named by {_short_path(Path(found_in[0]), state.home)}", "path"))
    if state.facts.get("writable") is False and dest is not None:
        # The remedy itself comes below, after the counts.
        lines += cannot_write_words(dest, state.platform, tui_hint(state),
                                    state.pad not in TUI_PAD_ROUTES, _on_its_card(state),
                                    screen=True, remedy=False)
    # Said again where it is the BIOS folder: the browser said it, and the
    # plan named ~ alone.
    lines += filter(None, [_no_setup_reads(state, dest)])
    # The data files missing among the missing: the headline counts them,
    # and "10888 need the internet" sat over "8252 missing".
    counts = (f"{check['present']} in place, {check['missing'] + data} missing, "
              f"{_plural(wrong, 'wrong copy')}")
    # A first install's missing files are its normal state, not a warning.
    lines.append(_detail(counts, "quiet" if not check["present"] and not wrong else ""))
    # The backup line goes right under the count it explains, before the
    # pack and copy split: at 40x12 and 40x15 it came after it, and was cut.
    count_at = len(lines)
    lines += _plan_split_line(fig)
    after_counts = len(lines)
    saves = (_choice_saves(state) if check is state.check
             else state.dry_saves if check is state.dry else None)
    saves_lines = _saves_lines(state, saves)
    lines += [_detail(line, "path" if index else "") for index, line in enumerate(saves_lines)]
    free = state.facts.get("free")
    if free is not None:
        lines.append(_detail(f"Free space: {format_size(free)}"))
        if space_needed(check) > free:
            lines.append(space_words(space_needed(check), free, _on_its_card(state)))
    backup = _plan_backups(check, state, fig)
    misplaced = _tui_misplaced(state) if check is state.check else []
    if misplaced:
        lines.insert(after_counts, _misplaced_line(misplaced))
    if backup:
        lines.insert(count_at, _backup_line(backup, wrong))
    if state.facts.get("writable") is False and dest is not None:
        lines += _commands(state, write_remedy(dest, state.platform, tui_hint(state),
                                               state.pad not in TUI_PAD_ROUTES))
    lines += _plan_check_lines(check, state)
    if check is state.check and state.from_folders:
        offline_lines = _plan_from_lines(state, fig, offline_lines)
    if fig.lacking and (fetch or fig.copied):
        offline_lines.insert(0, pack_lacks_words(len(fig.lacking), len(fig.lacking) + fetch))
    # On Confirm the remedy comes right after the headline: at 40x12 it was
    # what got cut, Back left alone below it. On the plan it comes after the
    # folder and what named it: between them, Named by sat lines under its
    # folder.
    at = 1 if check is state.dry else 3 if found_in else 2
    return lines[:at] + offline_lines + lines[at:]


def _choice_saves(state: TuiState) -> dict | None:
    """The check's saves event, counted again over the systems ticked while
    the plan estimates them: one ticked system without a save file kept
    the line of the whole list."""
    if not _tui_estimating(state) or not state.saves:
        return state.saves
    count = _choice_save_count(state)
    return {**state.saves, "files": count} if count else None


def _choice_summary(state: TuiState) -> dict | None:
    """The check's summary, its save files left out counted over the
    systems ticked while the plan estimates them."""
    summary = state.check_summary
    if not _tui_estimating(state) or not summary:
        return summary
    count = _choice_save_count(state)
    skipped = [group if group.get("reason") != "no_save_directory"
               else {**group, "files": count} for group in summary.get("skipped") or []]
    return {**summary, "skipped": skipped}


def _choice_save_count(state: TuiState) -> int:
    """The files of the choice read from the frontend's save directory,
    game data left out when it is."""
    return sum(1 for entry in _choice_entries(state) if entry.get("root") == "save"
               and not (state.no_game_data and entry.get("category") == GAME_DATA))


def _commands(state: TuiState, lines: list[str]) -> list[str]:
    """Lines holding a command the user may run, drawn as commands: wrapped
    between shell words, and the mouse left to the terminal over them."""
    hint = tui_hint(state)
    launchers = (hint.launcher(), hint.launcher(True))
    return [_command_line(line, hint) if any(launcher in line for launcher in launchers)
            else line for line in lines]


def _saves_lines(state: TuiState, saves: dict | None, whole: bool = False) -> list[str]:
    """Where the files read from the frontend's save directory go: a second
    folder this run writes to, named before anything is written. saves is
    the event of the run the screen shows. whole spells the folder in full,
    as the result names its other folders."""
    if not saves or not saves.get("files"):
        return []
    name = display_name(state.platform) if state.platform else "the frontend"
    count = saves["files"]
    words, folder = save_where_words(saves["folder"])
    # The folder alone is cut in the middle: cut with the sentence, it
    # lost "directory goes to" even at 80 columns.
    # The folder on its own line at the BIOS folder's indent: at the
    # label's, the two folders of a plan sat at two.
    return [f"{_plural(count, 'file')} read from {name}'s save directory "
            f"{'goes' if count == 1 else 'go'} to{' ' + words if words else ''}:",
            "  " + (shown_path(folder) if whole else _short_path(Path(folder), state.home))]


def _unplaced_lines(summary: dict | None, state: TuiState,
                    remedy: str = "") -> list[str]:
    """The files read from the frontend's save directory that the run left
    out, that directory being unknown: said, never silent."""
    count = sum(group.get("files", 0) for group in (summary or {}).get("skipped") or []
                if group.get("reason") == "no_save_directory")
    if not count:
        return []
    name = display_name(state.platform) if state.platform else "the frontend"
    left = f"{_plural(count, 'file')} read from {name}'s save directory left out"
    if state.manifest and not state.manifest.get("save_directory"):
        return [f"{left}.", _detail(f"{unlisted_saves_words(name)}.")]
    return [f"{left}. {remedy or TUI_SAVE_REMEDY}", _detail("Its place is not known.")]


# Said when ES-DE is found, and in fewer words where the long form would
# give way: at 40x12 it ended in the middle of its sentence.
TUI_ESDE_NOTE = "ES-DE found: its BIOS files go to each emulator, not to ES-DE itself."
TUI_ESDE_SHORT = "ES-DE: files go to each emulator."


def _reading_line(state: TuiState, elapsed: str) -> str:
    if state.games_reading and not state.reading:
        done, total = state.games_reading
        return f"Reading the games: {done} of {total}"
    if state.reading:
        done, total = state.reading
        return f"Reading the files already in the folder: {done} of {total}"
    return f"Reading the files already in the folder... {elapsed}"


def _estimated_head(state: TuiState, check: dict, lines: list, data: int) -> list:
    """The plan's lines under an estimate for the systems ticked."""
    # The headline counts the systems ticked, as the list just did: at
    # 40x12 the line below it was dropped, and the plan showed the
    # total of all of them. Their data files too, as line mode's head.
    # One total, the data files in it, the kinds under the folder
    # adding up to it.
    count, size = _ticked_estimate(state)
    lines[0] = _styled(f"About {_plural(count, 'file')}, {format_size(size)}"
                       f", for {len(state.ticked)} of {len(state.systems)} systems", "title")
    if _offline_only():
        # Offline, what the folders copied from hold of the systems
        # ticked: the plan counted the whole list beside "For your 1 of
        # 11 systems".
        held = _ticked_held(state)
        rest = len(_ticked_files(state)) - len(held) + data
        # Nothing at hand: the head the whole list's plan says, for the
        # systems ticked. "About 0 files, 0 B" stood over 20 files the
        # internet would bring.
        lines[0] = _styled(
            f"{agree(rest, 'file needs', 'files need')} the internet, which "
            f"{offline_named()} does not use, for {len(state.ticked)} of "
            f"{len(state.systems)} systems", "title") if not held else _styled(
            f"About {_plural(count, 'file')}, "
            f"{format_size(size)}, for {len(state.ticked)} of "
            f"{len(state.systems)} systems"
            + (f", {agree(rest, 'needs', 'need')} the internet "
               f"({offline_named()})" if rest else ""), "title")
        if not rest:
            # The remedy was for files of the whole list: none of the
            # choice needs the internet.
            names = [_last_name(str(folder)) for folder in state.from_folders]
            remedies = {_offline_remedy(names), _offline_remedy(names, named=True)}
            lines = [line for line in lines if str(line) not in remedies]
    # The in place and missing counts are the whole list's: under an
    # estimate for some systems they read as its own.
    whole = (f"{check['present']} in place, "
             f"{check['missing'] + check.get('data_missing', 0)} missing, "
             f"{check['wrong_hash']} wrong ")
    return [line for line in lines if not str(line).startswith(whole)]


def _plan_named(state: TuiState) -> str:
    """The choice named on the command line, in line mode's words."""
    games_count = (state.games or {}).get("games") if state.for_games else None
    named = [*([f"for the {_plural(games_count, 'game')} {games_where(state)}"
                + (", only what starts" if state.required_only else "")
                + (" (--for-games)" if state.games_choice == "cli" else "")]
               if games_count else []),
             *([f"for {len(state.systems)} of {len(tui_systems(state))} systems (--system)"]
                if state.cli_systems and state.systems else []),
             # Named as line mode names it, out of how many, the flag after
             # the words where the command line gave it: "--core" said
             # nothing of the count, and "--region." stood alone.
             *([core_count_words(state.cores, _core_base(state))
                + (" (--core)" if state.cores == state.cli_cores else "")]
               if tui_core_flags(state) else []),
             *(["regions ranked" + (" (--region)" if state.regions == state.cli_regions
                                    else "")] if state.regions else [])]
    said = ", ".join(named)
    if said and not said.startswith("for "):
        said = f"for this choice: {said}"
    return said


def _record_said(state: TuiState, said: str) -> tuple[str, list]:
    """The choice said and the changes since, where a record is kept."""
    since: list = []
    if tui_record_kept(state) and not state.cli_choice and state.record is not None:
        # The record's systems by name, its row saying whose choice it is:
        # nobody typed --system. The games and the other options are said
        # as the plan says them.
        what = record_says(state.record, state.manifest)
        if what == "every file":
            said = ""
        elif what not in ("the games", "the options chosen"):
            said = f"for {what}"
        updated, new = record_changes(state.record, [
            entry for entry in (state.manifest or {}).get("files") or []
            if entry.get("dest") in state.checked_dests])
        changes = [*([f"{_plural(updated, 'file')} updated in the list"] if updated else []),
                   *([f"{new} new"] if new else [])]
        if changes:
            since = [_detail(f"Since then: {', '.join(changes)}.")]
    return said, since


def _plan_kinds(state: TuiState, check: dict, estimating: bool, data: int,
                data_size: int | None) -> tuple[str, str]:
    """The split by kind under the folder and the definition it needs."""
    # Of the files the headline counts, by kind: those ticked when it
    # estimates them, those to install otherwise. Under the folder, never
    # above it: inserted second, it pushed the folder off a 40x12 plan.
    kinds_of = (_ticked_files(state) if estimating else
                [event for event in state.files if event["state"] != "present"])
    found = (_tui_found_elsewhere(state) if not estimating and _offline_only()
             and state.check is check else {})
    if found:
        # Some were found in a folder: the kinds split those the headline
        # says need the internet, named as such.
        took = {event["dest"] for events in found.values() for event in events}
        outside = [event for event in kinds_of if event["dest"] not in took]
        if outside or data:
            kinds_of = outside
        else:
            # Every file found: the kinds are those of the files copied,
            # and game data is defined as the pack's plan defines it. The
            # --from plan said neither.
            found = {}
    parts, defined = _kinds_lines(state, kinds_of, data, data_size, whole=bool(found))
    if _choice_in_place(state) or (state.emptied and state.systems and not state.ticked):
        # Nothing of the choice is left to install: a split of the whole
        # list under its headline counted files it does not hold.
        parts = defined = ""
    if found and parts:
        parts = (f"Not in {', '.join(_last_name(str(folder)) for folder in found)}: "
                 f"{parts}")
    return parts, defined


def _plan_tail_notes(state: TuiState, lines: list, defined: str) -> None:
    """The version, board, status and definition lines, each where it goes."""
    if state.version:
        # Before the free space, which gives way first: appended last, the
        # note was cut from the 40x12 plan with no sign.
        free = next((index for index, line in enumerate(lines)
                     if str(line).startswith("Free space:")), len(lines))
        lines.insert(free, state.version)
    if state.board:
        free = next((index for index, line in enumerate(lines)
                     if str(line).startswith("Free space:")), len(lines))
        lines.insert(free, _detail(state.board))
    if state.status:
        lines.append(state.status)
    if defined:
        # Once, after the counts and before the save line: last, it was
        # the first line to give way at 80 columns, where the counts named
        # data files nothing defined. The help says it
        # where the screen has no room.
        saves = next((index for index, line in enumerate(lines)
                      if "'s save directory" in str(line)), len(lines))
        lines.insert(saves, _detail(defined))


def _plan_text(state: TuiState) -> list:
    """Every line of the plan, the Details lines among them."""
    check = state.check or {}
    lines = _plan_lines(check, state.dest, state)
    choice = _choice_line(state)
    estimating = _tui_estimating(state)
    data, data_size = _plan_data(state, check)
    if state.emptied and state.systems and not state.ticked:
        lines = [_styled(_emptied_words(state), "title"), *lines[1:2]]
        estimating = False
    elif _choice_in_place(state):
        lines = [_styled(_choice_in_place(state), "title"), *lines[1:2]]
        choice = []
        estimating = False
    elif estimating:
        lines = _estimated_head(state, check, lines, data)
    # Under the folder and what named it, in this order: the card's note,
    # the choice named on the command line, the choice made here.
    at = next((index + 1 for index, line in enumerate(lines)
               if str(line).startswith("BIOS folder:")), 1)
    if at < len(lines) and str(lines[at]).startswith("Named by "):
        at += 1
    said, since = _record_said(state, _plan_named(state))
    # A system --system named that --no-game-data left empty, in line mode's
    # words.
    listed = {row["system"] for row in state.systems}
    emptied_named = game_data_only_words([
        system_title(system, state.manifest) for system in game_data_only(
            [name for name in state.cli_systems if name not in listed],
            (state.manifest or {}).get("files") or [])]) if state.no_game_data else ""
    # Named on the command line: said in line mode's words, and widened by
    # Choose systems. --core and --region were said in line mode alone
    parts, defined = _plan_kinds(state, check, estimating, data, data_size)
    lines[at:at] = [*([_detail(state.card_note)] if state.card_note
                      and state.card_note != state.status else []),
                    *([f"{said[0].upper()}{said[1:]}."] if said else []), *since,
                    *([emptied_named] if emptied_named else []), *choice,
                    *([_detail(parts)] if parts else []), *games_plan_words(state)]
    _plan_tail_notes(state, lines, defined)
    return lines


def _shown(state: TuiState, lines: list) -> list:
    """The lines a screen shows: with --verbose every line but the counts
    standing for them, else every line but Details."""
    if tui_verbose(state):
        return [line for line in lines if not getattr(line, "brief", False)]
    return [line for line in lines if not _is_detail(line)]


def _plan_body(state: TuiState, width: int, height: int, lines: list,
               rows: list[TuiRow], short: bool = False) -> list[TuiLine]:
    """The plan's text and rows. Where both do not fit, the headline, the
    whole BIOS folder and the version note stay and the rows scroll under
    them: at 40x12 the plan named ~/.var/app/ as the folder, and dropped the
    note that the list is for another version. With
    no room for its sentences the note is said in one line (short): at
    40x12 the RetroBat note was still dropped."""
    body = _compose(state, width, height, lines, rows)
    at = next((index for index, line in enumerate(lines)
               if str(line).startswith(_FOLDER_LABEL.rstrip())), None)
    kept = list(lines[:1])
    if at is not None:
        # The folder line and the rest of the folder wrapped after it.
        end = at + 1
        while end < len(lines) and getattr(lines[end], "style", "") == "folder":
            end += 1
        kept += lines[at:end]
    kept += [line for line in lines if state.version
             and str(line) in (state.version, state.version_short)]
    # Why the folder rows are offered, before Install anyway: at 40x12 the
    # plan offered Choose another folder and Install anyway and no word of
    # why.
    kept += [line for line in lines if str(line).startswith(CANNOT_WRITE)]
    # A file in place that the install replaces, said whatever the rows: the
    # More row every plan holds pushed it out of a 40x12 plan.
    kept += [line for line in lines if "backed up, replaced" in str(line)]
    top = _text_lines(kept, width)
    drawn = [str(line).strip() for line in body]
    # Three lines at least for the rows: two of them and where the list is,
    # the blank line above them given up first.
    if all(str(line).strip() in drawn for line in top):
        return body
    if len(top) + min(len(rows), 3) > height:
        if not short and state.version_short and state.version in map(str, lines):
            return _plan_body(state, width, height, [
                _styled(state.version_short) if str(line) == state.version else line
                for line in lines], rows, True)
        return body
    gap = [_styled("")] if len(top) + 1 + min(len(rows), 3) <= height else []
    return top + gap + _compose(state, width, height - len(top) - len(gap), [], rows)


def _kinds_lines(state: TuiState, events: list[dict], data: int,
                 data_size: int | None, whole: bool = False) -> tuple[str, str]:
    """The plan's files by kind (parts_words) and what each kind is: the
    same words as line mode's head, game data left out counted over the
    choice. whole: the kinds are said even when there is one."""
    categories = _tui_categories(state)
    categorized = bool(categories)
    if state.no_game_data:
        # Counted apart as left out, never also among the files installed.
        events = [event for event in events if categories.get(event["dest"]) != GAME_DATA]
    counts = (_tui_tally(state, events) if categorized
              else tally({"size": event["size"]} for event in events))
    left = 0
    if categorized and state.no_game_data:
        left = sum(1 for entry in _choice_entries(state) if entry.get("category") == GAME_DATA)
    parts = parts_words(counts, data, data_size, left)
    if whole and not parts and counts.files:
        parts = f"{_plural(counts.files, 'file')} ({format_size(counts.size)})"
    # Game data named as missing is defined too, on its own line: the
    # definition was spliced into that sentence.
    missing = any(entry.get("category") == GAME_DATA for entry in _unavailable(state)[0])
    defined = kinds_definition(categorized and bool(counts.games or left or missing),
                               bool(data))
    return (f"{parts}." if parts else ""), defined


def _screen_definition(state: TuiState) -> str:
    """What the kinds the plan or Confirm counts are, as their screen says
    it where there is room (kinds_definition), "" elsewhere."""
    if state.screen == "plan" and state.check:
        estimating = _tui_estimating(state)
        return _kinds_lines(state, _ticked_files(state) if estimating else [
            event for event in state.files if event["state"] != "present"],
            *_plan_data(state, state.check))[1]
    if state.screen == "confirm" and state.dry and not state.running:
        data = state.dry.get("data_missing", 0)
        return _kinds_lines(state, state.dry_files, data,
                            state.dry.get("data_bytes") if data else None)[1]
    return ""


def _confirm_text(state: TuiState) -> list:
    """Every line of Confirm, the Details lines among them."""
    lines = _plan_lines(state.dry or {}, state.dest, state)
    # The kinds apart, as the plan counts them, under the folder.
    data = (state.dry or {}).get("data_missing", 0)
    parts, _defined = _kinds_lines(state, state.dry_files, data,
                                   (state.dry or {}).get("data_bytes") if data else None)
    if parts:
        at = next((index + 1 for index, line in enumerate(lines)
                   if str(line).startswith(_FOLDER_LABEL)), len(lines))
        lines.insert(at, _detail(parts))
    if any(row.action == "install" for row in tui_rows(state)):
        lines.insert(0, "Counted again for these choices.")
        lines.insert(1, _detail("Nothing is written before Install."))
    return lines


def _unavailable(state: TuiState) -> tuple[list[dict], int]:
    """The list's files RetroBIOS cannot supply for the systems chosen: the
    ones an emulator needs to start, and how many others."""
    listed = {row["system"] for row in state.systems}
    chosen = state.ticked if state.systems else None
    needed, others = [], 0
    for entry in (state.manifest or {}).get("omitted_files") or []:
        system = entry.get("system") if entry.get("system") in listed else OTHER_SYSTEMS
        if chosen is not None and system not in chosen:
            continue
        if state.no_game_data and entry.get("category") == "game_data":
            continue
        if entry.get("required"):
            needed.append(entry)
        else:
            others += 1
    return needed, others


def _found_lines(state: TuiState) -> list[TuiLine]:
    """What the setups screen said of this machine, on a plan that opened
    in its place: the setup found by its label, and the notes (ES-DE found,
    what detection printed) on Details, one line on the plan saying so."""
    if not state.opened_on_plan or not state.setups:
        return []
    lines = _details([f"Found here: {state.setups[0][2]}.", *state.notes])
    if state.notes:
        brief = _styled(f"{_plural(len(state.notes), 'note')} on this machine: Details.")
        brief.brief = True
        lines.insert(0, brief)
    return lines


def _unavailable_brief(state: TuiState) -> list[TuiLine]:
    """The count of the files an emulator needs that cannot be supplied, on
    the screen itself: their names are on Details, and in place with
    --verbose, where the count is not said again."""
    needed, _others = _unavailable(state)
    if not needed:
        return []
    line = _styled(needed_absent_words(len(needed), "Details"))
    line.brief = True
    return [line]


def _unavailable_lines(state: TuiState) -> list[str]:
    """The files that cannot be supplied and stop an emulator, by name and
    system: "1 file ... an emulator needs it" named neither."""
    needed, _others = _unavailable(state)
    return unavailable_lines(needed, state.manifest, state.dest,
                             (state.manifest or {}).get("files") or [])


# The result's remedy for the save files left out, as the terminal says it
# once the screen is gone: Options are not there to choose from
# Line mode's words.
TUI_SAVE_REMEDY = "Choose it in Change, Save folder (--save-dir), next time."
