"""The rows of each screen and the moves between screens."""
from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from pathlib import Path

from installer.app import APP_OFFER, APP_OFFER_SHORT
from installer.arguments import build_parser
from installer.cards import _card_what, blank_cards_of, dest_drive, doubt_cards, mounted_cards_of, shown_bios_folder
from installer.constants import CARD_PLATFORMS, GAME_DATA, OTHER_SYSTEMS, TARGET_PLATFORMS
from installer.cores import CORE_PLATFORMS
from installer.datadirs import select_data_directories
from installer.embedded import _doubt_kinds, _mount_name, _mounted_cards, card_bound, share_doubt
from installer.games import GAMES_REASONS, games_probe
from installer.invocation import offline_requested
from installer.line_ui import (
    NO_CORE_FILES,
    _core_sized,
    _nearest_folder,
    _said_with,
    cores_words,
    emptied_words,
    emulator_names,
    folder_drives,
    region_title,
    share_targets,
)
from installer.local_files import save_directory_for, save_where_words
from installer.narrowing import available_choices, core_files, narrow, recorded_axes, resolve_regions
from installer.offline import LOCAL
from installer.outcome import CONFIRM_FROM_BYTES, TUI_INSTALL_ROW, TUI_SYSTEMS_ROW, _offline_only, on_its_card
from installer.pack import pack_holds_trees, pack_lacks
from installer.paths import SavePlace, spelled
from installer.probe import _is_dir
from installer.record import (
    RECORD_NARROWING,
    _RECORD_SAID,
    _tui_system_label,
    record_day,
    record_options,
    setup_record,
    system_title,
)
from installer.removal import _served, backup_words
from installer.run import TUI_MAX_WIDTH
from installer.setups import TuiRow, _matches, setup_list
from installer.tally import Tally, tally
from installer.text import _plural, agree, cell_width, format_size
from installer.tui_state import (
    TuiState,
    _app_offer,
    _core_base,
    _removing_misplaced,
    _tui_app_ready,
    _tui_slot_offered,
    _tui_standalone_offered,
    _tui_system_flags,
    _tui_systems_chosen,
    tui_flags,
    tui_pack_dir,
    tui_record_kept,
    tui_run_files,
)
from installer.tui_text import _detail, _short_path

# Screens that scroll text instead of listing rows.
_PAGERS = ("preview", "command", "result", "misplaced", "unreadable", "games", "details")
_CHECKLISTS = ("systems", "cores", "emulators")


def _needed(row: dict) -> int:
    return row["missing"] + row["wrong_hash"]


OTHER_HELP = ("Other systems and game engines: what cores load for systems this setup "
              "does not list, such as game engines and extra computers.")


def _filter_row(state: TuiState) -> TuiRow:
    text = state.filters.get(state.screen, "")
    if state.editing == state.screen:
        return TuiRow("filter", f"Filter: {text}_")
    if text:
        return TuiRow("filter", f"Filter: {text}")
    # A pad has no / and no letters: muxterm's own keyboard types.
    how = {"muxterm": "Select shows a keyboard", "gptokeyb": "with a keyboard",
           "gptokeyb_muxterm": "with a keyboard",
           "evmapy": "with a keyboard", "miyoo": "with a keyboard"}.get(state.pad, "/ to type")
    if state.screen == "platforms":
        # A device name finds its setups: said where it is typed. Plain, as
        # the first screen sends a beginner there.
        return TuiRow("filter", "Filter: setup or device (/)" if how == "/ to type"
                      else f"Filter ({how})")
    return TuiRow("filter", f"Filter ({how})")


def _system_titles(state: TuiState) -> dict:
    titles = (state.manifest or {}).get("system_titles")
    return titles if isinstance(titles, dict) else {}


def _sorted_systems(state: TuiState) -> list[dict]:
    """Systems with something to download first, the ones in place last, each
    group in the order of the names a person reads."""
    titles = _system_titles(state)
    return sorted(state.systems, key=lambda row: (
        _needed(row) == 0, _tui_system_label(row, titles).casefold()))


def tui_choices(state: TuiState) -> dict[str, list[str]]:
    """What the run lets one narrow to, read from the files it chooses among."""
    return available_choices(*tui_run_files(state))


def core_ticked(state: TuiState, name: str) -> bool:
    """Whether Cores draws name ticked: every core while none narrows the
    run (state.cores empty), else those chosen."""
    return name in state.cores or (not state.cores and not state.no_cores)


def tui_cores_ticked(state: TuiState) -> int:
    """The cores of the systems chosen that are ticked: a core of another
    system ticked counted toward "all cores"."""
    base = _core_base(state)
    if not state.cores:
        return 0 if state.no_cores else len(base)
    return len(set(state.cores) & set(base))


def _core_right(size: str | None) -> str:
    """A Cores row's right-hand text: what the core adds, or that it adds
    nothing (line mode's NO_CORE_FILES, in the room of a row)."""
    return size if size and size != NO_CORE_FILES else "no extra file"


def _core_narrow(size: str | None) -> tuple:
    if not size or size == NO_CORE_FILES:
        return ("none",)
    return tuple(form for form in [re.sub(r"^\d+ files?, ", "", size)] if form != size)


def tui_core_sizes(state: TuiState) -> dict[str, str]:
    """What each core adds for the systems chosen, in line mode's words."""
    systems = _tui_systems_chosen(state)
    files = tui_run_files(state)
    key = (id(files), tuple(systems))
    if state.core_sizes_cache is not None and state.core_sizes_cache[0] == key:
        return state.core_sizes_cache[1]
    kept = narrow(*files, systems, [], [])[0] if systems else files[0]
    extra = [entry for entry in kept if entry.get("cores") is not None]
    by_core: dict[str, list[dict]] = {}
    for entry in extra:
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]:
            for core in copy.get("cores") or []:
                listed = by_core.setdefault(core, [])
                if not listed or listed[-1] is not entry:
                    listed.append(entry)
    sizes = {core: _core_sized(core_files(held, core))
             for core, held in by_core.items()}
    state.core_sizes_cache = (key, sizes)
    return sizes


def _chosen_cores(state: TuiState) -> set[str] | None:
    """The cores of the systems chosen, None when every system is chosen."""
    if not _tui_systems_chosen(state):
        return None
    return set(_core_base(state))


def tui_systems(state: TuiState) -> list[str]:
    """The systems Choose systems lists for the run, as the check counted
    them (listed_systems): the file list's own count took in a system
    whose only file the run leaves out."""
    if state.choices is not None:
        return state.choices
    return tui_choices(state)["systems"]


def _setup_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the setups found here."""
    # The focused one's folder is spelled out below the list.
    rows = [TuiRow("setup", label, value=index)
            for index, (_plat, _path, label) in enumerate(state.setups)]
    # A drive two systems fit, under each: "Nothing was found here"
    # beside a KNULLI card in the reader.
    rows += [TuiRow("doubt", f"{_mount_name(mount)}: if it is {_doubt_kinds((plat,))}",
                    value=(plat, mount)) for plat, mount in state.doubts]
    return rows + [TuiRow("another", "Another setup or folder")]


def _card_screen_rows(state: TuiState, rows: list[TuiRow],
                      bound: tuple[str, str]) -> list[TuiRow]:
    """The folder rows of a setup that runs from a card."""
    # Only the cards whose own files say they run the system: A on the
    # first mount wrote Onion's layout on a muOS card.
    mounts = (state.cards if state.cards is not None
              else mounted_cards_of(bound[0], state.platform))
    cards = [TuiRow("card", f"{_mount_name(mount)} ({_card_what(mount)})", value=mount)
             for mount in mounts]
    # A drive this system and another both fit is its card, as --dest
    # takes it: "No KNULLI card is mounted" sat beside it.
    doubtful = [mount for mount in doubt_cards(state.platform) if mount not in mounts]
    cards += [TuiRow("card", f"{_mount_name(mount)} (could be "
                     f"{_doubt_kinds(share_doubt(mount)[0])})", value=mount)
              for mount in doubtful]
    mounts = [*mounts, *doubtful]
    # On the device itself its folder is found, and no card is looked for.
    here = state.folder_default is not None and state.folder_kind == "found"
    blank = [] if here else [
        TuiRow("card", f"{_mount_name(mount)} ({_card_what(mount)})", value=mount)
        for mount in blank_cards_of(bound[0], state.platform) if mount not in mounts]
    rescan = [] if cards or here else [TuiRow("rescan", "Look again")]
    if blank:
        # A blank drive is listed for a system that fills its card when
        # it first starts, after Look again: A never takes a stick.
        return rows + cards + rescan + blank + [TuiRow("browse", "Browse for a folder"),
                                                TuiRow("type", "Type a path")]
    rows += cards + [TuiRow("browse", "Browse for a folder"), TuiRow("type", "Type a path")]
    return rows + rescan


def _folder_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the BIOS folder question."""
    rows = [TuiRow("default", "Use this folder")] if state.folder_default else []
    bound = _tui_card_bound(state)
    if state.folder_kind == "share":
        # The drives mounted here first, each one's bios folder: the
        # share drive of a Batocera card or disk in a reader.
        rows += [TuiRow("share", label, value=folder)
                 for label, folder in share_targets(state.platform)]
    if not bound:
        # The drives mounted here, as line mode numbers them at the same
        # question, each by the BIOS folder its system reads, after the
        # Windows side's usual folder under WSL.
        # The Windows side's folder said missing where it is: taken, the
        # plan said RetroArch reads a folder no RetroArch had.
        # Every row whose folder is missing says so, in both modes: the
        # Windows row alone did.
        drives = [] if state.folder_kind == "share" else [
            TuiRow("drive", label if _is_dir(folder) else _said_with(label,
                                                                     "does not exist yet"),
                   value=folder)
            for label, folder in folder_drives(state.os_type, state.platform,
                                               state.folder_kind == "usual")]
        return rows + [TuiRow("browse", "Browse for a folder"),
                       TuiRow("type", "Type a path")] + drives
    return _card_screen_rows(state, rows, bound)


def _browse_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the folder browser."""
    return list(state.browse_rows)


def _create_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of Create the folder?."""
    label = "Create the whole path" if state.facts.get("risky") else "Create it and continue"
    return [TuiRow("create", label), TuiRow("other", "Choose another folder")]


def _cardroot_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the card root question."""
    return [TuiRow("cardroot", "Use the card root"), TuiRow("other", "Choose another folder")]


def _emulator_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of Emulators."""
    needle = state.filters.get(state.screen, "")
    return [_filter_row(state)] + [
        TuiRow("emulator", f"[{'x' if name in state.emulators else ' '}] {name}",
               value=name) for name in tui_emulators(state) if _matches(name, needle)
    ] + _REGIONS_END


def _region_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of Preferred regions."""
    known = sorted(set(tui_choices(state)["regions"]) | set(state.cli_regions),
                   key=region_title)
    # The order drawn when the screen opened, ranked regions first: a
    # tick moved its row to the top, and the next tap on the same spot
    # ticked the region that slid under the finger.
    # The rank says the order, and the screen opens on it next time.
    order = list(state.region_order or [*state.regions, *(
        name for name in known if name not in state.regions)])
    order += [name for name in [*state.regions, *known] if name not in order]
    ranks = {name: str(rank) for rank, name in enumerate(state.regions, 1)}
    return [TuiRow("region", f"[{ranks.get(name, ' ')}] {region_title(name)}", value=name)
            for name in order] + _REGIONS_END


def _core_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of Cores."""
    needle = state.filters.get(state.screen, "")
    # The cores the run accepts (choosable_cores): the whole list's
    # 189 held 8 that read only the save directory the run set aside,
    # and an untick sent them to a run that refused them.
    every = tui_choices(state)["cores"]
    theirs = _chosen_cores(state)
    # The cores of the systems chosen first, the others behind a row:
    # with --system sony-playstation the list opened on a5200 and
    # amiberry, 189 cores long. A core the command
    # line named stays in view.
    shown = every if theirs is None or state.cores_all else [
        name for name in every if name in theirs or name in state.cli_cores]
    sizes = tui_core_sizes(state)
    # Every core ticked when no core narrows the run, as Choose systems
    # ticks every system: all boxes empty read as nothing chosen, and
    # the owner ticked each one by hand. Each with what it adds, as
    # line mode sizes it.
    rows = [_filter_row(state)] + [
        TuiRow("core", f"[{'x' if core_ticked(state, name) else ' '}] {name}",
               _core_right(sizes.get(name)), name, "" if sizes.get(name) else "dim",
               _core_narrow(sizes.get(name)), keep_right=bool(sizes.get(name)))
        for name in shown if _matches(name, needle)]
    hidden = len(every) - len(shown)
    if hidden:
        rows.append(TuiRow("morecores", f"Cores of the other systems: {hidden}"))
    return rows + _CHECKLIST_END


def _confirm_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the confirm screen."""
    if state.running or state.dry is None:
        return []
    if not _needed(state.dry) and not state.dry.get("data_missing"):
        # Counted again, every file is in place: Install wrote nothing
        # and said Done.
        return [TuiRow("close", "Close"), TuiRow("back", "Back")]
    if _offline_only() and not _dry_copies(state):
        # The plan's rule: Install would only fail every file.
        return [TuiRow("back", "Back")]
    return [TuiRow("install", "Install"), TuiRow("back", "Back")]


def _error_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the error screen."""
    rows = ([TuiRow("retry", "Try again")]
            if state.run == "check" and state.error_title
            and state.error_title != TUI_OFFLINE_TITLE else [])
    # Its own verb on the bar: "A/Enter Back" under "Choose another
    # setup or folder".
    return rows + [TuiRow("elsewhere", "Choose another setup or folder")
                   if state.run == "check" else TuiRow("back", "Back"),
                   TuiRow("quit", "Quit")]


def _quit_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the quit question."""
    return [TuiRow("quit", "Quit"), TuiRow("stay", "Stay")]


def _result_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the result, when the app is offered."""
    if not _app_offer(state):
        return []
    # Exit first: the app is put only when it is chosen. Its short
    # form where the whole one does not fit: cut inside "from" at 40
    # columns.
    width = min(state.cols or TUI_MAX_WIDTH, TUI_MAX_WIDTH) - 2
    offer = APP_OFFER if cell_width(f"> {APP_OFFER}") <= width else APP_OFFER_SHORT
    return [TuiRow("exit", "Exit"), TuiRow("addapp", offer)]


def tui_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the current screen, in the order they are shown."""
    screen = state.screen
    if screen in _ACTION_SCREENS:
        return _action_rows(state)
    screens: dict[str, Callable[[TuiState], list[TuiRow]]] = {
        "setup": _setup_screen_rows, "platforms": _platform_rows,
        "folder": _folder_screen_rows, "browse": _browse_screen_rows,
        "create": _create_screen_rows, "cardroot": _cardroot_screen_rows,
        "plan": _plan_rows, "systems": _system_rows, "options": _option_rows,
        "device": _device_rows, "emulators": _emulator_screen_rows,
        "regions": _region_screen_rows, "cores": _core_screen_rows,
        "confirm": _confirm_screen_rows, "error": _error_screen_rows,
        "quit": _quit_screen_rows, "result": _result_screen_rows,
    }
    rows_of = screens.get(screen)
    return rows_of(state) if rows_of else []


def _emptied_words(state: TuiState) -> str:
    """The plan's headline when no system chosen holds a file under the
    options changed since: "Sega Dreamcast holds only game data"."""
    return emptied_words(state.emptied, state.no_game_data)


def _choice_in_place(state: TuiState) -> str:
    """The plan's headline when every file of the systems ticked is in
    place, while the check counted the whole list: "NEC PC Engine is in
    place", Install offered nothing. "" otherwise."""
    if not state.systems or not state.ticked or not _tui_estimating(state):
        return ""
    chosen = [row for row in state.systems if row["system"] in state.ticked]
    if not chosen or any(_needed(row) for row in chosen) or any(
            event["state"] != "present" for event in _ticked_files(state)):
        return ""
    if _plan_data(state, state.check or {})[0]:
        return ""
    titles = _system_titles(state)
    names = [_tui_system_label(row, titles) for row in chosen]
    subject = (", ".join(names[:-1]) + " and " + names[-1]) if len(names) > 1 else names[0]
    return f"{subject} {'are' if len(names) > 1 else 'is'} in place: nothing is left to install."


def _plan_rows(state: TuiState) -> list[TuiRow]:
    check = state.check or {}
    if (state.emptied and state.systems and not state.ticked) or _choice_in_place(state):
        # The choice emptied by an option: Choose systems first, never an
        # Install that would refuse or take the whole list.
        rows = [TuiRow("systems", TUI_SYSTEMS_ROW)]
        game_data = _game_data_row(state)
        return rows + ([game_data] if game_data is not None else []) + [
            *_details_row(state), TuiRow("options", "Change"), *_more_row(state),
            TuiRow("quit", "Quit")]
    if not (_needed(check) if check else 0) and not check.get("data_missing"):
        return [TuiRow("close", "Close"), *_games_rows(state), *_record_rows(state),
                *_where_rows(state), *_details_row(state), TuiRow("options", "Change"),
                *_more_row(state)]
    # The size the headline says: "Install 6.6 GB" stood under "14930 files
    # to download, 6.8 GB", the copies counted in one and the data files in
    # the other.
    size = _ticked_estimate(state)[1] if _tui_estimating(state) else _plan_fetch(state, check)[1]
    label = (f"{TUI_INSTALL_ROW} {format_size(size)}" if size >= CONFIRM_FROM_BYTES
             else TUI_INSTALL_ROW)
    rows = [TuiRow("install", label)]
    if _offline_only() and not _plan_copies(state, check):
        # Nothing here to copy, and the network refused: Install would
        # only fail every file, in this folder or another.
        rows = []
    files = {event["dest"] for event in state.files}
    if (LOCAL.pack is not None and files and not _plan_copies(state, check)
            and len(_tui_pack_lacks(state, sorted(files))) == len(files)
            and not (check.get("data_missing") and _tui_pack_trees(state))):
        # The pack holds none of them, nor the data files: Install would
        # fail every one.
        rows = []
    if _on_its_card(state) and (state.facts.get("writable") is False
                                or _short_of_space(state, check)):
        # Its system reads this card alone: room is made on it, or it is
        # unlocked, then counted again, first in focus. Install anyway on
        # a mount nobody can write would only fail.
        locked = state.facts.get("writable") is False
        rows = [TuiRow("recheck", "Check again"), TuiRow("folder", "Choose another folder"),
                *([TuiRow("install", "Install anyway")] if rows and not locked else [])]
    elif state.facts.get("writable") is False or _short_of_space(state, check):
        # Every file would fail alike, or the run would stop before the
        # first one: the way out is another folder.
        rows = [TuiRow("folder", "Choose another folder"),
                *([TuiRow("install", "Install anyway")] if rows else [])]
    # --system given: the choice stays offered, the list widened when it is
    # opened. With one system named it was neither shown nor changeable.
    copy = TuiRow("fromcard", "Copy the BIOS files from an old card or a folder")
    if not rows:
        # Nothing can be installed: the remedy the plan names comes first,
        # in focus. Choose systems was, whose systems need the internet
        # too.
        rows.append(copy)
    # Right under Install: the choice the plan opened on, the whole list one
    # press away.
    rows += _games_rows(state)
    rows += _record_rows(state)
    if "systems" in recorded_axes((state.manifest or {}).get("files", [])) and (
            len(state.systems) > 1 or state.cli_systems):
        rows.append(TuiRow("systems", TUI_SYSTEMS_ROW))
    game_data = _game_data_row(state)
    if game_data is not None:
        rows.append(game_data)
    if copy not in rows:
        rows.append(copy)
    if _tui_misplaced(state):
        rows.append(TuiRow("misplaced", "Show the files in the wrong place"))
    if state.unreadable:
        rows.append(TuiRow("unreadable", "Show the files that could not be read"))
    return rows + [*_where_rows(state), *_details_row(state), TuiRow("options", "Change"),
                   *_more_row(state), TuiRow("quit", "Quit")]


# The plan's row to remove files and to see or put back a backup.
TUI_MORE_ROW = TuiRow("more", "More")


def _more_row(state: TuiState) -> list[TuiRow]:
    """More, on every plan: a pack can always be made, and the folder's
    record or backups add removing and putting back."""
    return [TUI_MORE_ROW]


# The plan's row for the record's choice, and the one back to the setups.
TUI_RECORD_ROW = "Same choice as last time"
TUI_WHERE_ROW = TuiRow("where", "Change where")


def _record_rows(state: TuiState) -> list[TuiRow]:
    """Same choice as last time: yes or no, where the folder has a record."""
    if state.record is None or state.cli_choice:
        return []
    day = record_day(state.record)
    label = f"Same choice as on {day}" if day else TUI_RECORD_ROW
    return [TuiRow("record", f"{label}: {_yes(tui_record_kept(state))}")]


def _where_rows(state: TuiState) -> list[TuiRow]:
    """Change where, on a plan opened straight on the one setup found."""
    return [TUI_WHERE_ROW] if state.opened_on_plan and state.stack[:1] == ["setup"] else []


# The plan's explanations, counts and reasons, one press away: a pad has
# no d key.
TUI_DETAILS_ROW = TuiRow("details", "Details")


def _details_row(state: TuiState) -> list[TuiRow]:
    """The Details row, where the plan leaves lines out: --verbose shows
    them all on the plan itself."""
    return [] if tui_verbose(state) else [TUI_DETAILS_ROW]


def games_where(state: TuiState) -> str:
    """Where the games are, as the plan's rows say it."""
    return f"in {state.games_folder.name}" if state.games_folder else "on this card"


def _games_rows(state: TuiState) -> list[TuiRow]:
    """The plan's games rows, for a card that holds games or a run told to
    read them: one press for every file instead, one for only what starts,
    and the games themselves."""
    if not (state.for_games or state.games_here):
        return []
    games = state.games or {}
    count = games.get("games") if state.for_games else None
    rows = [TuiRow("games", f"For the games {games_where(state)}: {_yes(bool(state.for_games))}",
                   _plural(count, "game") if count else "", narrow=(str(count),) if count else ())]
    if state.for_games and count:
        rows.append(TuiRow("startonly", f"Only what starts: {_yes(state.required_only)}"))
    if state.for_games and count:
        rows.append(TuiRow("gameslist", "Show the games"))
    return rows


def games_pager_lines(state: TuiState) -> list[str]:
    """The games read, per system, then those that got every BIOS of their
    system with why: the screen behind Show the games."""
    games = state.games or {}
    lines = [f"{games.get('games', 0)} games in {games.get('folder', '')}, "
             f"{games.get('recognised', 0)} recognised by their content.", ""]
    for row in games.get("found") or []:
        title = system_title(str(row.get("system")), state.manifest)
        regions = ", ".join(region_title(str(r)) for r in row.get("regions") or [])
        lines.append(f"{title} ({row.get('folder')}): {_plural(int(row.get('games', 0)), 'game')}"
                     f", {row.get('recognised', 0)} recognised"
                     + (f", {regions} only" if regions else ", every region"))
    fallback = games.get("fallback") or []
    if fallback:
        lines += ["", "Every BIOS of their system kept, so that they start:"]
        lines += [f"{item.get('name')}: {GAMES_REASONS.get(str(item.get('reason')), '')}"
                  for item in fallback]
    return lines


def games_plan_words(state: TuiState) -> list[str]:
    """What the plan says of the games, under the counts."""
    if not state.for_games:
        return []
    if state.games_unavailable:
        return [f"What the games need is not known: {state.games_unavailable['message']}. "
                "Every file is kept."]
    games = state.games or {}
    if not games:
        return []
    if not games.get("games"):
        return [f"No game found {games_where(state)}: For the games installs nothing."]
    words: list[str] = []
    narrowed = [f"{system_title(str(row['system']), state.manifest)} "
                f"{', '.join(region_title(str(r)) for r in row['regions'])}"
                for row in games.get("found") or [] if row.get("regions")]
    if narrowed:
        words.append(_detail(f"One region where the games prove it: {'; '.join(narrowed)}."))
    fallback = len(games.get("fallback") or [])
    if fallback:
        words.append(_detail(f"{agree(fallback, 'game gets', 'games get')} every BIOS of "
                             f"{'its' if fallback == 1 else 'their'} system: Show the games."))
    return words


def _tui_categories(state: TuiState) -> dict[str, str]:
    """Each destination's category, from the list the screen holds, for a
    list that marks its game data. The second spellings a folder that keeps
    case installs are in it too: counted as nothing, the result's BIOS and
    game data fell short of its total."""
    manifest = state.manifest or {}
    if not manifest.get("categorized"):
        return {}
    return {str(entry.get("dest")): str(entry.get("category") or "")
            for entry in [*manifest.get("files", []), *manifest.get("case_variants", [])]}


def _tui_tally(state: TuiState, events: Iterable[dict]) -> Tally:
    """The count of file events (dest and size), each with the category the
    list gives its destination: the one count the plan, its game data row
    and the result divide."""
    categories = _tui_categories(state)
    return tally({"size": event["size"], "category": categories.get(event["dest"], "")}
                 for event in events)


def _tui_estimating(state: TuiState) -> bool:
    """Whether the plan counts the systems ticked since the check, not the
    check itself."""
    if not (_choice_line(state) and state.systems and state.check is not None):
        return False
    if _offline_only():
        # Offline the estimate is of the ticks alone: a folder to copy from
        # is counted by the check it starts.
        def ticked(flags: list) -> list:
            return [flag for flag in flags if flag[0] == "--system"]
        return ticked(tui_flags(state)) != ticked(state.checked_flags)
    return True


def _choice_entries(state: TuiState, hidden: bool = False) -> list[dict]:
    """The list's files the choice made keeps, game data included: the
    systems ticked (or named with --system), the cores and the regions, as
    line mode's menu_choice narrows them. The game data row, the save line
    and the data files count these: over the whole list, a plan of one
    system said 5089 game data files and 2.5 GB nothing would install.
    hidden adds the systems ticked that game data left out hides
    (hidden_ticks), whose files the game data row brings back."""
    manifest = state.manifest or {}
    systems = [value for flag, value in tui_flags(state) if flag == "--system" and value]
    if state.emptied and not state.ticked:
        systems = sorted(state.ticked_names)
    elif hidden and systems:
        systems = sorted({*systems, *state.hidden_ticks})
    # The second spellings the check installs, as line mode adds them where
    # the folder keeps case.
    variants = [entry for entry in manifest.get("case_variants") or []
                if entry.get("dest") in state.checked_dests]
    kept = narrow([*(manifest.get("files") or []), *variants], [], systems,
                  list(state.cores), list(state.regions))[0]
    # The check read the list as the run narrows it, --emulator, --target
    # and the installed cores included, and only the systems ticked are
    # left to apply: its files and the game data it left out are that
    # list. Narrowed by the axes alone, the row offered the 8 game data
    # files of every system under a plan for one.
    reached = _checked_scope(state)
    return [entry for entry in kept if entry.get("dest") in reached] if reached else kept


def _checked_scope(state: TuiState) -> set[str]:
    """Every destination the last check read, the game data it left out
    included: the list before the systems are chosen. Empty before a check."""
    left = {dest for group in (state.check_summary or {}).get("left_out") or []
            for dest in group.get("dests") or []}
    return set(state.checked_dests) | left if state.checked_dests or left else set()


def _game_data_row(state: TuiState) -> TuiRow | None:
    """The plan's game data row, one press to leave it out or keep it, for
    a list that marks game data: inside Options alone, it went unseen.

    Counted over the choice, as g at the line menu counts it, kept or left
    out alike, and gone when the choice holds none. --no-game-data given
    has none, as line mode offers no g then: one decision in both modes."""
    if not _tui_categories(state) or state.cli_no_game_data:
        return None
    games = tally(entry for entry in _choice_entries(state, hidden=True)
                  if entry.get("category") == GAME_DATA)
    if not games.games:
        return None
    # The state first, its count after and never cut inside a word: at 40
    # columns "kept, leave out" lost its state.
    sized = f"{_plural(games.games, 'file')}, {format_size(games.game_size)}"
    return TuiRow("gamedata", f"Game data: {'left out' if state.no_game_data else 'kept'}",
                  sized, narrow=(f"{games.games}, {format_size(games.game_size)}",),
                  keep_right=True)


def _plan_copies(state: TuiState, check: dict) -> list[str]:
    """The files to install that this machine holds, by destination."""
    if check is state.dry and check is not state.check:
        return _dry_copies(state)
    local = {event["dest"] for event in state.found} if check is state.check else set()
    sizes = {event["dest"] for event in state.files}
    return [dest for dest in local if dest in sizes]


def _dry_copies(state: TuiState) -> list[str]:
    """The files the confirm or preview run would install that this
    machine holds."""
    local = {event["dest"] for event in state.found}
    return [event["dest"] for event in state.dry_files if event["dest"] in local]


def _short_of_space(state: TuiState, check: dict) -> bool:
    free = state.facts.get("free")
    return free is not None and check.get("bytes_needed", 0) > free


def _system_rows(state: TuiState) -> list[TuiRow]:
    needle = state.filters.get("systems", "")
    titles = _system_titles(state)
    rows = [_filter_row(state)]
    shared = _shared_needed(state)
    for row in _sorted_systems(state):
        label = _tui_system_label(row, titles)
        if not _matches(f"{label} {row['system']}", needle):
            continue
        box = "[x]" if row["system"] in state.ticked else "[ ]"
        need = _needed(row)
        count, size = shared.get(row["system"], (0, 0))
        own, own_size = need - count, row["bytes_needed"] - size
        narrow: tuple = ()
        if not need:
            right = "in place"
        elif not count:
            right = f"{_plural(need, 'file')}, {format_size(row['bytes_needed'])}"
            narrow = (format_size(row["bytes_needed"]),)
        elif not own:
            # Two spellings of shared, never cut: "+ 28 sh." and ", shared"
            # sat beside "+ 1689 shared" on one 40-column screen.
            right = f"{_plural(need, 'file')}, {format_size(size)}, all shared"
            narrow = (f"{format_size(size)}, all shared", format_size(size))
        else:
            right = f"{_plural(own, 'file')}, {format_size(own_size)} + {count} shared"
            narrow = (f"{format_size(own_size)} + {count} shared", format_size(own_size))
        # The size is never rounded to fit: 2.7 KB read 3 KB at 40 columns,
        # beside a total of 2.7 KB. The name is cut instead.
        rows.append(TuiRow("system", f"{box} {label}", right, row["system"],
                           "" if need else "dim", narrow, keep_right=bool(need)))
    return rows + _CHECKLIST_END


# The rows a list of ticks ends on, the same on Choose systems, Cores and
# Preferred regions: below the items, so the focus a list opens on is its
# first item and A there ticks it. All and None sat above the items, and A
# on the None the systems opened on unticked every system. Preferred regions
# has no All: every region ranked in the order drawn is no choice anyone made,
# and none ticked keeps every region.
_CHECKLIST_END = [TuiRow("all", "All"), TuiRow("none", "None"), TuiRow("done", "Done")]
_REGIONS_END = [TuiRow("none", "None"), TuiRow("done", "Done")]


def _first_item(state: TuiState) -> int:
    """The row a list of ticks opens on: its first item. Elsewhere the
    first row that is no heading."""
    rows = tui_rows(state)
    return next((i for i, row in enumerate(rows) if row.action in TUI_TICK_ROWS),
                next((i for i, row in enumerate(rows) if row.action != "heading"), 0))


def _shared_needed(state: TuiState) -> dict[str, tuple[int, int]]:
    """Per system, the files to download that other systems carry too, and
    their size: `3DO 1704 files, 349.0 MB` read as the 3DO BIOS, when 1689
    are the MAME files six systems share. The line mode counts them apart
    the same way (_system_sized)."""
    shared: dict[str, tuple[int, int]] = {}
    for event in state.files:
        if len(event["systems"]) > 1:
            for system in event["systems"]:
                count, size = shared.get(system, (0, 0))
                shared[system] = (count + 1, size + event["size"])
    return shared


def _cores_dir_given(state: TuiState) -> bool:
    return any(flag == "--cores-dir" for flag, _value in state.passthrough)


def _yes(value: bool) -> str:
    return "yes" if value else "no"


# The Change screen's groups, in the order they are drawn: a heading is no
# row Up and Down stop on, and a group with no row is not drawn.
TUI_CHANGE_GROUPS = ("What to install", "Where", "For which device", "How", "See")


def _option_rows(state: TuiState) -> list[TuiRow]:
    """The Change screen: every option one level below the plan, grouped by
    what it decides, each row with its value and its flag."""
    manifest = state.manifest or {}
    choices = tui_choices(state)
    what: list[TuiRow] = []
    if choices["regions"]:
        what.append(TuiRow("regions", "Preferred regions: "
                           + (", ".join(map(region_title, state.regions)) or "any"),
                           "--region"))
    if _tui_slot_offered(state, tui_flags(state)):
        what.append(TuiRow("slot", "One BIOS per console and region: "
                           + _yes(state.one_per_slot), "--one-per-slot"))
    if len(choices["cores"]) > 1:
        # The plan's words, the noun left to the row's own label. A list
        # with one core asks nothing, as line mode does not.
        what.append(TuiRow("cores", "Cores: " + cores_words(
            tui_cores_ticked(state), len(_core_base(state))).replace(" cores", ""), "--core"))
    if "system_cores" in manifest and tui_emulators(state):
        what.append(TuiRow("emulators", f"Emulators: {_emulator_words(state)}",
                           "--emulator"))
    if _tui_standalone_offered(state):
        what.append(TuiRow("standalone", "Standalone version of it: "
                           + _yes(state.standalone), "--standalone"))
    if manifest.get("categorized"):
        # "Leave out game data: no" was a double negative.
        what.append(TuiRow("game_data", "Game data: "
                           + ("left out" if state.no_game_data else "kept"),
                           "--no-game-data"))
    copied = ", ".join(str(folder) for folder in state.from_folders) or "none"
    where = [
        # The plan's folder: AmberELEC's read the games part here and its
        # bios folder on the plan, two values under one name. --dest stays the
        # games part, as the command line takes it.
        TuiRow("folder", "BIOS folder: "
               + _short_path(_plan_folder(state, state.dest), state.home),
               "--dest", style="path"),
    ]
    if manifest.get("save_directory"):
        # The interface said "Name it with --save-dir" and had no row for it.
        where.append(TuiRow("savedir", f"Save folder: {_save_folder_words(state)}",
                            "--save-dir", style="path"))
    where += [TuiRow("from", f"Copy from: {copied}", "--from", style="path"),
              TuiRow("pack", "From a pack: "
                     + (state.packs[0].name if state.packs else "none"), "--from-pack")]
    device: list[TuiRow] = []
    if state.platform in TARGET_PLATFORMS:
        device.append(TuiRow("device", f"Device: {_device_words(state)}", "--target"))
    found = len(state.facts.get("cores", []))
    if _cores_dir_given(state):
        device.append(TuiRow("installed", "Installed cores only: yes, implied by --cores-dir",
                             "--cores-dir"))
    elif state.platform in CORE_PLATFORMS and "system_cores" in manifest and found:
        device.append(TuiRow("installed", f"Installed cores only: "
                             f"{_yes(state.installed_only)} ({found} found)",
                             "--installed-cores"))
    if _tui_app_ready(state):
        device.append(TuiRow("addapp", f"Put RetroBIOS on this card: {_yes(state.add_app)}",
                             "--add-app"))
    # Parallel downloads below: the row goes once nothing is downloaded,
    # and the focus stays on the row just changed.
    how = [TuiRow("offline", "Without the internet: "
                  + ("yes, a pack is read" if LOCAL.pack is not None
                     else _yes(offline_requested())), "--offline")]
    if not LOCAL.offline:
        # From a pack, or offline, nothing is downloaded.
        how.append(TuiRow("jobs", f"Parallel downloads: {state.jobs}", "--jobs"))
    see = [TuiRow("preview", "Preview the file list", "--dry-run"),
           TuiRow("command", "Show the command line")]
    rows: list[TuiRow] = []
    for heading, group in zip(TUI_CHANGE_GROUPS, (what, where, device, how, see)):
        if group:
            rows += [TuiRow("heading", heading, style="head"), *group]
    return rows


def tui_emulators(state: TuiState) -> list[str]:
    """The emulators Emulators lists: each profile once, by the name the
    list gives it, as --list-emulators names them."""
    if state.manifest is None:
        return []
    return sorted(set(emulator_names(state.manifest, *tui_run_files(state)).values()))


def _emulator_words(state: TuiState) -> str:
    """The emulators chosen, as the Change row says them."""
    if not state.emulators:
        return "all"
    if len(state.emulators) <= 2:
        return ", ".join(state.emulators)
    return f"{len(state.emulators)} chosen"


def _board_seen(state: TuiState) -> tuple[str, bool, bool] | None:
    """(board, applied, here) the last check read for this setup and folder."""
    seen = state.board_seen
    if seen is None or seen[:2] != (state.platform, state.dest):
        return None
    return seen[2], seen[3], seen[4]


def _board_where(here: bool) -> str:
    return "this device" if here else "named by the card"


def _device_choice(state: TuiState) -> str:
    """The board the runs install for, "" for every board."""
    if state.every_board:
        return ""
    if state.target:
        return state.target
    seen = _board_seen(state)
    return seen[0] if seen is not None and seen[1] else ""


def _device_words(state: TuiState) -> str:
    """The device as the Change row says it: the board, where the run read
    it when it chose it itself."""
    chosen = _device_choice(state)
    if not chosen:
        return "every board"
    seen = _board_seen(state)
    if not state.target and seen is not None:
        return f"{chosen}, {_board_where(seen[2])}"
    return chosen


def _device_rows(state: TuiState) -> list[TuiRow]:
    """Device: the platform's boards by the names its list gives them, the
    one read here or named by the card first, then every board."""
    targets = state.targets if state.targets_for == state.platform else None
    if not targets:
        return []
    seen = _board_seen(state)
    chosen = _device_choice(state)
    names = sorted(targets)
    if seen is not None and seen[0] in targets:
        names.remove(seen[0])
        names.insert(0, seen[0])
    rows = []
    for name in names:
        images = [str(image) for image in targets[name].get("images") or ()]
        # The device names an image carries say what a board code means.
        right = (_board_where(seen[2]) if seen is not None and name == seen[0]
                 else ", ".join(images))
        narrow = (images[0] + (f" +{len(images) - 1}" if len(images) > 1 else ""),) \
            if images and right != images[0] and name != (seen or ("",))[0] else ()
        rows.append(TuiRow("board", f"({'x' if name == chosen else ' '}) {name}", right,
                           name, narrow=narrow))
    rows.append(TuiRow("board", f"({' ' if chosen else 'x'}) Every board", value=""))
    return rows


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


def _save_dir_given(state: TuiState) -> Path | None:
    return next((Path(value) for flag, value in state.passthrough
                 if flag == "--save-dir" and value), None)


def _save_folder_words(state: TuiState) -> str:
    """The frontend's save directory as the Options row shows it."""
    given = _save_dir_given(state)
    if given is not None:
        return _short_path(given, state.home)
    if state.saves and state.saves.get("folder"):
        return _short_path(Path(save_where_words(state.saves["folder"])[1]), state.home)
    place = (save_directory_for(state.dest, state.manifest, None)
             if state.dest is not None and state.manifest else None)
    if isinstance(place, SavePlace):
        return _short_path(spelled(place.directory), state.home)
    return "not known"


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
    try:
        parsed = build_parser().parse_args(setup.get("choice") or [])
    except SystemExit:
        state.status = "The install record names options this installer lacks, so it is ignored."
        state.record = None
        return
    state.cli_systems = list(parsed.system or [])
    state.cores = [token.strip() for value in parsed.core or [] for token in value.split(",")
                   if token.strip()]
    try:
        state.regions = resolve_regions(parsed.region) if parsed.region else []
    except ValueError:
        state.regions = []
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


def _tui_card_bound(state: TuiState) -> tuple[str, str] | None:
    """The card the chosen setup runs from, when it runs from one."""
    if state.card_bound:
        return state.card_bound
    return card_bound(state.platform, state.platform) if state.platform in CARD_PLATFORMS else None


def _browse_rows(folder: Path | None, zips: bool = False,
                 skip: Path | None = None) -> tuple[list[TuiRow], str]:
    """A directory's rows for the browser, cards first, and what went wrong.
    With zips, the ZIP files too: a backup is often one archive. skip is a
    card never offered: the one being installed to, for the copy browser,
    as line mode's Copy from leaves it out."""
    if folder is None:
        drives = [Path(f"{letter}:\\") for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  if os.path.exists(f"{letter}:\\")]
        return [TuiRow("dir", str(drive), value=drive) for drive in drives], ""
    rows = [TuiRow("use", "Use this folder"), TuiRow("up", "..", value=folder.parent)]
    for card in _mounted_cards():
        if card not in (folder, skip):
            # Under WSL by its letter, as every other screen writes D:\BIOS.
            name = _mount_name(card)
            rows.append(TuiRow("dir", f"{name if name.endswith(':') else card} "
                               f"({_card_what(card)})", value=card))
    try:
        entries = list(os.scandir(folder))
    except OSError as exc:
        return rows, f"Cannot open this folder: {exc.strerror or exc}"
    entries.sort(key=lambda entry: (entry.name.startswith("."), entry.name.casefold()))
    rows += [TuiRow("dir", f"{entry.name}/", value=Path(entry.path))
             for entry in entries if entry.is_dir()]
    if zips:
        rows += [TuiRow("zip", entry.name, value=Path(entry.path)) for entry in entries
                 if entry.is_file() and entry.name.lower().endswith(".zip")]
    return rows, ""


# The folders of a system root that hold no one's files: A went into
# /bin from /, the first name in order.
_POSIX_ROOT_SYSTEM = frozenset((
    "bin", "boot", "dev", "efi", "etc", "lib", "lib32", "lib64", "libx32", "lost+found",
    "proc", "root", "run", "sbin", "snap", "srv", "sys", "tmp", "usr", "var",
))
# FILE_ATTRIBUTE_HIDDEN and FILE_ATTRIBUTE_SYSTEM: Explorer shows neither.
_WINDOWS_HIDDEN = 0x2 | 0x4


def _os_folder(path: Path, folder: Path) -> bool:
    """A folder of the system, not one a person keeps files in: the
    recycle bin and restore points of a Windows drive ($RECYCLE.BIN, System
    Volume Information, hidden by Explorer), and /bin, /etc, /usr and the
    like at the root of a Unix system."""
    name = path.name
    if name.startswith(("$", ".")) or name.casefold() == "system volume information":
        return True
    try:
        attributes = getattr(os.stat(path, follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        attributes = 0
    if attributes & _WINDOWS_HIDDEN:
        return True
    return folder == Path("/") and name in _POSIX_ROOT_SYSTEM


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


def _on_its_card(state: TuiState) -> bool:
    """Whether the BIOS folder is on the SD card of the setup it is for, a
    system that reads that card alone: room is made there, another folder
    being one it never reads."""
    if state.dest is None:
        return False
    return on_its_card(state.platform, state.dest,
                       state.card_bound[0] if state.card_bound else "")


def _dest_card(state: TuiState) -> Path | None:
    """The mounted card or drive the BIOS folder is on, None for none."""
    return dest_drive(state.dest)


def _no_setup_reads(state: TuiState, folder: Path | None) -> str:
    """Why folder is no BIOS folder, "" when it may be one: no frontend
    reads its BIOS files in the home folder or at a drive's root."""
    if folder is None:
        return ""
    if folder == state.home:
        return "No setup reads BIOS files in the home folder."
    if folder == Path(folder.anchor):
        return "No setup reads BIOS files at a drive's root."
    return ""


def _none_ticked(state: TuiState) -> str:
    """Why Done is refused on a list of ticks, "" when it is not."""
    if state.screen == "systems" and state.systems and not state.ticked:
        return "No system is ticked: tick one, or choose All."
    if state.screen == "cores" and state.no_cores:
        return "No core is ticked: tick one, or choose All."
    return ""


def _platform_rows(state: TuiState) -> list[TuiRow]:
    """The setup list of the screen, under its filter row (setup_list)."""
    return [_filter_row(state), *setup_list(
        state.setups, state.mounted_setups, state.filters.get("platforms", ""),
        state.os_type, LOCAL.serves())]


# The rows a tap ticks or unticks, as Space does: the lists of ticks.
TUI_TICK_ROWS = ("system", "core", "region", "emulator")


def _tui_misplaced(state: TuiState) -> list[dict]:
    """The files the BIOS folder holds at another place, each with its reason."""
    return [event for event in state.found if event["reason"]]


def _tui_found_elsewhere(state: TuiState, dests: set | None = None) -> dict[str, list[dict]]:
    """The files a --from folder holds, by the folder as it was named,
    those of dests alone when given (the files a dry run installs)."""
    found: dict[str, list[dict]] = {}
    for event in state.found:
        if not event["reason"] and (dests is None or event["dest"] in dests):
            found.setdefault(event["folder"], []).append(event)
    return found


def _plan_fetch(state: TuiState, check: dict) -> tuple[int, int, list, list, dict]:
    """(files to fetch, bytes the install fetches with the data files',
    dests copied from this machine, dests the pack lacks, the size of each
    file): the one size the plan's headline and its Install row say.

    A file found on this machine is copied, not downloaded: the count and
    the size to download leave it out, from the check's own events. On
    Confirm the dry run's files are matched the same way: it called the
    files a --from folder holds downloads, and sent an offline user for a
    pack. The files the pack does not hold are left out too: the plan
    offered "Install 6.6 GB" from a pack that held none of them.
    """
    dry = check is state.dry and check is not state.check
    sizes = {event["dest"]: event["size"]
             for event in (state.dry_files if dry else state.files)}
    copied = _plan_copies(state, check) if dry or check is state.check else []
    lacking = _tui_pack_lacks(state, [dest_ for dest_ in sizes if dest_ not in copied])
    fetch = max(0, _needed(check) - len(copied) - len(lacking))
    fetch_bytes = max(0, check.get("bytes_needed", 0) - sum(sizes[dest_] for dest_ in copied)
                      - sum(sizes[dest_] for dest_ in lacking))
    data_bytes = check.get("data_bytes", 0) if check.get("data_missing", 0) else 0
    return fetch, fetch_bytes + data_bytes, copied, lacking, sizes


def _tui_pack_trees(state: TuiState) -> bool:
    """Whether the pack given to the run holds a file of the list's data
    trees."""
    return pack_holds_trees((state.manifest or {}).get("data_directories") or [])


def _tui_pack_lacks(state: TuiState, dests: list[str]) -> list[str]:
    """The destinations of a plan the pack given to the run does not hold."""
    if LOCAL.pack is None or not dests:
        return []
    manifest = state.manifest or {}
    entries = {str(entry.get("dest")): entry for entry in [
        *(manifest.get("files") or []), *(manifest.get("case_variants") or [])]}
    held = {id(entry) for entry in pack_lacks([entries[dest] for dest in dests
                                               if dest in entries])}
    return [dest for dest in dests if dest in entries and id(entries[dest]) in held]


def _plan_folder(state: TuiState, dest: Path | None) -> Path | None:
    """The BIOS folder a plan names (shown_bios_folder), from the list."""
    if dest is None or not state.manifest:
        return dest
    return shown_bios_folder(dest, state.manifest.get("files") or [])


def _choice_line(state: TuiState) -> list[str]:
    """What the plan's numbers do not include yet. The options are read
    again by a check of their own, so only ticked systems are left here."""
    if tui_flags(state) == state.checked_flags:
        return []
    return [f"For the {len(state.ticked)} of {len(state.systems)} systems chosen, the exact "
            "count comes before the install."]


def tui_verbose(state: TuiState) -> bool:
    """Whether the screen was opened with --verbose: every line is shown
    where it belongs, as before the Details screen held them."""
    return any(flag == "--verbose" for flag, _value in state.passthrough)


def _plan_data(state: TuiState, check: dict) -> tuple[int, int | None]:
    """The data files the plan counts and their size: the check's, or,
    while the plan estimates the systems ticked, those of the data folders
    the choice keeps, as line mode's head counts them."""
    if not _tui_estimating(state):
        data = check.get("data_missing", 0)
        return data, check.get("data_bytes") if data else None
    required = any(flag == "--required-only" for flag, _value in tui_flags(state))
    named = [name for _flag, name in _tui_system_flags(state) if name]
    known = {row["system"] for row in state.systems}
    trees = select_data_directories(state.manifest or {}, _choice_entries(state), True, required,
                                    systems=named if named and set(named) <= known else None)
    sizes = [meta.get("size", 0) for entry in trees for meta in (entry.get("files") or {}).values()]
    return len(sizes), sum(sizes)


def _counts_predate_options(state: TuiState) -> bool:
    """Whether the check's counts were read under other options than the
    ones chosen since: a region or a core changes what each system needs."""
    def others(flags: list) -> list:
        return [flag for flag in flags if flag[0] != "--system"]
    return others(tui_flags(state)) != others(state.checked_flags)


def _ticked_files(state: TuiState) -> list[dict]:
    return [event for event in state.files
            if set(event["systems"]) & state.ticked
            or (not event["systems"] and OTHER_SYSTEMS in state.ticked)]


def _ticked_held(state: TuiState) -> list[dict]:
    """Offline, the files of the systems ticked that the folders copied
    from hold: all an install without the internet brings."""
    took = {event["dest"] for events in _tui_found_elsewhere(state).values()
            for event in events}
    return [event for event in _ticked_files(state) if event["dest"] in took]


def _ticked_estimate(state: TuiState) -> tuple[int, int]:
    """The files and bytes the systems ticked since the check bring, their
    data files in them, or offline what the folders copied from hold: the
    plan's headline and its Install row both say it. One system ticked,
    the headline said 82.2 MB and Install 6.6 GB, the whole list's size."""
    if _offline_only():
        held = _ticked_held(state)
        return len(held), sum(event["size"] for event in held)
    chosen = _ticked_files(state)
    data, data_size = _plan_data(state, state.check or {})
    return len(chosen) + data, sum(event["size"] for event in chosen) + (data_size or 0)


# The screens below More, each listing its rows in _action_rows.
_ACTION_SCREENS = ("more", "remove", "removal", "backups", "backup", "actconfirm", "actdone",
                   "packplan", "packdone")


def tui_removal_systems(state: TuiState) -> list[tuple[str, int, int]]:
    """(system, files, bytes) of each system the install record holds files
    of, by the list's systems, in the order Choose systems lists them."""
    if state.record is None or state.manifest is None:
        return []
    served = _served(state.manifest, False)
    held: dict[str, list[int]] = {}
    for item in state.record.get("files") or []:
        systems = served.get((str(item.get("root") or ""), str(item["dest"])),
                             (set(), [], set(), False))[1]
        for system in systems or [OTHER_SYSTEMS]:
            tally = held.setdefault(system, [0, 0])
            tally[0] += 1
            tally[1] += int(item.get("size") or 0)
    titles = {system: system_title(system, state.manifest) for system in held}
    return [(system, held[system][0], held[system][1])
            for system in sorted(held, key=titles.__getitem__)]


def _more_rows(state: TuiState) -> list[TuiRow]:
    """Removing and the backups where the folder has a record or a backup,
    then Make a pack."""
    rows = ([TuiRow("remove", "Remove files"), TuiRow("backups", "Backups"),
             TuiRow("putback", "Put back a backup"), TuiRow("dropbackup", "Delete a backup")]
            if state.record is not None or state.has_backups else [])
    return rows + [TuiRow("packmake", "Make a pack")]


def _pack_plan_rows(state: TuiState) -> list[TuiRow]:
    """Make the pack, once its dry run said what goes in, and Change where."""
    if state.running or state.pack_plan is None:
        return []
    rows = ([TuiRow("packgo", "Make the pack")]
            if state.pack_plan.get("status") == "planned" else [])
    return rows + [TuiRow("packwhere", "Change where")]


def _remove_rows(state: TuiState) -> list[TuiRow]:
    """Remove files: everything the record holds, then each system of it."""
    if state.record is None:
        return [TuiRow("back", "Back")]
    files = state.record.get("files") or []
    size = format_size(sum(int(item.get("size") or 0) for item in files))
    rows = [TuiRow("rmall", "All RetroBIOS files", size, keep_right=True),
            TuiRow("rmmisplaced", "Misplaced copies")]
    for system, count, length in tui_removal_systems(state):
        rows.append(TuiRow("rmsystem", system_title(system, state.manifest),
                           format_size(length), system, narrow=(_plural(count, "file"),),
                           keep_right=True))
    return rows


def _removal_rows(state: TuiState) -> list[TuiRow]:
    """The removal plan's rows: Remove with the space it frees, the backup
    choice, Details and Back."""
    plan = state.removal
    if state.running or plan is None:
        return []
    rows = []
    if plan["files"]:
        rows.append(TuiRow("rmgo", f"Move {format_size(plan['bytes'])} to a backup"
                           if state.removal_backup and not _removing_misplaced(state)
                           else f"Remove {format_size(plan['bytes'])}"))
        if not _removing_misplaced(state):
            rows.append(TuiRow("rmbackup", f"Keep a backup: {_yes(state.removal_backup)}",
                               "--backup"))
    # B goes back: a Back row pushed what stays out of a 40x12 screen.
    return rows + _details_row(state)


def _backup_rows(state: TuiState) -> list[TuiRow]:
    if state.running or state.backups is None:
        return []
    rows = [TuiRow("backup", backup_words(item["date"]),
                   f"{_plural(item['files'], 'file')}, {format_size(item['bytes'])}", index,
                   narrow=(format_size(item["bytes"]),), keep_right=True)
            for index, item in enumerate(state.backups)]
    return rows + [TuiRow("back", "Back")]


def _action_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the More screens, or None for another screen."""
    screen = state.screen
    if screen == "more":
        return _more_rows(state)
    if screen == "remove":
        return _remove_rows(state)
    if screen == "removal":
        return _removal_rows(state)
    if screen == "backups":
        return _backup_rows(state)
    if screen == "backup":
        return [TuiRow("bkrestore", "Put back"), TuiRow("bkdelete", "Delete"),
                TuiRow("back", "Back")]
    if screen == "actconfirm":
        verb = {"remove": "Move to a backup"
                if state.removal_backup and not _removing_misplaced(state) else "Remove",
                "restore": "Put back", "delete_backup": "Delete"}[state.action]
        return [TuiRow("actgo", verb), TuiRow("back", "Back")]
    if screen == "actdone" and not state.running:
        return [TuiRow("close", "Close"), TuiRow("recheck", "Check again")]
    if screen == "packplan":
        return _pack_plan_rows(state)
    if screen == "packdone" and not state.running:
        return [TuiRow("close", "Close")]
    return []


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


TUI_OFFLINE_TITLE = "No internet: offline mode"
