"""The rows each screen lists."""
from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from installer.backups import backup_words
from installer.cards import _doubt_kinds, _mount_name, _mounted_cards
from installer.choices import recorded_axes
from installer.cores import CORE_PLATFORMS
from installer.destination import _card_what
from installer.handheld_app import APP_OFFER, APP_OFFER_SHORT
from installer.install_record import record_day
from installer.manifest import GAME_DATA
from installer.offline import LOCAL
from installer.plan import CONFIRM_FROM_BYTES
from installer.plan_words import cores_words
from installer.platforms import TARGET_PLATFORMS, _tui_system_label, system_title
from installer.regions import region_title
from installer.setups import setup_list
from installer.tally import tally
from installer.text import _plural, cell_width, format_size
from installer.tui_choice import (
    _board_seen,
    _board_where,
    _choice_entries,
    _choice_in_place,
    _chosen_cores,
    _core_narrow,
    _core_right,
    _cores_dir_given,
    _device_choice,
    _device_words,
    _emulator_words,
    _needed,
    _on_its_card,
    _plan_copies,
    _plan_fetch,
    _plan_folder,
    _save_folder_words,
    _shared_needed,
    _short_of_space,
    _sorted_systems,
    _system_titles,
    _ticked_estimate,
    _tui_card_bound,
    _tui_categories,
    _tui_estimating,
    _tui_misplaced,
    _yes,
    core_ticked,
    games_where,
    tui_choices,
    tui_core_sizes,
    tui_cores_ticked,
    tui_emulators,
    tui_removal_systems,
    tui_verbose,
)
from installer.tui_commands import (
    _app_offer,
    _core_base,
    _removing_misplaced,
    _tui_app_ready,
    _tui_slot_offered,
    _tui_standalone_offered,
    tui_record_kept,
)
from installer.tui_folder_scan import FolderScan
from installer.tui_paint import _short_path
from installer.tui_state import TUI_MAX_WIDTH, TuiRow, _matches, tui_offline_only

if TYPE_CHECKING:
    from installer.tui_state import TuiState

# The plan's two rows a beginner reads first: the README and the site name
# them from here, so they say what the screen shows.
TUI_INSTALL_ROW = "Install"
TUI_SYSTEMS_ROW = "Choose systems"


# Screens that scroll text instead of listing rows.
_PAGERS = ("preview", "command", "result", "misplaced", "unreadable", "games", "details")
_CHECKLISTS = ("systems", "cores", "emulators")


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


def _card_screen_rows(state: TuiState, rows: list[TuiRow], scan: FolderScan) -> list[TuiRow]:
    """The folder rows of a setup that runs from a card."""
    # Only the cards whose own files say they run the system: A on the
    # first mount wrote Onion's layout on a muOS card.
    cards = [TuiRow("card", f"{_mount_name(mount)} ({what})", value=mount)
             for mount, what in scan.cards]
    # A drive this system and another both fit is its card, as --dest
    # takes it: "No KNULLI card is mounted" sat beside it.
    cards += [TuiRow("card", f"{_mount_name(mount)} (could be {kinds})", value=mount)
              for mount, kinds in scan.doubtful]
    # On the device itself its folder is found, and no card is looked for.
    here = state.folder_default is not None and state.folder_kind == "found"
    blank = [] if here else [TuiRow("card", f"{_mount_name(mount)} ({what})", value=mount)
                             for mount, what in scan.blank]
    rescan = [] if cards or here else [TuiRow("rescan", "Look again")]
    if blank:
        # A blank drive is listed for a system that fills its card when
        # it first starts, after Look again: A never takes a stick.
        return rows + cards + rescan + blank + [TuiRow("browse", "Browse for a folder"),
                                                TuiRow("type", "Type a path")]
    rows += cards + [TuiRow("browse", "Browse for a folder"), TuiRow("type", "Type a path")]
    return rows + rescan


def _folder_screen_rows(state: TuiState) -> list[TuiRow]:
    """The rows of the BIOS folder question, from the drives last looked for."""
    rows = [TuiRow("default", "Use this folder")] if state.folder_default else []
    scan = state.folder_scan or FolderScan()
    if state.folder_kind == "share":
        # The drives mounted here first, each one's bios folder: the
        # share drive of a Batocera card or disk in a reader.
        rows += [TuiRow("share", label, value=folder) for label, folder in scan.shares]
    if not _tui_card_bound(state):
        # The drives mounted here, as line mode numbers them at the same
        # question, each by the BIOS folder its system reads, after the
        # Windows side's usual folder under WSL.
        # The Windows side's folder said missing where it is: taken, the
        # plan said RetroArch reads a folder no RetroArch had.
        # Every row whose folder is missing says so, in both modes: the
        # Windows row alone did.
        drives = [] if state.folder_kind == "share" else [
            TuiRow("drive", label, value=folder) for label, folder in scan.drives]
        return rows + [TuiRow("browse", "Browse for a folder"),
                       TuiRow("type", "Type a path")] + drives
    return _card_screen_rows(state, rows, scan)


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
    if tui_offline_only(state) and not _plan_copies(state.dry):
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
    plan = _plan_fetch(state, check)
    size = _ticked_estimate(state)[1] if _tui_estimating(state) else plan.size
    label = (f"{TUI_INSTALL_ROW} {format_size(size)}" if size >= CONFIRM_FROM_BYTES
             else TUI_INSTALL_ROW)
    rows = [TuiRow("install", label)]
    if tui_offline_only(state) and not plan.copied:
        # Nothing here to copy, and the network refused: Install would
        # only fail every file, in this folder or another.
        rows = []
    if (LOCAL.pack is not None and state.files and not plan.copied
            and len(plan.lacking) == len(state.files) and not plan.data_files):
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
    if _tui_slot_offered(state):
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
                     else _yes(state.offline)), "--offline")]
    if LOCAL.pack is None and not state.offline:
        # From a pack, or offline, nothing is downloaded.
        how.append(TuiRow("jobs", f"Parallel downloads: {state.jobs}", "--jobs"))
    see = [TuiRow("preview", "Preview the file list", "--dry-run"),
           TuiRow("command", "Show the command line")]
    rows: list[TuiRow] = []
    for heading, group in zip(TUI_CHANGE_GROUPS, (what, where, device, how, see)):
        if group:
            rows += [TuiRow("heading", heading, style="head"), *group]
    return rows


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


def _platform_rows(state: TuiState) -> list[TuiRow]:
    """The setup list of the screen, under its filter row (setup_list)."""
    return [_filter_row(state), *setup_list(
        state.setups, state.mounted_setups, state.filters.get("platforms", ""),
        state.os_type, LOCAL.serves())]


# The rows a tap ticks or unticks, as Space does: the lists of ticks.
TUI_TICK_ROWS = ("system", "core", "region", "emulator")


# The screens below More, each listing its rows in _action_rows.
_ACTION_SCREENS = ("more", "remove", "removal", "backups", "backup", "actconfirm", "actdone",
                   "packplan", "packdone")


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


TUI_OFFLINE_TITLE = "No internet: offline mode"
