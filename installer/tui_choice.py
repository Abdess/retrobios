"""The choice made on screen and what it keeps: systems, cores, files, sizes and copies."""
from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from installer.cards import card_bound
from installer.choices import available_choices, core_files, emulator_names
from installer.datadirs import select_data_directories
from installer.destination import dest_drive, shown_bios_folder
from installer.embedded import CARD_PLATFORMS
from installer.frontend_folders import SAVE_NOT_KNOWN, save_directory_for, save_where_words
from installer.games_index import GAMES_REASONS
from installer.manifest import OTHER_SYSTEMS, entry_copies
from installer.narrowing import narrow
from installer.paths import SavePlace, spelled
from installer.plan_words import NO_CORE_FILES, _core_sized, emptied_words
from installer.platforms import _tui_system_label, system_title
from installer.regions import region_title
from installer.removal_plan import recorded_systems
from installer.tally import tally
from installer.text import _names_and, _plural, agree
from installer.tui_commands import _core_base, _tui_system_flags, _tui_systems_chosen, tui_flags, tui_run_files
from installer.tui_paint import _detail, _short_path
from installer.tui_state import tui_offline_only

if TYPE_CHECKING:
    from installer.tally import Tally
    from installer.tui_state import TuiState


def _needed(row: dict) -> int:
    return row["missing"] + row["wrong_hash"]


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
        for copy in entry_copies(entry):
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
    subject = _names_and(names)
    return f"{subject} {'are' if len(names) > 1 else 'is'} in place: nothing is left to install."


def games_where(state: TuiState) -> str:
    """Where the games are, as the plan's rows say it."""
    return f"in {state.games_folder.name}" if state.games_folder else "on this card"


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
    if tui_offline_only(state):
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


def _plan_copies(check: dict) -> list[str]:
    """The files to install that this machine holds, by destination, as the
    run that counted check decided it (its fetch_plan event)."""
    return list((check.get("fetch_plan") or {}).get("copied") or [])


def space_needed(check: dict) -> int:
    """What the run writes on the folder's drive, as its space event says
    it: the files and the data trees, the number its refusal holds against
    the free space. bytes_needed for a check that names none."""
    return check.get("space_bytes", check.get("bytes_needed", 0))


def _short_of_space(state: TuiState, check: dict) -> bool:
    free = state.facts.get("free")
    return free is not None and space_needed(check) > free


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
    # The cause the check gave, else the one the same rule gives here: a
    # RetroArch keeping saves beside each game read as "not known".
    why = state.unplaced_why.get("save")
    if why is None:
        place = (save_directory_for(state.dest, state.manifest, None)
                 if state.dest is not None and state.manifest else None)
        if isinstance(place, SavePlace):
            return _short_path(spelled(place.directory), state.home)
        why = place.cause if place is not None else ""
    return why if why and why != SAVE_NOT_KNOWN else "not known"


def _tui_card_bound(state: TuiState) -> tuple[str, str] | None:
    """The card the chosen setup runs from, when it runs from one."""
    if state.card_bound:
        return state.card_bound
    return card_bound(state.platform, state.platform) if state.platform in CARD_PLATFORMS else None


def _on_its_card(state: TuiState) -> bool:
    """Whether the BIOS folder is on the SD card of the setup it is for, a
    system that reads that card alone: room is made there, another folder
    being one it never reads. Read with the folder facts at the end of the
    check, so every frame of the plan and the result shows the same rows."""
    return state.dest is not None and bool(state.facts.get("on_card"))


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


class PlanFetch(NamedTuple):
    """What the run that counted a check fetches, from its fetch_plan event:
    the BIOS files and their bytes, the data files and theirs, the dests
    copied from this machine, those the pack lacks, the size of each file."""

    files: int
    bytes: int
    data_files: int
    data_bytes: int
    copied: list[str]
    lacking: list[str]
    sizes: dict[str, int]

    @property
    def size(self) -> int:
        """The one size the plan's headline and its Install row say."""
        return self.bytes + self.data_bytes


def _plan_fetch(state: TuiState, check: dict) -> PlanFetch:
    """The plan of check as the run decided it: the screen reads the
    counts, never works them out again. Worked out here, a file a --from
    folder held was called a download, a pack that held none of the files
    offered "Install 6.6 GB", and a pack without the data trees promised
    them."""
    dry = check is state.dry and check is not state.check
    plan = check.get("fetch_plan") or {}
    return PlanFetch(
        plan.get("files", 0), plan.get("bytes", 0), plan.get("data_files", 0),
        plan.get("data_bytes", 0), list(plan.get("copied") or []),
        list(plan.get("lacking") or []),
        {event["dest"]: event["size"] for event in (state.dry_files if dry else state.files)},
    )


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
    if tui_offline_only(state):
        held = _ticked_held(state)
        return len(held), sum(event["size"] for event in held)
    chosen = _ticked_files(state)
    data, data_size = _plan_data(state, state.check or {})
    return len(chosen) + data, sum(event["size"] for event in chosen) + (data_size or 0)


def tui_removal_systems(state: TuiState) -> list[tuple[str, int, int]]:
    """(system, files, bytes) of each system the install record holds files
    of, by the list's systems, in the order Choose systems lists them."""
    if state.record is None or state.manifest is None or state.dest is None:
        return []
    held: dict[str, list[int]] = {}
    for item, systems in recorded_systems(state.record, state.manifest, state.dest):
        for system in systems or [OTHER_SYSTEMS]:
            tally = held.setdefault(system, [0, 0])
            tally[0] += 1
            tally[1] += int(item.get("size") or 0)
    titles = {system: system_title(system, state.manifest) for system in held}
    return [(system, held[system][0], held[system][1])
            for system in sorted(held, key=titles.__getitem__)]
