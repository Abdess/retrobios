"""What a plan says on the line and on the screen: sizes, systems kept, space and folders."""
from __future__ import annotations

from collections.abc import Collection
from pathlib import Path
from typing import TYPE_CHECKING

from installer.choices import GamesChoice, available_choices, recorded_axes
from installer.destination import shown_bios_folder
from installer.datadirs import data_directory_state
from installer.host_fs import _exists, _folder_writable
from installer.local_check import not_in_place
from installer.manifest import GAME_DATA, OTHER_SYSTEMS
from installer.narrowing import _chosen, narrow
from installer.outcome import _on_read_only_mount, write_remedy
from installer.paths import _entry_path
from installer.platforms import entry_systems, system_title
from installer.space import bytes_written, free_space
from installer.tally import game_data_missing, sized_words, tally
from installer.text import _names_and, _no_widow, _wrap, cell_width, format_size

if TYPE_CHECKING:
    from installer.invocation import Invocation


def _sized(files: list[dict]) -> str:
    return sized_words(tally(files))


# A core whose files are all the platform's own. "pcsx_rearmed 0 files,
# 0 B" read as a core that gets nothing.
NO_CORE_FILES = "no extra file: it reads the platform's own, always kept"


def _core_sized(files: list[dict]) -> str:
    return _sized(files) if files else NO_CORE_FILES


def _system_sized(files: list[dict]) -> str:
    """A system's files, those other systems share counted apart.

    `3do 1704 files, 349.0 MB` read as the 3DO BIOS: 1689 of them are the
    MAME hash and plugin files six systems carry.
    """
    shared = [f for f in files if len(entry_systems(f)) > 1]
    if not shared:
        return _sized(files)
    if len(shared) == len(files):
        return f"{_sized(shared)}, all shared with other systems"
    own = [f for f in files if len(entry_systems(f)) <= 1]
    return f"{_sized(own)}, and {_sized(shared)} shared with other systems"


# The shared part of a size in fewer words, where the whole one does not
# fit beside its system (_size_lines), said once under the list.
_SHARED_LONG = " shared with other systems"
_SHARED_SHORT = " shared"
SHARED_NOTE = "Shared: files other systems read too."


def _size_lines(size: str, room: int, words: int = 0) -> list[str]:
    """A size in lines of at most room cells: whole, else its own part and
    its shared part apart. words shortens the shared part: 0 says "and
    1689 files, 334.2 MB shared with other systems", 1 "... shared", 2
    "+1689 files, 334.2 MB shared". 26 of 66 sizes were folded by an
    80-column terminal, and a row that fitted on one line took two."""
    if words:
        size = size.replace(_SHARED_LONG, _SHARED_SHORT)
    if words > 1:
        size = size.replace(", and ", ", +")
    if cell_width(size) <= room:
        return [size]
    for joint in (", and ", ", +", ", all "):
        own, found, shared = size.partition(joint)
        if found:
            return [*_no_widow(_wrap(f"{own},", room, ""), room),
                    *_no_widow(_wrap(found[2:] + shared, room, ""), room)]
    return _no_widow(_wrap(size, room, ""), room)


def listed_systems(files: list[dict]) -> list[str]:
    """The systems Choose systems lists for these files, in id order: each
    one a file belongs to, and the other systems for a file that names
    none. The plan, Choose systems and line mode count these: the plan
    said 12 systems where Choose systems listed 11, a system whose only
    file was left out counted."""
    systems = sorted({system for entry in files for system in entry_systems(entry)})
    if any(not entry_systems(entry) for entry in files):
        systems.append(OTHER_SYSTEMS)
    return systems


def choosable_systems(files: list[dict], omitted: list[dict],
                      cores: Collection[str] = (), regions: Collection[str] = ()) -> list[str]:
    """The systems a run with these cores and regions lets one choose
    among, --system aside: what the check reports (the choices event)."""
    if cores or regions:
        files = narrow(files, omitted, [], list(cores), list(regions))[0]
    return listed_systems(files)


def emptied_words(names: list[str], game_data: bool) -> str:
    """What a choice that keeps no file says, on the plan and in line mode,
    in place of "Everything is in place": Sega Dreamcast holds only game data."""
    subject = _names_and(names) if names else "This choice"
    verb = "hold" if len(names) > 1 else "holds"
    why = "only game data" if game_data else "no file under these options"
    return f"{subject} {verb} {why}: nothing is left to install."


def game_data_only(named: list[str], files: list[dict]) -> list[str]:
    """The systems named with --system whose files are all game data, of
    the list with its game data: --no-game-data leaves them empty."""
    return [system for system in named
            if any(_chosen(entry, {system}) for entry in files)
            and all(entry.get("category") == GAME_DATA for entry in files
                    if _chosen(entry, {system}))]


def game_data_only_words(titles: list[str]) -> str:
    """Said on the plan and in line mode's head of those systems, before the
    question: "For 1 of 8 systems (--system)" stood for two systems named
    and said nothing of the other. "" for none."""
    if not titles:
        return ""
    verb = "holds" if len(titles) == 1 else "hold"
    return f"{_names_and(titles)} {verb} only game data: left out (--no-game-data)."


def systems_in_order(systems: list[str], files: list[dict], manifest: dict | None,
                     bios_path: Path | None) -> list[str]:
    """Systems in the screen's order (_sorted_systems): those with a file
    to install first, each group by the title a person reads. Line mode
    listed them by id, nintendo-3ds before nintendo-ds where the screen
    put it after Nintendo Game Boy Advance. Before the check, a file is
    taken as in place when it exists."""
    def in_place(system: str) -> bool:
        if bios_path is None:
            return False
        held = [entry for entry in files if _chosen(entry, {system})]
        for entry in held:
            try:
                where = _entry_path(bios_path, entry)
            except ValueError:
                return False
            if not _exists(where):
                return False
        return bool(held)

    return sorted(systems, key=lambda system: (
        in_place(system), system_title(system, manifest).casefold()))


def _space_short(bios_path: Path, files: list[dict],
                 trees: Collection[dict] = ()) -> tuple[int, int] | None:
    """(bytes needed, bytes free) when what the run writes (bytes_written:
    the files not in place, missing or replaced, and the data trees) does
    not fit on the folder's drive, None when it fits or it cannot be told.
    Counted as the run's refusal counts it: the absent files alone said
    nothing of a run that then stopped for space after Enter."""
    free = free_space(bios_path)
    if free is None:
        return None
    # Every file and every tree file written: what fits so needs no read.
    if bytes_written(files, [(tree, (bios_path, tree.get("files") or {}, 0))
                             for tree in trees]) <= free:
        return None
    needed = bytes_written(not_in_place(bios_path, files),
                           [(tree, data_directory_state(tree, bios_path, remember=True))
                            for tree in trees])
    return (needed, free) if needed > free else None


def folder_warnings(plat: str, bios_path: Path, files: list[dict], hint: Invocation,
                    commands: bool = True, card: bool = False,
                    trees: Collection[dict] = ()) -> list[str]:
    """What the plan says of a folder the files and the data trees cannot go
    to, before the question that installs them: the folder refused, or too
    small. card is a setup that runs from that card, whose own folder is the
    one it reads."""
    lines = []
    if not _folder_writable(bios_path):
        lines += cannot_write_words(bios_path, plat, hint, commands, card)
    short = _space_short(bios_path, files, trees)
    if short is not None:
        lines += space_words(short[0], short[1], card, False, plat, hint, commands)
    return lines


CANNOT_WRITE = "This folder cannot be written to"


def cannot_write_words(bios_path: Path, plat: str, hint: Invocation, commands: bool,
                       card: bool, screen: bool = False, remedy: bool = True) -> list[str]:
    """What the plan says of a folder this user cannot write, one remedy
    for a card: unlock it, never another folder its system does not read.
    Line mode has no folder row: "choose another one" there offered no way
    to, so it names --dest, the screen its row."""
    said = write_remedy(bios_path, plat, hint, commands) if remedy else []
    if card and _on_read_only_mount(bios_path):
        return said
    another = ("choose another one" if screen
               else "run it again with another --dest" if commands
               else "run it again and choose another one")
    return [f"{CANNOT_WRITE}: {another}."] + said


def space_remedy(short: int, plat: str, hint: Invocation | None, commands: bool = True,
                 card: bool = False, screen: bool = False, refused: bool = False) -> list[str]:
    """What makes room for a run its drive cannot hold, the one remedy of the
    plan and of the run's refusal (refused): on a card setup's own card, room
    made there, another folder being one its system does not read; on the
    screen, its folder row. Line mode has no folder row, so it and the
    refusal name --dest, as the command once the platform is named. A second
    line is that command."""
    if card:
        # Its system reads this card alone: another drive, with RetroArch's
        # list, was offered for an Onion card.
        if refused:
            return [f"Free up {format_size(short)} on the card, then run it again: its system "
                    "reads its BIOS files there only."]
        return ["Free some space on the card first."]
    if screen:
        return ["Free some, or choose another folder."]
    if not commands:
        return [f"Free up {format_size(short)}, or run it again and choose another folder."]
    if not plat or hint is None:
        return [f"Free up {format_size(short)}, or use --dest to install to another drive."]
    # --dest alone used to mean RetroArch's list: the platform is named, so
    # a Batocera install moved to a USB drive stays Batocera's.
    return [f"Free up {format_size(short)}, or install to another drive:",
            hint.command(plat, "<folder on another drive>")]


def space_words(needed: int, free: int, card: bool, screen: bool = True, plat: str = "",
                hint: Invocation | None = None, commands: bool = True) -> list[str]:
    """Not enough room before the question, and what to do (space_remedy)."""
    said = f"Not enough free space: {format_size(needed)} needed"
    if card:
        said += f", {format_size(free)} free"
    remedy = space_remedy(needed - free, plat, hint, commands, card, screen)
    return [f"{said}. {remedy[0]}"] + remedy[1:]


def unlisted_saves_words(display: str) -> str:
    """Why a file list holds none of the files read from the save
    directory: the platform keeps it in no fixed place, and the list leaves
    them out with no hash or address, which --save-dir cannot change."""
    return f"{display} keeps it in no fixed place, and its file list holds none of them"


INSTALLED_ONLY = "installed"


def chosen_systems(choice: object) -> list[str] | None:
    """The systems a choice names, None for one that names none."""
    return list(choice[0]) or None if isinstance(choice, tuple) else None


def narrowing_words(files: list[dict], omitted: list[dict]) -> str:
    """What c chooses among for these files, in words, "" for nothing: a
    question with one answer is not asked."""
    axes = recorded_axes(files, omitted)
    choices = available_choices(files, omitted)
    named = [word for word, axis, enough in (
        ("systems", "systems", len(listed_systems(files)) > 1),
        ("cores", "cores", len(choices["cores"]) > 1),
        ("regions", "regions", bool(choices["regions"]))) if axis in axes and enough]
    return _names_and(named)


def chosen_flags(choice: object) -> list[tuple[str, str | None]]:
    """The options a choice made at the questions stands for."""
    if choice == INSTALLED_ONLY:
        return [("--installed-cores", None)]
    if isinstance(choice, GamesChoice):
        return choice.flags()
    assert isinstance(choice, tuple)
    systems, cores, regions = choice
    return [*(("--system", name) for name in systems), *(("--core", name) for name in cores),
            *([("--region", ",".join(regions))] if regions else [])]


def cores_words(chosen: int, total: int) -> str:
    """The cores a run keeps, as the plan, Options and line mode say it:
    all cores, or 3 of 12 cores."""
    return "all cores" if chosen >= total else f"{chosen} of {total} cores"


def core_count_words(cores: list[str], base: list[str]) -> str:
    """cores_words for the cores named out of those the systems chosen
    offer: a core of another system counted toward "all cores", the run
    keeping none of the system's own."""
    return cores_words(len(set(cores) & set(base)), len(base))


def unavailable_lines(needed: list[dict], manifest: dict | None, dest: Path | None,
                      files: list[dict]) -> list[str]:
    """The screen's plan and line mode's head say these sentences of the
    required files the collection cannot supply: line mode counted "1
    required, not found: 37" and never named the file or its folder."""
    if not needed:
        return []

    def system(name: str) -> str:
        label = system_title(name, manifest)
        # An id no title names (jazz-jackrabbit-2) read as a raw key.
        return label.replace("-", " ").title() if label == name else label

    # Named below the BIOS folder the plan names: bios/Machines/... under a
    # BIOS folder that is bios/ read as a second one.
    lead = ""
    if dest is not None and shown_bios_folder(dest, files) != dest:
        lead = shown_bios_folder(dest, files).name + "/"

    def where(dest: str) -> str:
        return dest[len(lead):] if lead and dest.startswith(lead) else dest

    def named(entries: list[dict]) -> str:
        names = [f"{where(entry['dest'])} ({system(entry['system'])})" if entry.get("system")
                 else where(entry["dest"]) for entry in entries[:3]]
        more = f" and {len(entries) - 3} more" if len(entries) > 3 else ""
        return f"{', '.join(names)}{more}"

    # A game's own data is not firmware: on every RetroArch plan the one
    # alarm named Jazz Jackrabbit 2's Anims.j2a, read as a broken install.
    games = [entry for entry in needed if entry.get("category") == GAME_DATA]
    firmware = [entry for entry in needed if entry.get("category") != GAME_DATA]
    lines = []
    if firmware:
        lines.append(f"Not available here, and needed to start "
                     f"{'its emulator' if len(firmware) == 1 else 'their emulators'}: "
                     f"{named(firmware)}. An owned copy goes in the BIOS folder.")
    if games:
        lines.append(game_data_missing(named(games), len(games), [
            (dest / entry["dest"]).parent for entry in games] if dest else []))
    return lines
