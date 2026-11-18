"""The line interface: folders asked, sizes shown and the selection menu."""
from __future__ import annotations

import concurrent.futures
import shutil
import sys
import time
from collections.abc import Callable, Collection
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TextIO

from installer.cards import (
    _ask_from_folder,
    _last_name,
    _missing_dest,
    card_choice,
    card_install_dest,
    shown_bios_folder,
)
from installer.constants import GAME_DATA, INSTALLER_PAGE, OTHER_SYSTEMS, WORLD_REGION
from installer.cores import entry_systems, normalize_platform
from installer.datadirs import data_directory_state, data_fetch_bytes, select_data_directories
from installer.detect_os import _os_default_dests, card_title
from installer.embedded import (
    _SHARE_FOLDERS,
    _doubt_kinds,
    _mount_name,
    _mounted_cards,
    _name_key,
    card_bound,
    card_system,
    display_name,
    setup_bios_folder,
    share_doubt,
    shown_path,
)
from installer.from_folders import _bytes, plan_local_copies
from installer.invocation import _INVOCATION, Invocation
from installer.local_files import _classify_local, save_lines
from installer.narrowing import (
    _chosen,
    _filter_by_target,
    available_choices,
    choosable_cores,
    core_files,
    narrow,
    parse_selection,
    recorded_axes,
)
from installer.offline import LOCAL, offline_named
from installer.outcome import _offline_only, _on_read_only_mount, game_data_missing, on_its_card, write_remedy
from installer.pack_source import _folder_writable
from installer.paths import _destination_path, _entry_path
from installer.platform_choice import _choose_platform
from installer.probe import _exists, _is_dir, _is_file
from installer.prompt import _ask, _names_and, _no_widow, _quit, _typed_folder
from installer.record import OTHER_TITLE, _RECORD_TAKEN, system_title
from installer.setups import _built_in_dest, _card_word, _default_dest, _setup_label, setup_folder
from installer.tally import (
    Tally,
    game_data_state,
    kinds_definition,
    leave_out_game_data,
    parts_words,
    sized_words,
    tally,
)
from installer.terminal import Terminal, terminal_size
from installer.text import _plural, _split_word, _wrap, agree, cell_width, format_size, screen_text

if TYPE_CHECKING:
    from installer.games import GamesPlan


def _prompt_manual_platform(os_type: str, ask: bool = True, check_typed: bool = False,
                            title: str = "", setups: list | None = None,
                            mounted: set | None = None) -> list[tuple[str, Path]]:
    """Ask for a platform and a BIOS directory: nothing was detected, or
    another setup or folder was asked for.

    A system that runs from its card gets the card's root asked for, as
    --platform rocknix does: /storage/roms/bios was offered on a PC.
    """
    named = _choose_platform(title or "Nothing was found here. Which setup?", "retroarch",
                             setups, mounted)
    plat = normalize_platform(named, say=False)
    folder, kind = setup_folder(os_type, setups or [], mounted or set(), plat, named)
    if card_bound(named, plat) is not None and kind != "found":
        return [(plat, card_install_dest(named, plat, True, ask))]
    return [(plat, ask_platform_folder(os_type, plat, ask, check_typed,
                                       folder if kind == "found" else None))]


def share_words(plat: str) -> str:
    """Where a computer sees the BIOS folder of a system it does not run."""
    return (f"From a computer, {display_name(plat)}'s BIOS folder is bios on its SHARE "
            f"drive, or its network share ({_SHARE_FOLDERS[plat]} on Windows).")


def share_targets(plat: str) -> list[tuple[str, Path]]:
    """(row label, BIOS folder) of each drive mounted here offered as the
    SHARE drive of a system a computer reaches over the network: its bios
    folder, the screen's rows and line mode's numbers. Line mode took the
    drive's root, where Batocera never reads. A drive whose own files name
    another system is left out: a muOS card was offered first, and one
    press put Batocera's list on it."""
    targets = []
    for mount in _mounted_cards():
        found = card_system(mount)
        doubt = share_doubt(mount)[0]
        if (found is not None and found[0] != plat) or (doubt and plat not in doubt):
            continue
        targets.append((f"{_mount_name(mount)}: bios", mount / "bios"))
    return targets


def drive_targets(plat: str) -> list[tuple[str, Path]]:
    """(row label, BIOS folder) of each drive mounted here offered at the
    folder question of a setup that runs from no card (RetroArch here): a
    card of a system that reads plat's list by its own BIOS folder, a drive
    nothing names by its bios folder. A drive's root is no answer: no setup
    reads its BIOS files there, and RetroArch's list landed beside the roms/
    and system/ of a Batocera SHARE drive. Another system's card or drive, and
    one two systems fit, are reached through their own setup
    (drives_left_out)."""
    targets = []
    for mount in _mounted_cards():
        found = card_system(mount)
        if (found is not None and found[0] != plat) or share_doubt(mount)[0]:
            continue
        if found is not None:
            below = found[1].relative_to(mount).as_posix() if found[1] != mount else ""
            what = f"{card_title(found[2])} {_card_word(found)}"
            targets.append((f"{_drive_folder(mount, below)} ({what})", found[1]))
        else:
            # A drive its files show to be no card is called a drive, under
            # the note that says so: "card or drive" sat under "nothing on
            # it shows a handheld's card".
            targets.append((f"{_drive_folder(mount, 'bios')} (drive)", mount / "bios"))
    return targets


def folder_drives(os_type: str, plat: str, side: bool = True) -> list[tuple[str, Path]]:
    """The folders the folder question numbers for a setup that runs from no
    card, in the one order both modes give them: the other side's usual
    folder (side, under WSL), then the drives. Line mode and the screen
    gave them in two orders."""
    return [*(other_side(os_type, plat) if side else []), *drive_targets(plat)]


def unproven_drives() -> list[Path]:
    """The drives with a bios folder nothing shows to be a handheld's card,
    no SHARE either: offered at the folder question, never its default."""
    return [mount for mount in _mounted_cards()
            if card_system(mount) is None and not share_doubt(mount)[0]
            and _is_dir(mount / "bios")]


def unproven_words() -> str:
    """The plain note on those drives, "" for none: what was looked for on
    them, and what the reader does."""
    drives = unproven_drives()
    if not drives:
        return ""
    names = _names_and([_mount_name(mount) for mount in drives])
    has, it = ("has", "it") if len(drives) == 1 else ("have", "one")
    return (f"{names} {has} a bios folder but no folder a handheld system writes. "
            f"Pick {it} below if the BIOS files go there.")


def _said_with(label: str, words: str) -> str:
    """label with words in its parenthesis, or in one of their own: two side
    by side read as a slip."""
    return f"{label[:-1]}, {words})" if label.endswith(")") else f"{label} ({words})"


def numbered_folder(label: str, folder: Path) -> str:
    """A folder numbered at the folder question: its row's label, then the
    folder and whether it exists in one parenthesis. "DATA: bios (card or
    drive) (/media/me/DATA/bios)" put two side by side. A label that spells its
    folder (the Windows side's) is not followed by it again. Said of a folder
    that is missing, as the screen says it."""
    shown = shown_path(folder)
    said = [] if shown in label else [shown]
    said += [] if _is_dir(folder) else ["does not exist yet"]
    return _said_with(label, ", ".join(said)) if said else label


def _drive_folder(mount: Path, below: str) -> str:
    """A folder on a mounted drive as a row names it: D:\\bios where the
    drive is a letter (Windows, and WSL's /mnt/d), USBSTICK: bios where it
    is a label. "D:: bios" and "D:\\: bios" doubled the colon."""
    name = _mount_name(mount)
    if name.endswith((":", ":\\")):
        return shown_path(mount / below) if below else shown_path(mount)
    return f"{name}: {below}" if below else name


def drives_left_out(plat: str) -> str:
    """Why the drives mounted here that another system reads are not offered
    at plat's folder question, in words, "" for none."""
    others = []
    for mount in _mounted_cards():
        found = card_system(mount)
        doubt = share_doubt(mount)[0]
        # The options that reach it, which work wherever this is asked: the
        # setup list is not offered once a platform is named.
        if doubt:
            names = " or ".join(f"--platform {name}" for name in doubt)
            others.append(f"{_mount_name(mount)} ({_doubt_kinds(doubt)}: {names} "
                          f"--dest {shown_path(mount)})")
        elif found is not None and found[0] != plat:
            word = _name_key(found[2]) or found[0]
            others.append(f"{_mount_name(mount)} ({card_title(found[2])} {_card_word(found)}: "
                          f"--platform {word} --dest {shown_path(mount)})")
    if not others:
        return ""
    return (f"Not offered here, each reads its own system's files: {', '.join(others)}.")


def ask_platform_folder(os_type: str, plat: str, ask: bool = True,
                        check: bool = True, found: Path | None = None) -> Path:
    """The BIOS folder for a setup chosen from the list, asked as the
    screen's Which folder? asks it: the folder detection found here (found)
    or its usual folder under Enter, the drives mounted here numbered. The
    usual folder was taken without a word, a mounted card beside it never
    offered. A system this computer only reaches over the network gets no
    default: /userdata/bios exists on the Batocera machine alone, and its
    drives are numbered by their bios folder, the screen's rows
    (share_targets)."""
    name = display_name(plat)
    shared = plat in _SHARE_FOLDERS and found is None
    default = found if found is not None else None if shared else _default_dest(os_type, plat)
    print(f"\nWhich folder do {name}'s BIOS files go to?")
    if shared:
        print(f"  {share_words(plat)}")
    elif found is not None:
        print(f"  {name} reads its BIOS files from: {shown_path(found)}.")
    elif default is not None:
        state = "" if _exists(default) else " (it does not exist yet and will be created)"
        print(f"  {side_name(os_type, plat)}'s default BIOS folder: {shown_path(default)}"
              f"{state}.")
    # A drive is offered by the BIOS folder its system reads, the screen's
    # rows: never its root, and never for a system that reads another list.
    targets = (share_targets(plat) if shared else folder_drives(os_type, plat, found is None))
    for index, (label, folder) in enumerate(targets, 1):
        print(f"    {index}) {numbered_folder(label, folder)}")
    left_out = "" if shared else drives_left_out(plat)
    if left_out:
        print(f"  {left_out}")
    unproven = "" if shared else unproven_words()
    if unproven:
        print(f"  {unproven}")
    numbers = "" if not targets else (" or 1" if len(targets) == 1
                                      else f" or 1 to {len(targets)}")
    why = ("" if default is not None or shared
           else " (no default, a folder above could not be opened)"
           if _default_set_aside(os_type, plat) else " (no default on this system)")
    enter = f"the folder {name} reads" if found is not None else "the default above"
    prompt = (f"BIOS folder{numbers}, q to quit (Enter for {enter}): " if default
              else f"BIOS folder{numbers}, q to quit{why}: ")
    usage = f"  Type a folder{', a number' if targets else ''}, or q to quit."
    while True:
        raw = _folder_answer(prompt, usage, default is not None, len(targets))
        if raw is None:
            assert default is not None
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(targets):
            # The screen's row, taken as it takes it.
            return targets[int(raw) - 1][1]
        else:
            # Named in full on BIOS folder:, Created and Location:, where
            # "q" alone said nothing of the folder it was in.
            folder = _typed_folder(raw).absolute()
        choice = card_choice(plat, plat, folder)
        if choice.refused:
            print(f"  {choice.refused}. Type {name}'s own folder, or q to quit.")
            continue
        for line in (choice.found, choice.note):
            if line:
                print(f"  {line}")
        folder = choice.folder
        if not check or folder == default or _missing_dest(folder, ask, "typed", again=True):
            return folder


def _folder_answer(prompt: str, usage: str, default: bool, numbers: int = 0) -> str | None:
    """A folder question's answer: None for Enter on a default, else the
    text typed. q quits as at every other question, a folder named q being
    typed ./q: q was a folder created in the current one and filled. Enter
    with no default, or a number out of range that names no folder, says
    what to type: the question came back with no word."""
    while True:
        raw = _ask(prompt)
        if not raw:
            if default:
                return None
            print(usage)
            continue
        if raw.lower() == "q":
            _quit()
        if raw.isdigit() and not 1 <= int(raw) <= numbers and not _is_dir(_typed_folder(raw)):
            print(usage)
            continue
        return raw


def other_side(os_type: str, plat: str) -> list[tuple[str, Path]]:
    """(label, folder) of the Windows side's usual folder under WSL, where
    the one offered first is this Linux's: a Windows RetroArch outside the
    folders detection knows never reads ~/.config/retroarch/system, and no
    row reached C:\\."""
    if os_type != "wsl":
        return []
    windows = _os_default_dests("windows").get(plat)
    if windows is None or windows == _default_dest(os_type, plat):
        return []
    return [(f"Windows {display_name(plat)}: {shown_path(windows)}", windows)]


def side_name(os_type: str, plat: str) -> str:
    """The setup named by its side where the folder question offers both
    (other_side): Linux RetroArch beside Windows RetroArch under WSL. The
    Windows one alone was named so."""
    name = display_name(plat)
    return f"Linux {name}" if other_side(os_type, plat) else name


def _default_set_aside(os_type: str, platform_name: str) -> bool:
    """Whether the platform's usual folder was set aside because detection
    met a closed folder, as against having none on this OS."""
    return (_default_dest(os_type, platform_name) is None
            and _built_in_dest(os_type, platform_name) is not None)


def _manual_usage_hint(os_type: str, listing: str = "") -> list[str]:
    """How to name the platform and directory when nothing is detected.

    In the form the run was started with: a one-liner user has no
    install.py, and `python3 install.py` failed with "can't open file".
    """
    example = {
        "windows": "C:\\RetroArch-Win64\\system",
        "android": "/storage/emulated/0/RetroArch/system",
    }.get(os_type, "~/.config/retroarch/system")
    hint = Invocation()
    hint.os_type, hint.options = os_type, _INVOCATION.options
    if listing:
        # A listing reads a platform's list and writes nothing: --dest is
        # not needed, and a rebuilt install command dropped the listing
        # and started a 6.5 GB download.
        return [
            "  Name the platform whose list to print, for example:",
            f"    {hint.command('retroarch', None)} {listing}",
            f"  The platforms: {hint.launcher()} --list-platforms",
        ]
    return [
        "  Name the setup with --platform and its folder with --dest, for example:",
        f"    {hint.command('retroarch', example)}",
        f"  Where each platform keeps its BIOS: {INSTALLER_PAGE}",
    ]


def _prompt_platform_choice(
    platforms: list[tuple[str, Path]], title: str = "Install for:",
    labels: dict | None = None,
    other: Callable[[], list[tuple[str, Path]]] | None = None,
) -> list[tuple[str, Path]]:
    """One of the setups found here, as the screen's Where to install?
    lists them: its labels, Enter taking the first as A does there, and o
    for another setup or folder (other). Line mode had no Enter default, an
    All the screen lacks, and no way to another setup once one was found."""
    print(f"\n{title}")
    named = [(labels or {}).get((name, path)) or _setup_label(name, path)
             for name, path in platforms]
    for i, ((plat, path), label) in enumerate(zip(platforms, named), 1):
        # The label and its folder, as the screen shows them: "Onion SD card
        # (ONION) (/media/me/ONION/BIOS)" put two pairs of brackets in a row.
        print(fold_line(f"  {i}) {label}: {shown_path(setup_bios_folder(plat, path))}",
                     " " * (len(str(i)) + 2)))
    if other is not None:
        print("  o) another setup or folder")
    print("  q) quit")
    # "a number from 1 to 1" for a single row.
    usage = ("  Type 1" if len(platforms) == 1 else
             f"  Type a number from 1 to {len(platforms)}") + (
        ", o for another setup or folder" if other is not None else "") + ", or q to quit."
    while True:
        choice = _ask(f"> [Enter for {named[0]}] ").lower()
        if not choice:
            return [platforms[0]]
        if choice == "q":
            _quit()
        if choice == "o" and other is not None:
            return other()
        idx = int(choice) if choice.isdigit() else 0
        if 1 <= idx <= len(platforms):
            return [platforms[idx - 1]]
        # A wrong answer used to bring back a bare prompt, and nothing said
        # how to leave it.
        print(usage)


def fold_line(text: str, hang: str = "  ") -> str:
    """A line wrapped between words at the terminal's width, the lines after
    the first indented by hang under its own lead, a word wider than a line
    cut after a slash: left to the terminal, below 40 columns "Found Onion
    at /media/moi/ONION/BIOS" broke inside "(RetroArch files)" and a folder
    inside its name."""
    width = terminal_size()[0]
    cols = max(width - 1, 8)
    if cell_width(text) <= cols or width >= TUI_MIN_COLS or not _is_terminal(sys.stdout):
        # A pipe or a log folds nothing, and from 40 columns a folder is left
        # whole for the terminal to fold, copied as one line.
        return text
    lead = text[:len(text) - len(text.lstrip(" "))]
    prefix = lead + hang
    lines: list[str] = []
    line = lead
    for word in text.split():
        joined = f"{line} {word}" if line.strip() else line + word
        if cell_width(joined) <= cols:
            line = joined
            continue
        if line.strip():
            lines.append(line)
        pieces = _split_word(word, max(cols - len(prefix), 1))
        lines += [prefix + piece for piece in pieces[:-1]]
        line = prefix + pieces[-1]
    lines.append(line)
    return "\n".join(lines)


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


def _pick(
    title: str, rows: list[tuple[str, list[dict]]], ordered: bool = False,
    sizer: Callable[[list[dict]], str] = _sized, labels: dict | None = None,
    note: str = "", short: dict | None = None,
) -> list[str]:
    """Numbered list of names. An empty answer keeps every one.

    sizer says what each name holds, labels how each one is shown, short
    in fewer words where those take fewer lines (a system's title without
    its id at 40 columns), note what the list needs said, under it.
    """
    if not rows:
        return []
    print(f"\n{title}")
    shown = {name: screen_text((labels or {}).get(name, name)) for name, _files in rows}
    sizes = {name: sizer(files) for name, files in rows}
    # One cell short of the terminal: a line as wide as it was folded by
    # some terminals, the next row then starting on its last cell.
    cols = terminal_size()[0] - 1
    # The fewest lines, the whole words where they cost no line: one
    # wording for the whole list, the id dropped where it takes a tenth
    # more lines (40 columns).
    briefs = [shown] + ([{name: screen_text(short.get(name, name)) for name, _files in rows}]
                        if short else [])
    layouts = [(len(lines) * (10 if brief is shown else 11), words, lines)
               for brief in briefs for words in range(3)
               for lines in [_pick_lines(rows, brief, sizes, cols, words)]]
    _cost, words, lines = min(layouts, key=lambda layout: layout[:2])
    for line in lines:
        print(line)
    notes = [*([SHARED_NOTE] if words and any(_SHARED_SHORT in size for size in sizes.values())
               else []), *([note] if note else [])]
    if notes:
        # At the terminal's width too: the note on the other systems passed
        # 40 columns.
        print("\n" + "\n".join(piece for text in notes
                                for piece in _no_widow(_wrap(text, cols, ""), cols)))
    hint = "order of preference, e.g. 2,1" if ordered else "e.g. 1,3-5"
    while True:
        text = _ask(f"Numbers ({hint}), Enter for all, q to quit: ")
        if not text:
            return []
        if text.lower() == "q":
            _quit()
        try:
            chosen = parse_selection(text, len(rows), ordered=ordered)
        except ValueError as exc:
            print(f"  {exc}")
            continue
        if chosen:
            return [rows[number - 1][0] for number in chosen]


def _pick_lines(rows: list[tuple[str, list[dict]]], shown: dict, sizes: dict,
                cols: int, words: int = 0) -> list[str]:
    """The numbered rows of a line question, cols wide at most. The sizes
    stand in one column placed for the labels, where every size of one
    part fits beside the longest label that leaves it room: the column was
    placed for the longest size, and every row but five took two lines.
    A row keeps one line where
    its label and its size fit, a longer size goes on under its column, and
    a label too long for the column takes its own line."""
    width = len(str(len(rows)))
    lead = 2 + width + 2
    plain = [cell_width(size) for size in sizes.values() if "shared" not in size]
    least = max([*plain, 16]) if plain else 16
    labels = sorted(cell_width(label) for label in shown.values())
    name_width = max([label for label in labels if lead + label + 2 + least <= cols]
                     or [0])
    column = lead + name_width + 2
    lines = []
    for index, (name, _files) in enumerate(rows, 1):
        label, size = shown[name], sizes[name]
        number = f"  {index:>{width}}) "
        if name_width and cell_width(label) <= name_width:
            parts = _size_lines(size, cols - column, words)
            lines.append(f"{number}{_pad(label, name_width)}  {parts[0]}")
            lines += [f"{' ' * column}{part}" for part in parts[1:]]
            continue
        # The size beside the label only where all of it fits there: its
        # first part alone left "21 files, 1.4 MB," with its shared files
        # unsaid.
        fitted = _size_lines(size, cols, words)
        whole = fitted[0] if len(fitted) == 1 else size
        if cell_width(f"{number}{label}  {whole}") <= cols:
            lines.append(f"{number}{label}  {whole}")
            continue
        lines += [f"{number}{part}" if not at else f"{' ' * lead}{part}"
                  for at, part in enumerate(_no_widow(_wrap(label, cols - lead, ""),
                                                      cols - lead))]
        at = column if name_width and cols - column >= least else lead
        lines += [f"{' ' * at}{part}" for part in _size_lines(size, cols - at, words)]
    return lines


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
    subject = (", ".join(names[:-1]) + " and " + names[-1]) if len(names) > 1 else (
        names[0] if names else "This choice")
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


def _space_short(bios_path: Path, files: list[dict]) -> tuple[int, int] | None:
    """(bytes needed, bytes free) when the files absent from the folder do
    not fit on its drive, None when they fit or it cannot be told. The
    screen's plan warns of this before Install, line mode only after Enter."""
    probe = _nearest_folder(bios_path)
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return None
    needed = 0
    for entry in files:
        try:
            where = _entry_path(bios_path, entry)
        except ValueError:
            continue
        if not _exists(where):
            needed += entry.get("size", 0)
    return (needed, free) if needed > free else None


def folder_warnings(plat: str, bios_path: Path, files: list[dict], hint: Invocation,
                    commands: bool = True, card: bool = False) -> list[str]:
    """What the plan says of a folder the files cannot go to, before the
    question that installs them: the folder refused, or too small. card is
    a setup that runs from that card, whose own folder is the one it reads."""
    lines = []
    if not _folder_writable(bios_path):
        lines += cannot_write_words(bios_path, plat, hint, commands, card)
    short = _space_short(bios_path, files)
    if short is not None:
        lines.append(space_words(short[0], short[1], card))
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


def space_words(needed: int, free: int, card: bool) -> str:
    """Not enough room, and what to do: on a card setup's own card, room is
    made on the card, another folder being one its system does not read."""
    if card:
        return (f"Not enough free space: {format_size(needed)} needed, "
                f"{format_size(free)} free. Free some space on the card first.")
    return (f"Not enough free space: {format_size(needed)} needed. Free some, or "
            "choose another folder.")


def unlisted_saves_words(display: str) -> str:
    """Why a file list holds none of the files read from the save
    directory: the platform keeps it in no fixed place, and the list leaves
    them out with no hash or address, which --save-dir cannot change."""
    return f"{display} keeps it in no fixed place, and its file list holds none of them"


INSTALLED_ONLY = "installed"


def _menu_trees_kept(trees: list[dict], kept: list[dict], narrowed: bool,
                     current: object) -> list[dict]:
    """The data trees of the files a line menu choice keeps."""
    return select_data_directories({"data_directories": trees}, kept,
                                   narrowed or current is not None,
                                   isinstance(current, GamesChoice) and current.required,
                                   current.plan if isinstance(current, GamesChoice) else None,
                                   chosen_systems(current))


class _SelectionMenu(NamedTuple):
    """What each round of the line menu reads, as it was given."""

    plat: str
    files: list[dict]
    omitted: list[dict]
    installed: tuple[list[dict], list[dict]] | None
    manifest: dict | None
    bios_path: Path | None
    dry_run: bool
    given: tuple[list[str], list[str], list[str]] | GamesChoice | None
    played: GamesPlan | None
    cut: list[bool] | None

    def choice(self, current: object, cutting: bool) -> tuple[list[dict], list[dict]]:
        return menu_choice(self.files, self.omitted, self.installed, current, cutting)


def _print_menu_enter(whole: str, emptied: str, dry_run: bool, offline: bool) -> None:
    """The Enter line of the line menu, none for a choice that keeps no file."""
    if emptied:
        pass
    elif dry_run:
        print(f"  Enter) list {whole}, nothing is written")
    elif offline and LOCAL.folders:
        print("  Enter) install what is found in "
              + ", ".join(screen_text(shown_path(index.label)) for index in LOCAL.folders))
    elif offline:
        print("  Enter) check the BIOS folder, nothing can be downloaded")
    else:
        print(f"  Enter) install {whole}")


def _print_menu_keys(menu: _SelectionMenu, current: object, shown: list[dict],
                     cutting: bool, games: Tally, emptied: str, axes: str) -> list[str]:
    """The lettered lines of the line menu, and the keys it takes."""
    played, installed = menu.played, menu.installed
    playing = bool(played is not None and played.games)
    if playing and isinstance(current, GamesChoice):
        other = GamesChoice(current.plan, not current.required)
        print(f"  r) {GAMES_REQUIRED_WORDS if other.required else 'every file the games read'}"
              f": {_sized(menu.choice(other, cutting)[0])}")
        print(f"  e) everything, whatever the games: {_sized(shown)}")
    elif playing and played is not None:
        kept_games = menu.choice(GamesChoice(played), cutting)[0]
        print(f"  h) only for the games {played.where()}: {_sized(kept_games)}")
    # The screen's "Same choice as last time: no": the whole list.
    widen = (menu.plat in _RECORD_TAKEN and current is not None
             and not (playing and isinstance(current, GamesChoice)))
    if widen:
        print(f"  e) everything: {_sized(shown)}")
    if installed is not None and current != INSTALLED_ONLY:
        print(f"  i) only what the installed cores read: {_sized(installed[0])}")
    choosable = bool(axes)
    if choosable:
        print(f"  c) choose {axes}" + (" again" if current is not menu.given else ""))
    # The screen's "Copy the BIOS files from an old card or a folder".
    copying = not menu.dry_run
    if copying:
        print("  f) copy from a folder or an old card")
    if menu.cut is not None and games.games:
        # The screen's row: one label, its state first.
        print(f"  g) {game_data_state(menu.cut[0], games)}: "
              f"{'keep it' if menu.cut[0] else 'leave it out'}")
    print("  q) quit")
    return [*([] if emptied else [""]), "q", *(["c"] if choosable else []),
            *((["r", "e"] if isinstance(current, GamesChoice) else ["h"]) if playing else []),
            *(["e"] if widen else []),
            *(["i"] if installed is not None and current != INSTALLED_ONLY else []),
            *(["f"] if copying else []), *(["g"] if games.games else [])]


def _menu_answered(
    menu: _SelectionMenu, answer: str,
    current: tuple[list[str], list[str], list[str]] | str | GamesChoice | None,
) -> tuple[list[str], list[str], list[str]] | str | GamesChoice | None:
    """The choice a key of the line menu makes, f copying from a folder."""
    if answer == "r" and isinstance(current, GamesChoice):
        return GamesChoice(current.plan, not current.required)
    if answer == "e":
        return None
    if answer == "h" and menu.played is not None:
        return GamesChoice(menu.played)
    if answer == "i":
        return INSTALLED_ONLY
    if answer == "c":
        return _choose_narrowing(menu.files, menu.omitted, menu.manifest, menu.bios_path)
    _ask_from_folder(menu.files, menu.bios_path)
    return current


class MenuContext(NamedTuple):
    """The list the line menu narrows, and the folder and setup it is for."""

    plat: str
    files: list[dict]
    omitted: list[dict]
    installed: tuple[list[dict], list[dict]] | None = None
    name: str = ""
    data_trees: list[dict] | None = None
    bios_path: Path | None = None
    manifest: dict | None = None
    narrowed: bool = False


def _prompt_custom_selection(
    context: MenuContext, *, dry_run: bool = False, choosable: bool = True,
    given: tuple[list[str], list[str], list[str]] | GamesChoice | None = None,
    command: Callable[[object], str] | None = None, cut: list[bool] | None = None,
    note: str = "", played: GamesPlan | None = None,
) -> tuple[list[str], list[str], list[str]] | str | GamesChoice | None:
    """Offer to narrow the install by system, core and region.

    cut, given for a list that marks its game data, holds whether g left
    it out: one key, as one row of the screen's plan, toggles it, and the
    caller applies it as --no-game-data does.

    Enter installs everything, the default most runs want. Returns None
    then, INSTALLED_ONLY for what `installed` (the files the cores found
    installed read) holds, or the three choices. Each empty list keeps
    everything on its axis. A list that records no system (a pack's own)
    has no c: the menu and its folder line are still shown, a pack having
    installed at once into a folder named only after Done. given is what
    --system, --core and --region named: Enter keeps it, c chooses anew from
    every system. The menu was skipped, and the folder never named.

    A choice made here is counted again before anything is written, as the
    screen's Confirm counts it: the menu comes back narrowed, with the
    command that makes the same choice (command, given the choice), and
    Enter installs. c installed as soon as the cores were answered, "Enter
    for all" read as a choice. narrowed says the list was narrowed before
    the menu (--target, --no-game-data): the data trees kept are then those
    of the systems kept, as the plan and --dry-run count them. note is said
    under the head (game_data_only_words). played, the games of the card
    when it holds some, is the first choice (h), the whole list one key
    away (e), and r keeps only what the games cannot start without.
    """
    plat, files, omitted, installed = (context.plat, context.files, context.omitted,
                                       context.installed)
    name, bios_path, manifest, narrowed = (context.name, context.bios_path, context.manifest,
                                           context.narrowed)
    trees = context.data_trees or []
    menu = _SelectionMenu(plat, files, omitted, installed, manifest, bios_path, dry_run,
                          given, played, cut)
    current: tuple[list[str], list[str], list[str]] | str | GamesChoice | None = given
    if current is None and played is not None and played.games:
        current = GamesChoice(played)
    toggled = False
    if bios_path is not None and not dry_run and current != INSTALLED_ONLY:
        kept = menu.choice(current, False)[0]
        kept_trees = _menu_trees_kept(trees, kept, narrowed, current)
        if kept and all_in_place(kept, kept_trees, bios_path):
            # Read before the menu, as the screen reads before it asks: a
            # rerun was offered an install that installs nothing, then told
            # so twice. The check after it reads none
            # of it again (_HEAD_READS).
            print(f"\n{name or display_name(plat)}: "
                  f"{_plural(len(kept) + sum(len(t.get('files') or {}) for t in kept_trees), 'file')}"
                  ", every one in place: nothing to install.")
            print(f"  BIOS folder: {shown_path(shown_bios_folder(bios_path, kept))}")
            return current
    while True:
        cutting = bool(cut and cut[0])
        shown, shown_omitted = ((leave_out_game_data(files, omitted)[:2])
                                if cutting else (files, omitted))
        # The game data of the choice the head counts, which g takes out of
        # it or puts back: counted over the whole list, it said 5089 files
        # under a head counting 12 for one system. Not offered for a
        # choice that holds none.
        games = tally(menu.choice(current, False)[0] if cut is not None else [])
        kept = menu.choice(current, cutting)[0]
        # A choice that keeps no file says so in the headline, as the screen
        # does, and offers no Enter and no command: both installed nothing.
        emptied = (emptied_words([system_title(name_, manifest) for name_ in current[0]],
                                 cutting)
                   if isinstance(current, tuple) and not kept else "")
        _print_menu_head(context._replace(files=shown, omitted=shown_omitted, data_trees=trees),
                         current, object() if toggled else given,
                         chosen=menu.choice(current, cutting),
                         cut_games=games.games if cutting else 0, emptied=emptied,
                         note=note if current is given else "")
        if (current is not given or toggled) and command is not None and not emptied:
            print(f"  Same choice without questions: {screen_text(command(current))}")
        offline = _offline_only()
        if offline:
            # Said before the menu: "install everything" was offered, then
            # nothing came and the run said Done.
            print(f"  {offline_named()}: only the files found on this machine are installed"
                  + ("." if LOCAL.folders else ", and no --from names a folder to copy "
                     "them from."))
        # A dry run installs nothing: "install everything" was asked before it.
        # Offline with nothing to copy from, nothing can be installed but
        # what is in place already.
        whole = ("everything" if current is None
                 else f"what the games {played.where()} need"
                 if isinstance(current, GamesChoice) and played is not None else "these")
        _print_menu_enter(whole, emptied, dry_run, offline)
        # What c asks, named: "systems, cores and regions" was offered with
        # a pack that records systems only.
        axes = narrowing_words(files, omitted) if choosable else ""
        choosable = bool(axes)
        keys = _print_menu_keys(menu, current, shown, cutting, games, emptied, axes)
        others = [key for key in keys if key not in ("", "q")]
        answer = _ask("> ").lower()
        while answer not in keys:
            print(f"  Type {', '.join([*([] if emptied else ['Enter']), *others])} or q.")
            answer = _ask("> ").lower()
        if answer == "":
            return current
        if answer == "q":
            _quit()
        if answer == "g" and cut is not None and games.games:
            cut[0] = not cut[0]
            toggled = True
        else:
            current = _menu_answered(menu, answer, current)


def _print_menu_head(
    context: MenuContext, current: object, given: object, *,
    chosen: tuple[list[dict], list[dict]] | None = None,
    cut_games: int = 0, emptied: str = "", note: str = "",
) -> None:
    """The plan above the line menu: what the choice holds, its folder, what
    stands in its way and where the save files go, as the screen's plan.
    chosen is what the choice keeps (menu_choice), the list every count of
    the head is taken from. cut_games is the game data g left out of it."""
    plat, files, omitted, installed = (context.plat, context.files, context.omitted,
                                       context.installed)
    name, bios_path, manifest = context.name, context.bios_path, context.manifest
    trees, narrowed = context.data_trees or [], context.narrowed
    shown, kept_omitted = chosen or menu_choice(files, omitted, installed, current, False)
    # The trees of the systems kept: 2636 data files of blueMSX, Dolphin
    # and PPSSPP were counted for every --system tried.
    kept_trees = _menu_trees_kept(trees, shown, narrowed, current)
    data = sum(len(entry.get("files") or {}) for entry in kept_trees)
    data_size = sum(meta.get("size", 0) for entry in kept_trees
                    for meta in (entry.get("files") or {}).values())
    named = ""
    if current == INSTALLED_ONLY:
        named = ", only what the installed cores read"
    elif isinstance(current, GamesChoice):
        named = f", {current.words()}" + (" (--for-games)" if current is given
                                          and plat not in _RECORD_TAKEN else "")
    elif isinstance(current, tuple):
        systems, cores, regions = current
        # A recorded choice was typed by nobody: no option is named.
        flag = current is given and plat not in _RECORD_TAKEN
        listed = choosable_systems(files, omitted, cores, regions)
        total = len(listed)
        # The systems chosen that still hold a file: Sega Dreamcast holding
        # only game data, g left the line at "2 of 8" where the screen,
        # which drops it, said "1 of 8".
        held = len(set(systems) & set(listed))
        named = ", " + ", ".join(filter(None, [
            f"for {held} of {total} systems" + (" (--system)" if flag else "")
            if systems else "",
            # Out of the cores the systems chosen offered, as Cores counts
            # them: "1 core chosen" read as one of one. A flag typed is
            # named after the words, never alone: "--region." stood as a
            # sentence of its own.
            core_count_words(cores, choosable_cores(files, omitted, systems))
            + (" (--core)" if flag else "") if cores else "",
            "regions ranked" + (" (--region)" if flag else "") if regions else ""]))
        named = "" if named == ", " else named
    if current is not given:
        print("\n  Counted again for these choices. Nothing is written before Enter.")
    counts = tally(shown)
    if emptied:
        # The screen's headline for a choice that keeps no file.
        print(f"\n{name or display_name(plat)}: {emptied}")
        if bios_path is not None:
            print(f"  BIOS folder: {shown_path(shown_bios_folder(bios_path, files))}")
        return
    # One total, data files in it, the kinds on the line under it adding up
    # to it, as the screen's headline. With --from,
    # what the folders hold first, as the screen's plan says it: nothing
    # said how many were found before Enter.
    found = (found_head(shown, kept_trees, bios_path)
             if LOCAL.folders and bios_path is not None else "")
    print(f"\n{name or display_name(plat)}: " + (found or (
          f"{_plural(counts.files + data, 'file')}, "
          f"{format_size(counts.size + data_size)}")) + named + ".")
    if note:
        print(f"  {note}")
    categorized = bool((manifest or {}).get("categorized"))
    kinds = counts if categorized else tally({"size": e.get("size")} for e in shown)
    parts = parts_words(kinds, data, data_size, cut_games)
    if parts:
        print(f"  {parts}.")
    defined = kinds_definition(categorized and bool(counts.games or cut_games), bool(data))
    if defined:
        print(f"  {defined}")
    if bios_path is None:
        return
    # Named before anything is written: line mode said where only after
    # Done, where the screen names it on every plan.
    print(f"  BIOS folder: {shown_path(shown_bios_folder(bios_path, files))}")
    for line in folder_warnings(plat, bios_path, shown, _INVOCATION, True,
                                on_its_card(plat, bios_path)):
        print(f"  {line}")
    # The frontend's save directory, named as the end of the run and the
    # screen name it: "Onion's" before the menu, "RetroArch's" after.
    for line in save_lines(shown, kept_omitted, bios_path, display_name(plat, manifest)):
        print(f"  {line}")
    # The required files the collection cannot supply, named as the screen's
    # plan names them.
    for line in unavailable_lines([entry for entry in kept_omitted if entry.get("required")],
                                  manifest, bios_path, (manifest or {}).get("files") or shown):
        print(f"  {line}")


def found_head(files: list[dict], trees: list[dict], bios_path: Path) -> str:
    """What the --from folders hold of the files not in place, and what is
    left, in the screen plan's words: "6 found in OLD, 16 need the
    internet". "" when they hold none of them. A file of the wrong size is
    not in place. One of the right size is read, as check_local reads it:
    judged by its size, a wrong copy of the right size was in place, and
    "nothing to download" stood over a run that left it. What is read here is
    kept for the check after Enter (_HEAD_READS): a card read twice is read at
    the speed of its reader."""

    def held(path: Path, size: object) -> bool:
        try:
            return _is_file(path) and path.stat().st_size == size
        except OSError:
            return False

    needed, sized = [], []
    for entry in files:
        try:
            path = _entry_path(bios_path, entry)
        except ValueError:
            continue
        if held(path, entry.get("size")):
            sized.append((entry, path))
        else:
            needed.append(entry)
    # Only a copy of the right size is read, on the check's workers and
    # with its count: one at a time and silent, 400 files of a card read
    # as a hung run before the menu.
    needed += [entry for (entry, _path), verdict in zip(sized, read_in_place(sized))
               if verdict != "up_to_date"]
    copies = plan_local_copies(needed, bios_path, None, LOCAL.folders)
    if not copies:
        return ""
    by_folder: dict[str, int] = {}
    for copy in copies.values():
        by_folder[copy.index.label] = by_folder.get(copy.index.label, 0) + 1
    data, data_bytes = 0, 0
    for tree in trees:
        _root, wanted, _present = data_directory_state(tree, bios_path, remember=True)
        data += len(wanted)
        data_bytes += data_fetch_bytes(tree, wanted)
    left = [entry for entry in needed if id(entry) not in copies]
    rest = len(left) + data
    where = ", ".join(f"{count} found in {_last_name(label)}"
                      for label, count in by_folder.items())
    if not rest:
        return f"{where}, nothing to download"
    if _offline_only():
        return f"{where}, {agree(rest, 'needs', 'need')} the internet"
    return f"{where}, {rest} to download ({format_size(_bytes(left) + data_bytes)})"


def all_in_place(files: list[dict], trees: list[dict], bios_path: Path) -> bool:
    """Whether every file and every data tree file is in place, read as the
    check reads it. Sizes first: a folder missing a file is told without a
    read. What is read is kept for the check (_HEAD_READS)."""
    paths = []
    for entry in files:
        try:
            path = _entry_path(bios_path, entry)
            if not _is_file(path) or path.stat().st_size != entry.get("size"):
                return False
        except (OSError, ValueError):
            return False
        paths.append((entry, path))
    for tree in trees:
        root = (_destination_path(bios_path, tree["dest"]) if tree.get("dest")
                else bios_path.resolve())
        for rel, meta in (tree.get("files") or {}).items():
            target = _destination_path(root, rel)
            try:
                if not _is_file(target) or target.stat().st_size != meta.get("size"):
                    return False
            except OSError:
                return False
    return (all(verdict == "up_to_date" for verdict in read_in_place(paths))
            and all(not data_directory_state(tree, bios_path, remember=True)[1]
                    for tree in trees))


def _live_stdout() -> bool:
    """Whether the standard output draws a moving line (Terminal.live)."""
    return Terminal(sys.stdout).live


def read_in_place(pairs: list[tuple[dict, Path]]) -> list[str]:
    """_classify_local of each (entry, path), read before the line menu as
    the check after it reads: on --jobs workers, a count moving at a
    terminal, what is read kept for that check (_HEAD_READS). Each file is
    read once whatever the question: the head reads the files of the right
    size only, and the check after Enter reads none of them again."""
    if not pairs:
        return []
    live = _live_stdout()
    verdicts: list[str] = []
    last = 0.0
    with concurrent.futures.ThreadPoolExecutor(max_workers=LOCAL.jobs) as pool:
        for done, verdict in enumerate(pool.map(
                lambda pair: _classify_local(pair[0], pair[1], remember=True), pairs), 1):
            verdicts.append(verdict)
            now = time.monotonic()
            if live and (now - last >= 0.1 or done == len(pairs)):
                last = now
                print(f"\r  read {done}/{len(pairs)}", end="", flush=True)
    if live:
        print("\r\033[K", end="", flush=True)
    return verdicts


def chosen_systems(choice: object) -> list[str] | None:
    """The systems a choice names, None for one that names none."""
    return list(choice[0]) or None if isinstance(choice, tuple) else None


def menu_choice(
    files: list[dict], omitted: list[dict],
    installed: tuple[list[dict], list[dict]] | None, current: object, cut: bool,
) -> tuple[list[dict], list[dict]]:
    """The files and omissions a choice at the line menu keeps, in the order
    the run applies it: the systems, cores and regions chosen, or what the
    installed cores read (i), then the game data left out (g)."""
    kept, kept_omitted = files, omitted
    if current == INSTALLED_ONLY and installed is not None:
        kept, kept_omitted = installed
    elif isinstance(current, GamesChoice):
        kept, kept_omitted = current.apply(files, omitted)
    elif isinstance(current, tuple):
        kept, kept_omitted = narrow(files, omitted, *current)
    return leave_out_game_data(kept, kept_omitted)[:2] if cut else (kept, kept_omitted)


def narrowing_words(files: list[dict], omitted: list[dict]) -> str:
    """What c chooses among for these files, in words, "" for nothing: a
    question with one answer is not asked."""
    axes = recorded_axes(files, omitted)
    choices = available_choices(files, omitted)
    named = [word for word, axis, enough in (
        ("systems", "systems", len(listed_systems(files)) > 1),
        ("cores", "cores", len(choices["cores"]) > 1),
        ("regions", "regions", bool(choices["regions"]))) if axis in axes and enough]
    return f"{', '.join(named[:-1])} and {named[-1]}" if len(named) > 1 else "".join(named)


def _choose_narrowing(files: list[dict], omitted: list[dict], manifest: dict | None,
                      bios_path: Path | None) -> tuple[list[str], list[str], list[str]]:
    """Systems, cores and regions asked one after the other, the systems
    titled and ordered as the screen's Choose systems lists them. A question
    with one answer is skipped: "Cores: 1) azahar" was asked after the 3DS
    alone was chosen."""
    listed = listed_systems(files) if "systems" in recorded_axes(files, omitted) else []
    systems_listed = (systems_in_order(listed, files, manifest, bios_path)
                      if len(listed) > 1 else [])
    # Said under the list it explains, before the question: above
    # "Systems:" it read as a heading.
    # One sentence wrapped at the width: its line break, placed for a
    # shorter title, left "platform" alone on a line.
    note = (f"'{OTHER_TITLE}' holds what cores load for systems this platform "
            "does not list, such as game engines and extra computers."
            if OTHER_SYSTEMS in systems_listed else "")
    labels = {}
    for system in systems_listed:
        title = system_title(system, manifest)
        labels[system] = title if system in title or system == OTHER_SYSTEMS \
            else f"{title}  {system}"
    systems = _pick("Systems:", [
        (system, [f for f in files if _chosen(f, {system})]) for system in systems_listed
    ], sizer=_system_sized, labels=labels, note=note,
        short={system: system_title(system, manifest) for system in systems_listed})
    kept, kept_omitted = narrow(files, omitted, systems, [], [])

    cores: list[str] = []
    core_names = choosable_cores(kept, kept_omitted)
    if len(core_names) > 1:
        print("\nThe platform's own files for these systems are always kept.")
        # Every core is kept, as Cores draws them all ticked: a list of
        # numbers read as nothing chosen yet.
        print("Every core's extra files are kept: Enter keeps them all, numbers keep "
              "only those cores.")
        cores = _pick("Cores:", [(core, core_files(kept, core)) for core in core_names],
                      sizer=_core_sized)
        kept, kept_omitted = narrow(kept, kept_omitted, [], cores, [])

    regions: list[str] = []
    region_names = available_choices(kept, kept_omitted)["regions"]
    if region_names:
        print("\nSome systems have one BIOS per region. Keeping only the")
        print("preferred region removes the others where a match exists.")
        regions = _pick("Regions:", [
            (region, [f for f in kept if region in (f.get("regions") or [])])
            for region in region_names
        ], ordered=True, labels={region: region_title(region) for region in region_names})
    return systems, cores, regions


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


def system_aliases(manifest: dict | None) -> dict[str, str]:
    """The platform's own names for its systems, then the titles the site
    and the installer print (SNK Neo Geo CD), each with the system id.

    A title two systems share names neither, and the platform's own name
    wins over a title spelled the same.
    """
    aliases = {
        alias: system
        for system, names in ((manifest or {}).get("system_names") or {}).items()
        for alias in names
    }
    taken = {_name_key(alias) for alias in aliases}
    titles = (manifest or {}).get("system_titles") or {}
    counts: dict[str, int] = {}
    for title in titles.values():
        counts[_name_key(title)] = counts.get(_name_key(title), 0) + 1
    for system, title in titles.items():
        key = _name_key(title)
        if key and counts[key] == 1 and key not in taken:
            aliases[title] = system
    return aliases


def _system_label(name: str, manifest: dict | None) -> str:
    """A system id with the names the platform gives it: nintendo-gba (gba)."""
    names = ((manifest or {}).get("system_names") or {}).get(name)
    return f"{name} ({', '.join(names)})" if names else name


def _print_choices(
    plat: str, files: list[dict], omitted: list[dict], systems: bool,
    manifest: dict | None = None,
) -> None:
    """What --system or --core accepts for a platform, with what each holds."""
    choices = available_choices(files, omitted)
    names = choices["systems"] if systems else choices["cores"]
    if not names:
        print(f"  {plat} records no {'systems' if systems else 'cores'}")
        return
    labels = {name: _system_label(name, manifest) if systems else name for name in names}
    width = min(max(len(label) for label in labels.values()), 40)
    for name in names:
        held = (
            [f for f in files if _chosen(f, {name})]
            if systems
            else _filter_by_target([f for f in files if f.get("cores") is not None], [name])
        )
        print(f"  {labels[name]:<{width}}  "
              f"{_system_sized(held) if systems else _core_sized(held)}")


def emulator_names(manifest: dict, files: list[dict], omitted: list[dict]) -> dict[str, str]:
    """Every name --emulator accepts, with the profile each one stands for.

    A profile answers to its own name and to the names its core is built
    under (core_names: beetle_psx and mednafen_psx). A core named by a file
    and by no profile stands for itself.
    """
    names = {core: core for core in available_choices(files, omitted)["cores"]}
    for profile, aliases in (manifest.get("core_names") or {}).items():
        names[profile] = profile
        for alias in aliases:
            names.setdefault(alias, profile)
    return names


def _print_emulators(plat: str, manifest: dict, files: list[dict], omitted: list[dict]) -> None:
    """What --emulator accepts for a platform, one name per line."""
    names = emulator_names(manifest, files, omitted)
    if not names:
        print(f"  {plat} records no emulators")
        return
    width = min(max(len(name) for name in names), 40)
    for name in sorted(names):
        profile = names[name]
        print(f"  {name:<{width}}  {'' if profile == name else 'same as ' + profile}".rstrip())


GAMES_REQUIRED_WORDS = "only what the games need to start"


class GamesChoice:
    """The line menu's choice of what the games of the card need, all of it
    or only what they cannot start without (required)."""

    def __init__(self, plan: GamesPlan, required: bool = False) -> None:
        self.plan = plan
        self.required = required

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, GamesChoice) and other.plan is self.plan
                and other.required == self.required)

    def __hash__(self) -> int:
        return hash((id(self.plan), self.required))

    def apply(self, files: list[dict], omitted: list[dict]) -> tuple[list[dict], list[dict]]:
        return self.plan.apply(files, omitted, self.required)

    def flags(self) -> list[tuple[str, str | None]]:
        folder = None if self.plan.card else str(self.plan.root)
        return [("--for-games", folder), *([("--required-only", None)] if self.required else [])]

    def words(self) -> str:
        """What the choice keeps, after a comma on the menu's head."""
        named = f"for the {_plural(len(self.plan.games), 'game')} {self.plan.where()}"
        return f"{named}, {GAMES_REQUIRED_WORDS}" if self.required else named


def _is_terminal(stream: TextIO) -> bool:
    isatty = getattr(stream, "isatty", None)
    try:
        return bool(isatty and isatty())
    except (OSError, ValueError):
        return False


TUI_MIN_COLS = 40


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - cell_width(text))


# Region names as a person writes them, where title case alone is wrong.
_REGION_TITLES = {"asia-ntsc": "Asia (NTSC)", "asia-pal": "Asia (PAL)",
                  "uk": "United Kingdom", WORLD_REGION: "World"}


def region_title(name: str) -> str:
    """north-america as North America, asia-ntsc as Asia (NTSC)."""
    return _REGION_TITLES.get(name) or " ".join(
        word.capitalize() for word in name.split("-"))


def cores_words(chosen: int, total: int) -> str:
    """The cores a run keeps, as the plan, Options and line mode say it:
    all cores, or 3 of 12 cores."""
    return "all cores" if chosen >= total else f"{chosen} of {total} cores"


def core_count_words(cores: list[str], base: list[str]) -> str:
    """cores_words for the cores named out of those the systems chosen
    offer: a core of another system counted toward "all cores", the run
    keeping none of the system's own."""
    return cores_words(len(set(cores) & set(base)), len(base))


def _nearest_folder(path: Path) -> Path:
    """The deepest folder on path that exists and can be looked at."""
    probe = path.absolute()
    while not _is_dir(probe) and probe.parent != probe:
        probe = probe.parent
    return probe


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
