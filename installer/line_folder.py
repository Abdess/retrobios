"""Line mode's folder question: the drives and folders offered, and the one typed."""
from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from installer.cards import (
    _SHARE_FOLDERS,
    _doubt_kinds,
    _mount_name,
    _mounted_cards,
    card_bound,
    card_system,
    setup_bios_folder,
    share_doubt,
)
from installer.console import _ask, _folder_answer, _numbers_hint, _quit, _typed_folder, fold_line
from installer.destination import (
    _last_name,
    _missing_dest,
    card_choice,
    card_install_dest,
    card_line,
    copy_source_refusal,
)
from installer.detect_os import _os_default_dests, card_title
from installer.from_folders import _read_from_folder, from_folder_problem
from installer.host_fs import _exists, _is_dir
from installer.invocation import _INVOCATION, Invocation
from installer.local_copies import plan_local_copies
from installer.offline import LOCAL
from installer.paths import shown_path
from installer.platforms import _name_key, display_name, normalize_platform
from installer.remote import INSTALLER_PAGE
from installer.setups import _built_in_dest, _card_word, _choose_platform, _default_dest, _setup_label, setup_folder
from installer.text import _names_and, screen_text


def _ask_from_folder(files: list[dict] | None = None, bios_path: Path | None = None) -> None:
    """A folder to copy from, asked at the menu: the screen offers it, the
    line menu had no way to it. What it holds of files is counted, as the
    screen's plan counts it: a folder holding none of them was kept, and
    the menu offered to install what it held."""
    # The drives mounted here, numbered as the screen's copy browser lists
    # them, the card being installed to left out: line mode listed none, and
    # took q for a folder named q.
    drives = [mount for mount in _mounted_cards() if not copy_source_refusal(mount, bios_path)]
    if drives:
        print("\nCopy from:")
        for number, mount in enumerate(drives, 1):
            print(f"  {number}) {card_line(mount)}")
    count = "" if not drives else "1, " if len(drives) == 1 else f"a number from 1 to {len(drives)}, "
    # A number out of range, said as one: "2" was read as the folder ./2.
    usage = f"  Type {count}a folder, or Enter."
    while True:
        raw = _folder_answer(f"Folder, old card or ZIP to copy from{_numbers_hint(len(drives))} "
                             "(Enter to go back, q to quit): ", usage, True, len(drives))
        if raw is None:
            return
        if raw.isdigit() and 1 <= int(raw) <= len(drives):
            label = str(drives[int(raw) - 1])
        else:
            label = os.path.normpath(str(_typed_folder(raw).absolute()))
        refused = copy_source_refusal(Path(label), bios_path)
        if refused:
            print(f"  {refused}")
            continue
        problem = from_folder_problem(label)
        if problem is not None:
            print(f"  {screen_text(shown_path(label))} {problem[1]}.")
            continue
        index = _read_from_folder(label)
        name = _last_name(label)
        held = len(plan_local_copies(files, bios_path, None, [index])) \
            if files and bios_path is not None else -1
        if held == 0:
            LOCAL.folders.remove(index)
            print(f"  {name} holds none of these files.")
            return
        if files and held > 0:
            print(f"  {held} of {len(files)} found in {name}.")
        _INVOCATION.options.append(("--from", label))
        return


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
    numbers = _numbers_hint(len(targets))
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
