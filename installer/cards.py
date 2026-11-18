"""Cards and folders chosen as the destination, and why one is refused."""
from __future__ import annotations

import os
import sys
from pathlib import Path, PurePosixPath
from typing import NamedTuple, NoReturn

from installer.constants import CARD_MARKER, CARD_PLATFORMS
from installer.cores import did_you_mean, info_dirs, info_firmware, normalize_platform, refuse_name, unknown_cores
from installer.detect_os import _DETECTED_OS, card_title, detect_os, os_conflict
from installer.embedded import (
    _EMBEDDED_RULES,
    _GAMES_PART_CARDS,
    _SHARE_FOLDERS,
    CardSetup,
    _a,
    _built_on,
    _card_boundary,
    _card_matches,
    _doubt_kinds,
    _mount_name,
    _mount_points,
    _mounted_cards,
    _name_key,
    card_bound,
    card_platform,
    card_setup,
    card_system,
    display_name,
    drive_kind,
    share_doubt,
    share_drive,
    shown_path,
)
from installer.events import EVENTS
from installer.from_folders import _read_from_folder, from_folder_problem, plan_local_copies
from installer.invocation import _INVOCATION
from installer.local_files import closed_folder_words
from installer.offline import LOCAL
from installer.platform_choice import _choose_platform, drive_example
from installer.probe import _exists, _is_dir, closed_folder
from installer.prompt import _ask, _names_and, _quit, _typed_folder
from installer.setups import _setup_label, found_setups
from installer.terminal import detail
from installer.text import _plural, screen_text


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
    numbers = "" if not drives else " or 1" if len(drives) == 1 else f" or 1 to {len(drives)}"
    while True:
        raw = _ask(f"Folder, old card or ZIP to copy from{numbers} (Enter to go back, "
                   "q to quit): ").strip()
        if not raw:
            return
        if raw.lower() == "q":
            _quit()
        if raw.isdigit() and 1 <= int(raw) <= len(drives):
            label = str(drives[int(raw) - 1])
        elif raw.isdigit() and drives and not _is_dir(_typed_folder(raw)):
            # A number out of range, said as one: "2" was read as the folder
            # ./2.
            count = "1" if len(drives) == 1 else f"a number from 1 to {len(drives)}"
            print(f"  Type {count}, a folder, or Enter.")
            continue
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


def _refuse_closed(dest: Path, named: str) -> None:
    """End the run, with its name, on a folder above dest this user cannot
    open."""
    closed = closed_folder(dest)
    if closed is None:
        return
    message = closed_folder_words(dest, closed)
    EVENTS.emit("error", stage="dest", reason="unreadable", platform="", message=message)
    print(f"Error: {screen_text(message)}. Give this user access to it, run as "
          f"its owner, or choose another folder than the one {named}.",
          file=sys.stderr)
    sys.exit(1)


def _refuse_file(dest: Path, named: str) -> None:
    """End the run on a BIOS folder that is a file, or lies under one.

    mkdir then failed on EEXIST or ENOTDIR, and the run blamed permissions
    and offered sudo, which fails the same way.
    """
    for folder in (dest, *dest.parents):
        if _exists(folder):
            break
    else:
        return
    if _is_dir(folder):
        return
    where = (f"{shown_path(dest)} is a file, not a folder" if folder == dest
             else f"{shown_path(dest)} cannot be a folder: {shown_path(folder)} is a file")
    EVENTS.emit("error", stage="dest", reason="not_a_folder", platform="", message=where)
    print(f"Error: {screen_text(where)}. Name the folder the BIOS files go in, not "
          f"the file {named}.", file=sys.stderr)
    sys.exit(1)


def _missing_dest(dest: Path, ask: bool, named: str = "named with --dest",
                  again: bool = False) -> bool:
    """Say that a --dest folder does not exist before anything goes there.

    A typo (~/.config/retroarh/system) was created with every missing
    parent, filled, and reported done in a folder no platform reads, and
    --check said only "0/7 present". One missing level is a BIOS folder not
    made yet and is created. Several make a path that may be mistyped:
    at a terminal the run asks first, and the answer defaults to no. A
    folder above it this user cannot open ends the run with its name.
    With again, no returns False, for the folder to be asked again: no to
    a card's folder ended the run where it meant "not that card".
    """
    _refuse_closed(dest, named)
    _refuse_file(dest, named)
    if dest.exists():
        return True
    nearest = dest.absolute()
    while not nearest.exists() and nearest.parent != nearest:
        nearest = nearest.parent
    missing = len(dest.absolute().relative_to(nearest).parts)
    # Said where it comes before a question: elsewhere the folder is made.
    (print if missing > 1 and ask else detail)(
        f"  {shown_path(dest)} does not exist. The nearest folder that does: "
        f"{shown_path(nearest)}")
    if missing > 1 and ask:
        answer = _ask(f"  Create {_plural(missing, 'folder')} under {shown_path(nearest)}? [y/N] ")
        if not answer.strip().lower().startswith("y"):
            if again:
                print("  Not created.")
                return False
            print(f"  Nothing installed. Check the folder {named}, then run "
                  "the command again.")
            sys.exit(2)
    return True


def _check_cores_dir(folder: Path) -> None:
    """Refuse a --cores-dir that cannot be listed, saying why: a typo
    (core/ for cores/) or a closed folder read as an empty one, and the
    run said "none in" and asked for the --cores-dir it was given."""
    try:
        with os.scandir(folder):
            return
    except FileNotFoundError:
        why = "does not exist"
    except NotADirectoryError:
        why = "is not a folder"
    except PermissionError as exc:
        closed = closed_folder(folder)
        why = (f"cannot be opened by this user ({exc.strerror or exc})"
               if closed is None or closed[0] == folder
               else f"cannot be opened: {closed_folder_words(folder, closed)}")
    except OSError as exc:
        why = f"could not be read ({exc.strerror or exc})"
    print(f"Error: --cores-dir {screen_text(str(folder))} {why}.", file=sys.stderr)
    print("  Name the folder RetroArch loads cores from (libretro_directory in "
          "retroarch.cfg, cores/ beside RetroArch by default).", file=sys.stderr)
    sys.exit(1)


def _unprofiled_cores_firmware(
    plat: str, bios_path: Path, manifest: dict, found: list[str], searched: list[Path],
) -> list[str]:
    """What the installed cores the list has no profile for declare, each said.

    Such a core reads systems the list cannot name, and narrowing to the
    installed cores dropped its BIOS without a word (issue 87, parallel_dc
    before its profile). Its .info is what RetroArch itself checks, so the
    files it declares are kept. A core without one is named.
    """
    unknown = unknown_cores(manifest, found)
    if not unknown:
        return []
    dirs = info_dirs(plat, bios_path, searched)
    dests: list[str] = []
    for core in unknown:
        declared = info_firmware(dirs, core)
        if declared is None:
            message = (f"{core}: a core this list does not know, with no .info to read: "
                       "its files may be missing. Run without --installed-cores "
                       "to install every file.")
        else:
            message = (f"{core}: a core this list does not know, "
                       f"{_plural(len(declared), 'file')} its .info declares kept")
        print(f"  {message}")
        EVENTS.emit("unknown_core", platform=plat, core=core,
                    info=declared is not None, dests=declared or [], message=message)
        dests.extend(declared or [])
    return dests


def _no_core_found(plat: str, bios_path: Path, searched: list[Path]) -> None:
    """Refuse --installed-cores with no core, and say how to point at them.

    With no retroarch.cfg naming the folder as its system_directory, and
    none beside it, nothing names the cores folder: the run stopped on "no
    known directory" with no way forward.
    """
    where = (f"none in {', '.join(map(str, searched))}" if searched
             else f"no retroarch.cfg was found for {bios_path} to name their folder")
    print(f"Error: no installed core found for {display_name(plat)}: {where}.",
          file=sys.stderr)
    print("  Name the folder RetroArch loads cores from (libretro_directory in "
          "retroarch.cfg, cores/ beside RetroArch by default):", file=sys.stderr)
    command = _INVOCATION.command(plat, bios_path, without=("--installed-cores", "--cores-dir"))
    print(f"    {command} --cores-dir <cores folder>", file=sys.stderr)
    print("  Or run it without --installed-cores to install every file.", file=sys.stderr)
    sys.exit(1)


def doubt_cards(plat: str) -> list[Path]:
    """The mounted drives whose files fit plat and another system."""
    return [mount for mount in _mounted_cards() if plat in share_doubt(mount)[0]]


def _ends_with(path: Path, relative: str) -> bool:
    """Whether path's last folders are relative's, compared folder by folder
    and without case: NOTMUOS/bios does not end with MUOS/bios."""
    tail = [part.casefold() for part in PurePosixPath(relative).parts]
    parts = [part.casefold() for part in path.parts]
    return len(parts) >= len(tail) and parts[len(parts) - len(tail):] == tail


class CardChoice(NamedTuple):
    """Where the files of a folder named for a card go, and what is said: a
    note, or why the folder is not the card of the system named."""

    plat: str
    folder: Path
    note: str = ""
    # Why the folder is not the card, with its path, and what was looked
    # for on it. short says it without the path, for a 40-column screen.
    refused: str = ""
    detail: str = ""
    short: str = ""
    # The system's folder below its card.
    below: str = ""
    # The card's root, when the folder refused lies inside it.
    root: Path | None = None
    # The card found and where its files go, said where nothing else names
    # the folder (line mode): the screen's plan names it.
    found: str = ""
    # The system whose card the folder refused is, when one is.
    other: str = ""


def card_where(name: str, below: str) -> str:
    """Where on its card a system keeps its BIOS files, in words."""
    if below:
        return f"on its SD card, in its {below} folder"
    if name in _GAMES_PART_CARDS:
        # Its card shows two drives on a computer: "the root of its SD
        # card" named neither.
        return "on the games part of its SD card"
    return "at the root of its SD card"


def shown_bios_folder(bios_path: Path, files: list[dict]) -> Path:
    """The BIOS folder a plan names: the bios folder nearly every file of
    the list goes below (AmberELEC writes bios/ on its games part, and two
    Neo Geo archives beside it), the folder given else. The plan named the
    card's games part, then listed files under bios/."""
    tops = [PurePosixPath(str(entry.get("dest", ""))).parts[:1] for entry in files
            if entry.get("root") != "save"]
    under = [top[0] for top in tops if top and top[0].casefold() == "bios"]
    if len(tops) > 1 and len(under) * 10 >= len(tops) * 9:
        return bios_path / under[0]
    return bios_path


def _card_is(setup: CardSetup, card: Path, above: bool = False) -> tuple[str, str]:
    """("own", name) when the files on card say it runs setup's system,
    ("other", names) when they name another one, ("unknown", "") when they
    name none. A MinUI card for NextUI's list is its own: one layout. above
    is for a folder above the one named (_card_matches)."""
    family = card_platform(card)
    if family:
        return ("own" if setup.plat in CARD_PLATFORMS else "other"), display_name(family)
    names = sorted({rule.name for rule in _card_matches(card, above)})
    if setup.name in names or _built_on(setup.name) in names:
        # dArkOS writes ArkOS's games part: an ArkOS card is its own.
        return "own", setup.name
    share = share_drive(card)
    if not names and share and not (share == "batocera" and setup.name == "KNULLI"):
        # A Recalbox share is no KNULLI card not started yet. A Batocera
        # one may be: KNULLI writes the same batocera.conf, and a card
        # older than its about.info has nothing else (_unknown_card_note).
        return "other", display_name(share)
    return ("other", " and ".join(names)) if names else ("unknown", "")


def _not_the_card(setup: CardSetup, folder: Path, card: Path, other: str) -> CardChoice:
    """folder refused for setup: card, its root, is another system's card
    (other names it) or names no system at all. The detail names what is
    looked for on the card: the help's "says more" said the refusal again."""
    name, shown = setup.name, shown_path(card)
    marker = (CARD_MARKER if setup.plat in CARD_PLATFORMS
              else setup.rules[0].values[0].split("/")[0] if setup.rules else "")
    detail = f"{name} keeps {marker} at the root of its card" if marker else ""
    games = [rule for rule in setup.rules if rule.method == "games_part"]
    if games:
        # The file the rule reads, never its first folder: AmberELEC's card
        # holds a bezels folder too, and EmuELEC's refusal named it as the
        # mark of an EmuELEC card.
        held = " or ".join(dict.fromkeys(_names_and(list(rule.values)) for rule in games))
        where = ("on the games part of its card" if setup.name in _GAMES_PART_CARDS
                 else "on its card")
        detail = f"{name} keeps {held} beside bios {where}"
    if " and " in other:
        return CardChoice(setup.plat, folder, refused=f"{shown} holds the files of {other}, "
                          f"not of {name}", detail=detail,
                          short=f"That card holds {other} files.", below=setup.below)
    if other:
        kind = "SHARE drive" if share_drive(card) else "card"
        return CardChoice(setup.plat, folder, refused=f"{shown} is {_a(other)} {kind}, not "
                          f"{_a(name)} card", detail=detail, short=f"That is {_a(other)} {kind}, "
                          f"not {_a(name)} card.", below=setup.below, other=other)
    return CardChoice(setup.plat, folder, refused=f"{shown} is not {_a(name)} SD card: no "
                      f"{name} files on it", detail=detail,
                      short=f"Not {_a(name)} SD card: no {name} files on it.",
                      below=setup.below)


def _refusal_words(choice: CardChoice, setup: CardSetup) -> str:
    """Why a card typed or numbered in line mode is refused, and what to do:
    another system's card is the top folder of a card, only not this one."""
    detail = f" {choice.detail}." if choice.detail else ""
    if choice.other:
        return (f"{choice.refused}.{detail} Insert the {setup.name} card, or choose "
                f"{choice.other} for that one.")
    if choice.root is not None:
        return f"{choice.refused}.{detail} Type its root: {shown_path(choice.root)}"
    return f"{choice.refused}.{detail} Type the top folder of the {setup.name} card."


def _dest_refusal_words(choice: CardChoice, setup: CardSetup | None) -> str:
    """Why a --dest is not the card of the system named, and the one remedy
    that works: "<card>/bios" was offered for a ROCKNIX card named for
    KNULLI, and for a blank stick named for Onion, both refused the same."""
    detail = f" {choice.detail}." if choice.detail else ""
    name = setup.name if setup else display_name(choice.plat)
    if choice.other and choice.plat in _SHARE_FOLDERS and setup is None:
        return (f"{choice.refused}.{detail} Connect the {name} SHARE drive, or name that "
                f"drive's own system: --platform {_name_key(choice.other)}")
    if choice.other:
        return (f"{choice.refused}.{detail} Insert the {name} card, or name that "
                f"card's own system: --platform {_name_key(choice.other)}")
    if choice.root is not None:
        return f"{choice.refused}.{detail} Name the card's root: --dest {shown_path(choice.root)}"
    if choice.plat in _SHARE_FOLDERS and setup is None:
        return (f"{choice.refused}.{detail} Connect the {name} SHARE drive and name its "
                "root with --dest")
    return f"{choice.refused}.{detail} Name the top folder of the {name} card with --dest"


def _unknown_card_note(setup: CardSetup, card: Path, folder: Path) -> str:
    """Said when a card nothing names is taken for setup's."""
    if setup.name in _GAMES_PART_CARDS:
        # Its list writes bios/ below the games part: the plan names that.
        folder = folder / "bios"
    plats, why = share_doubt(card)
    if setup.name == "KNULLI" and share_drive(card) == "batocera":
        plats, why = ((setup.plat,), "it holds the system/batocera.conf Batocera and KNULLI "
                      "both write, and no about.info naming KNULLI")
    if setup.plat in plats:
        return (f"{shown_path(card)} could be another system's: {why}. Taken as "
                f"{setup.name}'s, as named: the files go to {shown_path(folder)}")
    if setup.fresh:
        return (f"Nothing on {shown_path(card)} says it is {_a(setup.name)} card yet (not started "
                f"once?): the files go to {shown_path(folder)}")
    return (f"RetroBIOS cannot tell {_a(setup.name)} card by its files: the files go "
            f"to {shown_path(folder)}")


def _card_and_below(setup: CardSetup, path: Path) -> tuple[Path, bool]:
    """(card root, whether path is the BIOS folder below it) for a folder
    named for setup: its BIOS folder named outright stands for its card.

    A folder whose own files name a system is that card, whatever its
    name: an Onion card mounted as BIOS was read as a BIOS folder, its
    parent checked as the card and refused."""
    below = setup.below
    if (not below and setup.name in _GAMES_PART_CARDS and path.name.casefold() == "bios"
            and not _is_dir(path / "bios") and _card_is(setup, path)[0] == "unknown"
            and not _card_boundary(path)):
        # Its list writes bios/ below the games part's root: its BIOS
        # folder named got bios/bios, or was refused as inside the card.
        return path.parent, True
    depth = len(PurePosixPath(below).parts)
    if (below and _ends_with(path, below) and _card_is(setup, path)[0] == "unknown"
            and not any(_card_boundary(folder)
                        for folder in [path, *list(path.parents)[:depth - 1]])):
        return path.parents[depth - 1], True
    return path, False


def _card_above(setup: CardSetup, card: Path) -> tuple[str, str, Path] | None:
    """(kind, name, root) of the card a folder nothing names lies inside,
    when one of the folders above it, up to the drive's mount point, is a
    card: ROCKNIX's roms/bios named for KNULLI read as a KNULLI card not
    started once. Every folder up to that mount point is read: three at
    most took MUOS/a/b/c/d for a KNULLI card."""
    folder = card.absolute()
    points = _mount_points()
    for parent in folder.parents:
        if _card_boundary(folder, points):
            return None
        kind, what = _card_is(setup, parent, above=True)
        if kind != "unknown":
            return kind, what, parent
        folder = parent
    return None


def _list_card_choice(plat: str, dest: Path) -> CardChoice:
    """card_choice for a list named, not a card: a card's root it recognises
    is read as that card, with the list's own system, and another system's
    card is said, the user having named both."""
    found = card_system(dest)
    if found and (not plat or found[0] == plat) and found[1] != dest:
        if drive_kind(found) != "card":
            # Its root typed, the drive itself: the files go to its bios.
            return CardChoice(found[0], found[1],
                              found=f"{found[2]} SHARE drive: its BIOS folder is "
                              f"{shown_path(found[1])}")
        return CardChoice(found[0], found[1],
                          found=f"{card_title(found[2])} card: {display_name(found[0])} files, "
                          f"in {shown_path(found[1])}")
    if found and plat in _SHARE_FOLDERS and found[0] != plat and drive_kind(found) != "card":
        # Another system's drive, never filled beside its own files.
        shown = shown_path(dest)
        kind = drive_kind(found)
        return CardChoice(plat, dest, refused=f"{shown} is {_a(found[2])} {kind}, not "
                          f"{_a(display_name(plat))} SHARE drive",
                          short=f"That is {_a(found[2])} {kind}.", other=found[2])
    if found and plat and found[0] != plat:
        shown = shown_path(dest)
        return CardChoice(plat, dest, f"Note: {shown} is {_a(card_title(found[2]))} "
                          f"{drive_kind(found)}, "
                          "which reads "
                          f"the {display_name(found[0])} file list in {shown_path(found[1])}: "
                          f"--platform {_name_key(found[2])} --dest {shown}. The "
                          f"{display_name(plat)} list goes into it as named.")
    doubt, why = ((), "") if found else share_doubt(dest)
    if plat in doubt:
        # Named by the user, a drive its files cannot name is taken for the
        # system named, and the doubt is said.
        folder = dest / "bios"
        return CardChoice(plat, folder, f"Note: {shown_path(dest)} could be another system's: "
                          f"{why}. Taken as {display_name(plat)}'s, as named: the files go "
                          f"to {shown_path(folder)}")
    if doubt and plat in _SHARE_FOLDERS:
        name = display_name(plat)
        return CardChoice(plat, dest, refused=f"{shown_path(dest)} could be "
                          f"{_doubt_kinds(doubt)}, not {_a(name)} SHARE drive", detail=why,
                          short=f"That could be {_doubt_kinds(doubt)}.")
    matched = [] if found else _card_matches(dest)
    if len({(match.manifest, match.bios) for match in matched}) > 1:
        names = " and ".join(sorted({match.name for match in matched}))
        return CardChoice(plat, dest, f"{screen_text(str(dest))} holds the files of "
                          f"{names}: installing into it as named. Name the card's BIOS "
                          "folder with --dest to write there.")
    if plat == "retrodeck" and dest.name.lower() == "bios" and not _is_dir(dest / "bios"):
        # RetroDECK's list writes bios/, roms/ and the rest below its own
        # folder: its BIOS folder, which --help asks for, got bios/bios.
        return CardChoice(plat, dest.parent, f"{shown_path(dest)} is RetroDECK's BIOS "
                          f"folder: the files go below {shown_path(dest.parent)}, the "
                          "RetroDECK folder holding it")
    return CardChoice(plat, dest)


def card_choice(named: str, plat: str, root: Path) -> CardChoice:
    """The file list and BIOS folder for a folder named for what --platform
    or a row of the setup list names, or why it is not that system's card.

    The one reading of a card's root, wherever it is named: --dest, the
    setup list with --dest, a card listed, browsed or typed on the folder
    screen, a card numbered or typed in line mode. Two readings gave a blank
    stick named for KNULLI two folders, the root with --dest and bios below
    it typed. The card's root is where the user points, its BIOS folder is
    below it: `--platform muos --dest /media/me/SD1` wrote to the root,
    which muOS never reads. A card of another system is refused for every
    card system: KNULLI took a muOS card and wrote its layout into it. A
    folder nothing names is refused for a system whose card always carries
    its files (the MinUI family among them), and gets the system's folder
    and a note for one that fills its card on first start or leaves no
    file there that names it. A folder that does not exist is refused: a
    typo four folders deep was created and filled.
    """
    setup = card_setup(named, plat)
    if setup is None:
        return _list_card_choice(plat, root)
    # A folder its device reads (/run/muos/storage/bios): on the device.
    if root.as_posix() in {rule.bios for rule in _EMBEDDED_RULES if rule.name == setup.name}:
        return CardChoice(plat, root)
    card, inside = _card_and_below(setup, root)
    if not _is_dir(card):
        return CardChoice(plat, root, refused=f"{shown_path(card)} does not exist, or is not "
                          "a folder", short="That folder does not exist.", below=setup.below)
    if plat in CARD_PLATFORMS:
        above = card_root_above(root)
        if above:
            name = _a(display_name(above[0]))
            return CardChoice(plat, root, refused=f"{shown_path(root)} is inside {name} card, "
                              f"whose root is {shown_path(above[1])}",
                              short=f"That is inside {name} card.", root=above[1])
    kind, what = _card_is(setup, card)
    if kind == "unknown":
        holder = _card_above(setup, card)
        if holder and holder[0] == "other":
            return _not_the_card(setup, root, holder[2], holder[1])
        if holder:
            return CardChoice(plat, root, refused=f"{shown_path(root)} is inside the "
                              f"{setup.name} card, whose root is {shown_path(holder[2])}",
                              short=f"That is inside {_a(setup.name)} card.",
                              below=setup.below, root=holder[2])
    folder = (card if inside and not setup.below
              else root if inside or not setup.below else card / setup.below)
    if kind == "other":
        return _not_the_card(setup, root, card, what)
    if kind == "own":
        note = ("" if what == setup.name else f"Note: this card holds {what} "
                f"({CARD_MARKER}), and the {display_name(plat)} file list was asked for.")
        found = (f"{setup.name} card: {display_name(plat)} files, in {shown_path(folder)}"
                 if folder != root else "")
        return CardChoice(plat, folder, note, below=setup.below, found=found)
    if not setup.fresh and setup.known():
        return _not_the_card(setup, root, card, "")
    return CardChoice(plat, folder, _unknown_card_note(setup, card, folder),
                      below=setup.below)


def card_dest(named: str, plat: str, dest: Path) -> tuple[str, Path]:
    """The file list and folder for a --dest that names a handheld's card,
    the run ended on a folder that is not the card of the system named."""
    choice = card_choice(named, plat, dest)
    if choice.refused:
        message = _dest_refusal_words(choice, card_setup(named, plat))
        # A script reading the stream learned code 1 and no reason.
        EVENTS.emit("error", stage="detect", reason="not_found", platform=choice.plat,
                    message=message)
        print(f"Error: {message}", file=sys.stderr)
        sys.exit(1)
    for line in (choice.found, choice.note):
        if line:
            print(f"  {line}")
    system = card_bound(named, plat)
    if system is not None:
        _DETECTED_OS.setdefault((choice.plat, choice.folder), system[0])
    return choice.plat, choice.folder


def card_root_above(dest: Path) -> tuple[str, Path] | None:
    """(platform, root) of the MinUI-family card dest is inside, when dest is
    a folder below its root and not the root."""
    if card_platform(dest) is not None:
        return None
    for parent in list(dest.absolute().parents)[:2]:
        holder = card_platform(parent)
        if holder:
            return holder, parent
    return None


def mounted_cards_of(system: str, plat: str) -> list[Path]:
    """The mounted drives offered as system's card: those whose own files
    say they run it, or, for a system no file on its card names, those no
    other system claims."""
    setup = card_setup(system, plat)
    if setup is None:
        return []
    if plat in CARD_PLATFORMS:
        return [mount for mount in _mounted_cards() if card_platform(mount) == plat]
    wanted = "own" if setup.known() else "unknown"
    return [mount for mount in _mounted_cards() if _card_is(setup, mount)[0] == wanted]


def blank_cards_of(system: str, plat: str) -> list[Path]:
    """The mounted drives no system claims, offered too for a system that
    fills its card when it first starts (KNULLI, ROCKNIX): such a card is
    blank until then. Listed after its own cards, never taken by itself.
    The screen's browser listed a blank stick for KNULLI, line mode none."""
    setup = card_setup(system, plat)
    if setup is None or not setup.fresh or not setup.known():
        return []
    return [mount for mount in _mounted_cards() if _card_is(setup, mount)[0] == "unknown"]


def card_line(mount: Path) -> str:
    """A mounted drive in the line questions, named as the screen names it,
    its path after unless the name is the path: ONION (Onion card,
    /media/me/ONION), D: (Onion card) under WSL, where /mnt/d was printed."""
    name, shown = _mount_name(mount), shown_path(mount)
    if shown.rstrip("\\") == name:
        return f"{name} ({_card_what(mount)})"
    return f"{name} ({_card_what(mount)}, {shown})"


def card_install_dest(named: str, plat: str, interactive: bool, ask: bool = True) -> Path:
    """The folder for a card-bound system named without --dest, on a machine
    that is not the device.

    One mounted card that runs it is taken. At a terminal the card's root is
    asked for, never this machine's own folder, and asked again until it is
    that card. Only that system's cards are listed, as on the screen: a muOS
    card listed for Onion was taken, and the run became a muOS install.
    Without questions the run stops on the --dest that names the card. ask
    is whether creating several missing folders is asked first, as it is
    for --dest, and no to it asks for the card again.
    """
    setup = card_setup(named, plat) or CardSetup(display_name(plat), plat, "")
    system = setup.name
    cards = mounted_cards_of(system, plat)
    if setup.known() and len(cards) == 1:
        dest = cards[0] / setup.below if setup.below else cards[0]
        print(f"  {system} card found at {_mount_name(cards[0])}, BIOS folder "
              f"{shown_path(dest)}")
        _DETECTED_OS.setdefault((plat, dest), system)
        return dest
    # Pasted, the name of a system in words is two arguments: its key is one.
    word = named.strip() if _name_key(named) == named.strip().lower() else _name_key(named)
    example = f"--platform {word or plat} --dest {drive_example(detect_os(), '<card>')}"
    blank = [mount for mount in blank_cards_of(system, plat) if mount not in cards]
    if setup.known() and len(cards) > 1:
        print(f"  {len(cards)} {system} cards are mounted: "
              + ", ".join(_mount_name(card) for card in cards) + ".", file=sys.stderr)
    if not interactive:
        EVENTS.emit("error", stage="detect", reason="not_found", platform=plat,
                    message=f"{system} keeps its BIOS files on its SD card, and no "
                    "card was named with --dest")
        print(f"  {system} keeps its BIOS files on its SD card, not on this machine. "
              f"Mount it and give its root with --dest: {example}", file=sys.stderr)
        sys.exit(1)
    print(f"  {system} keeps its BIOS files {card_where(system, setup.below)}, not on "
          "this machine. "
          + ("" if setup.known() else
             f"RetroBIOS cannot tell {_a(system)} card by its files. ")
          + ("Type its number or its top folder:" if cards
             else _blank_offer(system, len(blank)) if blank
             else "Mount the card, then type its top folder."))
    listed = _list_cards(cards, blank)
    while True:
        numbers = ("" if not listed else " or 1" if len(listed) == 1
                   else f" or 1 to {len(listed)}")
        # Enter looks again, as the screen's Look again does: a card
        # inserted after the question was never found.
        raw = _ask(f"Card root{numbers}, Enter to look again, q to quit: ")
        if not raw:
            listed = _list_cards(mounted_cards_of(system, plat), blank_cards_of(system, plat),
                                 f"Still no {system} card is mounted.")
            continue
        if raw.lower() == "q":
            _quit()
        chosen = raw.isdigit() and 1 <= int(raw) <= len(listed)
        if raw.isdigit() and not chosen and not _is_dir(_typed_folder(raw)):
            print(f"  Type a number from 1 to {len(listed)}, a folder, Enter to look "
                  "again, or q to quit." if listed else
                  "  Type the card's top folder, Enter to look again, or q to quit.")
            continue
        root = listed[int(raw) - 1] if chosen else _typed_folder(raw).absolute()
        choice = card_choice(system, plat, root)
        if choice.refused:
            print(f"  {_refusal_words(choice, setup)}")
            continue
        # The card picked, echoed: the run went on to "RetroArch: 23 files"
        # with no word of which card. A card nothing names has its note,
        # which names the folder: said once.
        print(f"  {choice.note}" if choice.note else
              f"  {system} card {_mount_name(root)}, BIOS folder {shown_path(choice.folder)}")
        _DETECTED_OS.setdefault((choice.plat, choice.folder), system)
        if _missing_dest(choice.folder, ask, "typed", again=True):
            return choice.folder


def _blank_offer(system: str, count: int) -> str:
    """What line mode says above drives no file names, numbered for a
    system whose card they may be: "Mount the card" was said of a card in
    the reader."""
    if count == 1:
        return f"Type 1 if it is the {system} card, or type its top folder."
    return f"Type its number if one is the {system} card, or type its top folder."


def _list_cards(cards: list[Path], blank: list[Path], none: str = "") -> list[Path]:
    """Number a system's cards, then the blank drives it may take (the
    screen's rows), and return them in that order. none is said when
    there is none."""
    listed = cards + [mount for mount in blank if mount not in cards]
    for index, mount in enumerate(listed, 1):
        print(f"    {index}) {card_line(mount)}")
    if not listed and none:
        print(f"  {none}")
    return listed


def dest_default(setups: list) -> str:
    """The setup a folder named without a system is offered for, on the
    screen and in line mode: the one found here, else RetroArch."""
    found = list(dict.fromkeys(setup[0] for setup in setups))
    return found[0] if len(found) == 1 else "retroarch"


def _platform_for_dest(os_type: str, dest: Path, interactive: bool) -> tuple[str, Path]:
    """The file list for a --dest given without --platform.

    A folder says where, not for whom, and a card is often prepared on a PC
    for a console: --dest alone installed RetroArch's names and layout into
    a Batocera share. The platforms detected here are the evidence. At a
    terminal the user picks, Enter taking the one found. Otherwise the one
    found is used, RetroArch when none is, and several found are refused.
    """
    card = card_platform(dest)
    if card:
        print(f"  File list: {display_name(card)} (the card's {CARD_MARKER}). "
              f"Same choice without detection: --platform {card}")
        return card, dest
    print("Looking for setups here...")
    if interactive:
        # The screen's list for --dest: the setups found here first, in its
        # order and with its default. Without them the cards came after
        # RetroArch, and Onion was 19 here and 29 on the screen.
        setups, mounted = found_setups(os_type)
        default = dest_default(setups)
    while interactive:
        named = _choose_platform(f"Which platform's files go to {shown_path(dest)}?",
                                 default, setups, mounted)
        plat = normalize_platform(named, say=False)
        # A system that runs from its card checks dest as --platform does.
        choice = card_choice(named, plat, dest)
        if choice.refused:
            detail = f" {choice.detail}." if choice.detail else ""
            print(f"  {choice.refused}.{detail} Choose another.")
            continue
        if choice.note:
            print(f"  {choice.note}")
        print(f"  File list: {display_name(plat)}. Same choice without questions: "
              f"--platform {_name_key(named) if named != plat else plat}")
        return plat, choice.folder
    # The setups the screen and line mode find, cards mounted here included.
    found = list(dict.fromkeys(name for name, _path, _label in found_setups(os_type)[0]))
    default = found[0] if len(found) == 1 else "" if found else "retroarch"
    if not default:
        print(f"Error: {' and '.join(display_name(n) for n in found)} found here. "
              f"Name the platform {dest} is for with --platform.", file=sys.stderr)
        sys.exit(1)
    why = "the platform found here" if found else "nothing was detected here"
    print(f"  File list: {display_name(default)} ({why}). For another platform's "
          "list, add --platform (--list-platforms names them).")
    return default, dest


def _several_found(platforms: list[tuple[str, Path]], setups: list) -> None:
    """Stop a run without questions that found more than one setup, each
    named with the options that choose it."""
    labels = {(name, path): label for name, path, label in setups}
    shown = [(labels.get((name, path)) or _setup_label(name, path), name, path)
             for name, path in platforms]
    conflict = os_conflict(platforms)
    lead = (f"{' and '.join(conflict)} are both detected here, and a machine runs one"
            if conflict else f"{len(shown)} setups were found here")
    message = (f"{lead}, and a run without questions installs for one: "
               + ", ".join(label for label, _n, _p in shown))
    EVENTS.emit("error", stage="detect", reason="conflict", platform="", message=message)
    print(f"Error: {message}. Name the one to install for:", file=sys.stderr)
    for label, name, path in shown:
        print(f"  {label}: --platform {name} --dest {shown_path(path)}", file=sys.stderr)
    sys.exit(1)


def _unknown_target(target: str, plat: str, targets: dict, *after: str) -> NoReturn:
    if not targets:
        # No value can work: "unknown target" read as a typo of the board.
        refuse_name(plat, f"Error: {display_name(plat)} has no hardware targets: run again "
                    "without --target.", *after)
    refuse_name(plat, f"Error: unknown target '{target}' for {display_name(plat)}.",
                "  " + did_you_mean([target], sorted(targets), "--list-targets"), *after)


def _card_what(mount: Path) -> str:
    """What a mounted card is, as its own files say."""
    system = card_system(mount)
    return f"{card_title(system[2])} {drive_kind(system)}" if system else "card or drive"


def dest_drive(dest: Path | None) -> Path | None:
    """The mounted card or drive dest is on, None for none."""
    if dest is None:
        return None
    place = dest.absolute()
    return next((mount for mount in _mounted_cards()
                 if mount == place or mount in place.parents), None)


def copy_source_refusal(chosen: Path | None, dest: Path | None) -> str:
    """Why a folder cannot be copied from, "" when it can: the card being
    installed to, or the BIOS folder itself. The copy browser focused that
    card, and choosing it was taken without a word."""
    if chosen is None or dest is None:
        return ""
    place = chosen.absolute()
    if place == dest.absolute():
        return "That is the BIOS folder being installed to: choose the old card or a backup."
    if place == dest_drive(dest):
        return "That is the card being installed to: choose the old card or a backup."
    return ""


def _last_name(folder: str) -> str:
    """A folder or ZIP by its last name, a drive by itself (E:\\), a WSL
    path by the name Windows gives it (E:\\old is old, /mnt/e is E:\\)."""
    shown = shown_path(folder)
    if shown != str(folder):
        return shown.rstrip("\\").rsplit("\\", 1)[-1] + ("\\" if shown.endswith(":\\")
                                                            else "")
    return Path(folder).name or folder
