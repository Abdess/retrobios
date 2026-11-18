"""The command line: every option, its help and the epilog."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from installer.constants import INSTALLER_PAGE, RELEASE_REF
from installer.invocation import OFFLINE_VARIABLE, _INVOCATION, installer_id
from installer.local_files import BACKUP_DIR
from installer.text import format_size

# --pack writes the narrowed choice as a pack --from-pack reads: each file
# once by its SHA-1, at its destination (a file of another root under that
# root's name), each data tree at its place, and manifest.json carrying the
# list narrowed to the choice. For one zlib the bytes depend on the inputs
# alone: members in a fixed order, a fixed date and mode, one compression
# level set on each member. Another deflate gives other bytes for the same
# members (zlib-ng, which CPython 3.14 on Windows ships).
PACK_NAME_END = "_BIOS_Pack.zip"

MIN_PART_BYTES = 64 * 1024


def parse_part_size(text: str) -> int:
    """--split SIZE: bytes, or a number with K, M or G (powers of 1024)."""
    match = re.fullmatch(r"\s*(\d+)\s*([KMG]?)(?:I?B)?\s*", text, re.IGNORECASE)
    if match is None:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a size: give bytes, or a number with K, M or G (1900M)")
    size = int(match[1]) * 1024 ** " KMG".index((match[2] or " ").upper())
    if size < MIN_PART_BYTES:
        raise argparse.ArgumentTypeError(
            f"a part of {format_size(size)} is too small: give {format_size(MIN_PART_BYTES)} "
            "or more")
    return size


def _help_epilog() -> str:
    """Examples in the form the run was started with, and where the rest is."""
    run = _INVOCATION.launcher()
    card = "E:\\bios" if _INVOCATION.powershell() else "/media/SHARE/bios"
    examples = (
        ("install for the platforms found here", run),
        ("prepare a card or a share for another device",
         f"{run} --platform batocera --dest {card}"),
        ("only some systems (names: --list-systems)",
         f"{run} --platform retroarch --system sony-playstation,nintendo-gba"),
        ("check what is installed, writing nothing", f"{run} --check"),
    )
    lines = ["examples:"]
    for what, command in examples:
        lines += [f"  {what}", f"    {command}"]
    lines += ["", f"Every option, the environment variables and the exit codes: {INSTALLER_PAGE}"]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """The options, in the order --help and wiki/installer.md list them
    (scripts/generate_installer_doc.py writes its table from this parser)."""
    parser = argparse.ArgumentParser(
        # Never the file's own name: install.ps1 runs a copy named
        # retrobios-install-<guid>.py, which usage and errors printed.
        prog="install.py",
        allow_abbrev=False,
        description="Download missing BIOS files for retrogaming emulators. "
                    "For questions line by line, as a screen reader reads them, "
                    "add --plain.",
        epilog=_help_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--platform",
        metavar="NAME",
        help="target platform (retroarch, batocera, emudeck, ...)",
    )
    parser.add_argument(
        "--dest",
        metavar="PATH",
        type=Path,
        help="BIOS folder to install into. Without --platform, the file list is "
             "the platform detected here, asked at a terminal, RetroArch's when "
             "nothing is detected",
    )
    parser.add_argument(
        "--target",
        metavar="NAME",
        help="hardware target for core filtering (switch, rpi4, ...). "
        "On AmberELEC, EmuELEC, Batocera, Recalbox, ROCKNIX, Lakka, KNULLI and RetroPie "
        "the board is read from the system",
    )
    parser.add_argument(
        "--every-board",
        action="store_true",
        help="install the files of every board, not only the detected one",
    )
    parser.add_argument(
        "--installed-cores",
        action="store_true",
        help="install only what the cores already installed read "
             "(RetroArch, Lakka, RetroPie)",
    )
    parser.add_argument(
        "--cores-dir",
        type=Path,
        metavar="PATH",
        help="the folder RetroArch loads its cores from, when it is not found "
             "(implies --installed-cores)",
    )
    parser.add_argument(
        "--save-dir",
        type=Path,
        metavar="PATH",
        help="the frontend's save directory (RetroArch: savefile_directory), "
             "for the files some cores read there (Azahar's keys and system "
             "data), when it is not found",
    )
    parser.add_argument(
        "--system",
        action="append",
        metavar="NAMES",
        help="install only these systems (repeat or comma-separate, see "
             "--list-systems)",
    )
    parser.add_argument(
        "--core",
        action="append",
        metavar="NAMES",
        help="keep only the extra files these cores load (see --list-cores)",
    )
    parser.add_argument(
        "--emulator",
        action="append",
        metavar="NAMES",
        help="install what these emulators read on the platform, as a pack "
             "built for them carries (names: --list-emulators)",
    )
    parser.add_argument(
        "--region",
        action="append",
        metavar="LIST",
        help="preferred regions, best first, e.g. us,eu,jp: keep one BIOS per "
             "region where a system has several",
    )
    parser.add_argument(
        "--for-games",
        nargs="?",
        const=True,
        type=Path,
        metavar="FOLDER",
        help="install only what the games on the card need: the systems of its "
             "game folders, one region where a game's content proves it, an "
             "arcade set's BIOS sets. FOLDER names a games folder (on a computer, "
             "one subfolder per system), else the card's own beside the BIOS folder",
    )
    parser.add_argument(
        "--required-only",
        action="store_true",
        help="with --for-games, only the files the games cannot start without",
    )
    parser.add_argument(
        "--all-files",
        action="store_true",
        help="install the whole list even when the card holds games. A run that "
             "asks nothing (--yes, --no-input, --events) otherwise installs only "
             "what the card's games need, the plan's first choice",
    )
    parser.add_argument(
        "--no-game-data",
        action="store_true",
        help="leave out game data (files a game reads, not firmware) and "
             "install the firmware only",
    )
    parser.add_argument(
        "--declared-only",
        action="store_true",
        help="keep only the files the platform's own list names, not the extra "
             "files cores load: --check then answers for the list the platform checks",
    )
    parser.add_argument(
        "--one-per-slot",
        action="store_true",
        help="keep one BIOS per console and region, the one the emulators' own "
             "search order ranks first (a slot no order decides keeps every file)",
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="with --emulator: the files each emulator's standalone build reads, "
             "where that build reads them",
    )
    parser.add_argument(
        "--source",
        choices=("full", "truth"),
        default="full",
        help="truth: only the files the emulator profiles prove a core reads "
             "(default full: the platform's list and what its cores read)",
    )
    parser.add_argument(
        "--find",
        metavar="HASH",
        help="install the file of the list with this sha1 or sha256, or md5 or "
             "crc32 where the list records them",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="with --find: print the matching files as JSON and install nothing",
    )
    parser.add_argument(
        "--list-systems",
        action="store_true",
        help="list a platform's systems with their file counts and exit",
    )
    parser.add_argument(
        "--list-cores",
        action="store_true",
        help="list the cores whose extra files a platform installs and exit",
    )
    parser.add_argument(
        "--list-emulators",
        action="store_true",
        help="list every name --emulator accepts for a platform and exit",
    )
    parser.add_argument(
        "--romm-firmware",
        metavar="TEMPLATE",
        help="RomM: where each platform's firmware goes in the library, as "
             "filesystem.structure.firmware in its config.yml (default: read "
             "from config.yml, else bios/{platform})",
    )
    parser.add_argument(
        "--no-input",
        action="store_true",
        help="never ask a question and fail where an answer is needed",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="check existing files without downloading",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be downloaded, and how much, without writing anything",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="do not ask before a large download, nor anything else (implies --no-input)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="print only errors and the final summary (implies --no-input)",
    )
    parser.add_argument(
        "--events",
        action="store_true",
        help="write the run as JSON events on stdout, one per line, and the "
             "usual text on stderr (implies --no-input)",
    )
    parser.add_argument(
        "--from",
        action="append",
        type=Path,
        metavar="FOLDER",
        help="copy the BIOS files found in FOLDER (an old SD card, a backup, a "
             "ZIP) instead of downloading them: every file recognised by its "
             "hash, never moved. Repeat for several folders",
    )
    parser.add_argument(
        "--from-pack",
        action="append",
        type=Path,
        metavar="PATH",
        help="install from a pack already downloaded: its ZIP, one of its parts "
             "(the others are found beside it) or the folder holding them. "
             "Makes no network request, and checks every file's hash",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="make no network request: --check, --from, --from-pack and --manifest "
             "work without one, and a file the run would download fails at once "
             f"({OFFLINE_VARIABLE}=1 does the same)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        metavar="FILE",
        help="read the file list from FILE (install/<platform>.json) instead "
             "of downloading it",
    )
    parser.add_argument(
        "--restore",
        type=Path,
        metavar="FOLDER",
        help=f"put back the files an earlier run replaced and kept in FOLDER "
             f"(a dated folder inside {BACKUP_DIR})",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="remove what the installer placed in the BIOS folder, as its install "
             "record proves it: every file, or those of --system, --core, --emulator "
             "or --file. A file changed since, added by hand, still needed by "
             "something kept, or that the collection cannot give again stays",
    )
    parser.add_argument(
        "--file",
        action="append",
        type=Path,
        metavar="PATH",
        help="with --remove, one file of the BIOS folder (its path there, or the "
             "full path). Repeat for several",
    )
    parser.add_argument(
        "--misplaced",
        action="store_true",
        help="with --remove, delete instead the copies left in the wrong place of the "
             "BIOS folder: each one whose bytes the installer placed where the cores "
             "read them. A place a list reads, or a setup of the folder recorded, stays",
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help=f"with --remove, move the files into a dated folder of {BACKUP_DIR} "
             "instead of deleting them, for --restore to put back",
    )
    parser.add_argument(
        "--backups",
        action="store_true",
        help="list the backups of the BIOS folder, newest first, and exit",
    )
    parser.add_argument(
        "--delete-backup",
        type=Path,
        metavar="FOLDER",
        help=f"delete one backup (a dated folder inside {BACKUP_DIR}) after one "
             "question, to free its space",
    )
    parser.add_argument(
        "--pack",
        type=Path,
        metavar="PATH",
        help=f"download the choice into a pack ZIP at PATH instead of a BIOS folder, for "
             f"another device or an install without the internet (--from-pack reads it). "
             f"A folder takes <Platform>{PACK_NAME_END}. The narrowing options apply, and "
             "--dry-run lists what the pack would hold",
    )
    parser.add_argument(
        "--split",
        type=parse_part_size,
        metavar="SIZE",
        help="with --pack, write parts of at most SIZE (1900M, 4G), each a whole ZIP. "
             "A pack that would pass 4 GiB on a FAT32 drive is split by itself",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="open the full-screen interface, which a keyboard or a controller "
             "drives. It opens by itself for an install at a terminal of 40x12 "
             "or more",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="ask the questions line by line instead of the full-screen "
             "interface, as a screen reader reads them (RETROBIOS_PLAIN=1 or "
             "ACCESSIBLE=1 do the same)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"retrobios installer {installer_id()} (ref {RELEASE_REF})",
        help="print the installer version and exit",
    )
    parser.add_argument(
        "--list-platforms",
        action="store_true",
        help="list detected platforms and exit",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="list available targets for a platform and exit",
    )
    parser.add_argument(
        "--jobs", "-j",
        metavar="N",
        type=int,
        default=8,
        help="parallel download threads (default: 8)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="verbose output",
    )
    parser.add_argument(
        "--standalone-copies",
        action="store_true",
        help="opt in to copies into detected standalone-emulator directories",
    )
    parser.add_argument(
        "--add-app",
        action="store_true",
        help="after the install, put the RetroBIOS app on the handheld card the BIOS "
             "folder is on (muOS, KNULLI, ROCKNIX), to check and update the BIOS "
             "files from the console later",
    )
    return parser
