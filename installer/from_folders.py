"""The local sources of a run: opening --from folders, the list and the pack, refusing a folder that cannot be one."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from installer.console import SAID_FAILED
from installer.events import EVENTS
from installer.invocation import DEFAULT_JOBS
from installer.offline import LOCAL, local_manifest_platform
from installer.pack_source import _PART_FILE, PackSource
from installer.paths import shown_path
from installer.platforms import display_name, normalize_platform
from installer.refusal import Refusal
from installer.safe_replace import unreadable_words
from installer.text import _plural, screen_text

from installer.folder_index import FolderIndex, MAX_SCANNED_FILES, PSEUDO_FOLDERS


def sources_line(
    folders: list[tuple[str, int]], fixed: int, downloaded: int, missing: int,
    fetched: str = "downloaded", shared: int = 0, wrong: int = 0, failed: int = 0,
) -> str:
    """Where the files of a run that copied some came from, in words:
    "38 files copied from E:\\, 4 downloaded, 2 still missing." A file found
    in the wrong place of the BIOS folder is "copied", as the plan says:
    "fixed" read as a wrong copy, of files that were missing. wrong counts
    the wrong copies left in place, apart from missing: "1 still missing"
    was said of a file --check counts as a wrong copy.
    failed counts the files a run tried and could not write or fetch."""
    parts = [(count, f"copied from {screen_text(shown_path(label))}") for label, count in folders]
    parts.append((fixed, "copied from the wrong place in the BIOS folder"))
    parts.append((shared, "copied from another place of the BIOS folder"))
    if not any(count for count, _what in parts):
        return ""
    parts += [(downloaded, fetched), (failed, "failed"), (missing, "still missing")]
    words: list[str] = []
    for count, what in parts:
        if count:
            words.append(f"{_plural(count, 'file') if not words else count} {what}")
    if wrong:
        words.append(f"{_plural(wrong, 'wrong copy')} left")
    return ", ".join(words) + "."


def _open_local_sources(args: argparse.Namespace) -> None:
    """Line mode's sources: the --from folders read, then the file list and
    the pack this run was given."""
    reset_local_sources(args)
    open_from_folders(getattr(args, "from", None) or [])
    open_list_and_pack(args)


def reset_local_sources(args: argparse.Namespace) -> None:
    """Forget the sources and failures a previous run in this process kept."""
    LOCAL.reset()
    LOCAL.jobs = getattr(args, "jobs", DEFAULT_JOBS) or DEFAULT_JOBS
    SAID_FAILED.clear()


def open_list_and_pack(args: argparse.Namespace) -> None:
    """Take the file list and the pack this run was given, and the platform
    they are for when none is named."""
    if args.manifest is not None:
        LOCAL.manifest = args.manifest
        named = local_manifest_platform(args.manifest)
        if args.platform is None and named:
            args.platform = named
            args.platform_from_list = True
            print(f"  File list: {args.manifest} ({display_name(named)})")
    if not args.from_pack:
        return
    try:
        LOCAL.pack = PackSource(args.from_pack)
    except ValueError as exc:
        raise Refusal("pack", "invalid", args.platform or "", f"Error: {exc}") from None
    pack = LOCAL.pack
    parts = len(pack.files)
    print(f"  Pack: {pack.name}"
          + (f", {parts} parts" if parts > 1 or _PART_FILE.match(pack.files[0].name) else ""))
    spelled = pack.platforms()
    if args.platform is not None:
        plat = normalize_platform(args.platform, say=False)
        if spelled and plat not in spelled:
            raise Refusal("pack", "other_platform", plat,
                          f"Error: {pack.name} is a pack for "
                          f"{' and '.join(display_name(n) for n in spelled)}, not "
                          f"{display_name(plat)}.")
    elif len(spelled) == 1:
        # Named by the pack, not by the user: the setups that read its list
        # are offered, as for a --manifest.
        args.platform = spelled[0]
        args.platform_from_list = True
    else:
        among = (" (" + ", ".join(spelled) + ")") if spelled else ""
        raise Refusal("pack", "no_platform", "",
                      f"Error: name the platform {pack.name} is installed for with "
                      f"--platform{among}.")


def _system_folder(folder: Path) -> str:
    """Why a --from folder is one of the system's own, in words, or ""."""
    try:
        resolved = folder.resolve()
    except OSError:
        return ""
    text = str(resolved)
    if any(text == pseudo or text.startswith(pseudo + "/") for pseudo in PSEUDO_FOLDERS):
        return "is a folder the system makes up, it holds no copy"
    system_drive = os.environ.get("SYSTEMDRIVE", "C:") if os.name == "nt" else ""
    if resolved == Path(resolved.anchor) and (
            os.name != "nt" or resolved.drive.casefold() == system_drive.casefold()):
        return "is the root of the whole system"
    return ""


def from_folder_problem(label: str) -> tuple[str, str] | None:
    """Why a folder named with --from cannot be read, without reading what
    it holds: (reason, words), or None when it can.

    reason is the one the error event carries: not_found, not_a_folder (a
    file that is no ZIP), unreadable, or system (the root of the system,
    /proc, /sys or /dev). words follow the folder as given: "E:\\old does
    not exist". Cheap enough for a screen to call before indexing."""
    folder = Path(os.path.expanduser(label))
    zipped = folder.is_file() and folder.name.casefold().endswith(".zip")
    if not (folder.is_dir() or zipped):
        if folder.exists():
            return "not_a_folder", "is neither a folder nor a ZIP"
        return "not_found", "does not exist"
    try:
        if zipped:
            with open(folder, "rb"):
                pass
        else:
            with os.scandir(folder) as listing:
                next(listing, None)
    except OSError as exc:
        return "unreadable", f"could not be read: {unreadable_words(exc)}"
    system = "" if zipped else _system_folder(folder)
    return ("system", system) if system else None


def from_folder_refusal(label: str) -> Refusal | None:
    """The refusal of a folder named with --from that cannot be read, or None."""
    problem = from_folder_problem(label)
    if problem is None:
        return None
    reason, what = problem
    message = f"{label} {what}: --from names the folder to copy BIOS files from"
    return Refusal("from", reason, "", f"Error: {screen_text(message)}.", message=message)


def open_from_folders(folders: list[Path]) -> None:
    """Read each folder named with --from, or stop on one that cannot be."""
    for folder in folders:
        label = str(folder)
        refusal = from_folder_refusal(label)
        if refusal is not None:
            raise refusal
        _read_from_folder(label)


def _read_from_folder(label: str) -> FolderIndex:
    """Read a folder to copy BIOS files from, one from_folder_problem took."""
    index = FolderIndex(Path(os.path.expanduser(label)), label)
    LOCAL.folders.append(index)
    print(f"  Copying BIOS files from: {screen_text(shown_path(label))}")
    if index.truncated:
        print(f"  Read the first {MAX_SCANNED_FILES:,} files of {screen_text(label)} "
              "only. Name the folder that holds the BIOS files to search it all.")
    for drive in index.other_drives:
        print(f"  Did not go into {screen_text(str(drive))}: it is another drive. Name "
              "it with --from to read it too.")
    EVENTS.emit("scanned", folder=label, files=index.files, truncated=index.truncated,
                other_drives=[str(drive) for drive in index.other_drives])
    return index
