"""The backups a run leaves: listing them, deleting one, and the setup an action names."""
from __future__ import annotations

import argparse
import datetime
import os
import re
import stat
import sys
from pathlib import Path

from installer.console import QUIT_CODE, _answer_yes
from installer.destination import card_dest
from installer.detect_frontends import detect_platforms
from installer.detect_os import detect_os
from installer.events import EVENTS
from installer.host_fs import _clear_read_only
from installer.install_record import day_words, load_record
from installer.invocation import _INVOCATION
from installer.paths import shown_path, spelled
from installer.platforms import normalize_platform
from installer.refusal import Refusal
from installer.restore import _backup_note
from installer.safe_replace import KeptFiles, _backup_files, _is_backup_run, _tree
from installer.text import _plural, format_size


def _backup_date(run: Path) -> str:
    """When a run folder was made, read from its name: 2026-11-03 12:00:00."""
    match = re.match(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)", run.name)
    if not match:
        return ""
    year, month, day, hour, minute, second = match.groups()
    return f"{year}-{month}-{day} {hour}:{minute}:{second}"


def backup_words(date: str) -> str:
    """A backup's date as a list says it: 3 Nov 12:00."""
    try:
        when = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return date or "unknown date"
    return f"{day_words(when)} {when.hour:02d}:{when.minute:02d}"


def list_backups(folder: Path) -> list[dict]:
    """The backups of a BIOS folder, newest first: {folder, date, files,
    bytes, source}, source remove for a removal's and install for the files
    an install replaced. Only dated folders holding the marker count."""
    folder = Path(os.path.abspath(folder))
    found = []
    for holder, prefix in KeptFiles._holders(folder):
        try:
            if not stat.S_ISDIR(os.lstat(holder).st_mode):
                continue
            runs = sorted(holder.iterdir())
        except OSError:
            continue
        for run in runs:
            if not _is_backup_run(run):
                continue
            under = run / prefix if prefix else run
            files = [path for path in _backup_files(run) if under in path.parents]
            if files:
                found.append({"folder": run, "date": _backup_date(run), "files": len(files),
                              "bytes": sum(path.stat().st_size for path in files),
                              "source": "remove" if _backup_note(run) is not None
                              else "install"})
    return sorted(found, key=lambda item: item["folder"].name, reverse=True)


def run_backups(args: argparse.Namespace) -> int:
    """--backups: the backups of the BIOS folder, newest first."""
    folder = _action_folder(args)
    backups = list_backups(folder)
    if not backups:
        print(f"No backup of {shown_path(folder)}.")
        return 0
    print(f"Backups of {shown_path(folder)}, newest first:")
    for item in backups:
        made = "removed" if item["source"] == "remove" else "replaced by an install"
        print(f"  {backup_words(item['date'])}  {_plural(item['files'], 'file')}, "
              f"{format_size(item['bytes'])}, {made}")
        print(f"    {shown_path(item['folder'])}")
        EVENTS.emit("backup", folder=str(spelled(item["folder"])), date=item["date"],
                    files=item["files"], bytes=item["bytes"], source=item["source"],
                    status="listed", message="")
    print(f"To put one back: {_INVOCATION.launcher()} --restore FOLDER")
    return 0


def run_delete_backup(args: argparse.Namespace) -> int:
    """--delete-backup: one backup folder deleted after one confirmation.
    0 done, 1 a file failed, 2 refused or declined."""
    run = Path(os.path.abspath(os.path.expanduser(str(args.delete_backup))))
    if not _is_backup_run(run):
        raise Refusal("backup", "not_a_backup", "",
                      f"Error: {run} is not a folder the installer kept files in.",
                      "  Name one of the dated folders --backups lists.", code=2)
    files = _backup_files(run)
    size = sum(path.stat().st_size for path in files)
    date = _backup_date(run)
    source = "remove" if _backup_note(run) is not None else "install"
    print(f"Delete the backup of {backup_words(date)}: {_plural(len(files), 'file')}, "
          f"{format_size(size)}.")
    if args.dry_run:
        print("Nothing was deleted (--dry-run).")
        return 0
    if not args.yes:
        if args.no_input or not sys.stdin.isatty():
            raise Refusal("option", "needs_yes", "",
                          "Error: deleting a backup needs a yes: add --yes to delete it "
                          "without a question.", code=2)
        if not _answer_yes("Delete it for good? [y/N] "):
            print("Nothing was deleted.")
            return QUIT_CODE
    failed = 0
    # Bottom up, never through a link: a link goes, not what it names. A
    # junction is removed as a folder, which leaves its target alone.
    for path, info in _tree(run):
        try:
            if stat.S_ISDIR(info.st_mode):
                path.rmdir()
            else:
                _clear_read_only(path)
                path.unlink()
        except OSError as exc:
            failed += 1
            print(f"  failed: {path} ({exc.strerror or exc})", file=sys.stderr)
    try:
        run.rmdir()
    except OSError as exc:
        failed += 1
        print(f"  failed: {run} ({exc.strerror or exc})", file=sys.stderr)
    EVENTS.emit("backup", folder=str(spelled(run)), date=date, files=len(files), bytes=size,
                source=source, status="not_deleted" if failed else "deleted",
                message=f"{_plural(failed, 'file')} could not be deleted." if failed else "")
    if failed:
        return 1
    print(f"Deleted, {format_size(size)} freed.")
    return 0


def _action_folder(args: argparse.Namespace) -> Path:
    """The BIOS folder a listing of backups is for: --dest, else the one
    setup found here."""
    if args.dest and not args.platform:
        return Path(os.path.abspath(os.path.expanduser(str(args.dest))))
    return _action_setup(args)[1]


def _action_setup(args: argparse.Namespace) -> tuple[str, Path]:
    """The setup and BIOS folder a removal is for: --platform and --dest,
    the one setup a record names or the search here finds, never a guess.
    A choice left open exits 2, naming the option that settles it."""
    named = args.platform or ""
    plat = normalize_platform(args.platform, say=False) if args.platform else ""
    if args.dest:
        dest = Path(args.dest)
        if plat:
            plat, dest = card_dest(named, plat, dest)
        folder = Path(os.path.abspath(os.path.expanduser(str(dest))))
        if plat:
            return plat, folder
        setups = sorted((load_record(folder).data or {}).get("setups") or {})
        if len(setups) == 1:
            return setups[0], folder
        raise Refusal("detect", "conflict" if setups else "not_found", "",
                      f"Error: name the setup of {shown_path(folder)} with --platform"
                      + (f": {', '.join(setups)}." if setups else "."), code=2)
    found = [(name, path) for name, path in detect_platforms(detect_os())
             if not plat or name == plat]
    if len(found) == 1:
        return found[0][0], Path(os.path.abspath(found[0][1]))
    if not found:
        raise Refusal("detect", "not_found", plat,
                      "Error: no setup found here: name its BIOS folder with --dest"
                      + ("." if plat else " and its setup with --platform."), code=2)
    raise Refusal("detect", "conflict", plat,
                  "Error: several setups found here: name one with --platform and --dest.",
                  *(f"  --platform {name} --dest {_INVOCATION.word(str(path))}"
                    for name, path in found), code=2)
