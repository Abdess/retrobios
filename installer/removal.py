"""Removing what a run installed: the files, the record after, and what the run says."""
from __future__ import annotations

import argparse
import errno
import json
import os
import stat
import sys
import urllib.error
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from installer.backups import _action_setup, _backup_date
from installer.choices import available_choices, emulator_names, resolve_choices, resolve_systems
from installer.console import QUIT_CODE, _answer_yes
from installer.events import EVENTS
from installer.filesystems import keeps_case
from installer.host_fs import _clear_read_only, _is_link
from installer.install_record import _record_now, load_record, setup_record
from installer.invocation import _INVOCATION, offline_requested
from installer.lists import fetch_manifest
from installer.local_check import _digest_file
from installer.manifest import _validate_manifest
from installer.network import _fetch_json
from installer.paths import shown_path, spelled
from installer.platforms import display_name, refuse_name
from installer.refusal import Refusal
from installer.remote import MAX_MANIFEST_BYTES, active_remote
from installer.removal_plan import (
    CHANGED_SINCE_PLAN,
    REMOVAL_REASONS,
    Removal,
    _drive_key,
    _stamp,
    plan_misplaced_removal,
    plan_removal,
)
from installer.restore import _update_record
from installer.safe_replace import (
    BACKUP_DIR,
    KEPT,
    REMOVED_NOTE,
    _move_aside,
)
from installer.text import _plural, agree, format_size


def _left_by_hand(folder: Path, record: dict, fold: bool) -> list[str]:
    """The files in folder that no setup of its record names: placed by the
    user or another program, never touched, counted in the summary."""
    named = {_drive_key(item["dest"], fold)
             for setup in record["setups"].values() for item in setup.get("files") or []
             if str(item.get("root") or "") in ("", "data")}
    found = []
    for base, dirs, names in os.walk(folder, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != BACKUP_DIR)
        for name in sorted(names):
            rel = (Path(base) / name).relative_to(folder).as_posix()
            if _drive_key(rel, fold) not in named and name != ".nomedia":
                found.append(rel)
    return found


def _kept_words(kept: list[dict]) -> str:
    """Why files stay, counted by reason: 2 still needed, 1 changed since."""
    counts: dict[str, int] = {}
    for item in kept:
        counts[item["reason"]] = counts.get(item["reason"], 0) + 1
    order = list(REMOVAL_REASONS)
    return ", ".join(f"{count} {REMOVAL_REASONS[reason]}" for reason, count in sorted(
        counts.items(), key=lambda pair: (-pair[1], order.index(pair[0]))))


def kept_line(item: dict) -> str:
    """One file a removal leaves, and why."""
    why = REMOVAL_REASONS[item["reason"]]
    if item["reason"] == "shared" and item["what"]:
        why += f" by {item['what']}"
    return f"{item['dest']}: {why}"


def _other_setup_list(name: str) -> tuple[dict | None, str]:
    """The list of another setup of the folder, fetched from the address
    whatever list this run was given, or None and why it is not at hand."""
    if offline_requested():
        return None, "this run is offline: run it again with the internet"
    try:
        return _validate_manifest(_fetch_json(active_remote().manifest_url.format(platform=name),
                                              MAX_MANIFEST_BYTES, "file list"), name), ""
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, "no such list exists, as for a setup this installer no longer serves"
        return None, f"the server answered HTTP {exc.code}: run it again later"
    except (ValueError, OSError):
        return None, "it could not be fetched: run it again with the internet"


def _still_in_place(entry: dict) -> bool:
    """For a misplaced copy, whether the file it duplicates is still the one
    the plan read at its place: a copy is deleted only while that one holds
    its bytes. True for any other entry."""
    placed = entry.get("placed_path")
    if placed is None:
        return True
    try:
        info = os.lstat(placed)
        return (stat.S_ISREG(info.st_mode) and not _is_link(info)
                and _stamp(info) == entry["placed_inode"]
                and _digest_file(placed, ("sha1",))["sha1"] == entry["sha1"])
    except OSError:
        return False


class _ChangedSincePlan(OSError):
    """The file is not the one the plan read: it stays."""


def remove_files(removal: Removal, setup: dict, backup: bool
                 ) -> tuple[list[dict], list[dict], Path | None]:
    """Delete each file of the plan, or with backup move it into a new
    backup folder: (removed, failed {dest, reason, changed}, the backup
    folder). Each file is read again just before, and hashed again: one
    edited in place during the question, swapped, or turned into a link
    stays, as changed since the plan."""
    removed, failed = [], []
    run: Path | None = None
    under: Path | None = None
    for entry in removal.remove:
        path = entry["path"]
        kept: Path | None = None
        try:
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or _is_link(info)
                    or _stamp(info) != entry["inode"]
                    or _digest_file(path, ("sha1",))["sha1"] != entry["sha1"]
                    or not _still_in_place(entry)):
                raise _ChangedSincePlan(errno.ESTALE, CHANGED_SINCE_PLAN)
            if backup:
                if run is None or under is None:
                    run, under = KEPT.place(removal.folder, create=True)
                    _write_removed_note(run, removal, setup)
                kept = under / Path(*PurePosixPath(entry["dest"]).parts)
                kept.parent.mkdir(parents=True, exist_ok=True)
                _move_aside(path, kept)
            else:
                _clear_read_only(path)
                path.unlink()
        except OSError as exc:
            reason = exc.strerror or str(exc)
            failed.append({"dest": entry["dest"], "reason": reason,
                           "changed": isinstance(exc, _ChangedSincePlan)})
            EVENTS.emit("removed", platform=removal.plat, dest=entry["dest"],
                        size=entry["size"], ok=False, reason=reason, moved_to="")
            continue
        removed.append(entry)
        EVENTS.emit("removed", platform=removal.plat, dest=entry["dest"],
                    size=entry["size"], ok=True, reason="",
                    moved_to="" if kept is None else str(spelled(kept)))
    return removed, failed, run


def _write_removed_note(run: Path, removal: Removal, setup: dict) -> None:
    """What --restore needs to give the moved files back to their setup:
    the record's entries of every file the plan moves, the choice before."""
    dests = {entry["dest"] for entry in removal.remove}
    note = {"platform": removal.plat, "folder": str(removal.folder),
            "choice": list(setup.get("choice") or []),
            "files": [item for item in setup.get("files") or [] if item["dest"] in dests]}
    (run / REMOVED_NOTE).write_text(json.dumps(note, sort_keys=True), encoding="utf-8")


def _record_after_removal(removal: Removal, removed: list[dict]) -> str:
    """The setup's record without the files removed and those gone, with the
    choice left: the setup goes once it holds no file."""
    taken = {(entry["root"], entry["dest"]) for entry in removed} | {
        (str(item.get("root") or ""), item["dest"]) for item in removal.gone}

    def change(setup: dict | None) -> dict | None:
        if setup is None:
            return None
        files = [item for item in setup.get("files") or []
                 if (str(item.get("root") or ""), item["dest"]) not in taken]
        if not files:
            return None
        # A file that stayed (it failed, changed, or something still needs
        # it) keeps its entry. With nothing left chosen, the choice stays the
        # one recorded: no choice would read as the whole list.
        choice = setup.get("choice") if removal.choice is None else removal.choice
        return {**setup, "written": _record_now(), "choice": list(choice or []),
                "files": files}

    return _update_record(removal.folder, removal.plat, change)


def _named_files(values: Iterable[Path], folder: Path) -> tuple[list[str], str]:
    """The --file values as dests below folder, and why nothing is removed
    when one is outside it, else ""."""
    files = []
    for value in values:
        given = Path(os.path.expanduser(str(value)))
        if given.is_absolute():
            try:
                given = Path(os.path.abspath(given)).relative_to(folder)
            except ValueError:
                return [], (f"Error: {value} is not inside {shown_path(folder)}: --file "
                            "names a file of the BIOS folder.")
        files.append(PurePosixPath(*given.parts).as_posix())
    return files, ""


def _removal_refused(plat: str, folder: Path, message: str, backup: bool) -> int:
    """A removal that touches nothing: the reason said and sent, exit 2."""
    print(message, file=sys.stderr)
    if message.startswith("Error: "):
        message = message[len("Error: "):]
    EVENTS.emit("removal_plan", platform=plat, folder=str(folder), files=0, bytes=0,
                systems=[], dests=[], kept=[], gone=0, backup=backup,
                message=message)
    return 2


def _misplaced_others(plat: str, folder: Path, dropped: tuple, setups: dict
                      ) -> tuple[list[dict], str]:
    """The lists of the other setups of folder, or why nothing is removed."""
    # Every setup of the folder protects the places its list reads: one
    # whose list or record entry cannot be read leaves nothing to tell
    # its files from copies, so nothing is removed.
    message = ""
    if dropped:
        message = (f"Nothing was removed from {shown_path(folder)}: the install "
                   f"record's entry for {display_name(dropped[0])}, which shares "
                   "the folder, cannot be used, so its files would not be told from "
                   f"copies. Install {display_name(dropped[0])} again, with the "
                   "choice it was installed with, to rewrite it.")
    others = []
    for name in setups:
        if name == plat or message:
            continue
        other, why = _other_setup_list(name)
        if other is None:
            message = (f"Nothing was removed from {shown_path(folder)}: the file list "
                       f"of {display_name(name)}, which shares the folder, is needed "
                       f"to tell its files from copies, and {why}.")
        else:
            others.append(other)
    return others, message


def _removal_headline(removal: Removal, where: str, size: int, *, misplaced: bool,
                      backup: bool) -> str:
    """The plan's first line: what goes from where, and the space freed."""
    if not removal.remove:
        return (f"No copy in the wrong place of {where}." if misplaced
                else f"Nothing to remove from {where}.")
    if misplaced:
        return (f"Remove {_plural(len(removal.remove), 'copy')} in the wrong "
                f"place of {where}, {format_size(size)} freed. Each is a file "
                "RetroBIOS placed where the cores read it.")
    if backup:
        return (f"Move {_plural(len(removal.remove), 'file')} "
                f"({format_size(size)}) from {where} to a backup.")
    return (f"Remove {_plural(len(removal.remove), 'file')} from {where}, "
            f"{format_size(size)} freed.")


def _print_removal_plan(args: argparse.Namespace, removal: Removal, by_hand: list[str],
                        misplaced: bool) -> None:
    """The files a removal takes and those it leaves, as the plan lists them."""
    # The copies are the user's: they are named before any question.
    listed = (removal.remove if args.dry_run or args.verbose
              else removal.remove[:REMOVAL_KEPT_SHOWN] if misplaced else [])
    for entry in listed:
        print(f"  {entry['dest']}" + (f" (in place: {entry['placed']})"
                                      if entry.get("placed") else ""))
    if len(listed) < len(removal.remove) and misplaced:
        print(f"  and {len(removal.remove) - len(listed)} more (--dry-run lists them)")
    if removal.kept:
        print(f"{agree(len(removal.kept), 'file stays', 'files stay')}: "
              f"{_kept_words(removal.kept)}.")
        shown = removal.kept if args.verbose else removal.kept[:REMOVAL_KEPT_SHOWN]
        for item in shown:
            print(f"  {kept_line(item)}")
        if len(shown) < len(removal.kept):
            print(f"  and {len(removal.kept) - len(shown)} more (--verbose lists them)")
    if by_hand:
        print(f"{agree(len(by_hand), 'other file stays', 'other files stay')}, not "
              "installed by RetroBIOS.")
        if args.verbose:
            for rel in by_hand:
                print(f"  {rel}")


def _removal_answer(args: argparse.Namespace, plat: str) -> int | None:
    """The exit code when the plan stops before removing, None to go on."""
    if args.dry_run:
        print("Nothing was removed (--dry-run).")
        return 0
    if not args.yes:
        if args.no_input or not sys.stdin.isatty():
            raise Refusal("option", "needs_yes", plat,
                          "Error: removing files needs a yes: add --yes to remove them "
                          "without a question, or --dry-run to list them.", code=2)
        question = ("Move them to a backup? [y/N] " if args.backup
                    else "Remove them for good? [y/N] ")
        if not _answer_yes(question):
            print("Nothing was removed.")
            return QUIT_CODE
    return None


def _report_removal(removed: list[dict], failed: list[dict], run: Path | None, *,
                    misplaced: bool, problem: str) -> int:
    """What a removal did, said once it is done: 0 done, 1 a file or the record failed."""
    freed = sum(entry["size"] for entry in removed)
    if run is not None:
        print(f"Moved {_plural(len(removed), 'file')} ({format_size(freed)}) to "
              f"{shown_path(run)}.")
        print(f"To put them back: {_INVOCATION.launcher()} --restore "
              f"{_INVOCATION.word(str(spelled(run)))}")
        EVENTS.emit("backup", folder=str(spelled(run)), date=_backup_date(run),
                    files=len(removed), bytes=freed, source="remove", status="made",
                    message=f"Moved {_plural(len(removed), 'file')} here.")
    elif removed:
        print(f"Removed {_plural(len(removed), 'copy' if misplaced else 'file')}, "
              f"{format_size(freed)} freed.")
    changed = [item for item in failed if item["changed"]]
    if changed:
        print(f"{agree(len(changed), 'file stays', 'files stay')}: "
              f"{len(changed)} {CHANGED_SINCE_PLAN}.")
        for item in changed:
            print(f"  {item['dest']}: {CHANGED_SINCE_PLAN}")
    failed = [item for item in failed if not item["changed"]]
    for item in failed:
        print(f"  failed: {item['dest']} ({item['reason']})", file=sys.stderr)
    if problem:
        print(f"The install record could not be updated ({problem}).", file=sys.stderr)
    return 1 if failed or problem else 0


def run_removal(args: argparse.Namespace) -> int:
    """--remove: the plan, one confirmation, then each file deleted (or
    moved with --backup), and the record made to say so. 0 done, 1 a file
    or the record failed, 2 nothing done."""
    plat, folder = _action_setup(args)
    if not os.path.isdir(folder):
        # An unmounted card looks like every file gone: nothing is touched.
        message = (f"Nothing was removed: {shown_path(folder)} is not there (a card "
                   "not mounted?).")
        return _removal_refused(plat, folder, message, bool(args.backup))
    read = load_record(folder)
    setup, _path, problem = setup_record(plat, folder)
    if setup is None or read.data is None:
        why = problem or (f"its install record holds nothing for {display_name(plat)}"
                          if read.data is not None else
                          "no install record is beside it, so no file is known to be "
                          "the installer's")
        message = f"Nothing was removed from {shown_path(folder)}: {why}."
        return _removal_refused(plat, folder, message, bool(args.backup))
    manifest = fetch_manifest(plat)
    every = list(manifest.get("files") or [])
    omitted = list(manifest.get("omitted_files") or [])
    known = available_choices(every, omitted)
    try:
        systems = resolve_systems(args.system or [], manifest, every, omitted)
        cores = resolve_choices(args.core, known["cores"], "core") if args.core else []
        emulators = resolve_choices(args.emulator, sorted(emulator_names(
            manifest, every, omitted)), "emulator") if args.emulator else []
    except ValueError as exc:
        refuse_name(plat, f"Error: {plat}: {exc}")
    files, outside = _named_files(args.file or [], folder)
    if outside:
        return _removal_refused(plat, folder, outside, bool(args.backup))
    misplaced = bool(getattr(args, "misplaced", False))
    if misplaced:
        others, message = _misplaced_others(plat, folder, read.dropped, read.data["setups"])
        if message:
            return _removal_refused(plat, folder, message, False)
        removal = plan_misplaced_removal(plat, folder, read.data, [manifest, *others])
    else:
        removal = plan_removal(plat, folder, read.data, manifest, systems=systems,
                               cores=cores, emulators=emulators, files=files)
    size = sum(entry["size"] for entry in removal.remove)
    whole = not (systems or cores or emulators or files or misplaced)
    by_hand = _left_by_hand(folder, read.data, not keeps_case(folder)) if whole else []
    where = f"{shown_path(folder)} for {display_name(plat, manifest)}"
    headline = _removal_headline(removal, where, size, misplaced=misplaced,
                                 backup=bool(args.backup))
    EVENTS.emit("removal_plan", platform=plat, folder=str(folder), files=len(removal.remove),
                bytes=size, systems=removal.systems,
                dests=[entry["dest"] for entry in removal.remove],
                kept=[{"dest": item["dest"], "reason": item["reason"]}
                      for item in removal.kept],
                gone=len(removal.gone), backup=bool(args.backup), message=headline)
    print(headline)
    _print_removal_plan(args, removal, by_hand, misplaced)
    if not removal.remove:
        # The record keeps what it says until a removal is confirmed.
        return 2
    stop = _removal_answer(args, plat)
    if stop is not None:
        return stop
    KEPT.reset()
    removed, failed, run = remove_files(removal, setup, bool(args.backup))
    # The copies were never the record's: it stays as it is.
    problem = "" if misplaced else _record_after_removal(removal, removed)
    return _report_removal(removed, failed, run, misplaced=misplaced, problem=problem)


# The files a removal leaves named one by one by default: past this, a
# count and --verbose.
REMOVAL_KEPT_SHOWN = 10
