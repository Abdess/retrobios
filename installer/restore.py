"""--restore: a backup put back in place, and the install record after it."""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from installer.events import EVENTS
from installer.host_fs import _clear_read_only, _is_link, _replace_with_copy
from installer.install_record import (
    RECORD_SCHEMA,
    RECORD_SUFFIX,
    _read_record_bytes,
    _record_now,
    _save_record,
    _valid_setup,
    load_record,
)
from installer.invocation import _INVOCATION, installer_id
from installer.local_check import _digest_file
from installer.paths import _safe_relative_path
from installer.safe_replace import (
    BACKUP_DIR,
    KEPT,
    REMOVED_NOTE,
    _NotKept,
    _backup_files,
    _is_backup_run,
)
from installer.text import _plural, format_size


def _backup_note(run: Path) -> dict | None:
    """What a removal wrote beside the files it moved into run: the setup,
    its folder, its choice before and the record's entries. None for the
    backup of files an install replaced, or a note that cannot be read."""
    try:
        data = json.loads(_read_record_bytes(run / REMOVED_NOTE).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("platform"), str) \
            or not isinstance(data.get("folder"), str):
        return None
    setup = {"written": "", "choice": data.get("choice"), "files": data.get("files")}
    return data if _valid_setup(setup, Path(data["folder"])) else None


def _record_folder(run: Path, path: Path) -> tuple[Path, str] | None:
    """The BIOS folder whose record may name a file put back at path, and
    its dest there. The holder beside a folder keeps the folder's name as
    the first level of each run, the one inside it none."""
    holder, root = run.parent, run.parent.parent
    rel = PurePosixPath(*path.relative_to(root).parts)
    if len(rel.parts) > 1 and (holder / f"{rel.parts[0]}{RECORD_SUFFIX}").is_file():
        return root / rel.parts[0], PurePosixPath(*rel.parts[1:]).as_posix()
    if (holder / f"{root.name or 'folder'}{RECORD_SUFFIX}").is_file():
        return root, rel.as_posix()
    return None


def _record_without(gone: set[str]) -> Callable[[dict | None], dict | None]:
    """The change taking out a setup's entries at the folded dests of gone."""
    def change(setup: dict | None) -> dict | None:
        return None if setup is None else {
            **setup, "files": [item for item in setup["files"]
                               if str(item.get("root") or "") not in ("", "data")
                               or item["dest"].casefold() not in gone]}
    return change


def _record_after_restore(run: Path, put_back: list[Path]) -> str:
    """The record of the folder files went back into, made to say what is
    there now: "" once written, else why not. A removal's backup gives its
    files back to their setup, with the choice it had. Any other backup
    holds the user's own files, which the record never names: its entries
    at their places go."""
    note = _backup_note(run)
    if note is not None:
        folder = Path(note["folder"])
        back = []
        for item in note["files"]:
            path = _below(folder, item["dest"])[0]
            if path is not None and not _check_ours(path, item)[0]:
                back.append(item)
        if not back and put_back:
            # The files went back, but not where the record's folder is: the
            # folder moved or was renamed since the removal.
            return f"it is for {folder}, which does not hold the files put back"
        if not back:
            return ""
        return _update_record(folder, note["platform"],
                              lambda setup: _record_merge(setup, back, note["choice"]))
    by_folder: dict[Path, set[str]] = {}
    for path in put_back:
        found = _record_folder(run, path)
        if found is not None:
            by_folder.setdefault(found[0], set()).add(found[1].casefold())
    problems = [_update_record(folder, plat, _record_without(gone))
                for folder, gone in by_folder.items()
                for plat in sorted((load_record(folder).data or {}).get("setups") or {})]
    return next((problem for problem in problems if problem), "")


def _recorded_copy(run: Path, dest: Path) -> bool:
    """Whether the file at dest is the installer's own copy, as the record
    of its folder names it: the collection gives it again, so a restore
    replaces it without keeping it."""
    found = _record_folder(run, dest)
    if found is None:
        return False
    try:
        info = os.lstat(dest)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or _is_link(info):
        return False
    folder, rel = found
    items = [item for setup in ((load_record(folder).data or {}).get("setups") or {}).values()
             for item in setup.get("files") or []
             if str(item.get("root") or "") in ("", "data")
             and item["dest"].casefold() == rel.casefold() and item["size"] == info.st_size]
    if not items:
        return False
    try:
        sha1 = _digest_file(dest, ("sha1",))["sha1"]
    except OSError:
        return False
    return any(item["sha1"] == sha1 for item in items)


def _record_merge(setup: dict | None, files: list[dict], choice: list[str]) -> dict:
    """A setup with files given back and the choice it had before a removal."""
    merged = {(str(item.get("root") or ""), item["dest"]): item
              for item in (setup or {}).get("files") or []}
    for item in files:
        merged[(str(item.get("root") or ""), item["dest"])] = item
    return {"list": {"version": None, "generated": None}, **(setup or {}),
            "written": _record_now(), "choice": list(choice),
            "files": [merged[key] for key in sorted(merged)]}


def _update_record(folder: Path, plat: str,
                   change: Callable[[dict | None], dict | None]) -> str:
    """Rewrite the setup plat of folder's record as change makes it, None
    taking it out: "" once written, else why not. A record that cannot be
    read, or that a newer installer wrote, is left as it is."""
    folder = Path(os.path.abspath(folder))
    read = load_record(folder)
    if read.newer or (read.data is None and read.path is not None):
        return read.problem
    data = read.data or {"setups": {}, "folder": str(folder)}
    setups = dict(data["setups"])
    new = change(setups.get(plat))
    if new is None:
        setups.pop(plat, None)
    else:
        setups[plat] = new
    if not setups:
        if read.path is None:
            return ""
        # Nothing of ours is left in the folder: the record goes with it.
        try:
            read.path.unlink()
        except OSError as exc:
            return exc.strerror or str(exc)
        return ""
    data = {"schema": RECORD_SCHEMA, "installer": installer_id(),
            "folder": str(data.get("folder") or folder), "setups": setups}
    where, failure = _save_record(folder, data, read.path)
    return "" if where is not None else failure


class RestoreResult(NamedTuple):
    """What --restore did with a backup run folder, for the lines and the events.

    status: not_backup (the folder is no backup), empty (it holds no file),
    planned (--dry-run), done, or not_done (a file failed or the record
    could not be updated). dests are the places files went back to (would
    go back to, planned), failed [(dest, reason)] those that did not, kept
    the new backup folders the files at their places went to, as
    KeptFiles.summary gives them, problem why the record was not updated.
    """

    run: Path
    status: str
    dests: tuple[Path, ...] = ()
    size: int = 0
    failed: tuple[tuple[Path, str], ...] = ()
    kept: tuple[dict, ...] = ()
    problem: str = ""

    @property
    def root(self) -> Path:
        return self.run.parent.parent

    @property
    def code(self) -> int:
        """0 when every file went back, 1 when one failed or the record was
        not updated, 2 when the folder is no backup."""
        if self.status == "not_backup":
            return 2
        return 1 if self.status == "not_done" else 0


def _restore_one(run: Path, src: Path) -> tuple[Path, str]:
    """Put the backup's src back at its place: (dest, "") once there, else
    (dest, why not)."""
    root = run.parent.parent
    rel = PurePosixPath(*src.relative_to(run).parts)
    dest = root / Path(*rel.parts)
    try:
        sha1 = _digest_file(src, ("sha1",))["sha1"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        # A file at the place that is not the backup's copy (a newer one,
        # one the user put there) is moved aside first, into a new dated
        # backup, as an install keeps what it replaces. Its first level
        # is the folder the backup's holder sits in.
        holder = (root / rel.parts[0], PurePosixPath(*rel.parts[1:])) \
            if len(rel.parts) > 1 else (root, rel)
        if not _recorded_copy(run, dest):
            KEPT.keep(*holder, dest, {"sha1": sha1})
        _clear_read_only(dest)
        _replace_with_copy(src, dest)
    except (OSError, _NotKept) as exc:
        return dest, getattr(exc, "strerror", None) or str(exc)
    return dest, ""


def restore_backup(run: Path, dry_run: bool = False) -> RestoreResult:
    """Put every file of a backup run folder back where it was.

    run is a <holder>/<date-time> folder a run wrote, its holder named
    retrobios-backup. Each file goes to the same path below the holder's
    parent. A file there with other contents is moved into a new dated
    backup first, never lost. The install record of its folder is made to
    say so. The backup is left in place. Each file put back, or not, is a
    restored event as it happens.
    """
    run = Path(os.path.abspath(os.path.expanduser(str(run))))
    if not _is_backup_run(run):
        return RestoreResult(run, "not_backup")
    files = _backup_files(run)
    if not files:
        return RestoreResult(run, "empty")
    root = run.parent.parent
    if dry_run:
        return RestoreResult(run, "planned",
                             tuple(root / Path(*src.relative_to(run).parts) for src in files),
                             sum(src.stat().st_size for src in files))
    size = 0
    put_back: list[Path] = []
    failed: list[tuple[Path, str]] = []
    KEPT.reset()
    for src in files:
        length = src.stat().st_size
        dest, reason = _restore_one(run, src)
        EVENTS.emit("restored", folder=str(run), path=str(dest), size=length,
                    ok=not reason, reason=reason)
        if reason:
            failed.append((dest, reason))
            continue
        put_back.append(dest)
        size += length
    problem = _record_after_restore(run, put_back)
    return RestoreResult(run, "not_done" if failed or problem else "done", tuple(put_back),
                         size, tuple(failed), tuple(KEPT.summary()), problem)


def restore_message(result: RestoreResult) -> str:
    """Why a restore put nothing back, in one sentence, else ""."""
    if result.status == "not_backup":
        return f"{result.run} is not a folder the installer kept files in."
    if result.status == "empty":
        return f"{result.run} holds no file. Nothing to put back."
    return ""


def say_restore(result: RestoreResult) -> None:
    """--restore's outcome in lines."""
    if result.status == "not_backup":
        print(f"Error: {restore_message(result)}", file=sys.stderr)
        print(f"  Name one of the dated folders inside a {BACKUP_DIR} folder, as "
              "--backups lists them.", file=sys.stderr)
        return
    if result.status == "empty":
        print(restore_message(result))
        return
    if result.status == "planned":
        for dest in result.dests:
            print(f"  would put back {dest}")
        print(f"\nWould put back {_plural(len(result.dests), 'file')} "
              f"({format_size(result.size)}) under {result.root}. Nothing was written.")
        return
    for dest, reason in result.failed:
        print(f"  failed: {dest} ({reason})", file=sys.stderr)
    print(f"\nPut back {_plural(len(result.dests), 'file')} ({format_size(result.size)}) "
          f"under {result.root}.")
    for item in result.kept:
        # The files that sat at those places, never lost.
        print(f"Kept {_plural(item['files'], 'file')} that were in their place "
              f"({format_size(item['bytes'])}) in {item['folder']}")
    if result.failed:
        print(f"{_plural(len(result.failed), 'file')} could not be put back.", file=sys.stderr)
    if result.problem:
        print(f"The install record could not be updated ({result.problem}).", file=sys.stderr)
    print(f"The copies are still in {result.run}. To free the space: "
          f"{_INVOCATION.launcher()} --delete-backup {_INVOCATION.word(str(result.run))}")


def restore_kept(run: Path, dry_run: bool = False) -> int:
    """--restore: put a backup back, say it in lines and as a restore
    event, and return the exit code."""
    result = restore_backup(run, dry_run)
    say_restore(result)
    EVENTS.emit("restore", folder=str(result.run), status=result.status,
                files=len(result.dests), bytes=result.size, kept=list(result.kept),
                problem=result.problem, message=restore_message(result))
    return result.code


def _below(folder: Path, dest: str) -> tuple[Path | None, str]:
    """The file a record's dest names below folder, reached through no link:
    (path, "") or (None, why it is left). A dest that climbs or is absolute
    is outside, whatever a record says."""
    try:
        rel = _safe_relative_path(dest, "dest")
    except ValueError:
        return None, "outside"
    path = folder
    for part in rel.parts[:-1]:
        path = path / part
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None, "gone"
        except OSError:
            return None, "unreadable"
        if _is_link(info):
            return None, "link"
        if not stat.S_ISDIR(info.st_mode):
            return None, "not_a_file"
    return path / rel.parts[-1], ""


def _check_ours(path: Path, item: dict) -> tuple[str, os.stat_result | None]:
    """Why the file at path is not the one the record names, "" when it
    is, and what lstat read of it."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "gone", None
    except OSError:
        return "unreadable", None
    if _is_link(info):
        return "link", info
    if not stat.S_ISREG(info.st_mode):
        return "not_a_file", info
    if not re.fullmatch(r"[0-9a-f]{40}", str(item["sha1"])) or info.st_size != item["size"]:
        return "changed", info
    try:
        same = _digest_file(path, ("sha1",))["sha1"] == item["sha1"]
    except OSError:
        return "unreadable", info
    return ("" if same else "changed"), info
