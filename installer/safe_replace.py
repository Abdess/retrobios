"""A file put in place: its bytes checked first, the file it replaces set aside in a dated backup."""
from __future__ import annotations

import contextlib
import errno
import os
import shutil
import stat
import tempfile
import threading
import time
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import IO, TYPE_CHECKING, ContextManager

from installer.console import OUTPUT
from installer.host_fs import (
    NOT_WRITABLE,
    READ_ONLY,
    _UMASK,
    _Interrupted,
    _clear_read_only,
    _is_file,
    _is_link,
    _read_only_file,
    _stop,
    _write_refused,
)
from installer.invocation import _INVOCATION
from installer.local_check import _digest_file
from installer.paths import _MOVED_FOLDERS, _entry_path, _entry_place, _note_spelling, _safe_relative_path, spelled
from installer.text import _plural, format_size

if TYPE_CHECKING:
    from installer.console import Progress

# Where a file in place that this run replaces is kept: a folder beside the
# one written to, never inside it. Several emulators find their BIOS by
# content, not by name: DuckStation, SwanStation and Rustation read every
# file of the BIOS folder, BizHawk walks its firmware folder recursively. A
# kept copy anywhere under that folder could be taken for the BIOS.
BACKUP_DIR = "retrobios-backup"
# Written into every run folder the installer creates. --restore only accepts
# a folder holding it, so a folder someone else placed (a shared BIOS folder
# on a network share) is never copied over the user's files.
BACKUP_MARKER = ".retrobios-backup"


def _check_holder(holder: Path) -> os.stat_result:
    """Refuse a backup holder the user's files must not go into.

    A link would send them wherever it points. On a system with user ids, a
    folder another user owns was not made by this user's runs, and its owner
    could read or swap what is moved in. A storage that keeps no owner per
    file gives every file one owner: Android's shared storage shows a folder
    Termux has just made as another user's, as does a FAT card. A holder
    owned like the folder it sits in is that storage's owner, not someone
    else's folder. Returns what was checked, so the caller can confirm the
    same folder is still there once it has written into it.
    """
    info = os.lstat(holder)
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(errno.ELOOP, f"{holder} is a link or not a folder")
    getuid = getattr(os, "getuid", None)
    if (getuid is not None and info.st_uid != getuid()
            and info.st_uid != os.lstat(holder.parent).st_uid):
        raise OSError(errno.EPERM, f"{holder} belongs to another user")
    return info


def _same_folder(path: Path, checked: os.stat_result) -> bool:
    """Whether path is still the folder checked, not a link swapped in since."""
    now = os.lstat(path)
    return (stat.S_ISDIR(now.st_mode)
            and (now.st_dev, now.st_ino) == (checked.st_dev, checked.st_ino))


class _NotKept(Exception):
    """The file in place differs and could not be set aside: it stays."""


class KeptFiles:
    """The files this run moved aside before replacing them.

    A file is kept at <holder>/<run>/<folder name>/<path below the folder>,
    the holder being retrobios-backup beside the folder written to. The run
    folder is named by date and time, so a second run never mixes with the
    first, and copying its contents into the holder's parent puts every file
    back where it was. Only when nothing can be written beside the folder
    (a drive root, a read-only parent) does the holder go inside it, with
    no folder name, and the same copy puts the files back.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.stamp = ""
        # Holder -> the run folder this run created in it.
        self._runs: dict[Path, Path] = {}
        # Run folder -> [files, bytes] kept (or, under --dry-run, to keep).
        self.counts: dict[Path, list[int]] = {}

    def reset(self) -> None:
        with self._lock:
            self.stamp = ""
            self._runs.clear()
            self.counts.clear()

    def _stamp(self) -> str:
        if not self.stamp:
            self.stamp = time.strftime("%Y%m%d-%H%M%S")
        return self.stamp

    @staticmethod
    def _holders(folder: Path) -> list[tuple[Path, str]]:
        beside = [(folder.parent / BACKUP_DIR, folder.name)] if (
            folder.name and folder.parent != folder) else []
        return beside + [(folder / BACKUP_DIR, "")]

    def place(self, folder: Path, create: bool) -> tuple[Path, Path]:
        """(run folder, folder the relative path goes under) for files of folder."""
        with self._lock:
            stamp = self._stamp()
            failure: OSError | None = None
            for holder, prefix in self._holders(folder):
                if not create:
                    return holder / stamp, holder / stamp / prefix
                run = self._runs.get(holder)
                if run is None:
                    try:
                        holder.mkdir(parents=True, exist_ok=True)
                        checked = _check_holder(holder)
                        for n in range(1, 1000):
                            run = holder / (stamp if n == 1 else f"{stamp}-{n}")
                            try:
                                run.mkdir(mode=0o700)
                                break
                            except FileExistsError:
                                continue
                        else:
                            # Every name taken: never reuse a folder this run
                            # did not create.
                            raise OSError(errno.EEXIST, f"no free folder name in {holder}")
                        # The holder checked before is still the one the run
                        # folder was made in, and the run folder is a folder.
                        if not (_same_folder(holder, checked)
                                and stat.S_ISDIR(os.lstat(run).st_mode)):
                            raise OSError(errno.ELOOP, f"{holder} changed while in use")
                        (run / BACKUP_MARKER).write_text(
                            "Files the RetroBIOS installer replaced.\n", encoding="utf-8")
                    except OSError as exc:
                        failure = exc
                        continue
                    self._runs[holder] = run
                return run, run / prefix
            raise failure or OSError(errno.EEXIST, "no backup folder name left")

    def plan(self, folder: Path, size: int) -> Path:
        """Count a file a real run would keep, writing nothing. Returns its run folder."""
        run, _under = self.place(folder, create=False)
        with self._lock:
            tally = self.counts.setdefault(run, [0, 0])
            tally[0] += 1
            tally[1] += size
        return run

    def keep(
        self, folder: Path, rel: PurePosixPath, dest: Path,
        expected: dict[str, str], fresh: Path | None = None,
    ) -> None:
        """Move the file at dest aside when its content is not the one coming.

        Nothing is done for a missing file, a link (its target is not
        touched by the replace) or a file already holding the content, by
        the manifest's hashes or, without them, byte for byte against the
        fresh copy. Raises _NotKept when the file could not be set aside:
        the replace must not happen then.
        """
        try:
            info = os.lstat(dest)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _NotKept(exc.strerror or str(exc)) from exc
        if not stat.S_ISREG(info.st_mode):
            return
        try:
            if expected:
                same = _digest_file(dest, tuple(expected)) == expected
            else:
                same = fresh is not None and _same_bytes(dest, fresh)
        except FileNotFoundError:
            return  # another run replaced it meanwhile
        except OSError as exc:
            raise _NotKept(exc.strerror or str(exc)) from exc
        if same:
            return
        try:
            run, under = self.place(folder, create=True)
            kept = under / Path(*rel.parts)
            if os.path.lexists(kept):
                # This run kept the user's file at that path already: the
                # one in place now is one this run wrote.
                return
            kept.parent.mkdir(parents=True, exist_ok=True)
            _move_aside(dest, kept)
        except FileNotFoundError:
            if not os.path.lexists(dest):
                return  # another run moved or replaced it meanwhile
            raise _NotKept("the backup folder could not be written") from None
        except OSError as exc:
            raise _NotKept(exc.strerror or str(exc)) from exc
        with self._lock:
            tally = self.counts.setdefault(run, [0, 0])
            tally[0] += 1
            tally[1] += info.st_size

    def summary(self) -> list[dict]:
        """[{folder, files, bytes}], one per run folder, for the report and events."""
        with self._lock:
            # Named as the run names its BIOS folder: /sdcard, not the
            # /storage/emulated/0 the link resolves to.
            return [{"folder": str(spelled(run)), "files": files, "bytes": size}
                    for run, (files, size) in sorted(self.counts.items())]


KEPT = KeptFiles()


def _same_bytes(a: Path, b: Path) -> bool:
    if a.stat().st_size != b.stat().st_size:
        return False
    return _digest_file(a, ("sha1",)) == _digest_file(b, ("sha1",))


def _move_aside(dest: Path, kept: Path) -> None:
    """Move dest to kept: a rename on one drive, else a copy then a delete.

    The copy goes under a temporary name first, so an interrupted copy
    never leaves a cut file under the kept name, and dest is only deleted
    once its copy is whole.
    """
    try:
        os.rename(dest, kept)
        return
    except OSError:
        if not _is_file(dest):
            raise
    scratch = kept.parent / f".{kept.name}.part"
    try:
        shutil.copy2(dest, scratch)
        os.replace(scratch, kept)
    except OSError:
        if os.path.lexists(scratch):
            os.unlink(scratch)
        raise
    dest.unlink()


def _kept_slot(root: Path, value: object) -> tuple[Path, PurePosixPath]:
    """The folder a manifest destination is written in, and its path below
    it, as _destination_path places it: a RetroDECK folder moved elsewhere
    is its own folder."""
    relative = _safe_relative_path(value, "dest")
    moved = _MOVED_FOLDERS.get(root, {})
    if len(relative.parts) > 1 and relative.parts[0] in moved:
        return moved[relative.parts[0]].resolve(), PurePosixPath(*relative.parts[1:])
    return _note_spelling(root), relative


def plan_kept(entries: list[dict], root: Path) -> dict[Path, list[int]]:
    """Count, under --dry-run, the files in place a real run would keep.

    entries are files whose content check failed. Returns {run folder:
    [files, bytes]} for these entries, also counted in KEPT for the summary.
    """
    planned: dict[Path, list[int]] = {}
    for entry in entries:
        try:
            dest = _entry_path(root, entry)
            info = os.lstat(dest)
        except (OSError, ValueError):
            continue
        if stat.S_ISREG(info.st_mode):
            run = KEPT.plan(_kept_slot(*_entry_place(root, entry))[0], info.st_size)
            tally = planned.setdefault(run, [0, 0])
            tally[0] += 1
            tally[1] += info.st_size
    return planned


def _kept_lines() -> list[str]:
    """Where the files this run replaced are, and how to put them back."""
    lines = []
    for item in KEPT.summary():
        folder = Path(item["folder"])
        lines.append(f"Kept {_plural(item['files'], 'file')} already there "
                     f"({format_size(item['bytes'])}), which the collection's "
                     f"copies replaced, in {folder}")
        if OUTPUT.verbose:
            lines.append(f"  To put them back: {_INVOCATION.launcher()} --restore "
                         f"{_INVOCATION.word(str(folder))}")
    return lines


def _tree(top: Path) -> list[tuple[Path, os.stat_result]]:
    """Every entry below top with what lstat read of it, children before
    their folder. A link (a junction too) is listed, never entered."""
    found: list[tuple[Path, os.stat_result]] = []
    try:
        names = sorted(os.listdir(top))
    except OSError:
        return found
    for name in names:
        path = top / name
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and not _is_link(info):
            found += _tree(path)
        found.append((path, info))
    return found


def _is_backup_run(run: Path) -> bool:
    """Whether run is a dated folder a run of the installer made: a real
    folder holding the marker, inside a retrobios-backup holder that is no
    link."""
    try:
        info, holder = os.lstat(run), os.lstat(run.parent)
        marker = os.lstat(run / BACKUP_MARKER)
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and stat.S_ISDIR(holder.st_mode)
            and not _is_link(info) and not _is_link(holder)
            and run.parent.name == BACKUP_DIR and stat.S_ISREG(marker.st_mode))


def _backup_files(run: Path) -> list[Path]:
    """The files a backup run folder holds, its marker and note aside. Links
    inside it, junctions included, are never followed nor put back."""
    return sorted(
        path for path, info in _tree(run)
        if stat.S_ISREG(info.st_mode) and not _is_link(info)
        and not (path.name.startswith(".") and path.name.endswith(".part"))
        and not (path.parent == run and path.name in (BACKUP_MARKER, REMOVED_NOTE))
    )


# Written into a backup that a removal made: the setup, its folder, its
# choice before and the record's entries, so --restore gives them back.
REMOVED_NOTE = ".retrobios-removed.json"


# A file in place whose content differs, which could not be moved aside: it
# is left as it is rather than lost.
NOT_KEPT = "file in place could not be kept aside"


class _SourceUnreadable(Exception):
    """The bytes to write could not be read: the source's fault, never the
    folder's, so it falls back like any copy that failed."""


def unreadable_words(exc: BaseException) -> str:
    """Why a file or a ZIP member could not be read, in words."""
    if isinstance(exc, RuntimeError) and "encrypted" in str(exc):
        return "it is encrypted, a password is needed"
    if isinstance(exc, NotImplementedError):
        return "it is packed with a compression method this installer cannot read"
    if isinstance(exc, (zipfile.BadZipFile, zlib.error, EOFError)):
        return "it is damaged"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return str(exc) or type(exc).__name__


def _place_verified(f: dict, bios_path: Path, dest: Path, tmp_path: Path, size: int,
                    expected: dict[str, str], held_in: str) -> None:
    """Put the written file at dest once its size and hashes are the list's."""
    if size != f["size"]:
        raise ValueError(f"{held_in} holds {size} bytes, the list records {f['size']}")
    actual = _digest_file(tmp_path, tuple(expected))
    for name, label in (("sha256", "SHA-256"), ("sha1", "SHA-1")):
        if name in expected and actual[name] != expected[name]:
            raise ValueError(f"{label} mismatch in {held_in}")
    os.chmod(tmp_path, (0o777 if f.get("executable") else 0o666) & ~_UMASK)
    _clear_read_only(dest)
    KEPT.keep(*_kept_slot(*_entry_place(bios_path, f)), dest, expected, tmp_path)
    os.replace(tmp_path, dest)


def _write_verified(
    f: dict, bios_path: Path, dest: Path,
    source: Callable[[], ContextManager[IO[bytes]]], progress: Progress | None,
    held_in: str, local: bool = False, named: str = "",
) -> tuple[str, bool, str]:
    """Write the bytes source opens at dest once they match the list's size
    and hashes, the file in place kept aside first when it differs.

    The source is opened before the temporary file, and its read errors
    are told apart from the write errors: a copy that could not be read
    was reported as a folder not writable. named is the source in the
    reason then, held_in when empty."""
    expected = {name: f[name].lower() for name in ("sha256", "sha1") if f.get(name)}
    tmp_path: Path | None = None
    counted = 0

    def unreadable(exc: BaseException) -> _SourceUnreadable:
        return _SourceUnreadable(f"{named or held_in} could not be read: "
                                 f"{unreadable_words(exc)}")

    try:
        with contextlib.ExitStack() as stack:
            try:
                src = stack.enter_context(source())
            except _MEMBER_ERRORS as exc:
                raise unreadable(exc) from exc
            out = stack.enter_context(tempfile.NamedTemporaryFile(
                mode="wb", dir=dest.parent, prefix=f".{dest.name}.", suffix=".part",
                delete=False,
            ))
            tmp_path = Path(out.name)
            size = 0
            while True:
                if _stop.is_set():
                    raise _Interrupted()
                try:
                    chunk = src.read(min(1024 * 1024, f["size"] + 1 - size))
                except _MEMBER_ERRORS as exc:
                    raise unreadable(exc) from exc
                if not chunk:
                    break
                size += len(chunk)
                if size > f["size"]:
                    raise ValueError(f"{held_in} holds more bytes than the list records")
                out.write(chunk)
                if progress is not None:
                    progress.add(len(chunk), resumed=local, network=False)
                    counted += len(chunk)
        _place_verified(f, bios_path, dest, tmp_path, size, expected, held_in)
        tmp_path = None
        return f["dest"], True, ""
    except _Interrupted:
        return f["dest"], False, "stopped"
    except _NotKept as exc:
        return f["dest"], False, f"{NOT_KEPT} ({exc})"
    except (_SourceUnreadable, ValueError, *_MEMBER_ERRORS) as exc:
        if progress is not None and counted:
            progress.add(-counted, resumed=local, network=False)
        if isinstance(exc, OSError) and _write_refused(exc):
            return f["dest"], False, READ_ONLY if _read_only_file(dest) else NOT_WRITABLE
        return f["dest"], False, str(exc)
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()


# Errors a member of someone's ZIP can raise on reading: damaged, encrypted
# (RuntimeError), or packed with a method zipfile lacks.
_MEMBER_ERRORS = (OSError, EOFError, RuntimeError, NotImplementedError,
                  zipfile.BadZipFile, zlib.error)
