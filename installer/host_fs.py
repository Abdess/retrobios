"""Probes that note a folder this user may not read, WSL paths, and the stops and errors a write meets."""
from __future__ import annotations

import errno
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from installer.events import EVENTS
from installer.text import screen_text

# Set when the run is interrupted, so queued downloads end instead of draining
# the pool: every future is submitted before the first one completes.
_stop = threading.Event()
# Set once a run starts writing: Ctrl+C before that has nothing to carry on.
_writing = threading.Event()


class _Interrupted(Exception):
    """Raised inside a worker once the run has been stopped."""


# Read once, before any download thread runs: reading the umask sets it.
_UMASK = os.umask(0)
os.umask(_UMASK)


# Set under WSL: a Windows path read from a config or a rule names a drive
# that Linux sees under /mnt (drvfs). C:\\RetroBat\\bios was used as a relative
# path and nothing Windows-side was ever found from WSL.
# unasked: why Windows could not be asked for its folders, said once by
# detection.
_WSL: dict[str, Any] = {"active": False, "root": "/mnt", "unasked": ""}


def _host_path(text: str) -> Path:
    """A path as this machine opens it: under WSL, C:\\X is /mnt/c/X."""
    match = re.match(r"^([A-Za-z]):(?:[\\/]+(.*))?$", text) if _WSL["active"] else None
    if match:
        rest = [part for part in re.split(r"[\\/]", match.group(2) or "") if part]
        return Path(_WSL["root"], match.group(1).lower(), *rest)
    return Path(text)


# Set while detection runs on this thread: a probe this user may not make
# is then said once, and the probes of other threads (the files being
# hashed) stay silent.
_SETUP_SEARCH = threading.local()

# (folder, why in words) for each folder detection could not look in.
_DETECTION_REFUSED: list[tuple[Path, str]] = []
# Those of them that failed for another cause than a permission: a read
# error from a failing card, a link that loops.
_DETECTION_UNREADABLE: set[Path] = set()
# The errors that say a place is not there, as against one that is there
# and could not be read.
_ABSENT_ERRNOS = (errno.ENOENT, errno.ENOTDIR, errno.EINVAL, errno.ENAMETOOLONG)


def refused_words(folder: Path, why: str, shown: str = "") -> str:
    """The line said for a folder detection could not look in. shown is
    the folder as the screen writes it (~/.config/EmuDeck), the full path
    by default."""
    if _WSL["active"] and why == _WSL["unasked"] and folder == Path(_WSL["root"]):
        return (f"Could not look for setups on the Windows side: {why}. "
                "Run it again once Windows answers, or name the BIOS folder with --dest.")
    if folder in _DETECTION_UNREADABLE:
        return (f"Could not look for setups: {shown or folder} could not be read ({why}). "
                "A failing card or a link that loops gives this: check it, or name the "
                "BIOS folder with --dest.")
    return (f"Could not look for setups: this user cannot open {shown or folder} ({why}). "
            "Run as its owner (su - or sudo -H), or name the BIOS folder "
            "with --dest.")


def _note_refused(path: Path, exc: OSError) -> None:
    """Say once that a folder detection looks in is closed to this user,
    or could not be read.

    A probe refused there counts as absent and the others go on: a config
    folder a sudo run left at 0700 (~/.config/EmuDeck) hid a RetroArch whose
    retroarch.cfg was readable, and the run fell back to a folder it does
    not read.
    """
    if (not getattr(_SETUP_SEARCH, "active", False) or getattr(_SETUP_SEARCH, "quiet", False)
            or exc.errno in _ABSENT_ERRNOS):
        return
    refused = closed_folder(path) or (path, exc.strerror or str(exc))
    if refused in _DETECTION_REFUSED:
        return
    _DETECTION_REFUSED.append(refused)
    if not isinstance(exc, PermissionError):
        # An EIO on retroarch.cfg counted as absent: the card about to be
        # written to failed, and the run said nothing was detected.
        _DETECTION_UNREADABLE.add(refused[0])
    words = refused_words(*refused)
    EVENTS.emit("unsearched", folder=str(refused[0]), reason=refused[1], message=words)
    print(f"  {screen_text(words)}", file=sys.stderr)


def _held(path: Path) -> bool:
    """Whether something may sit at path. A place that cannot be looked at
    (a folder above it this user cannot enter, a card that answers a read
    error) counts as held, so the file is reported unreadable and the run
    goes on with the others: Path.exists() lets PermissionError through."""
    try:
        return path.exists()
    except OSError:
        return True


def _probed(probe: Callable[[], bool], path: Path) -> bool:
    """probe() for path, False where the place cannot be looked at. A
    refusal met while looking for setups is said once (_note_refused)."""
    try:
        found = probe()
    except OSError as exc:
        _note_refused(path, exc)
        return False
    if not found:
        # Python 3.14's Path.exists() answers False where earlier ones
        # raised: a refusal is told from absence by the stat it hides.
        try:
            os.stat(path)
        except OSError as exc:
            _note_refused(path, exc)
    return found


def _exists(path: Path) -> bool:
    """Path.exists(), False where the place cannot be looked at."""
    return _probed(path.exists, path)


def _is_dir(path: Path) -> bool:
    """Path.is_dir(), False where the place cannot be looked at."""
    return _probed(path.is_dir, path)


def _is_file(path: Path) -> bool:
    """Path.is_file(), False where the place cannot be looked at."""
    return _probed(path.is_file, path)


def _closed_to_this_user(path: Path) -> OSError | None:
    """The error that keeps path from being looked at, None when it can
    be, there or not."""
    try:
        os.stat(path)
    except OSError as exc:
        return None if exc.errno in _ABSENT_ERRNOS else exc
    return None


def closed_folder(path: Path) -> tuple[Path, str] | None:
    """The folder above path this user cannot open, and why in words, or
    None when path can be looked at, there or not.

    A BIOS folder under /root run without sudo, or a card mounted at 0700
    for another user: Path.exists() raised PermissionError before the
    first line said where.
    """
    try:
        os.stat(path)
        return None
    except OSError as exc:
        failure = exc
    probe = path.absolute()
    for folder in (*reversed(probe.parents), probe):
        try:
            os.stat(folder)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                return None
            why = exc.strerror or str(exc)
            if exc.errno == errno.ELOOP:
                # The link that loops, not the open folder holding it.
                return folder, why
            real = Path(os.path.realpath(folder))
            if real != folder:
                # ~/Emulation linked into a closed card: the closed folder
                # is under the link's target, and naming the link's
                # parent told the user they cannot open their own HOME.
                return closed_folder(real) or (real.parent, why)
            return folder.parent, why
    return probe, failure.strerror or str(failure)


def _is_link(info: os.stat_result) -> bool:
    """Whether what lstat read is a link: a symbolic link, or on Windows a
    junction or any other reparse point."""
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _clear_read_only(dest: Path) -> None:
    """Let the verified copy replace a read-only file the user already has.

    Windows refuses to replace a file carrying the read-only attribute
    (WinError 5) even in a writable folder. The file is about to be replaced
    by the copy the manifest names, so its attribute is cleared first.
    Elsewhere a rename only needs the folder to be writable.
    """
    if os.name != "nt":
        return
    try:
        if dest.is_file() and not os.access(dest, os.W_OK):
            os.chmod(dest, stat.S_IREAD | stat.S_IWRITE)
    except OSError:
        pass  # the replace that follows reports the refusal with its reason


def _ready_to_place(written: Path, dest: Path, executable: bool) -> None:
    """Give verified bytes the mode a plain open() gives, executable where
    the repository file is, and clear the read-only attribute of the file
    they replace. The temporary file is private, and a folder written with
    sudo has to stay readable by the emulator's user."""
    os.chmod(written, (0o777 if executable else 0o666) & ~_UMASK)
    _clear_read_only(dest)


def _replace_with_copy(src: Path, dest: Path) -> None:
    """Put a copy of src at dest's name without following what is there."""
    fd, scratch = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".part")
    os.close(fd)
    try:
        shutil.copy2(src, scratch)
        os.replace(scratch, dest)
    except OSError:
        if os.path.lexists(scratch):
            os.unlink(scratch)
        raise


def write_atomically(path: Path, data: bytes) -> None:
    """Write data at path through a scratch file beside it, removed when the
    write fails; a scratch that cannot be removed is named in the error."""
    fd, scratch = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(scratch, path)
    except OSError as exc:
        if os.path.lexists(scratch):
            try:
                os.unlink(scratch)
            except OSError as left:
                exc.strerror = (f"{exc.strerror or exc}, and {scratch} stays "
                                f"({left.strerror or left})")
        raise


# FILE_ATTRIBUTE_REPARSE_POINT: a junction, a mount point or a link on Windows.
# Before Python 3.12 lstat does not report a junction as a link, and
# os.walk(followlinks=False) descends into it.
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


_SHARING_VIOLATIONS = (32, 33)

# A write refused by the file system: retrying cannot change it, and the
# summary names the two ways out.
NOT_WRITABLE = "folder not writable"


def _write_refused(exc: OSError) -> bool:
    # A sharing violation is a file another process holds open, which a
    # later attempt can find released: no refusal of the folder.
    if getattr(exc, "winerror", None) in _SHARING_VIOLATIONS:
        return False
    return isinstance(exc, PermissionError) or exc.errno == errno.EROFS


# A file already at the destination, marked read-only, whose content differs,
# and whose attribute could not be cleared: replacing it is refused while its
# folder stays writable.
READ_ONLY = "file in place is read-only"


def _read_only_file(dest: Path) -> bool:
    return _is_file(dest) and not os.access(dest, os.W_OK) and _folder_writable(dest.parent)


def _folder_writable(path: Path) -> bool:
    """Whether a file can be created under path, read from its nearest
    existing folder: a BIOS folder not created yet is as writable as the
    folder it would go in."""
    probe = path
    while not _exists(probe) and probe.parent != probe:
        probe = probe.parent
    return os.access(probe, os.W_OK)


# A write the drive had no room for: the same run fails the same way until
# space is freed or another drive is named.
DRIVE_FULL = "the drive is full"


_FULL_ERRNOS = (errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC))


def _drive_full(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and exc.errno in _FULL_ERRNOS


def _nearest_folder(path: Path) -> Path:
    """The deepest folder on path that exists and can be looked at."""
    probe = path.absolute()
    while not _is_dir(probe) and probe.parent != probe:
        probe = probe.parent
    return probe
