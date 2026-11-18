"""File system probes that note a folder this user may not read instead of failing."""
from __future__ import annotations

import errno
import os
import re
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from installer.events import EVENTS
from installer.text import screen_text

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
