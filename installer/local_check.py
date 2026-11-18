"""Files already on disk: their digests, each file read once, and whether each is the list's."""
from __future__ import annotations

import concurrent.futures
import hashlib
import time
from pathlib import Path
from typing import IO, TYPE_CHECKING

from installer.events import EVENTS, EVENT_PROGRESS_INTERVAL
from installer.host_fs import _held
from installer.paths import _entry_path

if TYPE_CHECKING:
    from installer.terminal import Terminal


def _digest_file(path: Path, algorithms: tuple[str, ...]) -> dict[str, str]:
    """Compute several digests of a file in a single read.

    Checking a 3 GB collection against both a SHA-1 and a SHA-256 used to walk
    every file twice, single threaded. Hashing is cheap next to the I/O, so
    the read is what has to happen once.
    """
    with open(path, "rb") as fh:
        return _digest_handle(fh, algorithms)


def _digest_handle(fh: IO[bytes], algorithms: tuple[str, ...]) -> dict[str, str]:
    """Digests of an open file, read from its start."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    fh.seek(0)
    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
        for hasher in hashers.values():
            hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def _sha1_file(path: Path) -> str:
    """Compute SHA1 of a file."""
    return _digest_file(path, ("sha1",))["sha1"]


def _sha256_file(path: Path) -> str:
    """Compute SHA256 of a file."""
    return _digest_file(path, ("sha256",))["sha256"]


# The digests the line menu's head read of the files in place, by path and
# by what stat says of the file, kept for the check that follows Enter: the
# head named a wrong copy of the right size in place,
# and a card read twice is read at the speed of its reader. Emptied once
# that check has read them (head_reads_done).
_HEAD_READS: dict[tuple, dict[str, str]] = {}


def _stat_key(path: Path) -> tuple | None:
    """What tells a file apart from the same path rewritten: None for none."""
    try:
        info = path.stat()
    except OSError:
        return None
    return (str(path), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino)


def _read_digests(path: Path, algorithms: tuple[str, ...], remember: bool = False) -> dict:
    """_digest_file, answered from what the head read when the file is the
    same one, and remembered for the check when remember is set."""
    key = _stat_key(path)
    known = _HEAD_READS.get((key, algorithms)) if key is not None else None
    if known is not None:
        return known
    digests = _digest_file(path, algorithms)
    if remember and key is not None:
        _HEAD_READS[(key, algorithms)] = digests
    return digests


def head_reads_done() -> None:
    """The check after the head has read what it holds: nothing more is
    answered from it, a file the run writes being read again."""
    _HEAD_READS.clear()


def _classify_local(entry: dict, dest: Path, remember: bool = False) -> str:
    """Return 'up_to_date' or 'mismatched' for a file already on disk.
    remember keeps what was read for the check after the line menu."""
    expected = {
        name: entry.get(name, "").lower()
        for name in ("sha256", "sha1")
        if entry.get(name)
    }
    try:
        is_file = dest.is_file()
    except OSError:
        # A folder above it this user cannot enter: what sits there is not
        # known to be the right file.
        return "mismatched"
    if not is_file:
        # A folder at the file's place: --check says so, an install fails
        # on that file alone.
        return "mismatched"
    if not expected:
        return "up_to_date"
    try:
        actual = _read_digests(dest, tuple(expected), remember)
    except OSError:
        # Unreadable (no permission, a read error on a failing card): its
        # contents are not known to be the right ones.
        return "mismatched"
    if all(actual[name] == value for name, value in expected.items()):
        return "up_to_date"
    return "mismatched"


def closed_folder_words(dest: Path, closed: tuple[Path, str]) -> str:
    folder, why = closed
    return f"this user cannot open {folder} ({why}), which holds {dest}"


def unreachable_words(exc: OSError) -> str:
    """Why the place of a file could not be looked at, in words."""
    return (f"could not be read ({exc.strerror or exc}): this user may not "
            f"have access to its folder")


def check_local(
    files: list[dict], bios_path: Path, jobs: int = 8,
    term: "Terminal | None" = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Check which files exist locally and have correct hashes.

    Returns (to_download, up_to_date, mismatched). With a terminal, a count
    moves while the files are read: 3.9 GB on an SD card went by in minutes
    of silence, read as a hung run and stopped with Ctrl+C.
    """
    to_download: list[dict] = []
    present: list[tuple[dict, Path]] = []

    for f in files:
        dest = _entry_path(bios_path, f)
        if _held(dest):
            present.append((f, dest))
        else:
            to_download.append(f)

    up_to_date: list[dict] = []
    mismatched: list[dict] = []
    if present:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            verdicts = pool.map(
                lambda item: (item[0], _classify_local(item[0], item[1])), present
            )
            shown = term if term is not None and term.live and not term.quiet else None
            last = evented = 0.0
            for done, (entry, verdict) in enumerate(verdicts, 1):
                if verdict == "up_to_date":
                    up_to_date.append(entry)
                else:
                    mismatched.append(entry)
                now = time.monotonic()
                # The program driving the installer gets the count the
                # terminal gets: a screen with a bare timer over 6 GB on an
                # SD card read as hung.
                if EVENTS.on and (now - evented >= EVENT_PROGRESS_INTERVAL
                                  or done == len(present)):
                    evented = now
                    EVENTS.emit("checking", files_done=done, files_total=len(present))
                if shown is not None and (now - last >= 0.1 or done == len(present)):
                    last = now
                    print(f"\r  read {done}/{len(present)}", end="", file=shown.stream,
                          flush=True)
            if shown is not None:
                print("\r\033[K", end="", file=shown.stream, flush=True)

    return to_download, up_to_date, mismatched
