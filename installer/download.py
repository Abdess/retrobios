"""Downloading files in parallel: each resumed, retried and checked before it takes its name."""
from __future__ import annotations

import concurrent.futures
import contextlib
import http.client
import os
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from installer.console import Progress
from installer.events import EVENTS
from installer.folder_index import FOLDER_IN_PLACE, _copy_local
from installer.host_fs import (
    DRIVE_FULL,
    NOT_WRITABLE,
    READ_ONLY,
    _SHARING_VIOLATIONS,
    _Interrupted,
    _drive_full,
    _folder_writable,
    _is_file,
    _read_only_file,
    _ready_to_place,
    _stop,
    _write_refused,
    _writing,
)
from installer.invocation import DEFAULT_JOBS, offline_requested
from installer.local_check import _digest_file, _digest_handle, expected_hashes, unreachable_words
from installer.network import _retry_after_failure, _server_delay, network_words
from installer.offline import LOCAL, offline_words
from installer.failure_causes import HttpReason, NetworkReason, OfflineReason
from installer.outcome import _transfer_failure
from installer.pack_source import NOT_IN_PACK, _extract_from_pack
from installer.paths import _entry_path, _entry_place
from installer.remote import MAX_DOWNLOAD_SIZE, MAX_RETRIES, RELEASE_URL, RESUME_FROM_SIZE, active_remote
from installer.safe_replace import KEPT, NOT_KEPT, _NotKept, _kept_slot
from installer.terminal import Terminal

if TYPE_CHECKING:
    from installer.folder_index import LocalCopy


def _folder_failure(exc: OSError) -> str:
    """Why the folder a file goes in could not be made."""
    if _write_refused(exc):
        return NOT_WRITABLE
    if _drive_full(exc):
        return DRIVE_FULL
    return exc.strerror or str(exc)


def _download_dest(
    f: dict, bios_path: Path, copy: LocalCopy | None,
) -> Path | tuple[str, bool, str]:
    """Where f goes, its folder made, or the result of a file that cannot go there."""
    if _stop.is_set():
        return str(f.get("dest", "?")), False, "stopped"
    try:
        dest = _entry_path(bios_path, f)
    except ValueError:
        return str(f.get("dest", "?")), False, "unsafe destination"
    # Nothing to write, no folder made: a pack lacking the list's files
    # left 405 empty folders in the BIOS folder.
    if copy is None and LOCAL.pack is not None and LOCAL.pack.find(f) is None:
        return f["dest"], False, NOT_IN_PACK
    if copy is None and LOCAL.pack is None and offline_requested():
        return f["dest"], False, OfflineReason(f"not fetched: {offline_words()}")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f["dest"], False, _folder_failure(exc)
    try:
        in_place_folder = dest.is_dir()
    except OSError as exc:
        return f["dest"], False, unreachable_words(exc)
    if in_place_folder:
        # Fetched, it failed only at the rename, on an errno and two paths.
        return f["dest"], False, FOLDER_IN_PLACE
    return dest


def _download_copied(
    f: dict, bios_path: Path, dest: Path, copy: LocalCopy, verbose: bool,
    progress: Progress | None,
) -> tuple[str, bool, str]:
    """Copy f from where copy found it on this machine, fetched when the copy fails."""
    result = _copy_local(f, bios_path, dest, copy, progress)
    if result[1]:
        copy.index.count_copy(copy.misplaced)
        return result
    if result[2] in ("stopped", NOT_WRITABLE, READ_ONLY) or result[2].startswith(NOT_KEPT):
        return result
    # The copy went or changed since it was read (a card pulled out, a
    # file another run replaced): the file is fetched as if never found,
    # and a fetch that fails too names both reasons.
    if verbose:
        print(f"    {f['dest']}: {result[2]}, fetching it instead", file=sys.stderr)
    fetched = _download_one(f, bios_path, verbose, progress)
    why = fetched[2]
    if (fetched[1] or why in ("stopped", NOT_WRITABLE, READ_ONLY)
            or why.startswith(NOT_KEPT)):
        return fetched
    both = f"{result[2]}, and {why}"
    # The fetch's kind of failure stays, so the advice is the right one.
    kind = type(why) if isinstance(why, (NetworkReason, OfflineReason)) else str
    return fetched[0], False, kind(both)


def _download_one(
    f: dict, bios_path: Path, verbose: bool = False,
    progress: Progress | None = None, copy: LocalCopy | None = None,
) -> tuple[str, bool, str]:
    """Download a single file, or copy it from where copy found it on this
    machine. Returns (dest, success, reason it failed)."""
    dest = _download_dest(f, bios_path, copy)
    if not isinstance(dest, Path):
        return dest
    if copy is not None:
        return _download_copied(f, bios_path, dest, copy, verbose, progress)

    if LOCAL.pack is not None:
        return _extract_from_pack(f, bios_path, dest, progress)
    if offline_requested():
        return f["dest"], False, OfflineReason(f"not fetched: {offline_words()}")
    if f.get("release_asset"):
        url = RELEASE_URL.format(asset=urllib.parse.quote(f["release_asset"], safe=""))
    else:
        url = active_remote().raw_file_url.format(path=urllib.parse.quote(f["repo_path"], safe="/"))
    return _fetch_file(_FileFetch(f, bios_path, dest, url, verbose, progress))


class _FileFetch:
    """One file's download: where it goes, and what the current attempt holds."""

    def __init__(self, f: dict, bios_path: Path, dest: Path, url: str, verbose: bool,
                 progress: Progress | None) -> None:
        self.f = f
        self.bios_path = bios_path
        self.dest = dest
        self.url = url
        self.verbose = verbose
        self.progress = progress
        self.expected_size: int = f["size"]
        # A large file keeps a fixed partial name so the next attempt, or the
        # next run, asks only for what is missing.
        self.resumable = self.expected_size >= RESUME_FROM_SIZE
        self.full_partial = False
        self.mismatch = ""
        self.tmp_path: Path | None = None
        self.partial: BinaryIO | None = None
        self.counted = 0
        self.resumed_count = 0

    def begin(self) -> None:
        """Start an attempt holding nothing."""
        self.tmp_path = None
        self.counted = 0
        self.resumed_count = 0
        self.partial = None

    def drop_private(self) -> None:
        """Remove the private copy of this attempt, never the locked partial."""
        if self.tmp_path is not None and self.partial is None and self.tmp_path.exists():
            self.tmp_path.unlink()

    def take_back(self) -> None:
        """Take the bytes a failed attempt drew off the progress."""
        if self.progress is not None and self.counted:
            self.progress.add(-self.counted)
            if self.resumed_count:
                self.progress.forget_resumed(self.resumed_count)


def _fetch_file(job: _FileFetch) -> tuple[str, bool, str]:
    """Fetch job's file, retried, verified and moved into place."""
    f = job.f
    reason: str = "download failed"
    refused = False
    delay: float | None
    for attempt in range(1, MAX_RETRIES + 1):
        job.begin()
        try:
            _fetch_attempt(job)
            return f["dest"], True, ""

        except _Interrupted:
            # Stopped mid-transfer: a large file keeps its partial copy for
            # the next run, and a small one is dropped rather than left beside
            # the destination.
            job.drop_private()
            return f["dest"], False, "stopped"

        except _NotKept as exc:
            # No attempt changes it, and the file in place stays as it is.
            job.drop_private()
            return f["dest"], False, f"{NOT_KEPT} ({exc})"

        except _Corrupt:
            reason = job.mismatch
            if job.verbose:
                print(f"    {reason} on attempt {attempt}", file=sys.stderr)
            # Closed before the delete: Windows refuses to remove a file
            # still open (WinError 32), and the error ended the run.
            if job.partial is not None:
                job.partial.close()
            if job.tmp_path is not None and job.tmp_path.exists():
                job.tmp_path.unlink()
            delay = 0.0

        except urllib.error.HTTPError as exc:
            reason = _http_attempt_failure(job, exc, attempt)
            # A 416 refused the partial copy, dropped above: the next attempt
            # asks for the whole file.
            delay = (_server_delay(exc, attempt) if exc.code == 416 and attempt < MAX_RETRIES
                     else _retry_after_failure(exc, attempt, MAX_RETRIES))

        # http.client raises IncompleteRead (an HTTPException, not an
        # OSError) when a chunked transfer is cut, as a proxy re-encoding
        # the stream does: it is a dropped connection like any other.
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            reason, refused = _attempt_failure_reason(job.dest, exc)
            if job.verbose:
                print(f"    Attempt {attempt} failed: {exc}", file=sys.stderr)
            if not refused:
                job.drop_private()
            delay = _retry_after_failure(exc, attempt, MAX_RETRIES)

        finally:
            if job.partial is not None:
                job.partial.close()

        job.take_back()
        if refused or reason == DRIVE_FULL or delay is None:
            return f["dest"], False, reason
        if attempt < MAX_RETRIES and delay and _stop.wait(delay):
            return f["dest"], False, "stopped"

    return f["dest"], False, reason


def _http_attempt_failure(job: _FileFetch, exc: urllib.error.HTTPError, attempt: int) -> str:
    """The reason an attempt the server refused gives, its copy dropped."""
    words = f"HTTP {exc.code}"
    if exc.code in (403, 429):
        words += " (GitHub rate limit or access refused)"
    reason = (NetworkReason if exc.code >= 500 or exc.code == 429
              else HttpReason)(words)
    reason.url = job.url
    if job.verbose:
        print(f"    Attempt {attempt} failed: {exc}", file=sys.stderr)
    job.drop_private()
    if exc.code == 416 and job.tmp_path is not None and job.tmp_path.exists():
        if job.partial is not None:
            job.partial.close()
        job.tmp_path.unlink()  # the partial copy no longer fits the file
    return reason


def _attempt_failure_reason(dest: Path, exc: Exception) -> tuple[str, bool]:
    """The reason a failed attempt gives, and whether no attempt can change it."""
    if (isinstance(exc, OSError) and not isinstance(exc, urllib.error.URLError)
            and _write_refused(exc)):
        # No attempt can change a refused write. A read-only file in
        # place is not a folder this user cannot write.
        return (READ_ONLY if _read_only_file(dest) else NOT_WRITABLE), True
    if _drive_full(exc):
        # No attempt frees space either. A private copy is still
        # removed below: it holds the space the next file needs.
        return DRIVE_FULL, False
    if _transfer_failure(exc):
        return NetworkReason(network_words(exc)[1]), False
    return str(getattr(exc, "reason", "") or exc), False


def _fetch_attempt(job: _FileFetch) -> None:
    """One attempt: the bytes received, checked and moved into place."""
    offset = _resume_offset(job)
    request = urllib.request.Request(job.url)
    if offset:
        request.add_header("Range", f"bytes={offset}-")
    with urllib.request.urlopen(request, timeout=60) as resp:
        if job.partial is not None and offset and getattr(resp, "status", 200) != 206:
            offset = 0  # the server sent the whole file again
            job.partial.truncate(0)
        raw_length = resp.headers.get("Content-Length") if resp.headers else None
        if raw_length and int(raw_length) != job.expected_size - offset:
            raise ValueError(
                f"Content-Length {raw_length} != expected {job.expected_size - offset}"
            )
        written = _receive_file(job, resp, offset)
    _place_fetched(job, written)


def _resume_offset(job: _FileFetch) -> int:
    """Where the transfer starts: past the bytes the locked partial copy holds."""
    if not job.resumable:
        return 0
    tmp_path = job.dest.parent / f".{job.dest.name}.part"
    job.tmp_path = tmp_path
    _partial_size(tmp_path)
    # Two runs into one BIOS folder used to append to the same
    # partial copy: the one that finds it locked downloads into
    # a private file instead.
    partial = _claim_partial(tmp_path)
    job.partial = partial
    if partial is None:
        job.tmp_path = None
        return 0
    offset = os.fstat(partial.fileno()).st_size
    if offset >= job.expected_size and _NO_RENAME_WHILE_OPEN:
        # The run that verified this copy releases its lock
        # to rename it: truncating it there destroyed that
        # copy and failed the rename. It is left alone and
        # this run writes a private file.
        partial.close()
        job.partial = None
        job.tmp_path = None
        job.full_partial = True
        return 0
    if offset >= job.expected_size:
        partial.truncate(0)
        return 0
    return offset


def _receive_file(job: _FileFetch, resp: http.client.HTTPResponse, offset: int) -> Path:
    """Write the response into the partial copy or a private file, and
    return the path written."""
    partial, tmp_path = job.partial, job.tmp_path
    if partial is not None and tmp_path is not None:
        partial.seek(offset)
        out = _Unclosed(partial)
        with out:
            downloaded = _stream_response(job, resp, out.write, offset)
        written = tmp_path
    else:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=job.dest.parent, prefix=f".{job.dest.name}.",
            suffix=".part", delete=False,
        ) as temp:
            written = job.tmp_path = Path(temp.name)
            downloaded = _stream_response(job, resp, temp.write, offset)
    if downloaded != job.expected_size:
        raise ValueError(
            f"downloaded {downloaded} bytes, expected {job.expected_size}"
        )
    return written


def _stream_response(job: _FileFetch, resp: http.client.HTTPResponse,
                     write: Callable[[bytes], object], offset: int) -> int:
    """Copy the response through write, counted on the progress. Returns
    the bytes the file holds."""
    progress = job.progress
    downloaded = offset
    if progress is not None and offset:
        progress.add(offset, resumed=True)
        job.counted += offset
        job.resumed_count = offset
    while True:
        if _stop.is_set():
            raise _Interrupted()
        chunk = resp.read(1024 * 1024)
        if not chunk:
            break
        downloaded += len(chunk)
        if downloaded > job.expected_size or downloaded > MAX_DOWNLOAD_SIZE:
            raise ValueError("download exceeded declared size")
        write(chunk)
        if progress is not None:
            progress.add(len(chunk))
            job.counted += len(chunk)
    return downloaded


def _place_fetched(job: _FileFetch, written: Path) -> None:
    """Check the bytes written against the list, then give them the file's name."""
    f, dest = job.f, job.dest
    expected = expected_hashes(f)
    # A large file is hashed through the handle that holds its lock.
    # On Windows that lock is mandatory: reopening the path to read
    # it failed with a sharing violation, which read as an unwritable
    # folder for every file of 16 MB or more (issue 82).
    if job.partial is not None:
        actual = _digest_handle(job.partial, tuple(expected))
    else:
        actual = _digest_file(written, tuple(expected))
    if "sha256" in expected and actual["sha256"] != expected["sha256"]:
        job.mismatch = "SHA-256 mismatch"
        raise _Corrupt()
    if "sha1" in expected and actual["sha1"] != expected["sha1"]:
        job.mismatch = "SHA-1 mismatch"
        raise _Corrupt()

    _ready_to_place(written, dest, bool(f.get("executable")))
    # The file in place, a personal dump or another revision, is
    # moved aside first: replaced, it was gone for good.
    KEPT.keep(*_kept_slot(*_entry_place(job.bios_path, f)), dest, expected, written)
    if job.partial is not None and _NO_RENAME_WHILE_OPEN:
        # Windows renames no open file. Elsewhere the lock is held
        # until the copy has its final name.
        job.partial.close()
        _replace_released(written, dest, expected)
    else:
        os.replace(written, dest)
    if job.full_partial:
        _drop_full_partial(dest, job.expected_size)


# Windows renames no file another handle holds open, and Python opens files
# without FILE_SHARE_DELETE: a locked partial copy is closed before its rename.
_NO_RENAME_WHILE_OPEN = os.name == "nt"
# Seconds a closed partial copy waits for a sharing violation to clear: a
# second run closing it again, or a scanner reading the new file.
RELEASE_WAIT = 30.0


def _replace_released(source: Path, dest: Path, expected: dict[str, str]) -> None:
    """Rename a verified copy whose lock was just released.

    Another run may open the copy in that moment, which refuses the rename
    with a sharing violation until it lets go. When the copy is gone, that
    run placed the same file and removed it: the destination is checked
    against the manifest's hashes before it counts as installed.
    """
    deadline = time.monotonic() + RELEASE_WAIT
    while True:
        try:
            os.replace(source, dest)
            return
        except FileNotFoundError:
            if expected and _is_file(dest) and _digest_file(dest, tuple(expected)) == expected:
                return
            raise
        except PermissionError as exc:
            if (getattr(exc, "winerror", None) not in _SHARING_VIOLATIONS
                    or time.monotonic() >= deadline):
                raise
            time.sleep(0.2)


def _drop_full_partial(dest: Path, expected_size: int) -> None:
    """Remove a complete partial copy this run left alone.

    A copy at full size that nothing holds is what a run stopped between its
    check and its rename leaves behind. The destination now holds the
    verified file, so the copy is only clutter. One another run holds is
    left to it.
    """
    path = dest.parent / f".{dest.name}.part"
    if not _is_file(path):
        return
    try:
        handle = _claim_partial(path)
    except OSError:
        return
    if handle is None:
        return
    with handle:
        complete = os.fstat(handle.fileno()).st_size >= expected_size
    if complete:
        # another run opened it meanwhile and finishes with it
        with contextlib.suppress(OSError):
            path.unlink()
    else:
        # created by the claim and taken since by another run
        with contextlib.suppress(OSError):
            if path.stat().st_size == 0:
                path.unlink()


def _partial_size(path: Path) -> int:
    """Bytes already held by a partial copy. Anything but a plain file is dropped."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return 0
    if stat.S_ISREG(info.st_mode):
        return info.st_size
    path.unlink()
    return 0


def _claim_partial(path: Path) -> BinaryIO | None:
    """The partial copy, opened and locked for this run, or None when
    another run holds it. A link planted at its name is not followed."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    handle = os.fdopen(os.open(path, flags, 0o644), "r+b")
    try:
        if os.name == "nt":
            import importlib

            # typeshed declares msvcrt for win32 only: the module is read
            # as the runtime holds it.
            msvcrt = importlib.import_module("msvcrt")
            locking: Callable[[int, int, int], None] = msvcrt.locking
            locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    # Opened and locked are two steps: in between, the run that held the
    # partial may have renamed it into place and released it. The lock then
    # sits on the installed BIOS, which looks like a finished partial and
    # would be truncated. Only the file still under the partial's name is ours.
    try:
        ours = os.path.samestat(os.fstat(handle.fileno()), os.lstat(path))
    except OSError:
        ours = False
    if not ours:
        handle.close()
        return None
    return handle


def _release_claim(handle: BinaryIO, path: Path) -> None:
    """Free a file taken with _claim_partial and remove it. Removed while
    still held where the system allows it, so no other run takes the name
    in between. Windows refuses to remove an open file: there it is closed
    first, and one another run opened meanwhile is left to that run."""
    if not _NO_RENAME_WHILE_OPEN:
        path.unlink(missing_ok=True)
    handle.close()
    if _NO_RENAME_WHILE_OPEN:
        # another run holds it now and removes it when done
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)


class _Unclosed:
    """The locked partial copy, written through without closing it."""

    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle

    def __enter__(self) -> BinaryIO:
        return self._handle

    def __exit__(self, *_exc: object) -> None:
        self._handle.flush()

    def write(self, data: bytes) -> int:
        return self._handle.write(data)


class _Corrupt(Exception):
    """The bytes arrived but are not the file the manifest names."""


def download_files(
    files: list[dict], bios_path: Path, jobs: int = DEFAULT_JOBS, verbose: bool = False,
    term: Terminal | None = None, progress: Progress | None = None,
    copies: dict[int, LocalCopy] | None = None,
) -> tuple[list[tuple[str, str]], bool]:
    """Download files in parallel.

    Returns the destinations that failed, each with its reason, and whether
    the run was interrupted. progress.installed counts the files written.
    Every future is submitted up front, so a bare KeyboardInterrupt would
    let the pool drain the queue in full: the stop flag is what makes Ctrl+C
    end the run rather than only stop the reporting.
    """
    failed: list[tuple[str, str]] = []
    interrupted = False
    _stop.clear()
    _writing.set()
    term = term or Terminal()
    if progress is None:
        progress = Progress(len(files), sum(f.get("size", 0) for f in files), term)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        future_map = {
            pool.submit(_download_one, f, bios_path, verbose, progress,
                        (copies or {}).get(id(f))): f
            for f in files
        }
        refused = False
        refused_events = 0
        try:
            for future in concurrent.futures.as_completed(future_map):
                dest, success, reason = future.result()
                if refused:
                    # The folder they all go in refused the first: each
                    # would fail alike, counted without a line of its own,
                    # though a program reading the events still gets one.
                    if not success:
                        failed.append((dest, NOT_WRITABLE))
                        refused_events += 1
                        EVENTS.emit(
                            "downloaded", dest=dest, ok=False, reason=NOT_WRITABLE,
                            size=future_map[future].get("size", 0),
                            files_done=progress.files + refused_events,
                            files_total=progress.total_files, bytes_done=progress.bytes,
                            bytes_total=progress.expected_bytes,
                        )
                    continue
                if _stop.is_set():
                    continue
                progress.done(dest, success, reason)
                EVENTS.emit(
                    "downloaded", dest=dest, ok=success, reason=reason,
                    size=future_map[future].get("size", 0), files_done=progress.files,
                    files_total=progress.total_files, bytes_done=progress.bytes,
                    bytes_total=progress.expected_bytes,
                )
                if not success:
                    failed.append((dest, reason))
                    if reason == NOT_WRITABLE and not _folder_writable(bios_path):
                        # A read-only card or share: hundreds of identical
                        # FAILED lines buried the one cause and its advice.
                        refused = True
                        _stop.set()
        except KeyboardInterrupt:
            interrupted = True
            _stop.set()
            progress.finish()
            print("\n  Stopping. Files already installed are kept.")
    # The pool has run every future by now: a file that landed after Ctrl+C
    # is on disk and counts.
    progress.landed = [
        entry for future, entry in future_map.items()
        if not future.cancelled() and future.exception() is None and future.result()[1]
    ]
    progress.installed = len(progress.landed)
    progress.finish()
    progress.emit_transfer()
    return failed, interrupted
