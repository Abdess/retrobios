"""Data directories rebuilt from their source archive, each file checked."""
from __future__ import annotations

import functools
import hashlib
import http.client
import os
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import IO, TYPE_CHECKING, BinaryIO, ContextManager

from installer.download import _claim_partial, _release_claim
from installer.failure_causes import OfflineReason
from installer.host_fs import (
    DRIVE_FULL,
    NOT_WRITABLE,
    _Interrupted,
    _drive_full,
    _folder_writable,
    _ready_to_place,
    _stop,
    _write_refused,
    _writing,
)
from installer.install_record import recorded_data_copies
from installer.local_check import _read_digests
from installer.manifest import OTHER_SYSTEMS
from installer.network import _retry_after_failure, _retry_delay
from installer.offline import LOCAL, _Offline, _network_allowed, _offline_only
from installer.paths import _destination_path
from installer.platforms import entry_systems
from installer.remote import MAX_DATA_ARCHIVE_SIZE, MAX_DOWNLOAD_SIZE, MAX_RETRIES
from installer.safe_replace import KEPT, _MEMBER_ERRORS, _NotKept, _kept_slot, unreadable_words

if TYPE_CHECKING:
    from installer.console import Progress
    from installer.game_folders import GamesPlan


def _archive_validator(headers: http.client.HTTPMessage | Mapping[str, str] | None) -> str:
    """What names this revision of an archive to its server: an If-Range
    with it gets the rest of the same bytes, or the whole new archive."""
    if not headers:
        return ""
    etag = headers.get("ETag", "") or ""
    # A weak tag never answers a range (RFC 9110 13.1.5).
    return etag if etag and not etag.startswith("W/") else headers.get("Last-Modified", "") or ""


class _ArchiveCount:
    """The bytes one attempt at an archive drew on the progress."""

    def __init__(self, progress: Progress | None) -> None:
        self.progress = progress
        self.received = 0
        self.resumed = 0

    def take_back(self) -> None:
        """Take a failed attempt's bytes off the progress."""
        if self.progress is not None:
            if self.received:
                self.progress.add(-self.received)
            if self.resumed:
                self.progress.add(-self.resumed)
                self.progress.forget_resumed(self.resumed)


def _archive_resume_point(url: str, keep: Path | None, note: Path | None) -> tuple[int, str]:
    """(bytes the kept archive holds, its validator) when its note names
    url, else (0, "")."""
    if keep is None or note is None:
        return 0, ""
    try:
        recorded = note.read_text(encoding="utf-8").split("\n")
        if recorded[0] == url and len(recorded) > 1 and recorded[1]:
            return keep.stat().st_size, recorded[1]
    except (OSError, UnicodeError):
        return 0, ""
    return 0, ""


def _archive_file(keep: Path | None, offset: int, directory: Path) -> IO[bytes]:
    """The file an attempt writes: the kept archive, or a scratch file in directory."""
    if keep is not None:
        return open(keep, "r+b" if offset else "wb")
    return tempfile.NamedTemporaryFile(dir=directory, suffix=".archive", delete=False)


def _receive_archive(
    resp: http.client.HTTPResponse, handle: IO[bytes], offset: int, url: str,
    note: Path | None, count: _ArchiveCount,
) -> None:
    """Write the response into handle, past offset when the server sent the rest."""
    headers: http.client.HTTPMessage | Mapping[str, str] = resp.headers or {}
    ranged = (offset and getattr(resp, "status", 200) == 206 and str(
        headers.get("Content-Range", "")).startswith(f"bytes {offset}-"))
    if not ranged:
        offset = 0
    handle.seek(offset)
    handle.truncate()
    if note is not None and not offset:
        # Written before the first byte: a cut transfer is then
        # resumed only against the revision it holds.
        note.write_text(f"{url}\n{_archive_validator(headers)}\n",
                        encoding="utf-8")
    progress = count.progress
    if progress is not None:
        length = headers.get("Content-Length", "")
        if length.isdigit():
            progress.expect(offset + int(length))
        if offset:
            progress.add(offset, resumed=True)
            count.resumed = offset
    total = offset
    while True:
        if _stop.is_set():
            raise _Interrupted()
        chunk = resp.read(1024 * 1024)
        if not chunk:
            break
        count.received += len(chunk)
        total += len(chunk)
        if total > MAX_DATA_ARCHIVE_SIZE:
            raise ValueError("archive exceeds the size limit")
        handle.write(chunk)
        if progress is not None:
            progress.add(len(chunk))


def _fetch_archive(url: str, directory: Path, progress: Progress | None = None,
                   keep: Path | None = None) -> Path:
    """A data directory's source archive, in *directory*, retried like files.
    progress draws its bytes as they come, an attempt that failed taken back.

    With keep, the archive is written there and kept when the transfer is
    cut, beside a note of its address and the validator its server sent:
    the next attempt, or the next run, asks for the rest with Range and
    If-Range, and a server that changed the archive sends it whole. A cut
    50 MB archive started again from zero, and a link that drops more often
    than one archive takes never installed the tree.
    """
    _network_allowed(url)
    note = keep.with_name(keep.name + ".source") if keep is not None else None
    reason: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        offset, validator = _archive_resume_point(url, keep, note)
        request = urllib.request.Request(url)
        if offset:
            request.add_header("Range", f"bytes={offset}-")
            request.add_header("If-Range", validator)
        handle = _archive_file(keep, offset, directory)
        count = _ArchiveCount(progress)
        try:
            with handle, urllib.request.urlopen(request, timeout=60) as resp:
                _receive_archive(resp, handle, offset, url, note, count)
            return keep if keep is not None else Path(handle.name)
        except urllib.error.HTTPError as exc:
            if keep is None or exc.code == 416 or exc.code < 500 and exc.code != 429:
                # Refused, or a range past an archive that shrank: no
                # attempt resumes it.
                _drop_archive(Path(handle.name), note)
            if exc.code < 500 and exc.code not in (416, 429):
                raise
            reason = exc
            # A range past an archive that shrank is asked again whole.
            delay = (_retry_delay(attempt, None) if exc.code == 416 and attempt < MAX_RETRIES
                     else _retry_after_failure(exc, attempt, MAX_RETRIES))
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            if keep is None:
                Path(handle.name).unlink(missing_ok=True)
            reason = exc if isinstance(exc, OSError) else ConnectionError(repr(exc))
            delay = _retry_after_failure(exc, attempt, MAX_RETRIES)
        except ValueError:
            _drop_archive(Path(handle.name), note)
            raise
        except BaseException:
            # Stopped: a kept archive waits for the next run.
            if keep is None:
                Path(handle.name).unlink(missing_ok=True)
            raise
        count.take_back()
        if delay is None:
            break
        time.sleep(delay)
    raise reason if reason else OSError("download failed")


def _drop_archive(path: Path, note: Path | None) -> None:
    """Remove an archive and the note of where it came from."""
    path.unlink(missing_ok=True)
    if note is not None:
        note.unlink(missing_ok=True)


def _tar_member(tf: tarfile.TarFile, member: tarfile.TarInfo) -> IO[bytes]:
    """The bytes of a regular file of a tarball, which extractfile always opens."""
    handle = tf.extractfile(member)
    assert handle is not None
    return handle


def _archive_members(
    archive: Path, entry: dict
) -> Iterator[tuple[str, int, Callable[[], IO[bytes]]]]:
    """(path in the tree, declared size, opener) for each file the archive
    maps into it.

    The rules refresh_data_dirs applies to build the cache: a ZIP drops
    strip_components leading parts, a tarball keeps what sits under
    source_path, and a first part named in exclude is left out.
    """
    exclude = set(entry.get("exclude") or [])
    if entry["type"] == "zip":
        strip = entry.get("strip_components", 0)
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                parts = info.filename.split("/")
                if ".." in parts or info.filename.startswith("/"):
                    continue
                if strip:
                    if len(parts) <= strip:
                        continue
                    parts = parts[strip:]
                if parts[0] in exclude:
                    continue
                yield "/".join(parts), info.file_size, functools.partial(zf.open, info)
        return
    prefix = entry["source_path"].rstrip("/") + "/"
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            if not member.isfile() or not member.name.startswith(prefix):
                continue
            rel = member.name[len(prefix):]
            if not rel or ".." in rel.split("/") or rel.split("/")[0] in exclude:
                continue
            yield rel, member.size, functools.partial(_tar_member, tf, member)


def _slot(entry: dict, rel: str) -> str:
    """A tree member's place below the BIOS folder, as the record names it."""
    return f"{entry['dest']}/{rel}" if entry.get("dest") else rel


def data_directory_state(entry: dict, bios_path: Path,
                         remember: bool = False) -> tuple[Path, dict[str, dict], int]:
    """(tree root, files missing or wrong, files already right). remember
    keeps what was read for the check after the line menu (_HEAD_READS).

    A rolling tree's file is right as the list hashes it or as an earlier
    run wrote it from the source (the install record): the source has moved
    on from the pack's copy, and that file is the newer one."""
    root = _destination_path(bios_path, entry["dest"]) if entry.get("dest") else bios_path.resolve()
    needed: dict[str, dict] = {}
    present = 0
    written = recorded_data_copies(bios_path) if entry.get("rolling") else {}
    for rel, meta in entry["files"].items():
        target = _destination_path(root, rel)
        accepted = {(meta["sha1"], meta["size"])} | written.get(_slot(entry, rel).casefold(), set())
        try:
            size = target.stat().st_size if target.is_file() else -1
            held = (any(size == known for _sha1, known in accepted)
                    and (_read_digests(target, ("sha1",), remember)["sha1"], size) in accepted)
        except OSError:
            held = False
        if held:
            present += 1
        else:
            needed[rel] = meta
    return root, needed, present


def data_space_bytes(data_states: list[tuple[dict, tuple[Path, dict[str, dict], int]]]) -> int:
    """What the data trees take on the drive while they are rebuilt: every
    file they lack, plus the largest source archive, which sits in its tree
    until that tree is read. Only the BIOS files were held against the free
    space: 18.8 KB passed on a card with 20 MB left, and 81.8 MB followed.
    Nothing is written for them offline without a pack."""
    if LOCAL.pack is None and _offline_only():
        return 0
    files = sum(meta.get("size", 0) for _entry, (_root, needed, _present) in data_states
                for meta in needed.values())
    if LOCAL.pack is not None:
        return files
    return files + max((data_fetch_bytes(entry, state[1]) for entry, state in data_states
                        if state[1]), default=0)


def data_fetch_bytes(entry: dict, needed: dict[str, dict]) -> int:
    """What getting a tree's missing files costs: its source archive, which
    comes whole for one file, or from a pack the files themselves. A list
    that records no archive size gives the files' own sizes: a tarball whose
    tree is 10 KB was announced as 10 KB and was a download of 21 MB."""
    if not needed:
        return 0
    size = entry.get("archive_size")
    if LOCAL.pack is None and isinstance(size, int) and size > 0:
        return size
    return sum(meta.get("size", 0) for meta in needed.values())


def install_data_directory(entry: dict, bios_path: Path,
                           state: tuple[Path, dict[str, dict], int] | None = None,
                           progress: Progress | None = None) -> dict:
    """Rebuild one data tree from its source archive, file by file verified.
    state is the tree's data_directory_state when the run already read it:
    each read hashes every file in place.

    A rolling tree (a source that names no revision, the buildbot's nightly
    assets) is written as its source serves it now, as RetroArch's own
    downloader writes it: a member whose bytes differ from the list is
    written all the same, read to the size its archive declares and, in a
    ZIP, checked against its CRC-32. A tree listed at a commit keeps only
    the listed bytes.

    Returns counts: present, installed, updated (of those installed, the
    ones a rolling source holds newer than the list), changed (the source
    no longer holds the recorded bytes), absent (not in the archive), error,
    the reason
    the archive could not be read, not_kept, the (path, reason) of each
    file in place that differs and could not be moved aside, left as it is,
    and written, each file written (dest below the BIOS folder, sha1, size).
    """
    root, needed, present = state or data_directory_state(entry, bios_path)
    needed = dict(needed)
    written: list[dict] = []
    not_kept: list[tuple[str, str]] = []
    tallies = {"installed": 0, "updated": 0, "changed": 0}
    # What a rolling tree may write in all: a nightly grows from one build to
    # the next, never to a drive's worth. The space check counted the list.
    budget = [_follow_cap(sum(meta["size"] for meta in needed.values()))]
    # From a pack, the pack's copy is the tree: nothing newer to follow.
    rolling = bool(entry.get("rolling")) and LOCAL.pack is None
    counts: dict[str, object] = {
        "present": present, "installed": 0, "updated": 0, "changed": 0, "absent": 0, "error": "",
        "not_kept": not_kept, "written": written}
    if not needed:
        return counts
    _writing.set()
    fetched: Path | None = None
    lock: BinaryIO | None = None
    lock_path = root / f".{entry['ref']}.archive.lock"
    members: Iterable[tuple[str, int, Callable[[], IO[bytes]]]]
    try:
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as scratch:
            if LOCAL.pack is not None:
                # The pack holds the tree where it extracts, already mapped.
                members = LOCAL.pack.tree(entry.get("dest", ""))
            else:
                # Beside the tree, outside the scratch folder: a transfer
                # cut short is resumed by the next attempt or the next run.
                # Two runs into one folder truncated or deleted the archive
                # the other was still writing or reading: the run that finds
                # it locked downloads into its scratch folder instead.
                lock = _claim_partial(lock_path)
                kept = root / f".{entry['ref']}.archive.part" if lock is not None else None
                archive = _fetch_archive(entry["url"], Path(scratch), progress, kept)
                fetched = archive
                members = _archive_members(archive, entry)
            for rel, declared, opener in members:
                meta = needed.pop(rel, None)
                if meta is None:
                    continue
                # Read no more than the list records: the archive's own size
                # field is checked first, and the stream is cut at the
                # expected size whatever the member claims, so a member that
                # inflates without end costs one byte past it. A rolling
                # source's member is cut at the size its archive declares.
                if declared != meta["size"] and not (rolling and _followable(meta, declared, budget)):
                    tallies["changed"] += 1
                    continue
                budget[0] -= declared
                target = _destination_path(root, rel)
                target.parent.mkdir(parents=True, exist_ok=True)
                slot = _slot(entry, rel)
                outcome, landed = _install_data_member(
                    opener, meta, target, bios_path, slot, rel, not_kept,
                    declared if rolling else None)
                if outcome:
                    tallies[outcome] += 1
                if outcome == "updated":
                    # Installed too: updated counts the newer ones among them.
                    tallies["installed"] += 1
                if landed is not None:
                    written.append({"dest": slot, **landed})
    except _Offline as exc:
        # Kept apart, so the advice is the offline one, not the network's.
        counts["error"] = OfflineReason(str(exc))
    except (urllib.error.URLError, OSError, ValueError, tarfile.TarError) as exc:
        # The tree's folder refused, not the source: said as the BIOS files
        # say it, never as an archive that could not be read.
        # A full drive is said as one too: "could not read <url>: [Errno
        # 28]" put the cause on the source, and the end said to run again.
        counts["error"] = (NOT_WRITABLE if isinstance(exc, OSError)
                           and not isinstance(exc, urllib.error.URLError)
                           and _write_refused(exc) and not _folder_writable(root)
                           else DRIVE_FULL if _drive_full(exc)
                           else str(getattr(exc, "reason", None) or exc))
    except _MEMBER_ERRORS as exc:
        # A damaged, encrypted or unsupported member, in words.
        counts["error"] = unreadable_words(exc)
    finally:
        if fetched is not None:
            # Read whole: the next run fetches the archive afresh.
            _drop_archive(fetched, fetched.with_name(fetched.name + ".source"))
        if lock is not None:
            _release_claim(lock, lock_path)
    counts["installed"] = tallies["installed"]
    counts["updated"] = tallies["updated"]
    counts["changed"] = tallies["changed"]
    counts["absent"] = len(needed)
    return counts


def _follow_cap(listed: int) -> int:
    """The most a rolling source may serve where the list records listed
    bytes: twice as much, and 16 MiB more for a file that was tiny."""
    return min(2 * listed + 16 * 1024 * 1024, MAX_DOWNLOAD_SIZE)


def _followable(meta: dict, declared: int, budget: list[int]) -> bool:
    """Whether a rolling source's member of declared bytes is written: within
    its own cap and what the tree has left to write."""
    return 0 <= declared <= min(_follow_cap(meta["size"]), budget[0])


def _install_data_member(
    opener: Callable[[], ContextManager[IO[bytes]]], meta: dict, target: Path,
    bios_path: Path, slot: str, rel: str, not_kept: list[tuple[str, str]],
    follow: int | None = None,
) -> tuple[str, dict | None]:
    """Write one member of a data tree's archive at target once its bytes
    are the recorded ones: ("installed", what landed), ("changed", None)
    when they are not, or ("", None) when the file in place could not be
    moved aside (named in not_kept). follow is the size a rolling source's
    archive declares for the member: its bytes land whatever they hash to,
    ("updated", what landed) when they are not the listed ones, and a
    stream that ends short of that size or runs past it is "changed".
    A read or write error is raised, and leaves no .part behind."""
    expected = meta["size"] if follow is None else follow
    scratch: Path | None = None
    try:
        digest = hashlib.sha1()
        size = 0
        with opener() as src, tempfile.NamedTemporaryFile(
            dir=target.parent, prefix=f".{target.name}.", suffix=".part", delete=False,
        ) as out:
            scratch = Path(out.name)
            # Read to the end, one byte past at most: a ZIP member checks
            # its CRC-32 when its stream ends, and raises when it differs.
            while size <= expected:
                chunk = src.read(min(1024 * 1024, expected + 1 - size))
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                out.write(chunk)
        sha1 = digest.hexdigest()
        listed = sha1 == meta["sha1"] and size == meta["size"]
        if size != expected or not (listed or follow is not None):
            return "changed", None
        _ready_to_place(scratch, target, executable=False)
        try:
            KEPT.keep(*_kept_slot(bios_path, slot), target, {"sha1": sha1})
        except _NotKept as exc:
            not_kept.append((rel, str(exc)))
            return "", None
        os.replace(scratch, target)
        scratch = None
        return ("installed" if listed else "updated"), {"sha1": sha1, "size": size}
    finally:
        if scratch is not None:
            scratch.unlink(missing_ok=True)


def select_data_directories(manifest: dict, files: list[dict], narrowed: bool,
                            required_only: bool = False,
                            games: GamesPlan | None = None,
                            systems: list[str] | None = None) -> list[dict]:
    """The data trees this install keeps: all, or those of a kept system.
    systems, the systems chosen by name, decide when given: a file several
    systems share named them all, and the arcade choice took blueMSX's
    machines through FBNeo's msx.zip, which the pack built with --system
    arcade leaves out.
    --required-only leaves out a tree every core reading it runs without
    (`optional`): a GBA and a SNES game took FBNeo's cheats and samples,
    3,472 files no game opened. For the games of a card, a tree only cores
    read (`cores`) is kept when the plan runs one of them, or runs a system
    of the tree on a core no setup names."""
    entries = [e for e in manifest.get("data_directories") or []
               if not (required_only and e.get("optional"))]
    if games is not None:
        entries = [e for e in entries if not e.get("cores")
                   or set(e["cores"]) & games.profiles
                   or set(e.get("systems") or []) & games.any_core]
    if not narrowed:
        return entries
    kept = (set(systems) if systems else
            {system for f in files for system in entry_systems(f)})
    # A tree no platform system serves goes with the files of none, as the
    # pack built with --system puts it in the part of its own.
    other = (OTHER_SYSTEMS in kept if systems else
             any(not entry_systems(f) for f in files))
    return [e for e in entries if kept & set(e.get("systems") or [])
            or (other and not e.get("systems"))]
