"""--from: the folders BIOS files are copied from, found by their hash."""
from __future__ import annotations

import argparse
import contextlib
import os
import sys
import threading
import zipfile
from collections.abc import Callable, Collection, Iterator
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from installer.console import SAID_FAILED
from installer.events import EVENTS
from installer.host_fs import _REPARSE_POINT
from installer.local_check import _digest_file, _digest_handle, _sha1_file
from installer.offline import LOCAL, local_manifest_platform
from installer.pack_source import _PART_FILE, PackSource
from installer.paths import _entry_path, _safe_relative_path, shown_path
from installer.platforms import display_name, normalize_platform
from installer.safe_replace import BACKUP_DIR, _MEMBER_ERRORS, _write_verified, unreadable_words
from installer.tally import _bytes
from installer.text import _plural, format_size, screen_text, shown_lines

if TYPE_CHECKING:
    from installer.console import Progress

FOLDER_IN_PLACE = "a folder sits where this file goes: move it away, then run again"


@contextlib.contextmanager
def _open_copy(copy: LocalCopy) -> Iterator[IO[bytes]]:
    """The bytes of a copy found on this machine, opened for reading only."""
    if not copy.member:
        with open(copy.path, "rb") as handle:
            yield handle
        return
    with copy.index.open_member(copy.path, copy.member) as handle:
        yield handle


def _copy_local(
    f: dict, bios_path: Path, dest: Path, copy: LocalCopy, progress: Progress | None,
) -> tuple[str, bool, str]:
    """Copy one file found on this machine to its place, checked like a
    download. Its bytes count as already here, not in the download speed."""
    return _write_verified(f, bios_path, dest, lambda: _open_copy(copy), progress,
                           f"the copy in {shown_path(copy.index.label)}", local=True,
                           named=copy.named())


# Files --check reads to tell why a file is refused: past these, the folder
# is not one a person filled by hand, and walking it costs more than it tells.
MAX_SCANNED_FILES = 200_000
_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar")
# Cores named on the line that says who opens a file, before "and N more".
SHOWN_CORES = 4


# Folders a system writes on a drive for itself. No BIOS file a person
# copied is in them, and a Mac's Spotlight index alone holds thousands.
SYSTEM_FOLDERS = frozenset(name.casefold() for name in (
    ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems",
    ".DocumentRevisions-V100", "System Volume Information", "$RECYCLE.BIN",
))
# A Mac copying to a FAT or exFAT card writes ._name beside every file: its
# Finder data, 4 KB, never the file.
APPLE_DOUBLE = "._"
# Folders the kernel makes up on the fly: endless, and never a copy.
PSEUDO_FOLDERS = frozenset() if os.name == "nt" else frozenset(("/proc", "/sys", "/dev"))


class LocalCopy:
    """A file found on this machine with the contents an entry wants."""

    def __init__(self, index: FolderIndex, path: Path, member: str = "",
                 misplaced: bool = False) -> None:
        self.index = index
        self.path = path
        # The member holding the bytes when path is a ZIP, else "".
        self.member = member
        # In the BIOS folder at a place no entry of the list names: a mistake
        # the copy fixes. A copy from another entry's place is no mistake.
        self.misplaced = misplaced

    def where(self) -> str:
        """The copy as the folder it was found in names it."""
        rel = self.index.relative(self.path)
        return screen_text(f"{rel}, inside as {self.member}" if self.member else rel)

    def named(self) -> str:
        """The copy by its full path, the member first when it is one."""
        return screen_text(f"{self.member} inside {self.path}" if self.member
                           else str(self.path))


# The archives a FolderIndex keeps open at once.
OPEN_ARCHIVES = 16


class FolderIndex:
    """The files under a folder, by name and by size, hashed on demand.

    The folder is only read. A link is followed only where it leads to a
    file inside the folder, so an old card holding a link to the home
    folder is not walked through it. A ZIP named as the root is read as a
    folder holding that one archive.
    """

    def __init__(self, root: Path, label: str = "") -> None:
        self.label = label or str(root)
        self.root = root = root.resolve()
        self.by_name: dict[str, list[Path]] = {}
        self.by_size: dict[int, list[Path]] = {}
        self.size: dict[Path, int] = {}
        self.archives: list[Path] = []
        # Name a ._ file stands beside (casefolded) -> the ._ files.
        self.apple_double: dict[str, list[Path]] = {}
        LOCAL.indexes.add(self)
        # The list's destinations, casefolded (an archive among them is not
        # unpacked for its members) and as the list writes them.
        self.sealed: set[str] = set()
        self.listed: set[str] = set()
        self.truncated = False
        self.copied = 0
        self.fixed = 0
        self._lock = threading.Lock()
        self._sha1: dict[Path, str] = {}
        self._digests: dict[tuple[Path, str, str], str] = {}
        self._members: dict[Path, list[str]] = {}
        self._member_sizes: dict[int, list[tuple[Path, str]]] | None = None
        # (size, casefolded name) -> the files and the ZIP members, built
        # the first time a copy is looked for.
        self._loose_named: dict[tuple[int, str], list[Path]] | None = None
        self._member_named: dict[int, dict[str, list[tuple[Path, str]]]] = {}
        self._scans: dict[tuple[str, int, str], _HashScan] = {}
        self._member_size: dict[tuple[Path, str], int] = {}
        # The archives read so far, open, the last read at the end: a ZIP
        # was opened again, its directory parsed again, for each member.
        self._zips: dict[Path, zipfile.ZipFile] = {}
        self._zip_lock = threading.Lock()
        # The places this run writes, resolved. An archive among them is
        # never kept open: Windows refuses to move aside or replace a file
        # a process holds, and a --from folder can hold the BIOS folder.
        self._written: set[Path] = set()
        # (path, member or "") -> (its size or None when unknown, why) of each
        # file, member or folder below root that could not be read.
        self.unreadable: dict[tuple[Path, str], tuple[int | None, str]] = {}
        # Folders below root on another drive, not entered.
        self.other_drives: list[Path] = []
        self.files = 0
        self._walk(root)

    def _walk(self, root: Path) -> None:
        """Index the files under root, a ZIP named as root as its one archive."""
        if root.is_file():
            if root.name.casefold().endswith(".zip"):
                self.archives.append(root)
                self.files = 1
            return
        seen = 0
        try:
            device = os.stat(root).st_dev
        except OSError as exc:
            self._unread(root, "", None, exc)
            return

        def unlisted(exc: OSError) -> None:
            self._unread(Path(exc.filename or root), "", None, exc)

        for folder, dirs, names in os.walk(root, onerror=unlisted):
            dirs[:] = sorted(d for d in dirs
                             if d != BACKUP_DIR and d.casefold() not in SYSTEM_FOLDERS
                             and self._enters(Path(folder) / d, device))
            for name in sorted(names):
                path = Path(folder) / name
                if name.startswith(APPLE_DOUBLE):
                    self.apple_double.setdefault(name[2:].casefold(), []).append(path)
                    continue
                if name.startswith(".") and name.endswith(".part"):
                    continue  # a download of this installer, not finished
                try:
                    if path.is_symlink() and not _inside(path, root):
                        continue
                    if not path.is_file():
                        continue
                    size = path.stat().st_size
                except OSError as exc:
                    self._unread(path, "", None, exc)
                    continue
                self.by_name.setdefault(name.casefold(), []).append(path)
                self.by_size.setdefault(size, []).append(path)
                self.size[path] = size
                if name.casefold().endswith(_ARCHIVE_SUFFIXES):
                    self.archives.append(path)
                seen += 1
                self.files = seen
                if seen >= MAX_SCANNED_FILES:
                    self.truncated = True
                    return

    def _enters(self, path: Path, device: int) -> bool:
        """Whether the walk goes into a folder: not a pseudo file system, a
        Windows junction or reparse point (a link the walk cannot tell from
        a folder, which led out of the folder named), nor another drive
        mounted below the root, which is named instead."""
        if str(path) in PSEUDO_FOLDERS:
            return False
        try:
            held = os.lstat(path)
        except OSError as exc:
            self._unread(path, "", None, exc)
            return False
        if getattr(held, "st_file_attributes", 0) & _REPARSE_POINT:
            return False
        if held.st_dev != device:
            self.other_drives.append(path)
            return False
        return True

    def _archive(self, path: Path) -> zipfile.ZipFile:
        """The archive at path, opened once. Called with _zip_lock held.

        A few stay open, the least recently read closed first: a card of
        MAME sets would otherwise hold a descriptor per archive. Closing
        one leaves a member being read open until it is closed itself.
        An archive this run writes is never read this way (see writes).
        """
        archive = self._zips.pop(path, None)
        if archive is None:
            archive = zipfile.ZipFile(path)
            while len(self._zips) >= OPEN_ARCHIVES:
                self._zips.pop(next(iter(self._zips))).close()
        self._zips[path] = archive
        return archive

    def writes(self, paths: Collection[Path]) -> None:
        """Note the places this run writes, resolved, and close the archives
        among them: the next read of one opens it and closes it at once."""
        with self._zip_lock:
            self._written.update(paths)
            for held in [held for held in self._zips if self._is_written(held)]:
                self._zips.pop(held).close()

    def _is_written(self, path: Path) -> bool:
        return bool(self._written) and (
            path in self._written or Path(os.path.realpath(path)) in self._written)

    def infolist(self, path: Path) -> list[zipfile.ZipInfo]:
        with self._zip_lock:
            if self._is_written(path):
                with zipfile.ZipFile(path) as archive:
                    return archive.infolist()
            return self._archive(path).infolist()

    @contextlib.contextmanager
    def open_member(self, path: Path, member: str) -> Iterator[IO[bytes]]:
        """A member of an archive under the folder, read from any thread."""
        with self._zip_lock:
            if self._is_written(path):
                archive = zipfile.ZipFile(path)
                try:
                    handle = archive.open(member)
                finally:
                    # The member holds the file until it is closed itself.
                    archive.close()
            else:
                handle = self._archive(path).open(member)
        try:
            yield handle
        finally:
            # The archive counts its open members: the count moves under
            # the lock, as when the member was opened.
            with self._zip_lock:
                handle.close()

    def open_archives(self) -> int:
        with self._zip_lock:
            return len(self._zips)

    def close(self) -> None:
        """Close the archives the index holds open."""
        with self._zip_lock:
            for archive in self._zips.values():
                archive.close()
            self._zips.clear()

    def seed(self, path: Path, sha1: str) -> None:
        """A SHA-1 already known, so the file is not read again."""
        self._sha1[path] = sha1

    def _unread(self, path: Path, member: str, size: int | None, exc: BaseException) -> None:
        """Note a file, a member or a folder that could not be read: a copy
        the run needs may be the one, and it is named instead of dropped."""
        self.unreadable.setdefault((path, member), (size, unreadable_words(exc)))

    def sha1(self, path: Path) -> str:
        if path not in self._sha1:
            try:
                self._sha1[path] = _sha1_file(path)
            except OSError as exc:
                self._unread(path, "", self.size.get(path), exc)
                self._sha1[path] = ""
        return self._sha1[path]

    def digest(self, path: Path, algorithm: str, member: str = "") -> str:
        """The file's (or the member's) digest, read once, "" when unreadable."""
        if algorithm == "sha1" and not member:
            return self.sha1(path)
        key = (path, member, algorithm)
        if key not in self._digests:
            try:
                if member:
                    with self.open_member(path, member) as handle:
                        value = _digest_handle(handle, (algorithm,))[algorithm]
                else:
                    value = _digest_file(path, (algorithm,))[algorithm]
            except _MEMBER_ERRORS as exc:
                size = self._member_size.get((path, member)) if member else self.size.get(path)
                self._unread(path, member, size, exc)
                value = ""
            self._digests[key] = value
        return self._digests[key]

    def unreadable_for(self, sizes: Collection[int]) -> list[tuple[Path, str, str]]:
        """(path, member, why) of what could not be read and may hold a file
        of one of sizes: its size is one of them, or unknown (a folder, an
        archive whose list of members could not be read)."""
        return sorted((path, member, why)
                      for (path, member), (size, why) in self.unreadable.items()
                      if size is None or size in sizes)

    def _scan(self, kind: str, size: int, algorithm: str) -> _HashScan:
        """The files (kind "loose") or ZIP members ("member") of one size,
        hashed in the order the folder was read, each read once."""
        key = (kind, size, algorithm)
        if key not in self._scans:
            if kind == "loose":
                self._scans[key] = _HashScan(
                    self.by_size.get(size, []), lambda path: self.digest(path, algorithm))
            else:
                self._scans[key] = _HashScan(
                    self._members_of_size(size),
                    lambda item: self.digest(item[0], algorithm, item[1]))
        return self._scans[key]

    def first_holding(self, sizes: set[int], sha1s: set[str]) -> Path | None:
        """The first file whose contents are one of sha1s, the smallest size
        first, read only when the size fits."""
        for size in sorted(sizes):
            path = self._scan("loose", size, "sha1").first(sha1s)
            if path is not None:
                return path
        return None

    def zip_members(self, path: Path) -> list[str]:
        if path not in self._members:
            try:
                # Read once and closed: the archive may be a file of the
                # list, which Windows will not replace while it is open.
                with zipfile.ZipFile(path) as archive:
                    self._members[path] = [n.rsplit("/", 1)[-1].casefold()
                                           for n in archive.namelist()]
            except (OSError, zipfile.BadZipFile):
                self._members[path] = []
        return self._members[path]

    def _members_of_size(self, size: int) -> list[tuple[Path, str]]:
        """(archive, member) of every ZIP member of that size, the
        archives' directories read once, the first time one is asked."""
        if self._member_sizes is None:
            self._member_sizes = {}
            for path in self.archives:
                if (not path.name.casefold().endswith(".zip")
                        or self.relative(path).casefold() in self.sealed):
                    continue
                try:
                    infos = self.infolist(path)
                except OSError as exc:
                    # A ZIP that will not open may hold anything: named. A
                    # damaged one is a download cut short, not a copy.
                    self._unread(path, "", None, exc)
                    continue
                except zipfile.BadZipFile:
                    continue
                for info in infos:
                    if not info.is_dir():
                        self._member_sizes.setdefault(info.file_size, []).append(
                            (path, info.filename))
                        self._member_size[(path, info.filename)] = info.file_size
        return self._member_sizes.get(size, [])

    def find(self, entry: dict, skip: Collection[Path] = ()) -> LocalCopy | None:
        """A copy of the entry's own contents: its size first, then its hash,
        loose files before ZIP members, a file of the same name first."""
        size = entry.get("size")
        if not isinstance(size, int) or isinstance(size, bool):
            return None
        algorithm = "sha1" if entry.get("sha1") else "sha256"
        wanted = str(entry.get(algorithm) or "").lower()
        if not wanted:
            return None
        name = str(entry.get("dest", "")).rsplit("/", 1)[-1].casefold()
        if self._loose_named is None:
            self._loose_named = {}
            for path, held in self.size.items():
                self._loose_named.setdefault((held, path.name.casefold()), []).append(path)
        for path in self._loose_named.get((size, name), []):
            if not _being_written(path, skip) and self.digest(path, algorithm) == wanted:
                return LocalCopy(self, path)
        path = self._scan("loose", size, algorithm).first({wanted}, skip)
        if path is not None:
            return LocalCopy(self, path)
        if size not in self._member_named:
            named = self._member_named[size] = {}
            for item in self._members_of_size(size):
                named.setdefault(item[1].rsplit("/", 1)[-1].casefold(), []).append(item)
        for archive, member in self._member_named[size].get(name, []):
            if (not _being_written(archive, skip)
                    and self.digest(archive, algorithm, member) == wanted):
                return LocalCopy(self, archive, member)
        held = self._scan("member", size, algorithm).first({wanted}, skip)
        if held is not None:
            return LocalCopy(self, held[0], held[1])
        return None

    def count_copy(self, misplaced: bool = False) -> None:
        with self._lock:
            if misplaced:
                self.fixed += 1
            else:
                self.copied += 1

    def relative(self, path: Path) -> str:
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            return str(path)
        return rel if rel != "." else path.name


def _being_written(path: Path, skip: Collection[Path]) -> bool:
    """Whether a file, or the archive holding a member, is one this run
    writes: its bytes are being replaced, so they are no source."""
    return bool(skip) and (path in skip or Path(os.path.realpath(path)) in skip)


class _HashScan:
    """Candidates of one size, hashed in order and each once, so finding
    the first that holds a digest never reads the earlier ones again: 3,000
    same-sized files and 3,000 entries of that size cost 3,000 reads, not
    nine million comparisons."""

    def __init__(self, items: list, digest: Callable[[Any], str]) -> None:
        self.items = items
        self.digest = digest
        self.read = 0
        self.at: dict[str, list[int]] = {}

    def first(self, wanted: Collection[str], skip: Collection[Path] = ()) -> Any:
        """The first candidate, in the folder's order, whose digest is one of
        wanted and that skip does not name, or None."""
        best = None
        for value in wanted:
            for position in self.at.get(value, ()):
                if not _being_written(self._holder(position), skip):
                    best = position if best is None else min(best, position)
                    break
        if best is not None:
            return self.items[best]
        while self.read < len(self.items):
            position = self.read
            self.read += 1
            value = self.digest(self.items[position])
            self.at.setdefault(value, []).append(position)
            if value in wanted and not _being_written(self._holder(position), skip):
                return self.items[position]
        return None

    def _holder(self, position: int) -> Path:
        item = self.items[position]
        return item[0] if isinstance(item, tuple) else item


class _ZippedLookup:
    """The archives of a folder not listed as files to install, by the
    folder holding them: each one's names read once, so telling that a
    missing file is still zipped costs two lookups and never a walk."""

    def __init__(self, index: FolderIndex, known: set[str]) -> None:
        self.index = index
        self._by_parent: dict[Path, list[tuple[int, Path]]] = {}
        for position, path in enumerate(index.archives):
            if index.relative(path).casefold() not in known:
                self._by_parent.setdefault(path.parent, []).append((position, path))
        # folder -> (member name -> first archive, stem -> first archive).
        self._maps: dict[Path, tuple[dict[str, tuple[int, Path]],
                                     dict[str, tuple[int, Path]]]] = {}

    def _folder(self, folder: Path) -> tuple[dict[str, tuple[int, Path]],
                                             dict[str, tuple[int, Path]]]:
        if folder not in self._maps:
            members: dict[str, tuple[int, Path]] = {}
            stems: dict[str, tuple[int, Path]] = {}
            for position, path in self._by_parent.get(folder, []):
                lowered = path.name.casefold()
                if lowered.endswith(".zip"):
                    for member in self.index.zip_members(path):
                        members.setdefault(member, (position, path))
                stems.setdefault(lowered.rsplit(".", 1)[0], (position, path))
            self._maps[folder] = (members, stems)
        return self._maps[folder]

    def reason(self, name: str, folders: Collection[Path]) -> str:
        """Why name is missing when an archive in folders holds it or carries
        its name: the first such archive in the order the folder was read,
        and one holding it before one carrying its name."""
        lowered = name.casefold()
        stem = lowered.rsplit(".", 1)[0]
        best: tuple[int, int, Path] | None = None
        for folder in folders:
            members, stems = self._folder(folder)
            for kind, held in ((0, members.get(lowered)), (1, stems.get(stem))):
                if held is not None and (best is None or (held[0], kind) < best[:2]):
                    best = (held[0], kind, held[1])
        if best is None:
            return ""
        where = self.index.relative(best[2])
        if best[1] == 0:
            return f"still zipped: it is inside {where}"
        return f"still zipped: {where} needs extracting"


def _inside(path: Path, root: Path) -> bool:
    """Whether a link at path leads to a place under root."""
    try:
        Path(os.path.realpath(path)).relative_to(root)
    except ValueError:
        return False
    return True


def _known_destinations(files: list[dict]) -> set[str]:
    return {str(f.get("dest", "")).casefold() for f in files}


def _place_reason(
    entry: dict, path: Path, index: FolderIndex, expected: Path, known: set[str],
    contents: str = "",
) -> tuple[str, str]:
    """(reason, folder too deep) for an entry's file found at path in the
    BIOS folder, or ("", "") when that place says nothing. contents is
    ", with other contents" for a file of the right name and wrong bytes."""
    dest = str(entry.get("dest", ""))
    name = dest.rsplit("/", 1)[-1]
    rel = index.relative(path)
    # A dest below the save directory is not below this folder: a copy
    # here under the same tail is in the wrong place, not too deep.
    below = entry.get("root") != "save"
    if below and rel.endswith("/" + dest) and path.name == name:
        extra = rel[: -len(dest) - 1]
        top = index.root.name
        if extra.casefold() == top.casefold():
            return (f"nested folder: it is at {top}/{rel}{contents}, a "
                    f"{top} folder inside {top}"), extra
        depth = extra.count("/") + 1
        levels = "one folder" if depth == 1 else f"{depth} folders"
        return f"{levels} too deep: it is at {rel}{contents}", extra
    if path.name.casefold() == name.casefold():
        if path.parent == expected.parent and path.name != name:
            return (f"case of the name: the folder holds {path.name}{contents}, "
                    f"the cores open {name}"), ""
        return f"wrong folder: it is at {rel}{contents}", ""
    if contents:
        return "", ""
    if rel.casefold() in known:
        return f"its contents are at {rel}: copy that file to {dest}", ""
    return f"a name no core opens: its contents are at {rel}, rename it {name}", ""


def _copy_reason(entry: dict, copy: LocalCopy, bios_path: Path, known: set[str]) -> str:
    """Why a copy found in the BIOS folder is not at the entry's place."""
    if not copy.misplaced:
        # np2kai/2608_bd.wav and np2/2608_bd.wav hold the same bytes. Told
        # "wrong folder", a user moved np2's copy and broke that core.
        return f"the same file is at {copy.where()}, where the list installs it too"
    if copy.member:
        return f"still zipped: it is inside {copy.index.relative(copy.path)}"
    try:
        copy.path.relative_to(copy.index.root)
    except ValueError:
        return f"one folder too high: it is at {copy.path}"
    try:
        expected = _entry_path(bios_path, entry)
    except ValueError:
        return ""
    return _place_reason(entry, copy.path, copy.index, expected, known)[0]


def _above(entry: dict, index: FolderIndex) -> LocalCopy | None:
    """The entry's file at its place one folder above the BIOS folder."""
    if entry.get("root") == "save" or index.root.parent == index.root:
        return None
    try:
        above = index.root.parent / _safe_relative_path(entry.get("dest"), "dest")
        if above.stat().st_size != entry.get("size") or not above.is_file():
            return None
    except (OSError, ValueError):
        return None
    algorithm = "sha1" if entry.get("sha1") else "sha256"
    if index.digest(above, algorithm) != str(entry.get(algorithm, "")).lower():
        return None
    return LocalCopy(index, above)


def plan_local_copies(
    entries: list[dict], bios_path: Path, bios_index: FolderIndex | None,
    folders: list[FolderIndex],
) -> dict[int, LocalCopy]:
    """id(entry) -> where this machine already holds the entry's bytes: the
    BIOS folder itself first, a file misplaced in it, then each folder named
    with --from in turn. Every copy is found by size, then by hash."""
    if not entries or (bios_index is None and not folders):
        return {}
    # A file this run replaces is no source: its place is being written.
    written = set()
    for entry in entries:
        try:
            written.add(Path(os.path.realpath(_entry_path(bios_path, entry))))
        except ValueError:
            continue
    for index in ([bios_index] if bios_index is not None else []) + folders:
        index.writes(written)
    copies: dict[int, LocalCopy] = {}
    for entry in entries:
        copy = None
        if bios_index is not None:
            copy = bios_index.find(entry, written) or _above(entry, bios_index)
            if copy is not None:
                copy = LocalCopy(copy.index, copy.path, copy.member,
                                 _misplaced(entry, copy, bios_index))
        for index in folders:
            if copy is not None:
                break
            copy = index.find(entry, written)
        if copy is not None:
            copies[id(entry)] = copy
    return copies


def _misplaced(entry: dict, copy: LocalCopy, index: FolderIndex) -> bool:
    """Whether a copy in the BIOS folder sits where no other entry of the
    list goes: GBA_BIOS.BIN for gba_bios.bin is a mistake, np2/2608_bd.wav
    for np2kai/2608_bd.wav is the other core's file."""
    if copy.member:
        return True
    rel = index.relative(copy.path)
    if rel in index.listed:
        return False
    own = str(entry.get("dest", "")).casefold()
    return rel.casefold() not in index.sealed or rel.casefold() == own


def _counts_by_folder(
    entries: list[dict], copies: dict[int, LocalCopy], bios_index: FolderIndex | None,
) -> list[tuple[str, int]]:
    """(folder, files) for each --from folder that gives some of entries."""
    counts: dict[str, int] = {}
    for entry in entries:
        copy = copies.get(id(entry))
        if copy is not None and copy.index is not bios_index:
            counts[copy.index.label] = counts.get(copy.index.label, 0) + 1
    return list(counts.items())


def copy_plan_lines(
    entries: list[dict], copies: dict[int, LocalCopy], bios_index: FolderIndex | None,
    bios_path: Path, files: list[dict], every: bool, planned: bool,
) -> list[str]:
    """The files a run copies from this machine, by folder: the misplaced
    ones with the reason each was not where its cores open it."""
    known = _known_destinations(files)
    # By --from folder, "" for the misplaced files and "=" for the ones the
    # BIOS folder holds at another entry's place.
    groups: dict[str, list[dict]] = {}
    for entry in entries:
        copy = copies.get(id(entry))
        if copy is not None:
            key = (copy.index.label if copy.index is not bios_index
                   else "" if copy.misplaced else "=")
            groups.setdefault(key, []).append(entry)
    lines = []
    for key in sorted(groups, key=lambda k: (k != "", k != "=")):
        chosen = groups[key]
        sized = f"{_plural(len(chosen), 'file')} ({format_size(_bytes(chosen))})"
        if key == "":
            head = (f"Would fix {sized} misplaced in the BIOS folder, copied where the "
                    "cores open them:" if planned else
                    f"Fixing {sized} misplaced in the BIOS folder: copied where the cores "
                    "open them, the copies found left as they are.")
        elif key == "=":
            head = (f"Would copy {sized} the BIOS folder already holds at another "
                    "place of the list:" if planned else
                    f"{sized} the BIOS folder already holds at another place of the list:")
        else:
            head = (f"Would copy {sized} from {shown_path(key)}:" if planned else
                    f"{sized} found in {shown_path(key)}, each one checked by hash:")
        lines.append(f"\n  {head}" if planned else f"  {head}")
        for entry in chosen if every else chosen[:10]:
            copy = copies[id(entry)]
            why = (_copy_reason(entry, copy, bios_path, known) if key == ""
                   else f"from {copy.where()}" if key == "=" else copy.where())
            lines.append(f"    {entry['dest']}: {why}" if why else f"    {entry['dest']}")
        if len(chosen) > 10 and not every:
            lines.append(f"    ... and {len(chosen) - 10} more (--verbose lists them all)")
    return shown_lines(lines)


def emit_copies(
    plat: str, entries: list[dict], copies: dict[int, LocalCopy],
    bios_index: FolderIndex | None, bios_path: Path, files: list[dict],
) -> None:
    """One found event per file this machine holds, before it is copied."""
    known = _known_destinations(files)
    for entry in entries:
        copy = copies.get(id(entry))
        if copy is None:
            continue
        reason = (_copy_reason(entry, copy, bios_path, known)
                  if copy.index is bios_index else "")
        EVENTS.emit("found", platform=plat, dest=entry["dest"], folder=copy.index.label,
                    path=str(copy.path), member=copy.member, reason=reason)


class Unreadable:
    """A file, ZIP member or folder below a --from folder that could not be
    read, and may be a file the run still needs."""

    def __init__(self, index: FolderIndex, path: Path, member: str, why: str) -> None:
        self.index = index
        self.path = path
        self.member = member
        self.why = why

    def line(self) -> str:
        where = f"{self.member} inside {self.path}" if self.member else str(self.path)
        return screen_text(f"{where} could not be read: {self.why}")


def unreadable_copies(
    entries: list[dict], copies: dict[int, LocalCopy], folders: list[FolderIndex],
) -> list[Unreadable]:
    """What the --from folders hold that could not be read, of the size of
    a file no copy was found for, or of no known size: dropped silently,
    a file a user had read as one to download."""
    sizes = {e["size"] for e in entries
             if id(e) not in copies and isinstance(e.get("size"), int)}
    if not sizes:
        return []
    return [Unreadable(index, *held) for index in folders
            for held in index.unreadable_for(sizes)]


def unreadable_lines(found: list[Unreadable], every: bool) -> list[str]:
    lines = [f"  {item.line()}" for item in (found if every else found[:10])]
    if len(found) > len(lines):
        lines.append(f"  ... and {len(found) - len(lines)} more could not be read "
                     "(--verbose lists them all)")
    return shown_lines(lines)


def emit_unreadable(plat: str, found: list[Unreadable]) -> None:
    for item in found:
        EVENTS.emit("unreadable", platform=plat, folder=item.index.label,
                    path=str(item.path), member=item.member, reason=item.why)


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
    """Take the file list and the pack this run was given, and the platform
    they are for when none is named."""
    LOCAL.reset()
    LOCAL.jobs = getattr(args, "jobs", 8) or 8
    SAID_FAILED.clear()
    _open_from_folders(getattr(args, "from", None) or [])
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
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    pack = LOCAL.pack
    parts = len(pack.files)
    print(f"  Pack: {pack.name}"
          + (f", {parts} parts" if parts > 1 or _PART_FILE.match(pack.files[0].name) else ""))
    spelled = pack.platforms()
    if args.platform is not None:
        plat = normalize_platform(args.platform, say=False)
        if spelled and plat not in spelled:
            print(f"Error: {pack.name} is a pack for "
                  f"{' and '.join(display_name(n) for n in spelled)}, not "
                  f"{display_name(plat)}.", file=sys.stderr)
            sys.exit(1)
    elif len(spelled) == 1:
        # Named by the pack, not by the user: the setups that read its list
        # are offered, as for a --manifest.
        args.platform = spelled[0]
        args.platform_from_list = True
    else:
        among = (" (" + ", ".join(spelled) + ")") if spelled else ""
        print(f"Error: name the platform {pack.name} is installed for with "
              f"--platform{among}.", file=sys.stderr)
        sys.exit(1)


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


def _open_from_folders(folders: list[Path]) -> None:
    """Read each folder named with --from, or stop on one that cannot be."""
    for folder in folders:
        label = str(folder)
        problem = from_folder_problem(label)
        if problem is not None:
            reason, what = problem
            message = f"{label} {what}: --from names the folder to copy BIOS files from"
            EVENTS.emit("error", stage="from", reason=reason, platform="", message=message)
            print(f"Error: {screen_text(message)}.", file=sys.stderr)
            sys.exit(1)
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
