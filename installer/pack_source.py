"""Packs read in place of the network, and the checked writes every copy goes through."""
from __future__ import annotations

import contextlib
import errno
import functools
import json
import os
import re
import sys
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO, ContextManager

from installer.arguments import PACK_NAME_END
from installer.constants import (
    AVAILABLE_PLATFORMS,
    MAX_MANIFEST_BYTES,
    PLATFORM_NAMES,
    _SHA1_RE,
    _UMASK,
    _Interrupted,
    _stop,
)
from installer.detect_os import _VERSION_TEXT
from installer.events import EVENTS
from installer.local_files import _digest_file
from installer.manifest import _validate_manifest, _validate_targets
from installer.offline import LOCAL
from installer.paths import _entry_place
from installer.probe import _exists, _is_file
from installer.record import KEPT, _NotKept, _clear_read_only, _kept_slot
from installer.terminal import Progress
from installer.text import _CONTROLS

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
# A file in place whose content differs, which could not be moved aside: it
# is left as it is rather than lost.
NOT_KEPT = "file in place could not be kept aside"


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


# A pack too large for one release file is published as ZIP parts
# (scripts/split_pack.py), each holding at its root a marker that names the
# pack, the part and every part with its size. Extracted with the files,
# the markers say which part a folder lacks.
_PART_FILE = re.compile(r"^(?P<stem>.+_BIOS_Pack)\.part(?P<index>\d+)of(?P<count>\d+)\.zip$")

MAX_PARTS = 999

# A system id as the file lists write them (sony-playstation, other).
_SYSTEM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")


class PackSource:
    """A pack already downloaded, whole or in parts, read in place of the network.

    Every file it gives is checked against the hashes the file list records,
    as a download is.
    """

    def __init__(self, paths: list[Path]) -> None:
        self.files = self._resolve(paths)
        first = _PART_FILE.match(self.files[0].name)
        self.name = f"{first['stem']}.zip" if first else self.files[0].name
        self.archives: list[zipfile.ZipFile] = []
        self.members: dict[str, tuple[zipfile.ZipFile, zipfile.ZipInfo]] = {}
        # The system titles and names the pack's list records, if any.
        self.names: dict[str, dict] = {}
        # What its platform's install list narrows by (systems, cores,
        # regions), None for a pack that does not say: the remedy for an
        # option the pack cannot apply names that list only when it can.
        self.list_records: frozenset | None = None
        # The version of the platform's list the pack was built from, "" for
        # a pack that does not record it.
        self.list_version = ""
        # The platform's install list and its cores per board, which a pack
        # built since carries: with them a pack alone narrows to a board as
        # the network list does. None for a pack that carries none.
        self.install_list: dict | None = None
        self.targets: dict | None = None
        try:
            for path in self.files:
                archive = zipfile.ZipFile(path)
                self.archives.append(archive)
                for info in archive.infolist():
                    if not info.is_dir():
                        self.members.setdefault(info.filename, (archive, info))
        except (OSError, zipfile.BadZipFile) as exc:
            self.close()
            raise ValueError(f"{path.name} cannot be read as a ZIP ({exc}). A download "
                             "cut short gives this: download it again.") from exc
        try:
            self.listed = self._pack_list()
        except ValueError:
            # A ZIP that is no pack: its archives closed, not left open.
            self.close()
            raise
        self.by_sha1 = {f["sha1"]: f["path"] for f in self.listed}

    @staticmethod
    def _resolve(paths: list[Path]) -> list[Path]:
        """The archives of one pack: a whole ZIP, or every one of its parts."""
        given: list[Path] = []
        for path in paths:
            if path.is_dir():
                given += sorted(p for p in path.iterdir()
                                if p.is_file() and p.name.endswith(".zip")
                                and "_BIOS_Pack" in p.name)
            elif path.is_file():
                given.append(path)
            else:
                # "X does not exist" named neither the option nor the packs
                # beside it, where a typo in the name is the usual cause.
                near = sorted(p.name for p in path.parent.glob("*_BIOS_Pack*.zip")
                              if p.is_file()) if path.parent.is_dir() else []
                beside = (f" The packs in {path.parent}: {', '.join(near[:3])}"
                          + (f" and {len(near) - 3} more" if len(near) > 3 else "") + "."
                          if near else "")
                raise ValueError(f"{path} does not exist: --from-pack names a pack ZIP, "
                                 f"its parts or the folder holding them.{beside}")
        if not given:
            raise ValueError(f"no pack ZIP in {', '.join(map(str, paths))}")
        packs: dict[str, list[Path]] = {}
        for path in given:
            part = _PART_FILE.match(path.name)
            packs.setdefault(f"{part['stem']}.zip" if part else path.name, []).append(path)
        if len(packs) > 1:
            raise ValueError(f"these are several packs ({', '.join(sorted(packs))}): "
                             "name the one to install from")
        name, chosen = next(iter(packs.items()))
        whole = [p for p in chosen if not _PART_FILE.match(p.name)]
        if whole:
            return whole[:1]
        counts = [int(part["count"]) for part in (_PART_FILE.match(p.name) for p in chosen)
                  if part is not None]
        count = counts[0]
        if count > MAX_PARTS or any(other != count for other in counts):
            raise ValueError(f"the parts of {name} disagree on how many there are")
        stem = name[: -len(".zip")]
        folders = list(dict.fromkeys(p.parent for p in chosen))
        found: list[Path] = []
        missing: list[str] = []
        for number in range(1, count + 1):
            part_name = f"{stem}.part{number}of{count}.zip"
            place = next((folder / part_name for folder in folders
                          if (folder / part_name).is_file()), None)
            if place is None:
                missing.append(part_name)
            else:
                found.append(place)
        if missing:
            where = ", ".join(map(str, folders))
            raise ValueError(f"{name} comes in {count} parts and {len(missing)} "
                             f"{'is' if len(missing) == 1 else 'are'} not in {where}: "
                             f"{', '.join(missing)}")
        return found

    def _pack_list(self) -> list[dict]:
        """The file list the pack carries, every file with its SHA-1 and size."""
        held = self.members.get("manifest.json")
        if held is None:
            raise ValueError(f"{self.name} holds no manifest.json. Name the file list "
                             "with --manifest.")
        archive, info = held
        if info.file_size > MAX_MANIFEST_BYTES:
            raise ValueError(f"the manifest.json of {self.name} exceeds "
                             f"{MAX_MANIFEST_BYTES} bytes")
        try:
            data = json.loads(archive.read(info).decode("utf-8"))
        except (OSError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"the manifest.json of {self.name} cannot be read: {exc}") from exc
        files = data.get("files") if isinstance(data, dict) else None
        if not isinstance(files, list):
            raise ValueError(f"the manifest.json of {self.name} lists no files")
        # What a pack built since records of its systems (generate_pack.py
        # pack_systems): --system and Choose systems then work with the pack
        # alone. An older pack records none, and is read as before.
        # A pack is a file anyone can hand over: an id or a name holding a
        # control character would reach the terminal as an escape, and is
        # dropped.
        records = data.get("list_records")
        if isinstance(records, list) and all(isinstance(axis, str) for axis in records):
            self.list_records = frozenset(records) & {"systems", "cores", "regions"}
        version = data.get("list_version")
        if isinstance(version, str) and _VERSION_TEXT.fullmatch(version):
            self.list_version = version
        if isinstance(data.get("install_list"), dict):
            self.install_list = data["install_list"]
        if data.get("targets") is not None:
            try:
                self.targets = _validate_targets(data["targets"])
            except ValueError:
                # Read as a pack that carries none: --target is then refused
                # with the reason, never applied from a broken list.
                self.targets = None
        for key in ("system_titles", "system_names"):
            held = data.get(key)
            if isinstance(held, dict):
                self.names[key] = {
                    system: value for system, value in held.items()
                    if _SYSTEM_ID.fullmatch(str(system)) and (
                        isinstance(value, str) and not _CONTROLS.search(value)
                        or isinstance(value, list) and all(
                            isinstance(name, str) and not _CONTROLS.search(name)
                            for name in value))}
        listed = []
        for item in files:
            if (
                isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and isinstance(item.get("sha1"), str)
                and _SHA1_RE.fullmatch(item["sha1"].lower())
                and isinstance(item.get("size"), int)
            ):
                entry = {"path": item["path"], "sha1": item["sha1"].lower(),
                         "size": item["size"]}
                systems = item.get("systems")
                if isinstance(systems, list) and all(
                        isinstance(name, str) and _SYSTEM_ID.fullmatch(name)
                        for name in systems):
                    entry["systems"] = list(systems)
                listed.append(entry)
        return listed

    def platforms(self) -> list[str]:
        """The platforms the pack's name spells, several for a grouped pack."""
        spelled = pack_name_platforms(self.name)
        # A pack made by --pack says its platform inside, which a name of
        # the user's, or a file renamed, does not change.
        named = (self.install_list or {}).get("platform")
        if named in AVAILABLE_PLATFORMS and named not in spelled:
            return [named]
        return spelled

    def manifest(self, plat: str) -> dict:
        """A file list for plat: the install list the pack carries, else one
        built from the pack's own, the same files at the same places, as
        extracting the pack would leave them, with the systems it records."""
        if self.install_list is not None and self.install_list.get("platform") == plat:
            return self.install_list
        return {
            "manifest_version": 2,
            "platform": plat,
            **({"version": self.list_version} if self.list_version else {}),
            **{key: value for key, value in self.names.items() if value},
            "files": [
                {"dest": f["path"], "sha1": f["sha1"], "size": f["size"],
                 "repo_path": f"bios/{f['path']}",
                 **({"systems": f["systems"]} if "systems" in f else {})}
                for f in self.listed
            ],
        }

    def find(self, entry: dict) -> tuple[zipfile.ZipFile, zipfile.ZipInfo] | None:
        """The member holding an entry's bytes: by its SHA-1 in the pack's list,
        else at its destination. The size has to agree either way."""
        sha1 = str(entry.get("sha1", "")).lower()
        for name in (self.by_sha1.get(sha1), entry.get("dest")):
            held = self.members.get(name) if isinstance(name, str) else None
            if held is not None and held[1].file_size == entry.get("size"):
                return held
        return None

    def tree(self, prefix: str) -> Iterator[tuple[str, int, Callable[[], IO[bytes]]]]:
        """(path in the tree, size, opener) of every member below prefix."""
        lead = f"{prefix.rstrip('/')}/" if prefix else ""
        for name, (archive, info) in self.members.items():
            if name.startswith(lead):
                yield name[len(lead):], info.file_size, functools.partial(archive.open, info)

    def close(self) -> None:
        for archive in self.archives:
            archive.close()
        self.archives = []


NOT_IN_PACK = "not in the pack"


def pack_name_platforms(name: str) -> list[str]:
    """The platforms a pack's name spells, as PackSource reads them."""
    if not name.endswith(PACK_NAME_END):
        return []
    stem = "_" + name[: -len(PACK_NAME_END)] + "_"
    return [plat for plat in AVAILABLE_PLATFORMS
            if f"_{PLATFORM_NAMES[plat].replace(' ', '_')}_" in stem]


def read_local_manifest(path: Path, plat: str) -> dict:
    """A file list saved on disk, checked as a downloaded one is."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        print(f"  Cannot read the file list {path}: {exc.strerror or exc}.", file=sys.stderr)
        sys.exit(1)
    try:
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError(f"it exceeds {MAX_MANIFEST_BYTES} bytes")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"not JSON ({exc})") from exc
        return _validate_manifest(data, plat)
    except ValueError as exc:
        EVENTS.emit("error", stage="manifest", reason="invalid", platform=plat,
                    message=f"the file list is not valid: {exc}")
        print(f"  The file list {path} is not valid for {plat}: {exc}", file=sys.stderr)
        sys.exit(1)


def _extract_from_pack(
    f: dict, bios_path: Path, dest: Path, progress: Progress | None,
) -> tuple[str, bool, str]:
    """Copy one file out of the pack, checked like a download."""
    pack = LOCAL.pack
    held = pack.find(f) if pack is not None else None
    if held is None:
        return f["dest"], False, NOT_IN_PACK
    archive, info = held
    return _write_verified(f, bios_path, dest, lambda: archive.open(info), progress,
                           "the pack", named=f"{info.filename} inside {archive.filename}")


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
