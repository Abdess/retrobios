"""--pack: a pack written for a card a computer fills."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import zipfile
import zlib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NamedTuple

from installer.arguments import PACK_NAME_END
from installer.choices import recorded_axes
from installer.console import OUTPUT, detail
from installer.datadirs import install_data_directory
from installer.download import download_files
from installer.events import EVENTS
from installer.filesystems import fat32_drive
from installer.from_folders import plan_local_copies
from installer.host_fs import DRIVE_FULL, _drive_full, _is_dir, _stop
from installer.lists import fetch_targets, local_targets
from installer.offline import LOCAL
from installer.pack_source import (
    _PART_FILE,
    _PART_MARKER,
    MAX_PARTS,
    pack_name_platforms,
    part_file_name,
    part_marker_name,
)
from installer.paths import shown_path
from installer.platforms import PLATFORM_NAMES, TARGET_PLATFORMS, display_name
from installer.safe_replace import BACKUP_DIR
from installer.text import _plural, format_size, screen_text

if TYPE_CHECKING:
    from installer.terminal import Terminal

MAX_MARKER_BYTES = 64 * 1024


class PackPart:
    """What one part's marker says, and the folder it was found in."""

    def __init__(self, pack: str, index: int, count: int,
                 parts: tuple[tuple[str, int], ...], folder: Path) -> None:
        self.pack = pack
        self.index = index
        self.count = count
        self.parts = parts
        self.folder = folder


def read_part_marker(path: Path) -> PackPart | None:
    """The marker at path, None when it is not one split_pack wrote."""
    match = _PART_MARKER.match(path.name)
    if match is None:
        return None
    try:
        with open(path, "rb") as handle:
            text = handle.read(MAX_MARKER_BYTES).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    pack = ""
    index = count = 0
    parts: list[tuple[str, int]] = []
    for line in text.splitlines():
        key, _sep, value = line.partition(":")
        value = value.strip()
        if key == "pack":
            pack = value
        elif key == "part":
            numbers = value.split(" of ")
            if len(numbers) == 2 and all(n.isdigit() for n in numbers):
                index, count = int(numbers[0]), int(numbers[1])
        elif key == "file":
            size, _space, name = value.partition(" ")
            if size.isdigit() and _PART_FILE.match(name.strip()):
                parts.append((name.strip(), int(size)))
    if (
        not pack.endswith("_BIOS_Pack.zip")
        or not 1 <= index <= count <= MAX_PARTS
        or len(parts) != count
        or (index, count) != (int(match["index"]), int(match["count"]))
    ):
        return None
    return PackPart(pack, index, count, tuple(parts), path.parent)


def find_part_markers(root: Path) -> list[PackPart]:
    """Markers in root and in the folders right below it.

    A part extracted into a folder named after itself (the default of
    several archive tools) leaves its marker one level down.
    """
    found: list[PackPart] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return found
    for entry in entries:
        if entry.is_file():
            marker = read_part_marker(entry)
            if marker:
                found.append(marker)
        elif entry.is_dir() and not entry.is_symlink() and entry.name != BACKUP_DIR:
            try:
                below = sorted(entry.iterdir())
            except OSError:
                continue
            for child in below:
                marker = read_part_marker(child) if child.is_file() else None
                if marker:
                    found.append(marker)
    return found


def split_pack_lines(root: Path) -> list[str]:
    """What --check says about the parts of a pack extracted into root: one
    missing, or one extracted into a folder of its own."""
    by_pack: dict[str, list[PackPart]] = {}
    for marker in find_part_markers(root):
        by_pack.setdefault(marker.pack, []).append(marker)
    lines: list[str] = []
    for pack, markers in sorted(by_pack.items()):
        listed = max(markers, key=lambda m: m.count)
        here = {m.index for m in markers if m.folder == root and m.count == listed.count}
        missing = [n for n in range(1, listed.count + 1) if n not in here]
        deep = sorted({m.folder for m in markers if m.folder != root})
        if not missing and not deep:
            continue
        lines.append(f"\n  {pack} comes in {listed.count} parts, all needed.")
        for folder in deep:
            names = sorted(m.index for m in markers if m.folder == folder)
            which = ", ".join(str(n) for n in names)
            lines.append(f"    {'Parts' if len(names) > 1 else 'Part'} {which} went into "
                         f"{folder}, a folder of its own: move what it holds up into {root}.")
        absent = [n for n in missing
                  if not any(m.index == n and m.folder != root for m in markers)]
        for number in absent:
            name, size = listed.parts[number - 1]
            lines.append(f"    missing: part {number}, {name} ({format_size(size)})")
        if absent:
            lines.append(f"    Download {'it' if len(absent) == 1 else 'them'} and extract "
                         f"into {root}, beside the other parts.")
    return lines


PACK_MEMBER_DATE = (1980, 1, 1, 0, 0, 0)
PACK_COMPRESSLEVEL = 9
# FAT32 holds no file of 4 GiB or more (its size field is 32 bits). A pack
# that would pass that on such a drive is written in parts of at most this
# many bytes, the margin keeping each well under.
FAT_FILE_LIMIT = 4 * 1024 ** 3 - 1
FAT_PART_BYTES = 4 * 1024 ** 3 - 64 * 1024 ** 2

# The marker each part carries at its root, as scripts/split_pack.py writes
# it: the sizes at a fixed width, so its length does not depend on them.
PART_SIZE_WIDTH = 13
# A member may grow under deflate (zlib's deflateBound is under one byte in
# a thousand, plus a few), and its headers carry a ZIP64 field past 2 GiB.
# A part is planned on these bounds, never on the compressed size, which is
# known only once written.
_ZIP_LOCAL_BYTES = 30 + 20
_ZIP_CENTRAL_BYTES = 46 + 28
_ZIP_END_BYTES = 22 + 56 + 20


class PackError(Exception):
    """A pack that cannot be made as asked. left names the files a failure
    could not take away, none when nothing was left behind."""

    def __init__(self, words: str, left: list[Path] | None = None) -> None:
        super().__init__(words)
        self.left = list(left or [])


class PackWritten(NamedTuple):
    """What write_pack did: the files of the pack, the earlier files of
    its name it removed, and those it could not remove or left as they
    are, each with the reason."""

    files: list[Path]
    removed: list[Path]
    kept: list[tuple[Path, str]]


class PackMember(NamedTuple):
    """One member of a pack being made: its name, the bytes it must hold
    and the file they are read from."""

    name: str
    sha1: str
    size: int
    source: Path


def pack_default_name(plat: str, narrowed: bool) -> str:
    """<Platform>_BIOS_Pack.zip, with _Custom when the choice narrows the
    list, as generate_pack.py names a narrowed pack."""
    stem = PLATFORM_NAMES.get(plat, plat).replace(" ", "_")
    return f"{stem}{'_Custom' if narrowed else ''}{PACK_NAME_END}"


def pack_path(given: Path, plat: str, narrowed: bool) -> Path:
    """The pack --pack names: the file given, or the default name inside a
    folder given."""
    path = Path(os.path.expanduser(str(given)))
    if _is_dir(path) or str(given).endswith(("/", os.sep)):
        path = path / pack_default_name(plat, narrowed)
    return path.absolute()


def pack_layout(files: list[dict], data_dirs: list[dict]) -> tuple[
        dict[str, tuple[str, int]], list[dict], dict[str, dict]]:
    """Where each file of the choice goes in the pack: the members, by name,
    with their SHA-1 and size, the list manifest.json carries (path, sha1,
    size, systems) of the BIOS files, and the entry each member that no
    data tree holds is fetched as.

    A data tree's files take the path the reader looks under. A BIOS file
    is stored once by its SHA-1: at its dest, a file of another root (the
    save directory, an emulator's folder) under the root's name, and below
    by-sha1/ when another file already holds that name. A BIOS file whose
    bytes a tree holds is read from the tree's member."""
    members: dict[str, tuple[str, int]] = {}
    for entry in data_dirs:
        lead = f"{str(entry.get('dest') or '').rstrip('/')}/" if entry.get("dest") else ""
        for rel, meta in sorted((entry.get("files") or {}).items()):
            members.setdefault(f"{lead}{rel}", (str(meta["sha1"]), int(meta["size"])))
    by_sha1: dict[str, str] = {}
    for name, (sha1, _size) in sorted(members.items()):
        by_sha1.setdefault(sha1, name)
    systems: dict[str, set[str]] = {}
    listed: set[str] = set()
    sources: dict[str, dict] = {}
    for entry in sorted(files, key=lambda f: (str(f.get("root") or ""), str(f["dest"]))):
        sha1 = str(entry["sha1"]).lower()
        systems.setdefault(sha1, set()).update(entry.get("systems") or [])
        if sha1 not in by_sha1:
            root = str(entry.get("root") or "")
            name = f"{root}/{entry['dest']}" if root else str(entry["dest"])
            if name in members:
                name = f"by-sha1/{sha1}/{PurePosixPath(str(entry['dest'])).name}"
            members[name] = (sha1, int(entry["size"]))
            by_sha1[sha1] = name
            sources[name] = entry
        listed.add(by_sha1[sha1])
    rows = []
    for name in sorted(listed):
        sha1, size = members[name]
        row: dict = {"path": name, "sha1": sha1, "size": size}
        if systems.get(sha1):
            row["systems"] = sorted(systems[sha1])
        rows.append(row)
    return members, rows, sources


def pack_install_list(manifest: dict, files: list[dict], omitted: list[dict],
                      data_dirs: list[dict]) -> dict:
    """The platform's list narrowed to the choice, which the pack carries:
    --from-pack with no option installs what the choice kept, the same
    files at the same places."""
    narrowed = {key: value for key, value in manifest.items()
                if key not in ("files", "case_variants", "omitted_files",
                               "data_directories")}
    narrowed["files"] = [entry for entry in files if not entry.get("case_variant")]
    variants = [{key: value for key, value in entry.items() if key != "case_variant"}
                for entry in files if entry.get("case_variant")]
    if variants or "case_variants" in manifest:
        narrowed["case_variants"] = variants
    narrowed["omitted_files"] = list(omitted)
    if data_dirs or "data_directories" in manifest:
        narrowed["data_directories"] = list(data_dirs)
    return narrowed


def pack_manifest(plat: str, install_list: dict, rows: list[dict],
                  targets: dict | None) -> bytes:
    """manifest.json of a pack made here, as --from-pack reads it."""
    records = recorded_axes(install_list.get("files", []),
                            install_list.get("omitted_files", []))
    data: dict = {"platform": plat, "files": rows}
    for key in ("system_titles", "system_names"):
        if install_list.get(key):
            data[key] = install_list[key]
    data["list_records"] = sorted(records)
    if install_list.get("version"):
        data["list_version"] = install_list["version"]
    data["install_list"] = install_list
    if targets is not None:
        data["targets"] = targets
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _member_bound(name: str, size: int) -> int:
    """The most bytes a member can take in a part: both headers and its
    data deflated at worst."""
    encoded = len(name.encode("utf-8"))
    return _ZIP_LOCAL_BYTES + _ZIP_CENTRAL_BYTES + 2 * encoded + size + size // 1000 + 64


def pack_bound(manifest_size: int, members: list[PackMember]) -> int:
    """The most bytes the pack can take as one ZIP."""
    return (_ZIP_END_BYTES + _member_bound("manifest.json", manifest_size)
            + sum(_member_bound(member.name, member.size) for member in members))


def part_marker_text(name: str, index: int, sizes: list[int]) -> bytes:
    """The marker of part index, in the words scripts/split_pack.py writes
    and read_part_marker reads back."""
    count = len(sizes)
    lines = [
        "RetroBIOS split pack",
        f"This folder holds part {index} of {count} of {name}.",
        "Every part is needed: extract them all into this same folder.",
        "The installer's --check names a part missing from the folder.",
        "",
        f"pack: {name}",
        f"part: {index} of {count}",
    ]
    lines += [f"file: {size:>{PART_SIZE_WIDTH}} {part_file_name(name, number, count)}"
              for number, size in enumerate(sizes, 1)]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _marker_bound(name: str, count: int) -> int:
    marker = len(part_marker_name(name, count, count).encode("utf-8"))
    return 30 + 46 + 2 * marker + len(part_marker_text(name, count, [0] * count))


def plan_pack_parts(name: str, manifest_size: int, members: list[PackMember],
                    limit: int | None) -> list[list[PackMember]]:
    """The members of each part, in pack order, manifest.json in the first.
    One part without a limit, or when the whole pack stays under it. Each
    part's bound stays under the limit, room kept for its marker, the plan
    made again until the count it assumed is the count it gives."""
    if limit is None or pack_bound(manifest_size, members) < limit:
        return [list(members)]
    count = 2
    while True:
        floor = _ZIP_END_BYTES + _marker_bound(name, count)
        parts: list[list[PackMember]] = [[]]
        size = floor + _member_bound("manifest.json", manifest_size)
        if size >= limit:
            raise PackError(f"the list alone needs {format_size(size)}, more than a part "
                            f"of {format_size(limit)} holds")
        for member in members:
            weight = _member_bound(member.name, member.size)
            if floor + weight >= limit:
                raise PackError(f"{member.name} ({format_size(member.size)}) does not fit "
                                f"in a part of {format_size(limit)}")
            if size + weight >= limit or len(parts[-1]) >= 0xFFFE:
                parts.append([])
                size = floor
            parts[-1].append(member)
            size += weight
        if len(parts) > MAX_PARTS:
            raise PackError(f"the pack would take {len(parts)} parts, more than "
                            f"{MAX_PARTS}: give a larger size")
        if len(parts) <= count:
            return parts
        count = len(parts)


# ZipInfo's level is private before Python 3.13 (compress_level there, the
# old name kept as its alias), so typeshed does not declare it.
_ZIPINFO_LEVEL = "_compresslevel"


def _pack_info(name: str, compress: int = zipfile.ZIP_DEFLATED) -> zipfile.ZipInfo:
    """A member header that depends on its name alone."""
    info = zipfile.ZipInfo(name, date_time=PACK_MEMBER_DATE)
    info.compress_type = compress
    # A ZipInfo given to writestr or open keeps its own level, the
    # archive's left unread: without it every member was deflated at 6.
    setattr(info, _ZIPINFO_LEVEL,
            PACK_COMPRESSLEVEL if compress == zipfile.ZIP_DEFLATED else None)
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _write_member(archive: zipfile.ZipFile, member: PackMember) -> None:
    """Copy one member into the archive, its SHA-1 and size checked on the
    bytes written, before the archive is closed."""
    info = _pack_info(member.name)
    info.file_size = member.size
    digest = hashlib.sha1()
    size = 0
    with open(member.source, "rb") as src, archive.open(info, "w") as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            out.write(chunk)
    if size != member.size or digest.hexdigest() != member.sha1:
        raise PackError(f"{member.name} does not match the list: {size} bytes of SHA-1 "
                        f"{digest.hexdigest()}, the list says {member.size} of "
                        f"{member.sha1}")


def _patch_marker(path: Path, marker: str, body: bytes) -> None:
    """Write the real marker over its placeholder of the same length: the
    data, and the CRC-32 of the local and the central header."""
    with zipfile.ZipFile(path) as archive:
        first = archive.infolist()[0]
        central = int(archive.start_dir)
    if first.filename != marker or first.file_size != len(body) or first.header_offset:
        raise PackError(f"{path.name} does not start with its marker")
    crc = zlib.crc32(body).to_bytes(4, "little")
    with open(path, "r+b") as handle:
        local = handle.read(30)
        if local[:4] != b"PK\x03\x04":
            raise PackError(f"{path.name} has no local header at its start")
        data = (30 + int.from_bytes(local[26:28], "little")
                + int.from_bytes(local[28:30], "little"))
        handle.seek(14)
        handle.write(crc)
        handle.seek(data)
        handle.write(body)
        handle.seek(central)
        if handle.read(4) != b"PK\x01\x02":
            raise PackError(f"{path.name} has no central directory where it says")
        handle.seek(central + 16)
        handle.write(crc)


def _part_contents(name: str, index: int, count: int, manifest: bytes,
                   chosen: list[PackMember]) -> list[tuple[str, int]]:
    """(name, size) of each member of a part, in the order written."""
    held = ([(part_marker_name(name, index, count),
              len(part_marker_text(name, index, [0] * count)))] if count > 1 else [])
    held += [("manifest.json", len(manifest))] if index == 1 else []
    return held + [(member.name, member.size) for member in chosen]


def _discard(paths: Iterable[Path]) -> list[Path]:
    """Delete each file, the ones that could not be deleted returned."""
    left = []
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            left.append(path)
    return left


def _of_this_pack(path: Path, name: str) -> bool:
    """Whether path is a regular file that is a pack of this name: a part
    whose marker names it, or a ZIP holding a manifest.json."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            markers = [member for member in names if _PART_MARKER.match(member)]
            if markers:
                text = archive.read(markers[0])[:MAX_MARKER_BYTES].decode("utf-8", "replace")
                return f"pack: {name}" in text.splitlines()
            return "manifest.json" in names
    except (OSError, zipfile.BadZipFile, ValueError):
        return False


def _aside_name(path: Path) -> Path:
    """A name beside path no file holds, for the earlier pack while the
    new one takes its place."""
    for number in range(1000):
        aside = path.with_name(f".{path.name}.{os.getpid()}.{number}.old")
        if not os.path.lexists(aside):
            return aside
    raise PackError(f"no free name beside {path.name} to set it aside")


def write_pack(path: Path, manifest: bytes, members: list[PackMember],
               limit: int | None) -> PackWritten:
    """Write the pack at path, or in parts beside it when a limit is given
    and the pack would pass it.

    Each file is written beside its final name, every member checked
    against its SHA-1 and the archive read back with its CRCs. Then the
    earlier files of this pack (whole, or in parts) are set aside, the new
    ones renamed in, and the earlier ones deleted. A failure before the new
    set is whole puts the earlier set back and deletes the new files: the
    folder holds the pack before or the pack after, never a mix. A file
    deleted at the end that cannot be is reported, the pack being written."""
    name = path.name
    plan = plan_pack_parts(name, len(manifest), members, limit)
    count = len(plan)
    finals = ([path] if count == 1 else
              [path.with_name(part_file_name(name, index, count))
               for index in range(1, count + 1)])
    scratches: list[Path] = []
    try:
        for index, (final, chosen) in enumerate(zip(finals, plan), 1):
            handle, made = tempfile.mkstemp(prefix=f".{final.name}.", suffix=".partial",
                                            dir=str(path.parent))
            os.close(handle)
            scratches.append(Path(made))
            with zipfile.ZipFile(made, "w", zipfile.ZIP_DEFLATED,
                                 compresslevel=PACK_COMPRESSLEVEL) as archive:
                if count > 1:
                    archive.writestr(
                        _pack_info(part_marker_name(name, index, count), zipfile.ZIP_STORED),
                        part_marker_text(name, index, [0] * count))
                if index == 1:
                    archive.writestr(_pack_info("manifest.json"), manifest)
                for member in chosen:
                    if _stop.is_set():
                        raise KeyboardInterrupt
                    _write_member(archive, member)
        sizes = [scratch.stat().st_size for scratch in scratches]
        if count > 1:
            for index, scratch in enumerate(scratches, 1):
                _patch_marker(scratch, part_marker_name(name, index, count),
                              part_marker_text(name, index, sizes))
        for index, (scratch, chosen) in enumerate(zip(scratches, plan), 1):
            shown = finals[index - 1].name
            with zipfile.ZipFile(scratch) as archive:
                held = [(info.filename, info.file_size) for info in archive.infolist()]
                damaged = archive.testzip()
                if damaged is not None:
                    raise PackError(f"{shown}: {damaged} does not read back")
                if count > 1 and archive.read(part_marker_name(name, index, count)) != \
                        part_marker_text(name, index, sizes):
                    raise PackError(f"{shown}: its marker does not read back")
            if held != _part_contents(name, index, count, manifest, chosen):
                raise PackError(f"{shown} does not read back as written")
            if limit is not None and count > 1 and sizes[index - 1] >= limit:
                raise PackError(f"{shown} reached the limit of {format_size(limit)}")
    except BaseException as exc:
        left = _discard(scratches)
        if left and isinstance(exc, (OSError, PackError)):
            raise PackError(str(exc), left) from exc
        raise
    return _swap_in(path, scratches, finals)


def _swap_named(path: Path, finals: list[Path]) -> list[Path]:
    """The files beside path that the new pack may replace."""
    stem = path.name[: -len(".zip")]
    named: list[Path] = []
    for old in _listed_paths(path.parent):
        part = _PART_FILE.match(old.name)
        if old == path or old in finals or (part is not None and part["stem"] == stem):
            named.append(old)
    return named


def _swap_restore(exc: OSError | PackError, name: str, scratches: list[Path],
                  finals: list[Path], aside: list[tuple[Path, Path]],
                  placed: list[Path]) -> PackError:
    """Undo a swap that failed: the new files discarded, the earlier pack put
    back where it can be."""
    left = _discard([*placed, *(scratch for scratch, final in zip(scratches, finals)
                                if final not in placed)])
    unrestored = []
    for old, moved in reversed(aside):
        try:
            os.replace(moved, old)
        except OSError:
            unrestored.append((old, moved))
    words = f"{name} could not be put in place: {exc.strerror or exc}" \
        if isinstance(exc, OSError) else str(exc)
    if unrestored:
        words += ". The earlier pack is set aside as " + ", ".join(
            f"{moved.name} (was {old.name})" for old, moved in unrestored)
    return PackError(words, [*left, *(moved for _old, moved in unrestored)])


def _swap_in(path: Path, scratches: list[Path], finals: list[Path]) -> PackWritten:
    """Put the new files in place of the earlier pack of this name."""
    name = path.name
    named = _swap_named(path, finals)
    kept: list[tuple[Path, str]] = []
    earlier: list[Path] = []
    aside: list[tuple[Path, Path]] = []
    placed: list[Path] = []
    try:
        for old in named:
            if old in finals:
                if not stat.S_ISREG(os.lstat(old).st_mode):
                    raise PackError(f"{old.name} is in the way and is not a file")
                earlier.append(old)
            elif _of_this_pack(old, name):
                earlier.append(old)
            else:
                kept.append((old, "it is not a part of this pack, left as it is"))
        for old in earlier:
            moved = _aside_name(old)
            os.replace(old, moved)
            aside.append((old, moved))
        for scratch, final in zip(scratches, finals):
            os.replace(scratch, final)
            placed.append(final)
    except (OSError, PackError) as exc:
        raise _swap_restore(exc, name, scratches, finals, aside, placed) from exc
    removed = []
    for old, moved in aside:
        if old in finals:
            if _discard([moved]):
                kept.append((moved, "the earlier copy could not be deleted"))
            continue
        if _discard([moved]):
            kept.append((moved, f"the earlier {old.name}, set aside, could not be deleted"))
        else:
            removed.append(old)
    return PackWritten(finals, removed, kept)


def _listed_paths(folder: Path) -> list[Path]:
    """The files of a folder, [] when it cannot be listed."""
    return [folder / name for name in sorted(_listed(folder))]


def _pack_targets(plat: str) -> dict | None:
    """The cores per board the pack carries, as a pack built by the
    repository does: the list at hand offline, else the one fetched. None
    for a platform that publishes none, or a list that cannot be read."""
    if plat not in TARGET_PLATFORMS:
        return None
    if LOCAL.offline:
        return local_targets(plat)
    with contextlib.redirect_stderr(io.StringIO()):
        return fetch_targets(plat)


def _pack_event(plat: str, path: Path, members: dict[str, tuple[str, int]],
                parts: list[Path], status: str, message: str, size: int = 0) -> None:
    EVENTS.emit("pack", platform=plat, path=str(path), files=len(members),
                bytes=sum(length for _sha1, length in members.values()), size=size,
                parts=[str(part) for part in parts], status=status, message=message)


def _pack_refused(plat: str, path: Path, words: str, code: int,
                  members: dict[str, tuple[str, int]] | None = None) -> int:
    """Say why no pack is made, the event saying it too: code."""
    print(f"Error: {screen_text(words)}. No pack was written.", file=sys.stderr)
    _pack_event(plat, path, members or {}, [], "failed", f"{words}.")
    return code


def pack_parts_words(count: int, limit: int | None, fat: bool) -> str:
    """How the pack is written, in one line: whole, or in parts and why."""
    if count == 1:
        return "One ZIP."
    each = f"In {count} parts of at most {format_size(limit or 0)}"
    return f"{each}, as FAT32 holds no file of 4 GB." if fat else f"{each}."


def pack_space_bytes(files: int, bound: int, data_dirs: list[dict]) -> int:
    """What making a pack takes on its drive: the files fetched, the ZIP at
    its largest, and the largest source archive of a data tree, which is
    downloaded whole beside its tree until the tree is read. A pack read
    as the source fetches no archive."""
    archives = [int(entry.get("archive_size") or 0) for entry in data_dirs
                if entry.get("files") and isinstance(entry.get("archive_size"), int)]
    return files + bound + (max(archives, default=0) if LOCAL.pack is None else 0)


def run_pack(args: argparse.Namespace, plat: str, manifest: dict, files: list[dict],
             omitted: list[dict], data_dirs: list[dict], narrowed: bool,
             term: Terminal) -> int:
    """--pack: the choice downloaded into a pack instead of a folder, every
    member checked against its SHA-1 before the ZIP is closed. Returns the
    exit code: 0 once written (or listed with --dry-run), 1 when a file
    could not be had or the pack written, 2 when nothing was tried."""
    path = pack_path(args.pack, plat, narrowed)
    display = display_name(plat, manifest)
    if not path.name.endswith(PACK_NAME_END):
        return _pack_refused(plat, path, f"{path.name} does not end with {PACK_NAME_END}, "
                             "which --from-pack and the parts of a pack read", 2)
    if not _is_dir(path.parent):
        return _pack_refused(plat, path, f"the folder {shown_path(path.parent)} does not "
                             "exist", 2)
    spelled = pack_name_platforms(path.name)
    if spelled and plat not in spelled:
        return _pack_refused(plat, path, f"{path.name} names a pack for "
                             f"{' and '.join(display_name(name) for name in spelled)}, and "
                             f"this one is for {display_name(plat)}", 2)
    members, rows, sources = pack_layout(files, data_dirs)
    if not members:
        return _pack_refused(plat, path, "the choice keeps no file to put in a pack", 2)
    body = pack_manifest(plat, pack_install_list(manifest, files, omitted, data_dirs), rows,
                         _pack_targets(plat))
    planned = [PackMember(name, sha1, size, Path())
               for name, (sha1, size) in sorted(members.items())]
    fat = fat32_drive(path.parent)
    limit = args.split
    if fat and (limit is None and pack_bound(len(body), planned) > FAT_FILE_LIMIT
                or limit is not None and limit > FAT_PART_BYTES):
        limit = FAT_PART_BYTES
    try:
        plan = plan_pack_parts(path.name, len(body), planned, limit)
    except PackError as exc:
        return _pack_refused(plat, path, str(exc), 2, members)
    count = len(plan)
    finals = ([path] if count == 1 else
              [path.with_name(part_file_name(path.name, index, count))
               for index in range(1, count + 1)])
    total = sum(size for _sha1, size in members.values())
    print(f"\nPack for {display}: {_plural(len(members), 'file')} ({format_size(total)}).")
    print(f"Pack: {shown_path(path)}")
    how = pack_parts_words(count, limit, fat and limit == FAT_PART_BYTES)
    if count > 1:
        print(f"  {how}")
    if args.dry_run:
        for name in sorted(members):
            detail(f"    {screen_text(name)} ({format_size(members[name][1])})")
        if not OUTPUT.verbose:
            print("  --verbose lists the files.")
        _pack_event(plat, path, members, finals, "planned", how)
        return 0
    needed = pack_space_bytes(total, pack_bound(len(body), planned), data_dirs)
    try:
        free = shutil.disk_usage(path.parent).free
    except OSError:
        free = needed
    if free < needed:
        return _pack_refused(plat, path, f"the drive holding {shown_path(path.parent)} has "
                             f"{format_size(free)} free, and making the pack needs "
                             f"{format_size(needed)}", 2, members)
    staging = Path(tempfile.mkdtemp(prefix=f".{path.name}.", suffix=".staging",
                                    dir=str(path.parent)))
    try:
        return _fill_pack(args, _PackFill(plat, path, body, members, sources, data_dirs,
                                          limit), staging, term)
    except KeyboardInterrupt:
        _stop.set()
        print("\n  Stopped. No pack was written.", file=sys.stderr)
        _pack_event(plat, path, members, [], "failed", "Stopped before the pack was written.")
        return 130
    finally:
        shutil.rmtree(staging, ignore_errors=True)


class _PackFill(NamedTuple):
    """The pack _fill_pack writes: its path, manifest, members and their sources."""

    plat: str
    path: Path
    body: bytes
    members: dict[str, tuple[str, int]]
    sources: dict[str, dict]
    data_dirs: list[dict]
    limit: int | None


def _fill_pack(args: argparse.Namespace, pack: _PackFill, staging: Path,
               term: Terminal) -> int:
    """Fetch every member into staging, then write the pack from it."""
    plat, path, body, members, sources, data_dirs, limit = pack
    staged = [{**{key: value for key, value in entry.items()
                  if key not in ("root", "core_folder", "case_variant")}, "dest": name}
              for name, entry in sorted(sources.items())]
    copies = plan_local_copies(staged, staging, None, LOCAL.folders)
    fetched = sum(int(entry.get("size") or 0) for entry in staged)
    EVENTS.emit("download", platform=plat, files=len(staged), bytes=fetched)
    detail(f"\nDownloading {_plural(len(staged), 'file')} ({format_size(fetched)})...")
    failed, interrupted = download_files(staged, staging, jobs=args.jobs,
                                         verbose=args.verbose, term=term, copies=copies)
    if interrupted:
        raise KeyboardInterrupt
    owners: dict[str, Path] = {}
    trees_failed: list[tuple[str, str]] = []
    for index, entry in enumerate(data_dirs):
        lead = f"{str(entry.get('dest') or '').rstrip('/')}/" if entry.get("dest") else ""
        root = staging / ".trees" / str(index)
        names = [f"{lead}{rel}" for rel in sorted(entry.get("files") or {})]
        owned = [name for name in names if name in members and name not in sources
                 and name not in owners]
        if not owned:
            continue
        detail(f"  {entry.get('ref', 'data')}: {_plural(len(names), 'data file')}...")
        # The pack is rebuilt byte for byte: its tree is the listed one,
        # never what a rolling source serves since.
        counts = install_data_directory({**entry, "rolling": False}, root)
        problem = (str(counts["error"]) if counts["error"]
                   else f"{counts['changed']} changed in its source" if counts["changed"]
                   else f"{counts['absent']} not in its source" if counts["absent"]
                   else "")
        if problem:
            trees_failed.append((str(entry.get("ref", "data")), problem))
            continue
        for name in owned:
            owners[name] = root.joinpath(*PurePosixPath(name).parts)
    if failed or trees_failed:
        lines = [*failed, *trees_failed]
        print(f"\n  {_plural(len(lines), 'file')} could not be had: no pack was written.",
              file=sys.stderr)
        for dest, reason in lines[: None if args.verbose else 5]:
            print(f"    {screen_text(dest)}: {screen_text(str(reason))}", file=sys.stderr)
        if len(lines) > 5 and not args.verbose:
            print(f"    ... and {len(lines) - 5} more (--verbose lists them)", file=sys.stderr)
        _pack_event(plat, path, members, [], "failed",
                    f"{_plural(len(lines), 'file')} could not be had: no pack was written.")
        return 1
    ordered = [PackMember(name, sha1, size,
                          owners[name] if name in owners
                          else staging.joinpath(*PurePosixPath(name).parts))
               for name, (sha1, size) in sorted(members.items())]
    detail(f"\nWriting {path.name}...")
    try:
        result = write_pack(path, body, ordered, limit)
    except (OSError, PackError) as exc:
        words = (DRIVE_FULL if isinstance(exc, OSError) and _drive_full(exc)
                 else exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc))
        left = exc.left if isinstance(exc, PackError) else []
        after = ("Left behind, to delete: " + ", ".join(shown_path(f) for f in left) + "."
                 if left else "No pack was left behind.")
        print(f"\n  {path.name} could not be written: {screen_text(str(words))}. "
              f"{screen_text(after)}", file=sys.stderr)
        _pack_event(plat, path, members, [], "failed",
                    f"{path.name} could not be written: {words}. {after}")
        return 1
    written = result.files
    for old in result.removed:
        print(f"  Removed the earlier {shown_path(old)}.")
    for old, why in result.kept:
        print(f"  {shown_path(old)}: {why}.")
    size = sum(part.stat().st_size for part in written)
    print(f"\nPack made: {_plural(len(members), 'file')}, {format_size(size)}"
          + (f", in {len(written)} parts" if len(written) > 1 else "") + ".")
    for part in written if len(written) > 1 else []:
        print(f"  {shown_path(part)}")
    print("Install from it on the other device with --from-pack.")
    _pack_event(plat, path, members, written, "written",
                f"{path.name}: {_plural(len(members), 'file')}, every one checked.", size)
    return 0


def _listed(folder: Path) -> list[str]:
    try:
        return os.listdir(folder)
    except OSError:
        return []
