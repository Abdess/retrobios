"""Writing pack archives: members, generated files, copied archives, data trees."""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from core.artifacts import set_plain_mode
from core.hashing import compute_hashes
from core.paths import comparable_destination, sanitize_pack_path
from packs.paths import has_path_conflict, register_path, placement_block


# The minimum ZIP timestamp, carried by every pack member so a pack is a
# function of its inputs and not of the clock.
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)

# Formats that are already compressed: deflating them again took 28 s of the
# RetroArch build for 2.1 GB of members and saved 9.6 MB (0.45 %), 16 GB and
# about 72 MB across all packs. Measured per extension on the 2026-10-20
# packs; .pk3 (3 %), .jpg (6 %), .avi (44 %) and .jar (60 %) still shrink
# and stay deflated. Chosen by name alone, so a pack stays a function of its
# inputs.
_STORED_EXTENSIONS = frozenset({".7z", ".chd", ".ogg", ".pk4", ".png", ".zip"})


def _member_compression(arcname: str) -> int:
    """ZIP_STORED for a member whose format is already compressed."""
    if os.path.splitext(arcname)[1].lower() in _STORED_EXTENSIONS:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


class PackRecord:
    """A pack build kept in memory: the paths it writes, no archive.

    ``members`` is every path written, ``files`` the ones the build counts as
    the profile's files (archives and loose files, not trees or notes), and
    ``trees`` the members a platform pack takes from its data directories.
    The pipeline builds every emulator pack and every narrowed platform pack
    this way and compares them with what verify credits, without reading or
    compressing a byte.
    """

    def __init__(self) -> None:
        self.members: list[str] = []
        self.files: list[str] = []
        self.trees: list[str] = []
        # The collection file each copied member comes from: a split part
        # writes a file only where the full pack writes the same bytes.
        self.sources: dict[str, str] = {}


def add_pack_member(
    zf: zipfile.ZipFile | PackRecord, source_path: str, arcname: str
) -> None:
    """Add a file to the pack with metadata that does not depend on the build.

    ZipFile.write copies the source file's mtime into the member. For a file
    this build just produced in tmp/ that is the wall clock, and for a file
    from the collection it is whenever the clone was checked out, so a pack
    rebuilt from identical inputs differed from the last one although every
    byte of content matched: 348 members of the Recalbox pack moved between
    two consecutive builds. The content is streamed rather than read whole,
    because some members are firmware images of several hundred megabytes.
    """
    if isinstance(zf, PackRecord):
        zf.members.append(arcname)
        zf.sources[arcname] = source_path
        return
    info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_DATE_TIME)
    info.compress_type = _member_compression(arcname)
    # The executable bit is the one permission worth carrying: the RetroDECK
    # pack ships the two Voxatron engine binaries, and a user who extracts
    # them at 644 cannot run them. Git records the bit, so reading it from
    # the source keeps the pack the same from any clone. Nothing else about
    # the source's mode reaches the archive.
    stat_result = os.stat(source_path)
    mode = 0o755 if stat_result.st_mode & 0o111 else 0o644
    info.external_attr = (0o100000 | mode) << 16
    size = stat_result.st_size
    info.file_size = size
    with open(source_path, "rb") as source, zf.open(
        info, "w", force_zip64=size >= 1 << 31
    ) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)


def write_generated_member(
    zf: zipfile.ZipFile | PackRecord, arcname: str, text: str
) -> None:
    """Write a pack member the builder composes rather than copies.

    READMEs, instruction notes and the manifest are produced at build time,
    so writestr would stamp them with the wall clock and give the same pack
    a different hash on every run. Pinning them to the epoch the archive
    rebuilder already uses makes a pack a function of its inputs alone.
    """
    if isinstance(zf, PackRecord):
        zf.members.append(arcname)
        return
    info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, text)


@contextlib.contextmanager
def writing_pack(zip_path: str) -> Iterator[zipfile.ZipFile]:
    """A pack written beside its final name, swapped in once complete.

    Opened on the final name, a rebuild truncated the previous pack at once,
    and a build that raised half way still wrote a central directory: a
    readable ZIP holding part of the files, which the run then checked and
    summed as the pack.
    """
    directory = os.path.dirname(zip_path) or "."
    fd, scratch = tempfile.mkstemp(
        prefix=f".{os.path.basename(zip_path)}.", suffix=".partial", dir=directory
    )
    os.close(fd)
    try:
        with zipfile.ZipFile(scratch, "w", zipfile.ZIP_DEFLATED) as zf:
            yield zf
        set_plain_mode(scratch)
        os.replace(scratch, zip_path)
    except BaseException:
        Path(scratch).unlink(missing_ok=True)
        raise


# What the builder writes into a platform pack beside the files it carries.
PACK_DOCUMENTS = ("README.txt", "manifest.json")


@dataclass
class Placed:
    """The destinations a build has taken, and the folders they open.

    ``fold`` is whether a case twin of a taken path counts as taken. The
    builder, the manifest, verify's replay of the builder and the data
    tree walk all place files through this one record.

    ``content``, when given, records the sha1 of what each taken path holds,
    keyed by its folded destination: a case twin carrying the same
    bytes serves the core on a filesystem that folds the names.
    """

    fold: bool
    destinations: set[str] = field(default_factory=set)
    lower: set[str] = field(default_factory=set)  # only used when fold=True
    parents: set[str] = field(default_factory=set)  # parent dirs of added files (path conflict detection)
    content: dict[str, str | None] | None = None

    def take(self, dest: str, sha1: str | None = None) -> None:
        self.destinations.add(dest)
        register_path(dest, self.destinations, self.parents)
        if self.fold:
            self.lower.add(comparable_destination(dest))
        if self.content is not None:
            self.content[comparable_destination(dest)] = sha1

    def content_at(self, dest: str) -> str | None:
        """The sha1 recorded for the path a destination folds onto."""
        return (self.content or {}).get(comparable_destination(dest))

    def holds(self, dest: str) -> bool:
        return dest in self.destinations or (
            self.fold and comparable_destination(dest) in self.lower
        )

    def conflicts(self, dest: str) -> bool:
        return has_path_conflict(dest, self.destinations, self.parents)

    def block(self, dest: str) -> str | None:
        return placement_block(dest, self.destinations, self.lower, self.parents, self.fold)


def extract_zip_to_archive(
    source_zip: str,
    dest_prefix: str,
    target_zf: zipfile.ZipFile | PackRecord,
) -> None:
    """Extract contents of a source ZIP into target ZIP under dest_prefix."""
    with zipfile.ZipFile(source_zip, "r") as src:
        if isinstance(target_zf, PackRecord):
            target_zf.members.extend(
                f"{dest_prefix}/{name}" if dest_prefix else name
                for name in map(sanitize_pack_path, src.namelist())
                if name and not name.endswith("/")
            )
            target_zf.sources[dest_prefix] = source_zip
            return
        for info in src.infolist():
            if info.is_dir():
                continue
            clean_name = sanitize_pack_path(info.filename)
            if not clean_name:
                continue
            data = src.read(info.filename)
            target_path = f"{dest_prefix}/{clean_name}" if dest_prefix else clean_name
            member = zipfile.ZipInfo(
                filename=target_path, date_time=FIXED_DATE_TIME
            )
            member.compress_type = _member_compression(target_path)
            member.external_attr = 0o100644 << 16
            target_zf.writestr(member, data)


def add_zip_to_pack(
    source_zip: str,
    dest_path: str,
    target_zf: zipfile.ZipFile | PackRecord,
    file_entry: dict | None = None,
) -> None:
    """Write a source ZIP into the pack, byte for byte.

    The pack carries the collection's own bytes, so every member hashes to
    the sha1 the install list and the site publish. Rebuilt ZIPs gave about
    1,500 archives another hash than the list: an extracted pack then failed
    `install.py --check`. The collection's bytes are fixed in git, which keeps
    the pack reproducible without a rebuild.
    """
    if isinstance(target_zf, PackRecord):
        target_zf.members.append(dest_path)
        target_zf.sources[dest_path] = source_zip
        return
    _check_zip_members(source_zip)
    add_pack_member(target_zf, source_zip, dest_path)


def _check_zip_members(source_zip: str) -> None:
    """Refuse an archive whose members fail their own CRC.

    Copied as-is "for verify to flag", a damaged archive went into the pack
    and nothing flagged it.
    """
    try:
        with zipfile.ZipFile(source_zip) as zf:
            bad = zf.testzip()
    except zipfile.BadZipFile as exc:
        raise DamagedArchiveError(
            f"{source_zip}: {exc}; restore it from git or the release before packing"
        ) from exc
    if bad is not None:
        raise DamagedArchiveError(
            f"{source_zip}: member {bad} fails its CRC; "
            "restore it from git or the release before packing"
        )


class DamagedArchiveError(OSError):
    """An archive of the collection whose members fail their own CRC."""


def same_bytes(path: str, other: str | None) -> bool:
    if not other:
        return False
    if os.path.realpath(path) == os.path.realpath(other):
        return True
    return compute_hashes(path)["sha1"] == compute_hashes(other)["sha1"]


# Systems whose default filesystems fold case (NTFS, APFS, HFS+).
CASE_FOLDING_OS = frozenset({"windows", "darwin"})
