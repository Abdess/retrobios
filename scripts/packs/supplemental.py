"""The names data/ and the ZIPs under bios/ hold, and where each one sits."""

from __future__ import annotations

import io
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

from core.hashing import parse_hash_list, stream_hashes
from core.paths import BIOS_DIR
from core.ziptools import is_archive_path, zip_members


@dataclass(frozen=True)
class SupplementalIndex:
    """The names data/ and the ZIPs under bios/ hold, and where, for one pair of roots."""

    names: frozenset[str]
    data_root: str
    bios_root: str

    def __contains__(self, name: object) -> bool:
        return name in self.names

    def __bool__(self) -> bool:
        return bool(self.names)

    def locations(self) -> dict[str, list[tuple[str, str]]]:
        """Each name's files and members under the same roots, read on first use."""
        return supplemental_locations(self.data_root, self.bios_root)


def build_supplemental_index(
    data_root: str = "data", bios_root: str = BIOS_DIR
) -> SupplementalIndex:
    """Index the filenames in data/ and inside bios/ ZIPs.

    No directory is indexed: whether the collection holds a directory entry
    is resolve.directories.directory_members alone. A folder name proved
    nothing, and SuperTux's data/ read as held by MAME's plugins/data/.
    """
    names: set[str] = set()
    root_path = Path(data_root)
    if root_path.is_dir():
        for fpath in root_path.rglob("*"):
            if not fpath.name.startswith(".") and fpath.is_file():
                names.add(fpath.name)
                names.add(fpath.name.lower())
    bios_path = Path(bios_root)
    if bios_path.is_dir():
        names |= _zip_member_names(bios_path)
    return SupplementalIndex(frozenset(names), data_root, str(bios_root))


_zip_members_cache: dict[str, list[tuple[str, list[str]]]] = {}


def archive_members(bios_root: str | Path) -> list[tuple[str, list[str]]]:
    """Each ZIP under bios/ with the files it holds, walked once per root.

    An unreadable archive is reported and left out.
    """
    key = str(Path(bios_root))
    if key in _zip_members_cache:
        return _zip_members_cache[key]
    found: list[tuple[str, list[str]]] = []
    root = Path(bios_root)
    # .variants/ copies (x.zip.1a2b3c4d) are archives too.
    archives = sorted(
        p for p in (root.rglob("*") if root.is_dir() else ())
        if is_archive_path(p.name) and p.is_file()
    )
    for zpath in archives:
        try:
            members = [member.name for member in zip_members(zpath)]
        except (zipfile.BadZipFile, OSError) as exc:
            print(f"  WARNING: unreadable archive {zpath}: {exc}", file=sys.stderr)
            continue
        found.append((str(zpath), members))
    _zip_members_cache[key] = found
    return found


def _zip_member_names(bios_path: Path) -> set[str]:
    """Basenames of the files inside every ZIP under bios/, both cases."""
    names: set[str] = set()
    for _zpath, members in archive_members(bios_path):
        for member in members:
            basename = member.rsplit("/", 1)[-1]
            names.update((basename, basename.lower()))
    return names


def data_hit(
    fname: str, basename: str | None, file_entry: dict | None, data_names: SupplementalIndex
) -> bool:
    """Whether data/ or a ZIP holds a file of the name. A directory entry is
    never held here (directory_members decides it). A file entry that
    declares a hash is held only by a copy carrying it: touchhle's
    LiberationMono-Regular.ttf read as held because idtech4a++'s extras.zip
    has another font of that name."""
    if fname.endswith("/") or (file_entry or {}).get("type") == "directory":
        return False
    looked_up = [fname, fname.lower()] + ([basename, basename.lower()] if basename else [])
    if not any(name in data_names for name in looked_up):
        return False
    declared = declared_content(file_entry or {})
    if not declared:
        return True
    return any(
        content_matches(location, declared)
        for location in data_names.locations().get((basename or fname).lower(), ())
    )


_HASH_FIELDS = ("sha1", "md5", "sha256", "crc32")


def declared_content(file_entry: dict) -> dict[str, set[str]]:
    """The hashes an entry declares, lowercased, by algorithm."""
    declared: dict[str, set[str]] = {}
    for field in _HASH_FIELDS:
        found = set(parse_hash_list(file_entry.get(field)))
        if found:
            declared[field] = found
    return declared


_locations_cache: dict[tuple[str, str], dict[str, list[tuple[str, str]]]] = {}


def supplemental_locations(
    data_root: str = "data", bios_root: str = BIOS_DIR
) -> dict[str, list[tuple[str, str]]]:
    """Where each name of the supplemental index sits: a data/ file, or a
    member of a ZIP under bios/, keyed by lowercased basename."""
    key = (data_root, bios_root)
    if key in _locations_cache:
        return _locations_cache[key]
    found: dict[str, list[tuple[str, str]]] = {}
    root = Path(data_root)
    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_file() and not path.name.startswith("."):
                found.setdefault(path.name.lower(), []).append((str(path), ""))
    for zpath, members in archive_members(bios_root):
        for member in members:
            found.setdefault(member.rsplit("/", 1)[-1].lower(), []).append(
                (zpath, member)
            )
    _locations_cache[key] = found
    return found


def content_matches(location: tuple[str, str], declared: dict[str, set[str]]) -> bool:
    """Whether the file or member at *location* carries a declared hash."""
    path, member = location
    try:
        if member and set(declared) == {"crc32"}:
            return any(
                held.name == member and held.crc32 in declared["crc32"]
                for held in zip_members(path)
            )
        if member:
            with zipfile.ZipFile(path) as zf:
                data = zf.read(member)
        else:
            data = Path(path).read_bytes()
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        print(f"  WARNING: cannot read {path} {member}: {exc}", file=sys.stderr)
        return False
    actual = stream_hashes(io.BytesIO(data), frozenset({"sha1", "md5", "sha256", "crc32"}))
    return any(actual[field] in values for field, values in declared.items())
