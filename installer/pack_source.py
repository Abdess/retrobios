"""Packs read in place of the network, whole or in parts, and the files they lack."""
from __future__ import annotations

import functools
import json
import re
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO, TYPE_CHECKING

from installer.arguments import PACK_NAME_END
from installer.device import _VERSION_TEXT
from installer.manifest import _SHA1_RE, _validate_targets
from installer.offline import LOCAL
from installer.platforms import AVAILABLE_PLATFORMS, PLATFORM_NAMES
from installer.remote import MAX_MANIFEST_BYTES
from installer.safe_replace import _write_verified
from installer.text import _CONTROLS, _plural

if TYPE_CHECKING:
    from installer.console import Progress

# A pack too large for one release file is published as ZIP parts
# (scripts/split_pack.py), each holding at its root a marker that names the
# pack, the part and every part with its size. Extracted with the files,
# the markers say which part a folder lacks.
def _part_pattern(ext: str) -> re.Pattern:
    return re.compile(rf"^(?P<stem>.+_BIOS_Pack)\.part(?P<index>\d+)of(?P<count>\d+)\.{ext}$")


_PART_FILE = _part_pattern("zip")
_PART_MARKER = _part_pattern("txt")


def part_file_name(name: str, index: int, count: int) -> str:
    """Part index of count of the pack name."""
    return f"{name[: -len('.zip')]}.part{index}of{count}.zip"


def part_marker_name(name: str, index: int, count: int) -> str:
    """The marker part index of count of the pack name holds."""
    return f"{name[: -len('.zip')]}.part{index}of{count}.txt"


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
        folders = list(dict.fromkeys(p.parent for p in chosen))
        found: list[Path] = []
        missing: list[str] = []
        for number in range(1, count + 1):
            part_name = part_file_name(name, number, count)
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


def pack_lacks(entries: list[dict]) -> list[dict]:
    """The entries the pack given to this run does not hold, none without
    a pack: they cannot be installed from it."""
    return [] if LOCAL.pack is None else [e for e in entries if LOCAL.pack.find(e) is None]


def pack_holds_trees(data_dirs: list[dict]) -> bool:
    """Whether the pack given to this run holds a file of any of these data
    trees, which an install takes from it. A file of the tree, by its path:
    a member below the tree's folder was the test, and blueMSX's tree,
    whose folder is the BIOS folder itself, held every BIOS file of any
    pack. One holding none of the files offered and focused Install, and
    its result counted 8252 failed beside 10888 missing."""
    if LOCAL.pack is None:
        return False
    names = LOCAL.pack.members
    for entry in data_dirs:
        lead = f"{str(entry.get('dest') or '').rstrip('/')}/" if entry.get("dest") else ""
        if any(f"{lead}{rel}" in names for rel in entry.get("files") or {}):
            return True
    return False


def pack_lacks_words(count: int, total: int) -> str:
    """The pack's missing files, said before the plan names a size."""
    name = LOCAL.pack.name if LOCAL.pack is not None else "the pack"
    if count >= total:
        return (f"{name} holds none of these {_plural(total, 'file')}: nothing can be "
                "installed from it.")
    return (f"{count} of these {total} files {'is' if count == 1 else 'are'} not in "
            f"{name}: {'it' if count == 1 else 'they'} cannot be installed from it.")
