"""Emulator profile invariants the schema cannot express."""

from __future__ import annotations

from pathlib import Path

import core.paths
from model.alternatives import groups_of
from resolve.entryscope import read_from_save_dir


CHECK_FIELDS = {
    "crc32": ("crc32",),
    "md5": ("md5",),
    "sha1": ("sha1",),
    "sha256": ("sha256",),
    "size": ("size", "min_size", "max_size", "size_multiple"),
    "romdir": ("romdir",),
    "masked_sha1": ("masked_sha1",),
}


def config_reads_without_build(path: Path, document: object) -> list[str]:
    """A config_reads entry naming a platform the profile gives no pin_build.

    Such an entry is read at the build that platform ships, and pin_build is
    where that build is named.
    """
    if not isinstance(document, dict):
        return []
    builds = {str(b.get("platform")) for b in document.get("pin_build") or []}
    out: list[str] = []
    for index, read in enumerate(document.get("config_reads") or []):
        if not isinstance(read, dict):
            continue
        if read.get("revision") or read.get("binary_sha256"):
            continue
        out.extend(
            f"{path.relative_to(core.paths.REPO_ROOT)}: config_reads[{index}] ({read.get('file')}) "
            f"names {platform}, which has no pin_build"
            for platform in read.get("platforms") or [] if str(platform) not in builds
        )
    return out


def systems_outside_profile(path: Path, document: object) -> list[str]:
    """An entry's system: or systems: naming a system its profile does not list.

    A --system pick selects the profile by its systems: and then the entry
    by its own, so a name the profile lacks is one no pick ever reaches.
    """
    if not isinstance(document, dict):
        return []
    listed = {str(s) for s in document.get("systems") or []}
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict):
            continue
        named = [entry["system"]] if entry.get("system") else []
        named += list(entry.get("systems") or [])
        unknown = [str(s) for s in named if str(s) not in listed]
        if unknown:
            out.append(
                f"{path.relative_to(core.paths.REPO_ROOT)}: files[{index}] ({entry.get('name')}) "
                f"system {', '.join(unknown)} not in the profile's systems"
            )
    return out


def group_requirement_split(path: Path, document: object) -> list[str]:
    """A set named by a member and not declared, declared and never used,
    or a member that writes a required of its own.

    The requirement belongs to the set, in the profile's groups map, and a
    member's is derived from it. A value on the member is a second source
    that can contradict the first: a true on the first name only wrote the
    search order into required, and the other names read as optional.
    """
    if not isinstance(document, dict):
        return []
    label = path.relative_to(core.paths.REPO_ROOT)
    declared = set((document.get("groups") or {}).keys())
    used: set[str] = set()
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict):
            continue
        names = groups_of(entry)
        used.update(names)
        if names and "required" in entry:
            out.append(f"{label}: files[{index}] ({entry.get('name')}) is in a group "
                       "and writes required: the set's requirement is in groups")
    out.extend(f"{label}: group {g} has no entry in groups" for g in sorted(used - declared))
    out.extend(f"{label}: groups declares {g}, which no entry names" for g in sorted(declared - used))
    return out


def checks_without_values(path: Path, document: object) -> list[str]:
    """A check an entry declares with nothing to compare against.

    validation: [crc32] with no crc32 runs nothing: the file passes whatever
    it holds, and the report reads as checked. Fourteen profiles carried
    one, the code they describe either refusing or warning on a value the
    entry never wrote down.
    """
    out: list[str] = []
    files = document.get("files") if isinstance(document, dict) else None
    for index, entry in enumerate(files or []):
        if not isinstance(entry, dict):
            continue
        declared = entry.get("validation") or []
        if isinstance(declared, dict):
            declared = [check for checks in declared.values() for check in checks or []]
        for check in declared:
            fields = CHECK_FIELDS.get(check)
            if fields and not any(entry.get(field) not in (None, "", []) for field in fields):
                out.append(
                    f"{path.relative_to(core.paths.REPO_ROOT)}: files[{index}] ({entry.get('name')}) "
                    f"declares a {check} check with no {'/'.join(fields)} value"
                )
    return out


def save_dir_without_library_name(path: Path, document: object) -> list[str]:
    """A file the libretro build reads below the save directory, in a profile
    naming no library_name.

    RetroArch hands each core <save directory>/<library_name> by default
    (sort_savefiles_enable): without the name, packs and the installer
    cannot say where the file goes, and leave it out.
    """
    if not isinstance(document, dict):
        return []
    if "library_name" in document:
        return _save_folder_once_paths(path, document)
    return [
        f"{path.relative_to(core.paths.REPO_ROOT)}: files[{index}] ({entry.get('name')}) is read "
        "below the save directory and the profile declares no library_name"
        for index, entry in enumerate(document.get("files") or [])
        if isinstance(entry, dict)
        and read_from_save_dir(entry)
        and not ("path" in entry and entry["path"] is None)
    ]


def _save_folder_once_paths(path: Path, document: dict) -> list[str]:
    """A core adding its own folder once: each save path starts with it.

    The pack places such a file at <save directory>/<path> whether the
    frontend sorts saves by core or not, which holds only when the path
    already names the folder the core reads below.
    """
    if not document.get("save_folder_once"):
        return []
    folder = f"{document.get('library_name') or ''}/"
    return [
        f"{path.relative_to(core.paths.REPO_ROOT)}: files[{index}] ({entry.get('name')}) does not "
        f"start with {folder}, the folder save_folder_once says the core adds"
        for index, entry in enumerate(document.get("files") or [])
        if isinstance(entry, dict)
        and read_from_save_dir(entry)
        and entry.get("path")
        and not str(entry["path"]).startswith(folder)
    ]
