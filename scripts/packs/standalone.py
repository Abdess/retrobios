"""Files a standalone emulator reads where the platform places them."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from core.paths import REPO_ROOT
from packs.archive import PackRecord
from packs.emulatorpack import build_emulator_pack
from packs.manifestentry import manifest_entry
from resolve.layout import data_root_place


def _placed_copies(copies: list[dict], dests: list[str]) -> list[dict]:
    """Each standalone copy with the path this manifest gives its file.

    The registry names one path per file for every platform (one anchor),
    while each manifest places the file its own way: EmuDeck installs
    aes_keys.txt at the root and Batocera prod.keys under switch/, so the
    installer looked for Citra/sysdata/aes_keys.txt, found nothing and
    copied nothing. `file` stays as written, since it also lays out a custom
    emulator root. `source` says where the installed file is.
    """
    by_name: dict[str, list[str]] = {}
    for dest in dests:
        by_name.setdefault(dest.rsplit("/", 1)[-1].casefold(), []).append(dest)
    placed: list[dict] = []
    for copy in copies:
        wanted = copy.get("file")
        if not wanted or wanted in dests:
            placed.append(copy)
            continue
        tail = [d for d in dests if d.endswith("/" + wanted)]
        if tail:
            # The file whose path carries the least on top of the tail.
            shortest = min(len(d) for d in tail)
            tail = [d for d in tail if len(d) == shortest]
        else:
            tail = by_name.get(wanted.rsplit("/", 1)[-1].casefold(), [])
        placed.append({**copy, "source": tail[0]} if len(tail) == 1 else copy)
    return placed


# data_root keys of the profiles, as the copy targets name each system.
_DATA_ROOT_SYSTEMS = {"linux": "linux", "macos": "darwin", "windows": "windows",
                      "android": "android"}


def _data_root_target(system: str, text: str) -> str | None:
    """A profile's data_root on one system as a copy target, or None when it
    names no place a run can find: a folder beside an executable, a working
    directory, a folder picked in the app. Of `A, else B` the alternative
    under the home is kept, the default the registry's targets write.
    """
    for choice in (part.strip() for part in text.split(", else ")):
        if "<" in choice:
            continue
        if system == "windows" and re.match(r"^%[A-Za-z0-9_()]+%/", choice):
            return choice.replace("/", "\\")
        if system == "android" and choice.startswith("Android/data/"):
            return "$EXTERNAL_STORAGE/" + choice
        if system in ("linux", "darwin"):
            if choice.startswith("~/"):
                return "$HOME/" + choice[2:]
            if choice.startswith("$HOME/"):
                return choice
    return None


def _one_content(held: list[str], entries: dict[str, dict], emulator: str) -> list[str]:
    """The one dest a copy reads when every held dest carries the same bytes.

    Unchanged when the contents differ: the name then designates nothing.
    """
    if len({entries[dest].get("sha1") for dest in held}) != 1:
        return held
    own = [dest for dest in held if emulator in (entries[dest].get("cores") or ())]
    return [min(own or held, key=lambda dest: (dest.count("/"), len(dest), dest))]


def _profile_roots(profile: dict) -> dict[str, tuple[str, str]]:
    """The data_root key and copy target of each system the profile names a
    findable place for."""
    return {
        _DATA_ROOT_SYSTEMS[key]: (key, target)
        for key, value in (profile.get("data_root") or {}).items()
        if key in _DATA_ROOT_SYSTEMS and isinstance(value, dict)
        and (target := _data_root_target(_DATA_ROOT_SYSTEMS[key], value.get("path", "")))
    }


def _copy_source(
    entry: dict,
    by_tail: dict[str, list[str]],
    entries: dict[str, dict] | None,
    profile_name: str,
) -> str | None:
    """The manifest dest a profile entry's standalone copy is taken from."""
    standalone = entry.get("standalone_path")
    if (not standalone or standalone.endswith("/") or entry.get("mode") == "libretro"
            or entry.get("type") == "directory" or entry.get("found_by") == "content"):
        return None
    held = by_tail.get(entry.get("path") or entry["name"], [])
    if len(held) > 1 and entries is not None:
        held = _one_content(held, entries, profile_name)
    if len(held) != 1:
        return None
    return held[0]


def _profile_copies(
    profiles: dict[str, dict], dests: list[str], declared: list[dict],
    entries: dict[str, dict] | None = None,
) -> list[dict]:
    """The standalone copies the emulator profiles document: each file with
    a standalone_path, into the data_root of each system that names a place.

    The registry's list was kept by hand for eight emulators, while the
    profiles give the folder of 61 with the code that builds it: a machine
    with standalone Cemu only got none of its keys. A target the registry
    already gives for the same name is left to it, and a file the manifest
    does not carry, or carries under the save directory, has no source. A
    file found by content (found_by) sits wherever the folder the user set
    for the scan points: Amiberry reads its ROMs from rom_path, which
    amiberry.conf moves, so its name under data_root proves nothing.
    ``entries`` maps each dest to its manifest entry: one file carried at
    two paths with the same bytes is one source, the copy whose cores name
    the emulator, else the shortest path. DuckStation's ps2_scph50006.bin
    sits at the BIOS root and under pcsx2/bios/ for the libretro PS2 cores.
    """
    from fnmatch import fnmatch

    taken: list[tuple[str, str, str, bool]] = []
    for copy in declared:
        name = copy.get("pattern") or PurePosixPath(copy.get("file", "")).name
        for system, targets in (copy.get("targets") or {}).items():
            taken += [(system, target, name, "pattern" in copy) for target in targets]

    def covered(system: str, target: str, name: str) -> bool:
        return any(
            system == t_system and target == t_target
            and (fnmatch(name, t_name) if is_pattern else name == t_name)
            for t_system, t_target, t_name, is_pattern in taken
        )

    by_tail: dict[str, list[str]] = {}
    for dest in dests:
        parts = dest.split("/")
        for start in range(len(parts)):
            by_tail.setdefault("/".join(parts[start:]), []).append(dest)
    copies: list[dict] = []
    for profile_name in sorted(profiles):
        profile = profiles[profile_name]
        roots = _profile_roots(profile)
        if not roots:
            continue
        for entry in profile.get("files", []):
            source = _copy_source(entry, by_tail, entries, profile_name)
            if source is None:
                continue
            placed: dict[str, list[str]] = {}
            for system, (key, root) in roots.items():
                # The app reads the file there, else no copy on this system.
                place = data_root_place(profile, entry, key)
                if not place:
                    continue
                where = PurePosixPath(place)
                sep = "\\" if system == "windows" else "/"
                target = root if str(where.parent) == "." else (
                    root + sep + str(where.parent).replace("/", sep))
                if not covered(system, target, where.name):
                    placed[system] = [target]
            if not placed:
                continue
            copy = {"file": source, "targets": placed}
            name = PurePosixPath(entry["standalone_path"]).name
            if name != PurePosixPath(source).name:
                copy["as"] = name
            copies.append(copy)
    return copies


def standalone_copies(
    declared: list[dict], profiles: dict[str, dict], manifest_files: list[dict],
) -> list[dict]:
    """A manifest's standalone copies: the registry's, placed where this
    manifest puts each file, then the ones the profiles document. A platform
    whose registry entry declares none gets none."""
    if not declared:
        return []
    kept = [entry for entry in manifest_files if entry.get("root") != "save"]
    dests = [entry["dest"] for entry in kept]
    entries = {entry["dest"]: entry for entry in kept}
    return _placed_copies(declared, dests) + _profile_copies(profiles, dests, declared, entries)


STANDALONE_DIR = "standalone"


def standalone_layouts(
    profiles: dict[str, dict],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    zip_contents: dict,
    offline: bool | None,
    platforms_dir: str,
    result: dict,
) -> dict[str, list]:
    """Per emulator with a standalone build, the files `--emulator X
    --standalone` packs, at the destinations that build reads.

    Built by the emulator pack itself, in memory. A file whose content the
    list already carries is written as [dest, sha1], its download read from
    that entry. Another is written whole. A data tree member is left to the
    list's data directories.
    """
    repo_root = str(REPO_ROOT)
    known = {
        copy["sha1"]
        for entry in [*result["files"], *result.get("truth_files", [])]
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]
        if copy.get("sha1") and (copy.get("repo_path") or copy.get("release_asset"))
    }
    layouts: dict[str, list] = {}
    for name, profile in sorted(profiles.items()):
        if "standalone" not in str(profile.get("type", "")):
            continue
        record = PackRecord()
        build_emulator_pack(
            [name], emulators_dir, db, bios_dir, "", standalone=True,
            zip_contents=zip_contents, offline=offline,
            platforms_dir=platforms_dir, record=record,
        )
        items: list = []
        for member in record.files:
            entry, _size = manifest_entry(
                record.sources.get(member), member, [name], db, repo_root, {}
            )
            if entry is None:
                continue
            items.append([member, entry["sha1"]] if entry["sha1"] in known else entry)
        layouts[name] = items
    return layouts
