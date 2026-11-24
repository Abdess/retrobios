"""The hashes a review knows: every file the platforms and the profiles declare, with its folder and systems."""

from __future__ import annotations

import os
import sys
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

from core.hashing import parse_hash_list
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import list_registered_platforms
from resolve.nativemode import platform_mode


def _note_sizes(sizes: dict[str, list], names: list[str], entry: dict) -> None:
    """Record the sizes an entry accepts under each of its names.

    An entry that declares no size says nothing about it, so a name is
    judged only by the declarations that do.
    """
    size = entry.get("size")
    accepted = []
    if isinstance(size, list):
        accepted = [(int(v), int(v)) for v in size]
    elif isinstance(size, int) and size > 0:
        accepted = [(size, size)]
    if entry.get("min_size") or entry.get("max_size"):
        accepted.append((int(entry.get("min_size") or 0),
                         int(entry.get("max_size") or 2 ** 63)))
    for name in names if accepted else []:
        sizes.setdefault(name, []).extend(accepted)


def load_platform_hashes(platforms_dir: str, db: dict | None = None) -> dict:
    """Load all known hashes from platform configs.

    With the database, `folders` maps each declared hash to the
    bios/<Manufacturer>/<Console>/ folders the collection files its system
    under, read from the other files of that system it holds.
    """
    known: dict[str, Any] = {"sha1": set(), "md5": set(), "sha256": set(), "crc32": set(),
             "names": set(), "folders": {}, "sizes": {}, "entries": {}, "named": {},
             "name_systems": {}, "system_dirs": {}, "system_folders": {}}
    systems_of: dict[str, set[str]] = {}
    folders_of: dict[str, dict[str, int]] = {}
    files = (db or {}).get("files", {})
    by_md5 = (db or {}).get("indexes", {}).get("by_md5", {})

    if not os.path.isdir(platforms_dir) or yaml is None:
        return known

    # Read the way verify reads them: inheritance and shared groups resolved,
    # and a Recalbox md5 field split into the revisions it lists. The raw
    # file kept "a,b,c" as one value, so a PR adding the seventh accepted
    # falcon.img was told its hash differs.
    for name in list_registered_platforms(platforms_dir):
        try:
            config = load_platform_config(name, platforms_dir)
        except (OSError, yaml.YAMLError) as exc:
            print(f"WARNING: {name}: {exc}", file=sys.stderr)
            continue

        mode, rule = platform_mode(config), config.get("hash_rule", "")
        for system_id, system in config.get("systems", {}).items():
            for file_entry in system.get("files", []):
                sha1s = parse_hash_list(file_entry.get("sha1"))
                md5s = parse_hash_list(file_entry.get("md5"))
                sha256s = parse_hash_list(file_entry.get("sha256"))
                known["sha1"].update(sha1s)
                known["md5"].update(md5s)
                known["sha256"].update(sha256s)
                if not (sha1s or md5s or sha256s) and isinstance(file_entry.get("size"), int):
                    # The resolver's reading: a crc32 counts where no stronger
                    # hash is declared, bounded by the declared size.
                    known["crc32"].update(
                        (crc.zfill(8), file_entry["size"])
                        for crc in parse_hash_list(file_entry.get("crc32"))
                    )
                if "name" in file_entry:
                    known["names"].add(file_entry["name"])
                    _note_sizes(known["sizes"], [file_entry["name"]], file_entry)
                    # A frontend that hashes a ZIP's member or its members
                    # together, or that takes any hash at the declared size,
                    # answers by its own rule, read per entry.
                    known["entries"].setdefault(file_entry["name"].lower(), []).append(
                        (file_entry, mode, rule, name)
                    )
                    known["name_systems"].setdefault(file_entry["name"].lower(), set()).add(system_id)
                for value in (*sha1s, *md5s):
                    systems_of.setdefault(value, set()).add(system_id)
                for value in (*sha1s, *md5s, *sha256s):
                    if "name" in file_entry:
                        known["named"].setdefault(value, set()).add(file_entry["name"])
                _note_folder(folders_of, system_id, files, by_md5, sha1s, md5s,
                             known["system_dirs"])

    known["folders"] = _system_homes(systems_of, folders_of)
    known["system_folders"] = _single_maker_folders(folders_of)
    return known


def _note_folder(
    folders_of: dict[str, dict[str, int]], system_id: str, files: dict,
    by_md5: dict, sha1s: list[str], md5s: list[str],
    dirs_of: dict[str, set[str]] | None = None,
) -> None:
    """Count the bios/<Manufacturer>/<Console>/ folder a held file sits in,
    and note the directory it sits in under *dirs_of*."""
    held = next((s for s in sha1s if s in files), None) or next(
        (by_md5[m] for m in md5s if m in by_md5), None
    )
    path = str(files.get(held, {}).get("path", ""))
    if dirs_of is not None and "/" in path and "/.variants/" not in path:
        dirs_of.setdefault(system_id, set()).add(path.rsplit("/", 1)[0] + "/")
    parts = path.split("/")
    if len(parts) >= 4 and parts[0] == "bios" and not parts[2].startswith("."):
        folder = "/".join(parts[:3]) + "/"
        counts = folders_of.setdefault(system_id, {})
        counts[folder] = counts.get(folder, 0) + 1


def _single_maker_folders(folders_of: dict[str, dict[str, int]]) -> dict[str, set[str]]:
    """System id to the folders the collection files it under, for a system
    filed under one manufacturer only, the rule _system_homes applies."""
    return {
        system_id: set(held_in) for system_id, held_in in folders_of.items()
        if len({folder.split("/")[1] for folder in held_in}) == 1
    }


def _system_homes(
    systems_of: dict[str, set[str]], folders_of: dict[str, dict[str, int]]
) -> dict[str, set[str]]:
    """Hash value to the folders the collection files its systems under.

    A system whose files sit under several manufacturers (arcade sets,
    computers sharing ROM chips) names no single home: only a system filed
    under one manufacturer says where a newcomer belongs.
    """
    homes: dict[str, set[str]] = {}
    for value, systems in systems_of.items():
        folders: set[str] = set()
        for system_id in systems:
            held_in = folders_of.get(system_id, {})
            if len({folder.split("/")[1] for folder in held_in}) == 1:
                folders.update(held_in)
        if folders:
            homes[value] = folders
    return homes


def load_profile_hashes(
    emulators_dir: str, db: dict | None = None
) -> dict[str, dict[str, set[str]]]:
    """Hash value to the emulators whose profile declares it, per algorithm.

    A file only a core reads (a standalone emulator's firmware, a game
    engine's data) is in no platform list: the review called every such
    contribution "not referenced, needs manual review". With the database,
    `folders` maps each declared hash to the folders the collection files
    the entry's system under, as load_platform_hashes does: a contributor
    holding a file only a profile declares was told to pick a
    bios/Manufacturer/Console/ folder alone.
    """
    known: dict[str, dict] = {
        "sha1": {}, "sha256": {}, "md5": {}, "crc32": {}, "sizes": {}, "folders": {},
        "named": {}, "name_systems": {}, "system_dirs": {}, "system_folders": {},
    }
    systems_of: dict[str, set[str]] = {}
    folders_of: dict[str, dict[str, int]] = {}
    files = (db or {}).get("files", {})
    indexes = (db or {}).get("indexes", {})
    by_md5, by_sha256 = indexes.get("by_md5", {}), indexes.get("by_sha256", {})
    for emulator, profile in load_emulator_profiles(emulators_dir).items():
        declared_systems = profile.get("systems") or []
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            names = [entry.get("name"), *(entry.get("aliases") or [])]
            _note_sizes(known["sizes"], [n for n in names if isinstance(n, str)], entry)
            # The resolver's reading: comma lists split (mesence's four
            # sha256), and a crc32 counts only where no stronger hash is
            # declared, bounded by the declared size (626 entries name a
            # file by crc32 alone, clk's Electron os.rom among them).
            hashes = {
                algo: parse_hash_list(entry.get(algo)) for algo in ("sha1", "sha256", "md5")
            }
            for algo, values in hashes.items():
                for value in values:
                    known[algo].setdefault(value, set()).add(emulator)
                    if isinstance(entry.get("name"), str):
                        known["named"].setdefault(value, set()).add(entry["name"])
            # The entry's own system, or the profile's when it emulates one.
            system = entry.get("system") or (
                declared_systems[0] if len(declared_systems) == 1 else None
            )
            if isinstance(system, str):
                for value in (v for values in hashes.values() for v in values):
                    systems_of.setdefault(value, set()).add(system)
                for n in names:
                    if isinstance(n, str):
                        known["name_systems"].setdefault(n.lower(), set()).add(system)
                sha1s = [*hashes["sha1"], *(
                    by_sha256[v] for v in hashes["sha256"] if v in by_sha256
                )]
                _note_folder(folders_of, system, files, by_md5, sha1s, hashes["md5"],
                             known["system_dirs"])
            if not any(entry.get(algo) for algo in ("sha1", "sha256", "md5")):
                size = entry.get("size")
                sizes = [int(v) for v in size] if isinstance(size, list) else (
                    [int(size)] if size else [None]
                )
                for value in parse_hash_list(entry.get("crc32")):
                    for accepted in sizes:
                        key = (value.zfill(8), accepted)
                        known["crc32"].setdefault(key, set()).add(emulator)
    known["folders"] = _system_homes(systems_of, folders_of)
    known["system_folders"] = _single_maker_folders(folders_of)
    return known


def name_systems(filename: str, platform_hashes: dict, profile_hashes: dict | None) -> set[str]:
    """The systems whose platform or profile entries declare this name."""
    return {
        system for table in (platform_hashes, profile_hashes or {})
        for system in table.get("name_systems", {}).get(filename.lower(), ())
    }
