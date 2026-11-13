#!/usr/bin/env python3
"""Validate BIOS file contributions in Pull Requests.

Usage:
    python scripts/validate_pr.py [files...]
    python scripts/validate_pr.py --changed   # Auto-detect changed files via git

Multi-layer validation:
1. Hash verified against known databases (System.dat, batocera-systems)
2. File size within limits and within the sizes declared for its name
3. File referenced in ≥1 platform config
4. Duplicate detection against database.json
5. Security checks (no executables, reasonable sizes)

Outputs a structured report suitable for PR comments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    compute_hashes,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    parse_md5_list,
    require_directory,
)
from hashing import parse_hash_list
from nativemode import digest_algorithm
from dedup import _in_nodedup_dir
from validation import frontend_digest_matches, inner_rom_check

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_EMULATORS_DIR = "emulators"

BLOCKED_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".sh",
    ".ps1",
    ".vbs",
    ".js",
    ".msi",
    ".dll",
    ".so",
    ".dylib",
    ".py",
    ".rb",
    ".pl",
}

MAX_FILE_SIZE = 100 * 1024 * 1024
LARGE_FILE_ISSUE_URL = (
    "https://github.com/Abdess/retrobios/issues/new?template=missing-bios.yml"
)


def large_file_issue_url(result: ValidationResult) -> str:
    """The issue form with the values this run computed already filled in.

    GitHub fills an issue form field from the query parameter named by its
    id: filename, sha1, md5 and size in missing-bios.yml.
    """
    fields = {
        "title": f"[BIOS] Missing: {result.filename}",
        "filename": result.filename,
        "sha1": result.sha1,
        "md5": result.md5,
        "size": str(result.size),
    }
    return f"{LARGE_FILE_ISSUE_URL}&{urllib.parse.urlencode(fields)}"


class ValidationResult:
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.checks = []  # (status, message) tuples
        self.sha1 = ""
        self.md5 = ""
        self.crc32 = ""
        self.size = 0
        # "held" (a copy of a file the collection has) or "unknown" (no list
        # or profile declares it): no check fails, and neither is a file
        # the pull request adds to the collection.
        self.outcome = ""
        # Where --place copies the file: one folder and one declared name, or
        # the .variants/ slot of a name the collection already holds.
        self.destination = ""

    def add_check(self, passed: bool, message: str) -> None:
        self.checks.append(("PASS" if passed else "FAIL", message))

    def add_warning(self, message: str) -> None:
        self.checks.append(("WARN", message))

    def add_info(self, message: str) -> None:
        self.checks.append(("INFO", message))

    @property
    def passed(self) -> bool:
        return all(s != "FAIL" for s, _ in self.checks)

    @property
    def status(self) -> str:
        return "FAIL" if not self.passed else "REVIEW" if self.outcome else "PASS"

    def to_markdown(self) -> str:
        status = self.status
        lines = [f"### {status} `{self.filename}`"]
        lines.append("")
        lines.append(f"- **Path**: `{self.filepath}`")
        # A path refused before it was read has no size or digest to show:
        # empty fields read as an empty file contributed.
        if self.sha1:
            lines.append(f"- **Size**: {self.size:,} bytes")
            lines.append(f"- **SHA1**: `{self.sha1}`")
            lines.append(f"- **MD5**: `{self.md5}`")
            lines.append(f"- **CRC32**: `{self.crc32}`")
        lines.append("")

        for status_str, message in self.checks:
            if status_str == "PASS":
                lines.append(f"- Pass: {message}")
            elif status_str == "FAIL":
                lines.append(f"- Fail: {message}")
            elif status_str == "WARN":
                lines.append(f"- Warning: {message}")
            else:
                lines.append(f"- Info: {message}")

        return "\n".join(lines)


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
    known = {"sha1": set(), "md5": set(), "sha256": set(), "crc32": set(),
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

        mode, rule = config.get("verification_mode"), config.get("hash_rule", "")
        for system_id, system in config.get("systems", {}).items():
            for file_entry in system.get("files", []):
                sha1s = parse_hash_list(file_entry.get("sha1"))
                md5s = parse_md5_list(file_entry.get("md5"))
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


def _archive_members(
    filepath: str, db: dict | None, platform_hashes: dict, profile_hashes: dict
) -> list[str] | None:
    """What each file of a ZIP is, None when filepath is not a ZIP.

    Read only for an archive no list declares as a whole: MAME and FBNeo
    sets are ZIP BIOS files in their own right.
    """
    if not zipfile.is_zipfile(filepath):
        return None
    held = (db or {}).get("files", {})
    described = []
    try:
        with zipfile.ZipFile(filepath) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_FILE_SIZE:
                    described.append(f"`{info.filename}` too large to read here")
                    continue
                sha1, md5 = hashlib.sha1(), hashlib.md5()
                with archive.open(info) as handle:
                    for chunk in iter(lambda: handle.read(1 << 20), b""):
                        sha1.update(chunk)
                        md5.update(chunk)
                sha1_hex, md5_hex = sha1.hexdigest(), md5.hexdigest()
                crc = f"{info.CRC:08x}"
                if sha1_hex in held:
                    state = f"already held at `{held[sha1_hex]['path']}`"
                elif (
                    sha1_hex in platform_hashes.get("sha1", set())
                    or md5_hex in platform_hashes.get("md5", set())
                    or (crc, info.file_size) in platform_hashes.get("crc32", set())
                    or profile_hashes.get("sha1", {}).get(sha1_hex)
                    or profile_hashes.get("md5", {}).get(md5_hex)
                    or profile_hashes.get("crc32", {}).get((crc, info.file_size))
                ):
                    state = "declared and not held"
                else:
                    state = "not recognised"
                described.append(f"`{info.filename}` {state}")
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        # An encrypted member raises RuntimeError.
        described.append(f"unreadable ({exc})")
    return described


def validate_file(
    filepath: str,
    db: dict | None,
    platform_hashes: dict,
    profile_hashes: dict | None = None,
) -> ValidationResult:
    """Run all validation checks on a file."""
    result = ValidationResult(filepath)

    # Whoever opened the pull request chose this path, so its shape is
    # settled before anything is read. A symlink to an endless device would
    # otherwise be hashed until the job timed out, and a symlink out of the
    # checkout would be reported as though its target had been contributed.
    if os.path.islink(filepath):
        result.add_check(False, "Symlinks are not allowed")
        return result

    if not os.path.exists(filepath):
        result.add_check(False, f"File not found: {filepath}. A path is read from the folder "
                                "the command runs in, or pass --changed to check the files "
                                "changed under bios/")
        return result

    if os.path.isdir(filepath):
        result.add_check(False, "Folder with no file in it")
        return result

    if not os.path.isfile(filepath):
        result.add_check(False, "Not a regular file: a device, a pipe or a socket")
        return result

    result.size = os.path.getsize(filepath)
    hashes = compute_hashes(filepath)
    result.sha1 = hashes["sha1"]
    result.md5 = hashes["md5"]
    result.crc32 = hashes["crc32"]

    ext = os.path.splitext(filepath)[1].lower()
    blocked = ext in BLOCKED_EXTENSIONS

    too_large = result.size > MAX_FILE_SIZE
    if too_large:
        # GitHub refuses a pushed file over 100 MiB, so a pull request cannot
        # carry it. Only a maintainer can add an asset to the release.
        result.add_check(
            False,
            f"File too large for git ({result.size:,} > {MAX_FILE_SIZE:,} bytes). "
            "Leave it out of the pull request and open an issue, its hashes "
            f"filled in ({large_file_issue_url(result)}), saying where the file "
            "can be obtained: a maintainer adds it to the `large-files` release.",
        )
    elif result.size == 0:
        result.add_check(False, "File is empty (0 bytes)")
    else:
        result.add_check(True, f"File size within limits ({result.size:,} bytes)")

    # Paths are compared as the database writes them, relative to the
    # checkout: an absolute path to the file itself read as its duplicate.
    relative = filepath
    if os.path.isabs(filepath):
        candidate = os.path.relpath(filepath, os.getcwd())
        if not candidate.startswith(".."):
            relative = candidate

    if db:
        if result.sha1 in db.get("files", {}):
            existing = db["files"][result.sha1]
            held_at = {
                os.path.normpath(p)
                for p in [existing.get("path"), *(existing.get("paths") or [])] if p
            }
            if os.path.normpath(relative) in held_at:
                # The file the database was built from, not a copy of it: a
                # PR that regenerated database.json was told each new file
                # duplicated itself.
                result.add_check(True, "Already in the database at this path")
            elif _in_nodedup_dir(relative):
                result.add_info(
                    f"Identical to `{existing['path']}`, kept: this tree is read by path"
                )
            else:
                result.outcome = "held"
                result.add_warning(
                    f"Already held at `{existing['path']}`: nothing to add, "
                    "leave this copy out of the pull request"
                )
        else:
            result.add_check(True, "Not a duplicate in database")

    sha1_known = result.sha1 in platform_hashes.get("sha1", set())
    md5_known = result.md5 in platform_hashes.get("md5", set())
    other_known = (
        hashes.get("sha256", "") in platform_hashes.get("sha256", set())
        or (result.crc32, result.size) in platform_hashes.get("crc32", set())
    )
    accepted_by = (
        set() if sha1_known or md5_known or other_known
        else _platforms_accepting(filepath, result.filename, platform_hashes)
    )
    name_known = result.filename in platform_hashes.get("names", set())

    profile_hashes = profile_hashes or {}
    by_profile = (
        profile_hashes.get("sha1", {}).get(result.sha1)
        or profile_hashes.get("sha256", {}).get(hashes.get("sha256", ""))
        or profile_hashes.get("md5", {}).get(result.md5)
        or profile_hashes.get("crc32", {}).get((result.crc32, result.size))
        or profile_hashes.get("crc32", {}).get((result.crc32, None))
    )

    if blocked:
        # An executable is refused unless an emulator profile pins its exact
        # bytes: PICO-8's pico8.exe and SDL2.dll are declared by sha1 from the
        # official archive. A weak hash (md5, crc32) never vouches for code.
        pinned = (
            profile_hashes.get("sha1", {}).get(result.sha1)
            or profile_hashes.get("sha256", {}).get(hashes.get("sha256", ""))
        )
        if pinned:
            result.add_check(
                True,
                f"Executable whose bytes an emulator profile pins by sha1: {', '.join(sorted(pinned))}",
            )
        else:
            result.add_check(False, f"Blocked file extension: {ext}")

    # The files of a ZIP no list declares whole, when the upload is one.
    members: list[str] | None = None
    if sha1_known:
        result.add_check(True, "SHA1 matches known platform requirement")
    elif md5_known:
        result.add_check(True, "MD5 matches known platform requirement")
    elif other_known:
        result.add_check(True, "Hash matches known platform requirement")
    elif accepted_by:
        result.add_check(
            True, "Accepted by the platform's own check: " + ", ".join(sorted(accepted_by))
        )
    elif by_profile:
        names = sorted(by_profile)
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        result.add_check(True, f"Hash matches a file the emulator profile declares: {shown}")
    elif name_known:
        result.add_warning(
            "Filename matches a known requirement but hash differs - may be a variant"
        )
    else:
        result.outcome = "unknown"
        members = None if too_large else _archive_members(
            filepath, db, platform_hashes, profile_hashes
        )
        if members is not None:
            # A folder zipped to upload many files at once was hashed as one
            # file and its contributor asked where that dump came from.
            shown = "; ".join(members[:10]) + (
                f"; and {len(members) - 10} more" if len(members) > 10 else ""
            )
            result.add_warning(
                "A ZIP no platform list or emulator profile declares as a whole: "
                "add the files it holds, unzipped, not the archive. Inside: "
                + (shown or "nothing")
            )
        else:
            result.add_warning(
                "Not recognised: no platform list or emulator profile declares this "
                f"file. Say in the {'issue' if too_large else 'pull request'} which "
                "emulator reads it, for which system, and where the dump comes from"
            )

    normalized = os.path.normpath(relative)
    values = (result.sha1, result.md5, hashes.get("sha256", ""))
    expected = expected_folders(values, platform_hashes, profile_hashes)
    if too_large:
        # The file stays out of the pull request, so no folder of bios/ is
        # the contributor's to choose: the release asset is placed by hand.
        pass
    elif normalized.startswith("bios" + os.sep):
        parts = normalized.split(os.sep)
        here = f"bios/{parts[1]}/{parts[2]}/" if len(parts) >= 4 else ""
        makers = {folder.split("/")[1] for folder in expected}
        if expected and (len(parts) < 4 or parts[1] not in makers):
            # Depth alone passed a PS1 BIOS filed under bios/Nintendo/Game Boy/.
            result.add_warning(
                "Placed under " + (here or "the bios/ root") + ", while the other files of "
                "its system are in " + " or ".join(f"`{f}`" for f in expected)
            )
        elif len(parts) >= 4:
            result.add_check(True, f"Correct placement: bios/{parts[1]}/{parts[2]}/")
        else:
            result.add_warning("File should be in bios/Manufacturer/Console/ structure")
    elif result.outcome == "held" or members is not None:
        # Nothing to place: a copy, or an archive whose files go in unzipped.
        pass
    else:
        # The contributor asks before forking: say where it goes.
        spot = placement(
            values, result.filename, db, platform_hashes, profile_hashes,
            declared=bool(sha1_known or md5_known or other_known or accepted_by or by_profile),
        )
        result.destination = spot.destination(result.sha1)
        copies = f". --place copies it to `{result.destination}`" if result.destination else ""
        if spot.folders:
            result.add_warning(
                "File is not under bios/ yet. Its system's files are in "
                + " or ".join(f"`{f}`" for f in spot.folders) + copies
            )
        elif spot.home:
            result.add_warning(
                f"File is not under bios/ yet. The collection keeps this name in `{spot.home}`"
                + copies
            )
        else:
            result.add_warning(
                "File is not under bios/ yet. Place it in bios/Manufacturer/Console/"
            )

    declared = [
        *platform_hashes.get("sizes", {}).get(result.filename, []),
        *profile_hashes.get("sizes", {}).get(result.filename, []),
    ]
    size_fits = not declared or any(lo <= result.size <= hi for lo, hi in declared)
    if not size_fits:
        expected = sorted({lo if lo == hi else f"{lo:,} to {hi:,}" for lo, hi in declared},
                          key=str)
        shown = ", ".join(f"{v:,}" if isinstance(v, int) else v for v in expected)
        result.add_warning(
            f"Every declaration of {result.filename} expects {shown} bytes, "
            f"this file has {result.size:,}: truncated or another file"
        )

    if (name_known and not (sha1_known or md5_known or other_known or accepted_by)
            and not by_profile and size_fits):
        owners = name_systems(result.filename, platform_hashes, profile_hashes)
        home = _variant_home(db, result.filename, "", set() if len(owners) > 1 else {
            d for table in (platform_hashes, profile_hashes or {}) for s in owners
            for d in table.get("system_dirs", {}).get(s, ())
        } if owners else None)
        if not home and normalized.startswith("bios" + os.sep):
            # Beside the file, in the folder the contributor chose.
            home = os.path.dirname(normalized).replace(os.sep, "/") + "/"
        slot = f"{home}.variants/{result.filename}.{result.sha1[:8]}"
        if home and not normalized.startswith("bios" + os.sep):
            result.destination = slot
        if home:
            result.add_info(
                f"This may be a valid variant. If accepted, it will be placed in `{slot}`"
            )
        else:
            result.add_info("This may be a valid variant of a file the collection lacks")

    return result


def _platforms_accepting(filepath: str, filename: str, platform_hashes: dict) -> set[str]:
    """Platforms whose declaration of this name accepts the file by their
    own check, as verify and the pack builder read it.

    Batocera pins a ROM inside the ZIP (zipped_file), Recalbox hashes a
    ZIP's members together, RomM takes any hash at the declared size: the
    container's sha1 or md5 is in none of those lists, and adam_fdc.zip,
    which Batocera accepts, was called an unknown variant.
    """
    accepted: set[str] = set()
    for entry, mode, rule, platform in platform_hashes.get("entries", {}).get(
        filename.lower(), []
    ):
        if platform in accepted:
            continue
        if entry.get("zipped_file"):
            ok = inner_rom_check(entry, filepath) == "ok"
        else:
            algorithm = digest_algorithm(mode)
            ok = bool(algorithm or rule) and frontend_digest_matches(
                entry, filepath, algorithm or "", rule
            )
        if ok:
            accepted.add(platform)
    return accepted


def expected_folders(
    values: Iterable[str], platform_hashes: dict, profile_hashes: dict | None
) -> list[str]:
    """The bios/<Manufacturer>/<Console>/ folders the files of a hash's
    system are in, read from the first of *values* a table knows.

    A platform's declaration first, then a profile's: most files the gaps
    page lists are declared by a profile alone.
    """
    for table in (platform_hashes, profile_hashes or {}):
        for value in values:
            if value and value in table.get("folders", {}):
                return sorted(table["folders"][value])
    return []


@dataclass(frozen=True)
class Placement:
    """Where a file not under bios/ yet goes.

    ``folders`` are those of its system, ``home`` the folder the collection
    keeps its name in when its system names none. ``name`` is the name it
    is copied under, empty when the declarations do not settle one.
    ``variant`` says a file of that name is already in the folder: a copy
    goes beside it in .variants/, never over it.
    """

    folders: tuple[str, ...] = ()
    home: str = ""
    name: str = ""
    variant: bool = False

    @property
    def folder(self) -> str:
        return self.folders[0] if self.folders else self.home

    def destination(self, sha1: str) -> str:
        if not self.name:
            return ""
        if self.variant:
            return f"{self.folder}.variants/{self.name}.{sha1[:8]}"
        return self.folder + self.name


def placement(
    values: Iterable[str],
    filename: str,
    db: dict | None,
    platform_hashes: dict,
    profile_hashes: dict | None,
    declared: bool,
    exists: Callable[[str], bool] = os.path.exists,
    systems: Iterable[str] = (),
    directory: str = "",
) -> Placement:
    """Where a file goes, by its hashes and its name.

    The review and the site's wanted page both read this one rule, so the
    folder a contributor is sent to is the folder the review accepts.
    *declared* says a list or a profile declares one of the hashes: a file
    known by its name alone gets a slot only once its size fits.

    Without a folder from its hashes, the folder comes from its system:
    *systems*, or every system that declares the name (several of them
    name no copy to sit beside). A file of that name held elsewhere is a
    homonym and says nothing: AmberELEC's MSX config.ini
    was sent beside msx.emu's ColecoVision config.ini. A declared
    *directory* (Machines/MSX2/ for one machine's config.ini) narrows it: a
    copy by name counts only in a directory of that tail, and a held
    directory of that tail is the folder.
    """
    values = [value for value in values if value]
    folders = expected_folders(values, platform_hashes, profile_hashes)
    if folders:
        names = {
            name
            for table in (platform_hashes, profile_hashes or {})
            for value in values
            for name in table.get("named", {}).get(value, ())
        }
        name = next(iter(names)) if len(names) == 1 else ""
        if len(folders) == 1 and name and "/" not in name:
            return Placement(tuple(folders), name=name, variant=exists(folders[0] + name))
        return Placement(tuple(folders))
    held = next((value for value in values if value in (db or {}).get("files", {})), "")
    owners = set(systems) or name_systems(filename, platform_hashes, profile_hashes)
    tables = (platform_hashes, profile_hashes or {})
    # A name several systems declare does not say which one a file is:
    # a copy held for one of them is no answer.
    within = set() if not systems and len(owners) > 1 else {
        d for table in tables for s in owners for d in table.get("system_dirs", {}).get(s, ())
    }
    tail = _directory_tail(db, directory)
    if tail:
        within = {d for d in within if d.endswith("/" + tail) or d == tail} if owners else None
    home = _variant_home(db, filename, held, within if owners or tail else None)
    if declared and home and filename and "/" not in filename:
        # The folder holds a file of that name already.
        return Placement(home=home, name=filename, variant=True)
    if home:
        return Placement(home=home)
    if tail:
        return Placement(home=next(d for d in _held_directories(db) if d.endswith("/" + tail) or d == tail))
    homes = {f for table in tables for s in owners for f in table.get("system_folders", {}).get(s, ())}
    return Placement(tuple(sorted(homes)))


_HELD_DIRECTORIES: dict[int, frozenset[str]] = {}


def _held_directories(db: dict | None) -> frozenset[str]:
    """Every directory a file of the database sits in, .variants/ aside."""
    key = id(db)
    if key not in _HELD_DIRECTORIES:
        _HELD_DIRECTORIES[key] = frozenset(
            path.rsplit("/", 1)[0] + "/"
            for record in (db or {}).get("files", {}).values()
            for path in [record.get("path"), *(record.get("paths") or [])]
            if path and "/" in path and "/.variants/" not in path
        )
    return _HELD_DIRECTORIES[key]


def _directory_tail(db: dict | None, directory: str) -> str:
    """The longest tail of a declared directory, two segments at least,
    that exactly one held directory ends with, empty when none does."""
    parts = [p for p in directory.strip("/").split("/") if p]
    held = _held_directories(db)
    for size in range(len(parts), 1, -1):
        tail = "/".join(parts[-size:]) + "/"
        found = [d for d in held if d.endswith("/" + tail) or d == tail]
        if len(found) == 1:
            return tail
        if found:
            return ""
    return ""


def name_systems(filename: str, platform_hashes: dict, profile_hashes: dict | None) -> set[str]:
    """The systems whose platform or profile entries declare this name."""
    return {
        system for table in (platform_hashes, profile_hashes or {})
        for system in table.get("name_systems", {}).get(filename.lower(), ())
    }


def _variant_home(db: dict | None, name: str, held: str = "",
                  within: set[str] | None = None) -> str:
    """The folder the collection keeps a name in, for its variants beside it.

    The folder of an identical copy comes first: adam_fdc.zip, held in
    bios/Coleco/Adam/, was sent to bios/Arcade/MAME/, the first folder
    the name index gave. A copy found by name alone counts only in a
    directory of *within*, those the file's own systems are held in, when
    the systems are known.
    """
    files = (db or {}).get("files", {})
    by_name = (db or {}).get("indexes", {}).get("by_name", {}).get(name, [])
    copies = [(held, True)] if held in files else []
    for sha1, identical in copies + [(sha1, False) for sha1 in by_name]:
        path = str(files.get(sha1, {}).get("path", ""))
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
        if not folder or "/.variants" in "/" + folder:
            continue
        if identical or within is None or folder in within:
            return folder
    return ""


def _git_lines(*args: str) -> list[str] | None:
    """Output lines of a git command, or None when git refuses it."""
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


PROJECT_URLS = (
    "https://github.com/Abdess/retrobios",
    "https://github.com/Abdess/retroarch_system",
)


def _repo_key(url: str) -> str:
    """owner/name of a clone URL, whatever its scheme."""
    path = url.strip().rstrip("/").removesuffix(".git")
    return "/".join(re.split(r"[/:]", path)[-2:]).casefold()


def _project_main_line() -> str | None:
    """The project's main line, fetched when this clone does not hold it.

    A fork's clone has origin alone. Once the commit is pushed to the fork's
    main, origin/main is HEAD and the diff against it was empty, so --changed
    found nothing and exited 0. A remote added as CONTRIBUTING says and never
    fetched did the same: upstream/main did not exist and origin/main won.
    None leaves the upstream/ and origin/ lines in charge when the clone has
    no remote at all and only its uncommitted files can be read.
    """
    remotes = _git_lines("remote") or []
    if not remotes:
        return None
    project = {_repo_key(url) for url in PROJECT_URLS}
    source = PROJECT_URLS[0]
    for remote in remotes:
        urls = _git_lines("remote", "get-url", "--all", remote) or []
        if any(_repo_key(url) in project for url in urls):
            if _git_lines("rev-parse", "--verify", "--quiet", f"{remote}/main"):
                return f"{remote}/main"
            source = remote
            break
    fetched = subprocess.run(
        ["git", "fetch", "--quiet", "--no-tags", source, "main"],
        capture_output=True, text=True, check=False,
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            f"this clone does not hold the main of {PROJECT_URLS[0]}, and "
            f"fetching its main from {source} failed: {fetched.stderr.strip()}"
        )
    return "FETCH_HEAD"


def get_changed_files() -> list[str]:
    """BIOS files this checkout changes against the project's main line.

    Committed changes are read against the project's main line: the remote
    that names the project (upstream/<base> first, then origin/<base>), or
    the project's main fetched when no remote does. Uncommitted and
    untracked files count too,
    since CONTRIBUTING has the file copied into bios/ before any commit.
    A git that fails outright is an error, never "nothing changed".
    """
    changed: list[str] = []
    compared = False
    project_base = _project_main_line()
    remotes = [[project_base]] if project_base else [
        [f"{remote}/{base}" for base in ("main", "master", "v2")]
        for remote in ("upstream", "origin")
    ]
    for candidates in remotes:
        for line in candidates:
            committed = _git_lines("diff", "--name-only", f"{line}...HEAD")
            if committed is None:
                continue
            compared = True
            changed.extend(committed)
            break
        if compared and changed:
            break
    staged = _git_lines("diff", "--cached", "--name-only")
    local = _git_lines("diff", "--name-only")
    untracked = _git_lines("ls-files", "--others", "--exclude-standard", "--", "bios")
    if staged is None and local is None and untracked is None:
        raise RuntimeError("git cannot read this checkout")
    for found in (staged, local, untracked):
        changed.extend(found or [])
    if not compared:
        print(
            "no upstream/ or origin/ main line to compare against, reading the "
            "staged, modified and untracked files only",
            file=sys.stderr,
        )
    seen: set[str] = set()
    return [
        f for f in changed
        if f.startswith("bios/") and not (f in seen or seen.add(f)) and os.path.isfile(f)
    ]


def expand_folders(paths: list[str]) -> list[str]:
    """Each folder named replaced by the files under it, subfolders included.

    A card's BIOS folder was refused as "Not a regular file", and the
    contributor had to list its files by hand. A link inside the folder
    stays listed, so it is refused like a named one, and an empty folder
    stays as itself to be reported.
    """
    out: list[str] = []
    for path in paths:
        if not os.path.isdir(path) or os.path.islink(path):
            out.append(path)
            continue
        found = sorted(
            str(f) for f in Path(path).rglob("*") if f.is_symlink() or f.is_file()
        )
        out.extend(found or [path])
    return out


def _files_to_validate(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> list:
    """The files named on the command line, or the changed ones."""
    if args.changed and args.files:
        # Named files were dropped for the git diff, and the run reported
        # "No changed BIOS files detected" about files it never looked at.
        parser.error("--changed reads the git diff: name files or pass --changed, not both")
    if not args.changed:
        if not args.files:
            parser.error("No files specified. Use --changed or provide file paths.")
        return expand_folders(args.files)
    try:
        files = get_changed_files()
    except (RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    if not files and not args.json:
        print("No changed BIOS files detected")
    return files


def place(results: list[ValidationResult]) -> list[str]:
    """Copy each placeable file to its destination, never over a file.

    The report named the folder of each file and left 40 copies from a card
    to be made by hand, each .variants/ name retyped. The source is copied,
    not moved: it is often a card or another tree the contributor keeps.
    """
    placed = []
    for r in results:
        if not (r.passed and r.destination and not r.outcome):
            continue
        target = Path(r.destination)
        if target.exists():
            print(f"not placed: {target} exists", file=sys.stderr)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(r.filepath, target)
        placed.append(r.destination)
        print(f"placed {r.filepath} at {r.destination}", file=sys.stderr)
    return placed


def _load_database_if_any(path: str) -> dict | None:
    """The database, optional only where the default is meant.

    A mistyped --db read as "no database" and every file passed its
    duplicate and placement checks unchecked. A damaged one did the same
    after a warning.
    """
    if path == DEFAULT_DB and not os.path.exists(path):
        return None
    return load_database(path)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Validate BIOS file contributions")
    parser.add_argument("files", nargs="*", help="Files to validate")
    parser.add_argument(
        "--changed", action="store_true", help="Auto-detect changed BIOS files"
    )
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to database.json")
    parser.add_argument(
        "--platforms-dir", default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default=DEFAULT_EMULATORS_DIR,
        help="emulator profile directory (default: %(default)s)",
    )
    # One output format: --json beside --markdown printed JSON and dropped
    # the markdown without a word.
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--markdown", action="store_true", help="Output as markdown (for PR comments)"
    )
    output.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--place", action="store_true",
        help="copy each recognised file from outside bios/ to the folder and name "
        "the report gives, or to .variants/ beside the name it varies",
    )
    args = parser.parse_args()

    # The database, platforms and profiles are read from the repository
    # root. Run from elsewhere, every file read as referenced by no platform
    # and placed outside bios/. The files named are read from where they
    # were typed.
    from verify import REPO_ROOT, work_from_repo_root

    if os.path.realpath(os.getcwd()) != os.path.realpath(REPO_ROOT):
        args.files = [os.path.abspath(f) for f in args.files]
    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])

    files = _files_to_validate(args, parser)
    if not files:
        if args.json:
            print("[]")
        return

    db = _load_database_if_any(args.db)
    require_directory(args.platforms_dir, "--platforms-dir")
    platform_hashes = load_platform_hashes(args.platforms_dir, db)
    profile_hashes = load_profile_hashes(args.emulators_dir, db)

    results = []
    for f in files:
        result = validate_file(f, db, platform_hashes, profile_hashes)
        results.append(result)

    all_passed = all(r.passed for r in results)

    if args.json:
        output = []
        for r in results:
            output.append(
                {
                    "file": r.filepath,
                    "passed": r.passed,
                    # A file that failed, unread or refused, is not a new one.
                    "outcome": r.outcome or ("new" if r.passed else "failed"),
                    "destination": r.destination,
                    "sha1": r.sha1,
                    "md5": r.md5,
                    "size": r.size,
                    "checks": [{"status": s, "message": m} for s, m in r.checks],
                }
            )
        print(json.dumps(output, indent=2))
    elif args.markdown:
        lines = ["## BIOS Validation Report", ""]
        held = sum(r.outcome == "held" for r in results)
        unknown = sum(r.outcome == "unknown" for r in results)
        review = ", ".join(part for part in (
            f"{held} already held" if held else "",
            f"{unknown} not recognised" if unknown else "",
        ) if part)
        status = ("some checks failed" if not all_passed
                  else f"no check failed, to review: {review}" if review
                  else "all checks passed")
        lines.append(f"**Status**: {status}")
        lines.append("")

        for r in results:
            lines.append(r.to_markdown())
            lines.append("")

        print("\n".join(lines))
    else:
        for r in results:
            print(f"\n[{r.status}] {r.filepath}")
            if r.sha1:
                print(f"  SHA1: {r.sha1}")
                print(f"  MD5:  {r.md5}")
                print(f"  Size: {r.size:,}")
            for s, m in r.checks:
                marker = (
                    "ok"
                    if s == "PASS"
                    else "fail"
                    if s == "FAIL"
                    else "warn"
                    if s == "WARN"
                    else "info"
                )
                print(f"  [{marker}] {m}")

    if args.place:
        place(results)

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
