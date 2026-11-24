"""Merge fetched hash data into emulator YAML profiles.

Supports two strategies:
- MAME: bios_zip entries with contents lists
- FBNeo: individual ROM entries grouped by archive field
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


from model.sources import source_yaml_file


_MAME_RELEASE_RE = re.compile(r"^0\.\d+")
_MAMEDEV = "https://github.com/mamedev/mame"


def mame_ref_role(profile: dict[str, Any]) -> str:
    """Role word a ref read from mamedev/mame carries in this profile.

    A profile that builds from another tree (libretro/mame) cites lines of
    mamedev/mame as "upstream <path>:<line>". Written bare, the ref was read
    against the libretro port, and every refresh rewrote the 171 prefixed refs
    of mame.yml into that form.
    """
    upstream = str(profile.get("upstream") or "").rstrip("/")
    source = str(profile.get("source") or "").rstrip("/")
    if upstream.startswith(_MAMEDEV) and source and source != upstream:
        return "upstream "
    return ""


def settled_required(entry: dict, set_data: dict) -> bool:
    """The required flag a bios_zip entry carries after a refresh.

    set_data["required"] is what romload.cpp does with the set missing: False
    when every ROM is NO_DUMP or ROM_OPTIONAL, so the machine runs without
    it, and nothing outranks that. True only says the machine itself stops;
    whether the core needs that machine is the profile's call, so a curated
    false is kept. The exception is a false over no contents, which is
    what an undumped set leaves: once a ROM is dumped, the set is required.
    """
    current = entry.get("required", True)
    code = set_data.get("required")
    if code is False:
        return False
    if code is True and current is False and not entry.get("contents"):
        return True
    return current


def mame_pin(profile: dict[str, Any], hashes: dict[str, Any]) -> dict[str, Any]:
    """The core_version and upstream_commit a refresh gives a MAME profile."""
    # The version follows the refs only for profiles already labelled with a
    # MAME release. A derivative pins its own line: same_cdi ("Git") and a7800
    # ("5.2") would otherwise be relabelled with a MAME version they were
    # never built from.
    if not _MAME_RELEASE_RE.match(str(profile.get("core_version") or "")):
        return {}
    pin = {"core_version": hashes.get("version", profile.get("core_version"))}
    # The refs about to be written are line numbers of that release's
    # mamedev/mame tree: the pin moves with them, or the profile cites lines
    # its declared revision does not hold.
    if profile.get("upstream") == _MAMEDEV and hashes.get("commit"):
        pin["upstream_commit"] = hashes["commit"]
    return pin


def merge_mame_profile(
    profile: dict[str, Any],
    hashes: dict[str, Any],
    add_new: bool = True,
) -> dict[str, Any]:
    """Merge MAME bios_zip entries from upstream hash data.

    Preserves system and note per entry. Updates contents and source_ref
    from the hashes JSON, and required where the source settles it (see
    settled_required). New sets are only added when add_new=True (main
    profile). Entries not in the hash data are left untouched (the scraper
    only covers MACHINE_IS_BIOS_ROOT sets, not all machine ROM sets).

    Returns the merged profile and leaves the input dict as it was. Writing
    is write_mame_profile's.
    """
    profile = dict(profile)
    profile.update(mame_pin(profile, hashes))

    files = profile.get("files", [])
    bios_zip, non_bios = _split_files(files, lambda f: f.get("category") == "bios_zip")

    existing_by_name: dict[str, dict] = {}
    for entry in bios_zip:
        key = _zip_name_to_set(entry["name"])
        existing_by_name[key] = entry

    updated_bios: list[dict] = []
    matched_names: set[str] = set()

    role = mame_ref_role(profile)
    for set_name, set_data in hashes.get("bios_sets", {}).items():
        contents = _build_contents(set_data.get("roms", []))
        source_ref = _build_source_ref(set_data, role)

        if set_name in existing_by_name:
            # Update existing entry: preserve manual fields, update contents
            entry = existing_by_name[set_name].copy()
            entry["contents"] = contents
            if source_ref:
                entry["source_ref"] = source_ref
            entry["required"] = settled_required(existing_by_name[set_name], set_data)
            updated_bios.append(entry)
            matched_names.add(set_name)
        elif add_new:
            # New BIOS set, only added to the main profile
            entry = {
                "name": f"{set_name}.zip",
                "required": settled_required({}, set_data),
                "category": "bios_zip",
                "system": None,
                "source_ref": source_ref,
                "contents": contents,
            }
            updated_bios.append(entry)

    # Entries not matched by the scraper stay untouched
    # (computer ROMs, device ROMs, etc., outside BIOS root set scope)
    for set_name, entry in existing_by_name.items():
        if set_name not in matched_names:
            updated_bios.append(entry)

    profile["files"] = non_bios + updated_bios
    return profile


def merge_fbneo_profile(
    profile: dict[str, Any],
    hashes: dict[str, Any],
    add_new: bool = True,
) -> dict[str, Any]:
    """Merge FBNeo individual ROM entries from upstream hash data.

    Preserves system, required per entry. Updates crc32, size, and
    source_ref. New ROMs are only added when add_new=True (main profile).
    Entries not in the hash data are left untouched.

    Returns the merged profile and leaves the input dict as it was. Writing
    is write_fbneo_profile's.
    """
    profile = dict(profile)

    # core_version stays as written: it is the version of the code at the
    # profile's own pin, read through version_basis (profile_sync
    # --set-version). The hashes come from finalburnneo/FBNeo's tip, a
    # revision the libretro/FBNeo pin does not name: writing its version
    # left fbneo, fbneo_cps12 and fbneo_neogeo on a release their pin
    # never was.

    files = profile.get("files", [])
    archive_files, non_archive = _split_files(files, lambda f: "archive" in f)

    existing_by_key: dict[tuple[str, str], dict] = {}
    for entry in archive_files:
        key = (entry["archive"], entry["name"])
        existing_by_key[key] = entry

    merged: list[dict] = []
    matched_keys: set[tuple[str, str]] = set()

    for set_name, set_data in hashes.get("bios_sets", {}).items():
        archive_name = f"{set_name}.zip"
        source_ref = _build_source_ref(set_data)

        for rom in set_data.get("roms", []):
            rom_name = rom["name"]
            key = (archive_name, rom_name)

            if key in existing_by_key:
                entry = existing_by_key[key].copy()
                entry["size"] = rom["size"]
                entry["crc32"] = rom["crc32"]
                if rom.get("sha1"):
                    entry["sha1"] = rom["sha1"]
                if source_ref:
                    entry["source_ref"] = source_ref
                merged.append(entry)
                matched_keys.add(key)
            elif add_new:
                entry = {
                    "name": rom_name,
                    "archive": archive_name,
                    "required": True,
                    "size": rom["size"],
                    "crc32": rom["crc32"],
                }
                if rom.get("sha1"):
                    entry["sha1"] = rom["sha1"]
                if source_ref:
                    entry["source_ref"] = source_ref
                merged.append(entry)

    # Entries not matched stay untouched
    for key, entry in existing_by_key.items():
        if key not in matched_keys:
            merged.append(entry)

    profile["files"] = non_archive + merged
    return profile


def compute_diff(
    profile: dict[str, Any],
    hashes: dict[str, Any],
    mode: str = "mame",
) -> dict[str, Any]:
    """Compute diff between profile and hashes without writing.

    Returns counts of added, updated, removed, and unchanged entries.
    """
    if mode == "mame":
        return diff_mame(profile, hashes)
    return diff_fbneo(profile, hashes)


def diff_mame(
    profile: dict[str, Any],
    hashes: dict[str, Any],
) -> dict[str, Any]:
    """Sets the hash data adds to or changes in a MAME profile."""
    files = profile.get("files", [])
    bios_zip, _ = _split_files(files, lambda f: f.get("category") == "bios_zip")

    existing_by_name: dict[str, dict] = {}
    for entry in bios_zip:
        existing_by_name[_zip_name_to_set(entry["name"])] = entry

    added: list[str] = []
    updated: list[str] = []
    unchanged = 0

    role = mame_ref_role(profile)
    bios_sets = hashes.get("bios_sets", {})
    for set_name, set_data in bios_sets.items():
        if set_name not in existing_by_name:
            added.append(set_name)
            continue

        old_entry = existing_by_name[set_name]
        new_contents = _build_contents(set_data.get("roms", []))
        old_contents = old_entry.get("contents", [])
        new_ref = _build_source_ref(set_data, role)

        # A driver keeping the same ROMs still moves inside its file between
        # releases. Without this the hashes stay current while the source_ref
        # rots, which is exactly what profile_sync then reports as drift.
        ref_moved = bool(new_ref) and old_entry.get("source_ref") != new_ref

        required_moved = old_entry.get("required", True) != settled_required(old_entry, set_data)

        if _contents_differ(old_contents, new_contents) or ref_moved or required_moved:
            updated.append(set_name)
        else:
            unchanged += 1

    # Items in profile but not in scraper output = out of scope (not removed)
    out_of_scope = len(existing_by_name) - sum(
        1 for s in existing_by_name if s in bios_sets
    )

    # A release that leaves every BIOS root set as it was still moves the pin.
    # merge_mame_profile writes it, so the write gate has to see it.
    pin = {
        field: (profile.get(field), value)
        for field, value in mame_pin(profile, hashes).items()
        if profile.get(field) != value
    }

    return {
        "added": added,
        "updated": updated,
        "removed": [],
        "unchanged": unchanged,
        "out_of_scope": out_of_scope,
        "pin": pin,
    }


def diff_fbneo(
    profile: dict[str, Any],
    hashes: dict[str, Any],
) -> dict[str, Any]:
    """ROMs the hash data adds to or changes in an FBNeo profile."""
    files = profile.get("files", [])
    archive_files, _ = _split_files(files, lambda f: "archive" in f)

    existing_by_key: dict[tuple[str, str], dict] = {}
    for entry in archive_files:
        existing_by_key[(entry["archive"], entry["name"])] = entry

    added: list[str] = []
    updated: list[str] = []
    unchanged = 0

    seen_keys: set[tuple[str, str]] = set()
    bios_sets = hashes.get("bios_sets", {})

    for set_name, set_data in bios_sets.items():
        archive_name = f"{set_name}.zip"
        for rom in set_data.get("roms", []):
            key = (archive_name, rom["name"])
            seen_keys.add(key)
            label = f"{archive_name}:{rom['name']}"

            if key not in existing_by_key:
                added.append(label)
                continue

            old = existing_by_key[key]
            # source_ref is deliberately not compared here. The scraper knows
            # one line per driver, the struct, while a curated entry cites the
            # RomDesc line of its own ROM. Treating the difference as drift
            # would replace per-ROM precision with a single driver line, which
            # the profiling rules call the signature of a faulty entry.
            if old.get("crc32") != rom.get("crc32") or old.get("size") != rom.get(
                "size"
            ):
                updated.append(label)
            else:
                unchanged += 1

    out_of_scope = sum(1 for k in existing_by_key if k not in seen_keys)

    return {
        "added": added,
        "updated": updated,
        "removed": [],
        "unchanged": unchanged,
        "out_of_scope": out_of_scope,
    }


# Helpers


def load_profile(path: str | Path) -> dict[str, Any]:
    """The profile at path as the merge reads it, empty when the file is."""
    return source_yaml_file(path) or {}


def _split_files(
    files: list[dict],
    predicate: Any,
) -> tuple[list[dict], list[dict]]:
    matching: list[dict] = []
    rest: list[dict] = []
    for f in files:
        if predicate(f):
            matching.append(f)
        else:
            rest.append(f)
    return matching, rest


def _zip_name_to_set(name: str) -> str:
    if name.endswith(".zip"):
        return name[:-4]
    return name


def _build_contents(roms: list[dict]) -> list[dict]:
    contents: list[dict] = []
    for rom in roms:
        entry: dict[str, Any] = {
            "name": rom["name"],
            "size": rom["size"],
            "crc32": rom["crc32"],
        }
        if rom.get("sha1"):
            entry["sha1"] = rom["sha1"]
        desc = rom.get("bios_description") or rom.get("bios_label") or ""
        if desc:
            entry["description"] = desc
        if rom.get("bad_dump"):
            entry["bad_dump"] = True
        contents.append(entry)
    return contents


def _build_source_ref(set_data: dict, role: str = "") -> str:
    source_file = set_data.get("source_file", "")
    source_line = set_data.get("source_line")
    if not source_file:
        return ""
    if source_line is not None:
        return f"{role}{source_file}:{source_line}"
    return f"{role}{source_file}"


def _contents_differ(old: list[dict], new: list[dict]) -> bool:
    if len(old) != len(new):
        return True
    old_by_name = {c["name"]: c for c in old}
    for entry in new:
        prev = old_by_name.get(entry["name"])
        if prev is None:
            return True
        if prev.get("crc32") != entry.get("crc32"):
            return True
        if prev.get("size") != entry.get("size"):
            return True
        if prev.get("sha1") != entry.get("sha1"):
            return True
    return False
