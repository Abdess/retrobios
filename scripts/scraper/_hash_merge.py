"""Merge fetched hash data into emulator YAML profiles.

Supports two strategies:
- MAME: bios_zip entries with contents lists
- FBNeo: individual ROM entries grouped by archive field
"""

from __future__ import annotations

import json
import re
import shutil
import textwrap
from pathlib import Path
from typing import Any


from common import PROFILE_BACKUP_SUFFIX, write_text_atomic, yaml_load


_MAME_RELEASE_RE = re.compile(r"^0\.\d+")
_MAMEDEV = "https://github.com/mamedev/mame"
DEVICE_SECTION = "  # --- Device ROM sets (generated from MAME -listxml) ---"
SOFTLIST_SECTION = "  # --- Software lists (generated from MAME -listxml) ---"
_FILES_END = re.compile(r"^\S", re.M)


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


def merge_mame_profile(
    profile_path: str,
    hashes_path: str,
    write: bool = False,
    add_new: bool = True,
) -> dict[str, Any]:
    """Merge MAME bios_zip entries from upstream hash data.

    Preserves system and note per entry. Updates contents and source_ref
    from the hashes JSON, and required where the source settles it (see
    settled_required). New sets are only added when add_new=True (main
    profile). Entries not in the hash data are left untouched (the scraper
    only covers MACHINE_IS_BIOS_ROOT sets, not all machine ROM sets).

    If write=True, backs up existing profile to .old.yml before writing.
    """
    profile = _load_yaml(profile_path)
    hashes = _load_json(hashes_path)

    # The version follows the refs only for profiles already labelled with a
    # MAME release. A derivative pins its own line: same_cdi ("Git") and a7800
    # ("5.2") would otherwise be relabelled with a MAME version they were
    # never built from.
    if _MAME_RELEASE_RE.match(str(profile.get("core_version") or "")):
        profile["core_version"] = hashes.get("version", profile.get("core_version"))
        # The refs about to be written are line numbers of that release's
        # mamedev/mame tree: the pin moves with them, or the profile cites
        # lines its declared revision does not hold.
        if profile.get("upstream") == _MAMEDEV and hashes.get("commit"):
            profile["upstream_commit"] = hashes["commit"]

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

    if write:
        _backup_and_write(profile_path, profile)

    return profile


def merge_fbneo_profile(
    profile_path: str,
    hashes_path: str,
    write: bool = False,
    add_new: bool = True,
) -> dict[str, Any]:
    """Merge FBNeo individual ROM entries from upstream hash data.

    Preserves system, required per entry. Updates crc32, size, and
    source_ref. New ROMs are only added when add_new=True (main profile).
    Entries not in the hash data are left untouched.

    If write=True, backs up existing profile to .old.yml before writing.
    """
    profile = _load_yaml(profile_path)
    hashes = _load_json(hashes_path)

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

    if write:
        _backup_and_write_fbneo(profile_path, profile, hashes)

    return profile


def compute_diff(
    profile_path: str,
    hashes_path: str,
    mode: str = "mame",
) -> dict[str, Any]:
    """Compute diff between profile and hashes without writing.

    Returns counts of added, updated, removed, and unchanged entries.
    """
    profile = _load_yaml(profile_path)
    hashes = _load_json(hashes_path)

    if mode == "mame":
        return _diff_mame(profile, hashes)
    return _diff_fbneo(profile, hashes)


def _diff_mame(
    profile: dict[str, Any],
    hashes: dict[str, Any],
) -> dict[str, Any]:
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

    return {
        "added": added,
        "updated": updated,
        "removed": [],
        "unchanged": unchanged,
        "out_of_scope": out_of_scope,
    }


def _diff_fbneo(
    profile: dict[str, Any],
    hashes: dict[str, Any],
) -> dict[str, Any]:
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


def _load_yaml(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml_load(f) or {}


def _load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


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


def _backup_and_write(path: str, data: dict) -> None:
    """Write merged profile using text-based patching to preserve formatting.

    Instead of yaml.dump (which destroys comments, quoting, indentation),
    this reads the original file as text, patches specific fields
    (core_version, contents, source_ref), and appends new entries.
    """
    p = Path(path)
    backup = p.with_suffix(PROFILE_BACKUP_SUFFIX)
    shutil.copy2(p, backup)

    original = p.read_text(encoding="utf-8")
    patched = _patch_core_version(original, data.get("core_version", ""))
    patched = _patch_scalar(patched, "upstream_commit", data.get("upstream_commit", ""))
    patched = _patch_bios_entries(patched, data.get("files", []))
    patched = _append_new_entries(patched, data.get("files", []), original)

    write_text_atomic(str(p), patched)


def _patch_core_version(text: str, version: str) -> str:
    """Replace core_version value in-place."""
    return _patch_scalar(text, "core_version", version)


def _patch_scalar(text: str, key: str, value: str) -> str:
    """Replace a top-level scalar in-place, quoted. An absent value changes nothing."""
    if not value:
        return text
    return re.sub(
        rf"^({re.escape(key)}:\s*).*$",
        rf'\g<1>"{value}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )


def _patch_bios_entries(text: str, files: list[dict]) -> str:
    """Patch contents, source_ref and required of bios_zip entries in-place.

    Processes entries in reverse order to preserve line offsets.
    Each entry's "owned" lines are: the `- name:` line plus all indented
    lines that follow (4+ spaces), stopping at blank lines, comments,
    or the next `- name:`.
    """
    import re

    patches: dict[str, dict] = {}
    for fe in files:
        if fe.get("category") != "bios_zip":
            continue
        patches[fe["name"]] = fe

    if not patches:
        return text

    lines = text.split("\n")
    # Find all entry start positions (line indices)
    entry_starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = re.match(r"^  - name:\s*(.+?)\s*$", line)
        if m:
            entry_starts.append((i, m.group(1).strip('"').strip("'")))

    # Process in reverse so line insertions don't shift indices
    for idx in range(len(entry_starts) - 1, -1, -1):
        start_line, entry_name = entry_starts[idx]
        if entry_name not in patches:
            continue

        fe = patches[entry_name]
        contents = fe.get("contents", [])
        source_ref = fe.get("source_ref", "")

        # Find the last "owned" line of this entry
        # Owned = indented with 4+ spaces (field lines of this entry)
        last_owned = start_line
        for j in range(start_line + 1, len(lines)):
            stripped = lines[j].strip()
            if not stripped:
                break  # blank line = end of entry
            if stripped.startswith("#"):
                break  # comment = belongs to next entry
            if re.match(r"^  - ", lines[j]):
                break  # next list item
            if re.match(r"^    ", lines[j]) or re.match(r"^  \w", lines[j]):
                last_owned = j
            else:
                break

        # Patch source_ref in-place
        if source_ref:
            found_sr = False
            for j in range(start_line + 1, last_owned + 1):
                if re.match(r"^    source_ref:", lines[j]):
                    lines[j] = f'    source_ref: "{source_ref}"'
                    found_sr = True
                    break
            if not found_sr:
                lines.insert(last_owned + 1, f'    source_ref: "{source_ref}"')
                last_owned += 1

        # The source settles required for a set the machine runs without
        if "required" in fe:
            for j in range(start_line + 1, last_owned + 1):
                if re.match(r"^    required:", lines[j]):
                    lines[j] = f"    required: {str(fe['required']).lower()}"
                    break

        # Remove existing contents block if present
        contents_start = None
        contents_end = None
        for j in range(start_line + 1, last_owned + 1):
            if re.match(r"^    contents:", lines[j]):
                contents_start = j
            elif contents_start is not None:
                if re.match(r"^      ", lines[j]):
                    contents_end = j
                else:
                    break
        if contents_end is None and contents_start is not None:
            contents_end = contents_start

        if contents_start is not None:
            del lines[contents_start : contents_end + 1]
            last_owned -= contents_end - contents_start + 1

        # Insert new contents after last owned line
        if contents:
            new_lines = _format_contents(contents).split("\n")
            for k, cl in enumerate(new_lines):
                lines.insert(last_owned + 1 + k, cl)

    return "\n".join(lines)


def _append_new_entries(text: str, files: list[dict], original: str) -> str:
    """Append new bios_zip entries (system=None) that aren't in the original."""
    # Parse original to get existing entry names (more reliable than text search)
    existing_data = yaml_load(original) or {}
    existing_names = {f["name"] for f in existing_data.get("files", [])}

    new_entries = []
    for fe in files:
        if fe.get("category") != "bios_zip" or fe.get("system") is not None:
            continue
        if fe["name"] in existing_names:
            continue
        new_entries.append(fe)

    if not new_entries:
        return text

    lines = []
    profile_type = str(existing_data.get("type") or "")
    for fe in new_entries:
        lines.append(f"\n  - name: {_yaml_scalar(fe['name'])}")
        lines.extend(set_path_lines(profile_type, fe["name"]))
        lines.append(f"    required: {str(fe['required']).lower()}")
        lines.append("    category: bios_zip")
        if fe.get("source_ref"):
            lines.append(f'    source_ref: "{fe["source_ref"]}"')
        if fe.get("contents"):
            lines.append(_format_contents(fe["contents"]))

    if lines:
        # New BIOS root sets go before the generated sections, which run to
        # the end of the files list.
        at = generated_start(text)
        if at is None:
            text = text.rstrip("\n") + "\n" + "\n".join(lines) + "\n"
        else:
            text = text[:at].rstrip("\n") + "\n" + "\n".join(lines) + "\n\n" + text[at:]

    return text


def _device_section_start(text: str) -> int | None:
    """Offset of the generated device section header, if the profile has one."""
    match = re.search(rf"^{re.escape(DEVICE_SECTION)}$", text, re.M)
    return match.start() if match else None


def _softlist_section_start(text: str) -> int | None:
    """Offset of the generated software list section header, if any."""
    match = re.search(rf"^{re.escape(SOFTLIST_SECTION)}$", text, re.M)
    return match.start() if match else None


def generated_start(text: str) -> int | None:
    """Offset of the first generated section: what a reader wrote ends there."""
    found = [at for at in (_softlist_section_start(text), _device_section_start(text)) if at is not None]
    return min(found) if found else None


def _device_contents(roms: list[dict], old: list[dict]) -> list[dict]:
    """Contents of a device set, keeping the member descriptions a reader wrote."""
    written = {str(c.get("name")): c.get("description") for c in old or []}
    contents = _build_contents(roms)
    for member in contents:
        if written.get(member["name"]):
            member["description"] = written[member["name"]]
        elif member.get("description"):
            # A biosset description is MAME's text, quoted as written.
            member["description"] = f"`{member['description']}`"
    return contents


def _device_note(description: str) -> str:
    """The note of a generated entry. The device name is MAME's own text,
    quoted verbatim in backticks: `Sun-1 Workstation Monitor; PROM 1&3: Rev AJ`
    is a name, not a sentence."""
    return f"Device ROM set, loaded when a machine instantiates `{description}`."


def _zip_scalar(name: str) -> str:
    """An archive name as the written entries spell it: bare when YAML keeps it."""
    return name if re.fullmatch(r"[a-z0-9_]+\.zip", name) else _yaml_scalar(name)


_PLAIN_SYSTEM = re.compile(r"^[a-z][a-z0-9-]*$")


def _system_lines(systems: list[str]) -> list[str]:
    """`system:` for one system, `systems:` for several, nothing for none."""
    def scalar(value: str) -> str:
        return value if _PLAIN_SYSTEM.match(value) else _yaml_scalar(value)

    if not systems:
        return []
    if len(systems) == 1:
        return [f"    system: {scalar(systems[0])}"]
    return ["    systems:", *(f"      - {scalar(s)}" for s in systems)]


def _entry_systems(entry: dict) -> list[str]:
    """The systems an entry states, in the shape _system_lines writes."""
    if entry.get("system"):
        return [str(entry["system"])]
    return [str(s) for s in entry.get("systems") or []]


def _section_names(text: str) -> set[str]:
    """Entry names inside the generated device section."""
    start = _device_section_start(text)
    if start is None:
        return set()
    end = _FILES_END.search(text, text.index("\n", start) + 1)
    section = text[start : end.start() if end else len(text)]
    return {
        m.group(1).strip('"').strip("'")
        for m in re.finditer(r"^  - name:\s*(.+?)\s*$", section, re.M)
    }


def _set_section_systems(text: str, systems: dict[str, list[str]]) -> str:
    """Rewrite the system fields of the named entries of the device section.

    Any `system:` or `systems:` the entry holds is dropped and the new one
    written right after its category, where a written entry keeps it.
    """
    if not systems:
        return text
    start = _device_section_start(text)
    if start is None:
        return text
    return text[:start] + _rewrite_systems(text[start:], systems)


def _rewrite_systems(section: str, systems: dict[str, list[str]]) -> str:
    """Rewrite the system fields of the named entries of one stretch of text."""
    out: list[str] = []
    current = ""
    in_list = False
    for line in section.split("\n"):
        entry_head = re.match(r"^  - name:\s*(.+?)\s*$", line)
        if entry_head:
            current = entry_head.group(1).strip('"').strip("'")
        if current in systems:
            if in_list and line.startswith("      - "):
                continue
            in_list = False
            if re.match(r"^    system:", line):
                continue
            if re.match(r"^    systems:\s*$", line):
                in_list = True
                continue
        out.append(line)
        if current in systems and re.match(r"^    category:", line):
            out.extend(_system_lines(systems[current]))
    return "\n".join(out)


def set_path_lines(profile_type: str, name: str) -> list[str]:
    """Where each build of a MAME profile reads a set it lists.

    The libretro build searches the content folder, then <system>/mame/bios
    and <system>/mame/roms (libretro-internal/retro_init.cpp,
    Set_Path_Option), never the system folder itself. The standalone build
    reads the top of its rompath.
    """
    if "libretro" not in profile_type:
        return []
    lines = [f'    path: "mame/bios/{name}"']
    if "standalone" in profile_type:
        lines.append(f'    standalone_path: "{name}"')
    return lines


def _format_device_entry(name: str, device: dict, role: str, profile_type: str = "") -> str:
    """One generated device entry, in the field order of the written ones."""
    lines = [
        f"  - name: {_zip_scalar(name)}",
        *set_path_lines(profile_type, name),
        "    required: false",
        "    category: bios_zip",
        *_system_lines(device.get("systems") or []),
    ]
    if device.get("source_line"):
        lines.append(f'    source_ref: "{_build_source_ref(device, role)}"')
    lines.append("    note: >-")
    lines.extend(
        textwrap.wrap(
            _device_note(device.get("description") or name[:-4]),
            width=78,
            initial_indent="      ",
            subsequent_indent="      ",
            break_on_hyphens=False,
        )
    )
    lines.append(_format_contents(_device_contents(device["roms"], [])))
    return "\n".join(lines)


def merge_mame_devices(
    profile_path: str,
    devices: dict[str, dict],
    write: bool = False,
) -> dict[str, list[str]]:
    """Merge MAME device ROM sets into a profile.

    *devices* maps a device shortname to its listxml description, its dumped
    ROMs and, when found, source_file and source_line. A set the profile
    already lists keeps every field a reader wrote: its contents are refreshed
    with the member descriptions kept, and a source_ref is added only where it
    has none. A set it lacks is written under the generated section, in name
    order, with required false. An entry of another category under a device
    name is reported, never touched.

    A device carrying `systems` (attribute_systems) has them written on its
    entry when the entry is in the generated section: `system:` for one,
    `systems:` for several, neither for none. An entry above the section
    keeps the system a reader gave it.
    """
    path = Path(profile_path)
    text = path.read_text(encoding="utf-8")
    profile = yaml_load(text) or {}
    role = mame_ref_role(profile)
    entries: dict[str, list[dict]] = {}
    for entry in profile.get("files") or []:
        entries.setdefault(str(entry.get("name")), []).append(entry)

    report: dict[str, list[str]] = {
        "added": [], "updated": [], "unchanged": [], "conflict": [],
    }
    contents_patches: list[dict] = []
    ref_patches: dict[str, str] = {}
    system_patches: dict[str, list[str]] = {}
    new_blocks: dict[str, str] = {}
    generated = _section_names(text)
    for set_name, device in sorted(devices.items()):
        name = f"{set_name}.zip"
        existing = entries.get(name)
        if not existing:
            new_blocks[name] = _format_device_entry(
                name, device, role, str(profile.get("type") or "")
            )
            report["added"].append(set_name)
            continue
        if any(e.get("category") != "bios_zip" for e in existing):
            report["conflict"].append(set_name)
            continue
        old = existing[0]
        contents = _device_contents(device["roms"], old.get("contents") or [])
        changed = False
        if _contents_differ(old.get("contents") or [], contents):
            contents_patches.append({"name": name, "category": "bios_zip", "contents": contents})
            changed = True
        if not old.get("source_ref") and device.get("source_line"):
            ref_patches[name] = _build_source_ref(device, role)
            changed = True
        if (
            "systems" in device
            and name in generated
            and _entry_systems(old) != list(device["systems"])
        ):
            system_patches[name] = list(device["systems"])
            changed = True
        report["updated" if changed else "unchanged"].append(set_name)

    if write and (contents_patches or ref_patches or system_patches or new_blocks):
        patched = _add_source_refs(text, ref_patches)
        patched = _set_section_systems(patched, system_patches)
        patched = _patch_bios_entries(patched, contents_patches)
        patched = _insert_device_entries(patched, new_blocks)
        shutil.copy2(path, path.with_suffix(PROFILE_BACKUP_SUFFIX))
        write_text_atomic(str(path), patched)
    return report


def _softlist_section(profile: dict, lists: dict[str, list[str]], role: str) -> str:
    """The generated software list section, one entry per list and tree.

    A list takes the fields of each hash/ tree the profile delivers (a
    bundled tree ships with the emulator, not in a pack) and the path of
    that tree. Members the section names leave the tree's own entry.
    """
    trees = [
        entry for entry in profile.get("files") or []
        if entry.get("type") == "directory"
        and str(entry.get("name")) == "hash/"
        and not entry.get("bundled")
    ]
    blocks: list[str] = []
    for tree in trees:
        base = str(tree.get("path") or tree["name"])
        for name, systems in sorted(lists.items()):
            lines = [
                f"  - name: {_yaml_scalar(name + '.xml')}",
                f"    path: {_yaml_scalar(base + name + '.xml')}",
            ]
            if tree.get("mode"):
                lines.append(f"    mode: {tree['mode']}")
            lines += [
                "    category: game_data",
                "    required: false",
                *_system_lines(systems),
            ]
            blocks.append("\n".join(lines))
    if not blocks:
        return ""
    lead = [
        SOFTLIST_SECTION,
        "  # software_list_device::parse opens <list>.xml for each software list a",
        "  # machine declares. Each list below is filed under the systems whose",
        "  # machines declare it, a list no such machine declares stays with its",
        "  # hash/ tree.",
        f"  # ref: {role}src/emu/softlist_dev.cpp:281-313,",
        f"  #      {role}src/frontend/mame/infoxml.cpp:2184-2198",
    ]
    return "\n".join(lead) + "\n\n" + "\n\n".join(blocks) + "\n"


def merge_mame_support(
    profile_path: str,
    lists: dict[str, list[str]],
    samples: dict[str, list[str]],
    write: bool = False,
) -> dict[str, list[str]]:
    """File the software lists and the floppy samples of a MAME profile.

    *lists* maps a software list to the systems whose machines declare it,
    for the lists the release ships. They are written as the generated
    software list section, ahead of the device section, and a refresh
    rewrites the whole section. *samples* maps a floppy sample name to the
    systems whose drives load it: each written entry named <sample>.wav
    under a samples/floppy/ path gets them, and one no system loads gets
    none.
    """
    path = Path(profile_path)
    text = path.read_text(encoding="utf-8")
    profile = yaml_load(text) or {}
    role = mame_ref_role(profile)

    original = text
    start = _softlist_section_start(text)
    if start is not None:
        device = _device_section_start(text)
        if device is not None and device > start:
            end = device
        else:
            end_match = _FILES_END.search(text, text.index("\n", start) + 1)
            end = end_match.start() if end_match else len(text)
        text = text[:start] + text[end:]
    section = _softlist_section(profile, lists, role)

    head_end = generated_start(text)
    head = text if head_end is None else text[:head_end]
    written = yaml_load(head) or {}
    sample_systems: dict[str, list[str]] = {}
    for entry in written.get("files") or []:
        name = str(entry.get("name") or "")
        if "samples/floppy/" not in str(entry.get("path") or "") or not name.endswith(".wav"):
            continue
        wanted = samples.get(name[:-4], [])
        if _entry_systems(entry) != wanted:
            sample_systems[name] = wanted
    head = _rewrite_systems(head, sample_systems) if sample_systems else head
    rest = "" if head_end is None else text[head_end:]

    if section and not rest:
        files_at = re.search(r"^files:[ \t]*$", head, re.M)
        if files_at is None or _FILES_END.search(head, files_at.end()):
            raise ValueError(
                "files: must be the last top-level key to hold a software list section"
            )
    patched = head.rstrip("\n") + "\n"
    if section:
        patched += "\n" + section
    if rest:
        patched += "\n" + rest

    if write and patched != original:
        shutil.copy2(path, path.with_suffix(PROFILE_BACKUP_SUFFIX))
        write_text_atomic(str(path), patched)
    return {
        "lists": sorted(lists),
        "samples": sorted(sample_systems),
        "changed": [str(path)] if patched != original else [],
    }


def _add_source_refs(text: str, refs: dict[str, str]) -> str:
    """Give each named entry a source_ref line, right after its category."""
    if not refs:
        return text
    lines = text.split("\n")
    current = ""
    out: list[str] = []
    for line in lines:
        head = re.match(r"^  - name:\s*(.+?)\s*$", line)
        if head:
            current = head.group(1).strip('"').strip("'")
        out.append(line)
        if current in refs and re.match(r"^    category:", line):
            out.append(f'    source_ref: "{refs[current]}"')
    return "\n".join(out)


def _insert_device_entries(text: str, blocks: dict[str, str]) -> str:
    """Place new device entries in name order inside the generated section.

    The section opens at its header and runs to the end of the files list.
    Entries already there stay in the order they are written, each new one
    goes before the first whose name sorts after it.
    """
    if not blocks:
        return text
    start = _device_section_start(text)
    if start is None:
        files_at = re.search(r"^files:[ \t]*$", text, re.M)
        if files_at is None or _FILES_END.search(text, files_at.end()):
            raise ValueError(
                "files: must be the last top-level key to hold a device section"
            )
        text = text.rstrip("\n") + "\n\n" + DEVICE_SECTION + "\n"
        start = _device_section_start(text)
    body_at = text.index("\n", start) + 1
    end_match = _FILES_END.search(text, body_at)
    end = end_match.start() if end_match else len(text)
    section = text[body_at:end]
    starts = [m.start() for m in re.finditer(r"^  - name:", section, re.M)]
    lead = (section[: starts[0]] if starts else section).strip("\n")
    present = [
        section[a:b].rstrip("\n") for a, b in zip(starts, starts[1:] + [len(section)])
    ]

    def block_name(block: str) -> str:
        return block.split("\n", 1)[0].split(":", 1)[1].strip().strip('"')

    merged: list[str] = []
    pending = sorted(blocks)
    for block in present:
        while pending and pending[0] < block_name(block):
            merged.append(blocks[pending.pop(0)])
        merged.append(block)
    merged.extend(blocks[name] for name in pending)
    body = (lead + "\n" if lead else "") + "\n\n".join(merged) + "\n"
    rest = text[end:]
    return text[:body_at] + body + ("\n" + rest if rest else "")


def _yaml_scalar(value: object) -> str:
    """Quote a scalar so YAML reads back exactly what the source said.

    A MAME ROM named ``01`` written bare re-parses as the integer 1, and the
    set stops naming the file the driver loads. Quoting is not cosmetic here.
    """
    return json.dumps(str(value), ensure_ascii=False)


def _format_contents(contents: list[dict]) -> str:
    """Format a contents list as YAML text."""
    lines = ["    contents:"]
    for rom in contents:
        lines.append(f"      - name: {_yaml_scalar(rom['name'])}")
        if rom.get("description"):
            lines.append(f"        description: {_yaml_scalar(rom['description'])}")
        if rom.get("size"):
            lines.append(f"        size: {rom['size']}")
        if rom.get("crc32"):
            lines.append(f'        crc32: "{rom["crc32"]}"')
        if rom.get("sha1"):
            lines.append(f'        sha1: "{rom["sha1"]}"')
        if rom.get("bad_dump"):
            lines.append("        bad_dump: true")
    return "\n".join(lines)


# Content values an FBNeo entry carries, in the order a new one is written.
_FBNEO_VALUES = ("size", "crc32", "sha1")
_ENTRY_START = re.compile(r"^  - name: ", re.M)
_FIELD_LINE = re.compile(r"^    (?P<key>[a-z0-9_]+):\s*(?P<value>[^#\n]*?)\s*(?P<comment>#.*)?$")


def _patch_fbneo_values(text: str, changed: dict[tuple[str, str], dict]) -> str:
    """Rewrite size/crc32/sha1 inside the blocks of the changed entries."""
    starts = [m.start() for m in _ENTRY_START.finditer(text)] + [len(text)]
    out = [text[: starts[0]]]
    for begin, end in zip(starts, starts[1:]):
        block = text[begin:end]
        fields = {}
        for line in block.splitlines()[1:]:
            match = _FIELD_LINE.match(line)
            if match:
                fields[match["key"]] = match["value"].strip().strip('"')
        name = block.splitlines()[0].removeprefix("  - name:").strip().strip('"')
        entry = changed.get((fields.get("archive", ""), name))
        if entry is not None:
            block = _patch_block_values(block, entry)
        out.append(block)
    return "".join(out)


def _patch_block_values(block: str, entry: dict) -> str:
    lines = block.split("\n")
    for key in _FBNEO_VALUES:
        value = entry.get(key)
        if not value:
            continue
        rendered = str(value) if key == "size" else f'"{value}"'
        for i, line in enumerate(lines):
            match = _FIELD_LINE.match(line)
            if match and match["key"] == key:
                if match["value"].strip().strip('"') != str(value):
                    # A size comment spells the old value, so it goes with it.
                    lines[i] = f"    {key}: {rendered}"
                break
        else:
            anchor = max(
                (i for i, line in enumerate(lines)
                 if (m := _FIELD_LINE.match(line)) and m["key"] in ("archive", *_FBNEO_VALUES)),
                default=0,
            )
            lines.insert(anchor + 1, f"    {key}: {rendered}")
    return "\n".join(lines)


def _backup_and_write_fbneo(path: str, data: dict, hashes: dict) -> None:
    """Write merged FBNeo profile using text-based patching.

    FBNeo profiles have individual ROM entries with archive: field.
    Patches the content values of existing entries that changed and
    appends new ROM entries. core_version is the pin's, never written here.
    Comments and curated source_refs stay as written.
    """
    p = Path(path)
    backup = p.with_suffix(PROFILE_BACKUP_SUFFIX)
    shutil.copy2(p, backup)

    original = p.read_text(encoding="utf-8")
    patched = original

    # Identify new ROM entries by comparing parsed data keys, not text search
    existing_data = yaml_load(original) or {}
    existing_by_key = {
        (f["archive"], f["name"]): f
        for f in existing_data.get("files", [])
        if f.get("archive")
    }
    existing_keys = set(existing_by_key)
    changed = {
        (f["archive"], f["name"]): f
        for f in data.get("files", [])
        if f.get("archive")
        and (f["archive"], f["name"]) in existing_by_key
        and any(
            str(f.get(k) or "") != str(existing_by_key[(f["archive"], f["name"])].get(k) or "")
            for k in _FBNEO_VALUES
            if f.get(k)
        )
    }
    if changed:
        patched = _patch_fbneo_values(patched, changed)
    new_roms = [
        f
        for f in data.get("files", [])
        if f.get("archive") and (f["archive"], f["name"]) not in existing_keys
    ]

    if new_roms:
        lines = []
        for fe in new_roms:
            lines.append(f"  - name: {_yaml_scalar(fe['name'])}")
            lines.append(f"    archive: {_yaml_scalar(fe['archive'])}")
            lines.append(f"    required: {str(fe.get('required', True)).lower()}")
            if fe.get("size"):
                lines.append(f"    size: {fe['size']}")
            if fe.get("crc32"):
                lines.append(f'    crc32: "{fe["crc32"]}"')
            if fe.get("source_ref"):
                lines.append(f'    source_ref: "{fe["source_ref"]}"')
            lines.append("")
        patched = patched.rstrip("\n") + "\n\n" + "\n".join(lines)

    write_text_atomic(str(p), patched)
