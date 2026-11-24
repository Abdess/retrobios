"""The generated device and software list sections of a MAME profile."""

from __future__ import annotations

import re
import shutil
import textwrap
from pathlib import Path

from core.artifacts import write_text_atomic
from model.profiles import PROFILE_BACKUP_SUFFIX
from model.safeparse import yaml_load
from ._hash_merge import _build_contents, _build_source_ref, contents_differ, mame_ref_role
from ._hash_write import (
    DEVICE_SECTION,
    SOFTLIST_SECTION,
    device_section_start,
    format_contents,
    patch_bios_entries,
    softlist_section_start,
    yaml_scalar,
    generated_start,
    set_path_lines,
)


_FILES_END = re.compile(r"^\S", re.M)


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
    return name if re.fullmatch(r"[a-z0-9_]+\.zip", name) else yaml_scalar(name)


_PLAIN_SYSTEM = re.compile(r"^[a-z][a-z0-9-]*$")


def _system_lines(systems: list[str]) -> list[str]:
    """`system:` for one system, `systems:` for several, nothing for none."""
    def scalar(value: str) -> str:
        return value if _PLAIN_SYSTEM.match(value) else yaml_scalar(value)

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
    start = device_section_start(text)
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
    start = device_section_start(text)
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
    lines.append(format_contents(_device_contents(device["roms"], [])))
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
        if contents_differ(old.get("contents") or [], contents):
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
        patched = patch_bios_entries(patched, contents_patches)
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
                f"  - name: {yaml_scalar(name + '.xml')}",
                f"    path: {yaml_scalar(base + name + '.xml')}",
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
    start = softlist_section_start(text)
    if start is not None:
        device = device_section_start(text)
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
    start = device_section_start(text)
    if start is None:
        files_at = re.search(r"^files:[ \t]*$", text, re.M)
        if files_at is None or _FILES_END.search(text, files_at.end()):
            raise ValueError(
                "files: must be the last top-level key to hold a device section"
            )
        text = text.rstrip("\n") + "\n\n" + DEVICE_SECTION + "\n"
        start = device_section_start(text)
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
