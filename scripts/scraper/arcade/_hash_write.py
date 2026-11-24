"""Text patches that write merged hashes into a profile and keep its formatting."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from core.artifacts import write_text_atomic
from model.profiles import PROFILE_BACKUP_SUFFIX
from model.safeparse import yaml_load


DEVICE_SECTION = "  # --- Device ROM sets (generated from MAME -listxml) ---"
SOFTLIST_SECTION = "  # --- Software lists (generated from MAME -listxml) ---"


def write_mame_profile(path: str | Path, data: dict) -> None:
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
    patched = _set_scalar(
        patched, "upstream_commit", data.get("upstream_commit", ""),
        after=("source_commit", "upstream"),
    )
    patched = patch_bios_entries(patched, data.get("files", []))
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


def _set_scalar(text: str, key: str, value: str, after: tuple[str, ...]) -> str:
    """Write a top-level scalar, adding its line after the first key of *after* found.

    The merge sets the value whether or not the profile carries the key: a
    patch that only rewrites an existing line would report the change and
    leave the file without it.
    """
    if not value or re.search(rf"^{re.escape(key)}:", text, re.MULTILINE):
        return _patch_scalar(text, key, value)
    for anchor in after:
        match = re.search(rf"^{re.escape(anchor)}:[^\n]*$", text, re.MULTILINE)
        if match:
            return f'{text[: match.end()]}\n{key}: "{value}"{text[match.end():]}'
    raise ValueError(f"no {' or '.join(after)} line to place {key} after")


def _owned_end(lines: list[str], start_line: int) -> int:
    """The last "owned" line of the entry starting at start_line.

    Owned = indented with 4+ spaces (field lines of this entry).
    """
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
    return last_owned


def _patch_source_ref(lines: list[str], start_line: int, last_owned: int, source_ref: str) -> int:
    """Patch source_ref in-place, or add it. Returns the new last owned line."""
    for j in range(start_line + 1, last_owned + 1):
        if re.match(r"^    source_ref:", lines[j]):
            lines[j] = f'    source_ref: "{source_ref}"'
            return last_owned
    lines.insert(last_owned + 1, f'    source_ref: "{source_ref}"')
    return last_owned + 1


def _patch_required(lines: list[str], start_line: int, last_owned: int, required: bool) -> int:
    """Rewrite required in-place, or add it before category when it is false.

    An absent line reads as true, so only a false needs a line of its own.
    Returns the new last owned line.
    """
    value = f"    required: {str(required).lower()}"
    for j in range(start_line + 1, last_owned + 1):
        if re.match(r"^    required:", lines[j]):
            lines[j] = value
            return last_owned
    if required:
        return last_owned
    at = next(
        (j for j in range(start_line + 1, last_owned + 1) if re.match(r"^    category:", lines[j])),
        last_owned + 1,
    )
    lines.insert(at, value)
    return last_owned + 1


def _drop_contents(lines: list[str], start_line: int, last_owned: int) -> int:
    """Remove an existing contents block. Returns the new last owned line."""
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
    if contents_start is None:
        return last_owned
    if contents_end is None:
        contents_end = contents_start
    del lines[contents_start : contents_end + 1]
    return last_owned - (contents_end - contents_start + 1)


def _patch_entry(lines: list[str], start_line: int, fe: dict) -> None:
    contents = fe.get("contents", [])
    source_ref = fe.get("source_ref", "")

    last_owned = _owned_end(lines, start_line)

    if source_ref:
        last_owned = _patch_source_ref(lines, start_line, last_owned, source_ref)

    # The source settles required for a set the machine runs without
    if "required" in fe:
        last_owned = _patch_required(lines, start_line, last_owned, fe["required"])

    last_owned = _drop_contents(lines, start_line, last_owned)

    # Insert new contents after last owned line
    if contents:
        new_lines = format_contents(contents).split("\n")
        for k, cl in enumerate(new_lines):
            lines.insert(last_owned + 1 + k, cl)


def patch_bios_entries(text: str, files: list[dict]) -> str:
    """Patch contents, source_ref and required of bios_zip entries in-place.

    Processes entries in reverse order to preserve line offsets.
    Each entry's "owned" lines are: the `- name:` line plus all indented
    lines that follow (4+ spaces), stopping at blank lines, comments,
    or the next `- name:`.
    """
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
        if entry_name in patches:
            _patch_entry(lines, start_line, patches[entry_name])

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
        lines.append(f"\n  - name: {yaml_scalar(fe['name'])}")
        lines.extend(set_path_lines(profile_type, fe["name"]))
        lines.append(f"    required: {str(fe['required']).lower()}")
        lines.append("    category: bios_zip")
        if fe.get("source_ref"):
            lines.append(f'    source_ref: "{fe["source_ref"]}"')
        if fe.get("contents"):
            lines.append(format_contents(fe["contents"]))

    if lines:
        # New BIOS root sets go before the generated sections, which run to
        # the end of the files list.
        at = generated_start(text)
        if at is None:
            text = text.rstrip("\n") + "\n" + "\n".join(lines) + "\n"
        else:
            text = text[:at].rstrip("\n") + "\n" + "\n".join(lines) + "\n\n" + text[at:]

    return text


def device_section_start(text: str) -> int | None:
    """Offset of the generated device section header, if the profile has one."""
    match = re.search(rf"^{re.escape(DEVICE_SECTION)}$", text, re.M)
    return match.start() if match else None


def softlist_section_start(text: str) -> int | None:
    """Offset of the generated software list section header, if any."""
    match = re.search(rf"^{re.escape(SOFTLIST_SECTION)}$", text, re.M)
    return match.start() if match else None


def generated_start(text: str) -> int | None:
    """Offset of the first generated section: what a reader wrote ends there."""
    found = [at for at in (softlist_section_start(text), device_section_start(text)) if at is not None]
    return min(found) if found else None


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


def yaml_scalar(value: object) -> str:
    """Quote a scalar so YAML reads back exactly what the source said.

    A MAME ROM named ``01`` written bare re-parses as the integer 1, and the
    set stops naming the file the driver loads. Quoting is not cosmetic here.
    """
    return json.dumps(str(value), ensure_ascii=False)


def format_contents(contents: list[dict]) -> str:
    """Format a contents list as YAML text."""
    lines = ["    contents:"]
    for rom in contents:
        lines.append(f"      - name: {yaml_scalar(rom['name'])}")
        if rom.get("description"):
            lines.append(f"        description: {yaml_scalar(rom['description'])}")
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


def write_fbneo_profile(path: str | Path, data: dict) -> None:
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
            lines.append(f"  - name: {yaml_scalar(fe['name'])}")
            lines.append(f"    archive: {yaml_scalar(fe['archive'])}")
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
