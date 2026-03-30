"""Merge fetched hash data into emulator YAML profiles.

Supports two strategies:
- MAME: bios_zip entries with contents lists
- FBNeo: individual ROM entries grouped by archive field
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml


def merge_mame_profile(
    profile_path: str,
    hashes_path: str,
    write: bool = False,
    add_new: bool = True,
) -> dict[str, Any]:
    """Merge MAME bios_zip entries from upstream hash data.

    Preserves system, note, required per entry. Updates contents and
    source_ref from the hashes JSON. New sets are only added when
    add_new=True (main profile). Entries not in the hash data are
    left untouched (the scraper only covers MACHINE_IS_BIOS_ROOT sets,
    not all machine ROM sets).

    If write=True, backs up existing profile to .old.yml before writing.
    """
    profile = _load_yaml(profile_path)
    hashes = _load_json(hashes_path)

    profile['core_version'] = hashes.get('version', profile.get('core_version'))

    files = profile.get('files', [])
    bios_zip, non_bios = _split_files(files, lambda f: f.get('category') == 'bios_zip')

    existing_by_name: dict[str, dict] = {}
    for entry in bios_zip:
        key = _zip_name_to_set(entry['name'])
        existing_by_name[key] = entry

    updated_bios: list[dict] = []
    matched_names: set[str] = set()

    for set_name, set_data in hashes.get('bios_sets', {}).items():
        contents = _build_contents(set_data.get('roms', []))
        source_ref = _build_source_ref(set_data)

        if set_name in existing_by_name:
            # Update existing entry: preserve manual fields, update contents
            entry = existing_by_name[set_name].copy()
            entry['contents'] = contents
            if source_ref:
                entry['source_ref'] = source_ref
            updated_bios.append(entry)
            matched_names.add(set_name)
        elif add_new:
            # New BIOS set — only added to the main profile
            entry = {
                'name': f'{set_name}.zip',
                'required': True,
                'category': 'bios_zip',
                'system': None,
                'source_ref': source_ref,
                'contents': contents,
            }
            updated_bios.append(entry)

    # Entries not matched by the scraper stay untouched
    # (computer ROMs, device ROMs, etc. — outside BIOS root set scope)
    for set_name, entry in existing_by_name.items():
        if set_name not in matched_names:
            updated_bios.append(entry)

    profile['files'] = non_bios + updated_bios

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

    profile['core_version'] = hashes.get('version', profile.get('core_version'))

    files = profile.get('files', [])
    archive_files, non_archive = _split_files(files, lambda f: 'archive' in f)

    existing_by_key: dict[tuple[str, str], dict] = {}
    for entry in archive_files:
        key = (entry['archive'], entry['name'])
        existing_by_key[key] = entry

    merged: list[dict] = []
    matched_keys: set[tuple[str, str]] = set()

    for set_name, set_data in hashes.get('bios_sets', {}).items():
        archive_name = f'{set_name}.zip'
        source_ref = _build_source_ref(set_data)

        for rom in set_data.get('roms', []):
            rom_name = rom['name']
            key = (archive_name, rom_name)

            if key in existing_by_key:
                entry = existing_by_key[key].copy()
                entry['size'] = rom['size']
                entry['crc32'] = rom['crc32']
                if rom.get('sha1'):
                    entry['sha1'] = rom['sha1']
                if source_ref:
                    entry['source_ref'] = source_ref
                merged.append(entry)
                matched_keys.add(key)
            elif add_new:
                entry = {
                    'name': rom_name,
                    'archive': archive_name,
                    'required': True,
                    'size': rom['size'],
                    'crc32': rom['crc32'],
                }
                if rom.get('sha1'):
                    entry['sha1'] = rom['sha1']
                if source_ref:
                    entry['source_ref'] = source_ref
                merged.append(entry)

    # Entries not matched stay untouched
    for key, entry in existing_by_key.items():
        if key not in matched_keys:
            merged.append(entry)

    profile['files'] = non_archive + merged

    if write:
        _backup_and_write_fbneo(profile_path, profile, hashes)

    return profile


def compute_diff(
    profile_path: str,
    hashes_path: str,
    mode: str = 'mame',
) -> dict[str, Any]:
    """Compute diff between profile and hashes without writing.

    Returns counts of added, updated, removed, and unchanged entries.
    """
    profile = _load_yaml(profile_path)
    hashes = _load_json(hashes_path)

    if mode == 'mame':
        return _diff_mame(profile, hashes)
    return _diff_fbneo(profile, hashes)


def _diff_mame(
    profile: dict[str, Any],
    hashes: dict[str, Any],
) -> dict[str, Any]:
    files = profile.get('files', [])
    bios_zip, _ = _split_files(files, lambda f: f.get('category') == 'bios_zip')

    existing_by_name: dict[str, dict] = {}
    for entry in bios_zip:
        existing_by_name[_zip_name_to_set(entry['name'])] = entry

    added: list[str] = []
    updated: list[str] = []
    unchanged = 0

    bios_sets = hashes.get('bios_sets', {})
    for set_name, set_data in bios_sets.items():
        if set_name not in existing_by_name:
            added.append(set_name)
            continue

        old_entry = existing_by_name[set_name]
        new_contents = _build_contents(set_data.get('roms', []))
        old_contents = old_entry.get('contents', [])

        if _contents_differ(old_contents, new_contents):
            updated.append(set_name)
        else:
            unchanged += 1

    # Items in profile but not in scraper output = out of scope (not removed)
    out_of_scope = len(existing_by_name) - sum(
        1 for s in existing_by_name if s in bios_sets
    )

    return {
        'added': added,
        'updated': updated,
        'removed': [],
        'unchanged': unchanged,
        'out_of_scope': out_of_scope,
    }


def _diff_fbneo(
    profile: dict[str, Any],
    hashes: dict[str, Any],
) -> dict[str, Any]:
    files = profile.get('files', [])
    archive_files, _ = _split_files(files, lambda f: 'archive' in f)

    existing_by_key: dict[tuple[str, str], dict] = {}
    for entry in archive_files:
        existing_by_key[(entry['archive'], entry['name'])] = entry

    added: list[str] = []
    updated: list[str] = []
    unchanged = 0

    seen_keys: set[tuple[str, str]] = set()
    bios_sets = hashes.get('bios_sets', {})

    for set_name, set_data in bios_sets.items():
        archive_name = f'{set_name}.zip'
        for rom in set_data.get('roms', []):
            key = (archive_name, rom['name'])
            seen_keys.add(key)
            label = f"{archive_name}:{rom['name']}"

            if key not in existing_by_key:
                added.append(label)
                continue

            old = existing_by_key[key]
            if old.get('crc32') != rom.get('crc32') or old.get('size') != rom.get('size'):
                updated.append(label)
            else:
                unchanged += 1

    out_of_scope = sum(1 for k in existing_by_key if k not in seen_keys)

    return {
        'added': added,
        'updated': updated,
        'removed': [],
        'unchanged': unchanged,
        'out_of_scope': out_of_scope,
    }


# ── Helpers ──────────────────────────────────────────────────────────


def _load_yaml(path: str) -> dict[str, Any]:
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def _load_json(path: str) -> dict[str, Any]:
    with open(path, encoding='utf-8') as f:
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
    if name.endswith('.zip'):
        return name[:-4]
    return name


def _build_contents(roms: list[dict]) -> list[dict]:
    contents: list[dict] = []
    for rom in roms:
        entry: dict[str, Any] = {
            'name': rom['name'],
            'size': rom['size'],
            'crc32': rom['crc32'],
        }
        if rom.get('sha1'):
            entry['sha1'] = rom['sha1']
        desc = rom.get('bios_description') or rom.get('bios_label') or ''
        if desc:
            entry['description'] = desc
        if rom.get('bad_dump'):
            entry['bad_dump'] = True
        contents.append(entry)
    return contents


def _build_source_ref(set_data: dict) -> str:
    source_file = set_data.get('source_file', '')
    source_line = set_data.get('source_line')
    if source_file and source_line is not None:
        return f'{source_file}:{source_line}'
    return source_file


def _contents_differ(old: list[dict], new: list[dict]) -> bool:
    if len(old) != len(new):
        return True
    old_by_name = {c['name']: c for c in old}
    for entry in new:
        prev = old_by_name.get(entry['name'])
        if prev is None:
            return True
        if prev.get('crc32') != entry.get('crc32'):
            return True
        if prev.get('size') != entry.get('size'):
            return True
        if prev.get('sha1') != entry.get('sha1'):
            return True
    return False


def _backup_and_write(path: str, data: dict) -> None:
    """Write merged profile using text-based patching to preserve formatting.

    Instead of yaml.dump (which destroys comments, quoting, indentation),
    this reads the original file as text, patches specific fields
    (core_version, contents, source_ref), and appends new entries.
    """
    p = Path(path)
    backup = p.with_suffix('.old.yml')
    shutil.copy2(p, backup)

    original = p.read_text(encoding='utf-8')
    patched = _patch_core_version(original, data.get('core_version', ''))
    patched = _patch_bios_entries(patched, data.get('files', []))
    patched = _append_new_entries(patched, data.get('files', []), original)

    p.write_text(patched, encoding='utf-8')


def _patch_core_version(text: str, version: str) -> str:
    """Replace core_version value in-place."""
    if not version:
        return text
    import re
    return re.sub(
        r'^(core_version:\s*).*$',
        rf'\g<1>"{version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )


def _patch_bios_entries(text: str, files: list[dict]) -> str:
    """Patch contents and source_ref for existing bios_zip entries in-place.

    Processes entries in reverse order to preserve line offsets.
    Each entry's "owned" lines are: the `- name:` line plus all indented
    lines that follow (4+ spaces), stopping at blank lines, comments,
    or the next `- name:`.
    """
    import re

    # Build a lookup of what to patch
    patches: dict[str, dict] = {}
    for fe in files:
        if fe.get('category') != 'bios_zip':
            continue
        patches[fe['name']] = fe

    if not patches:
        return text

    lines = text.split('\n')
    # Find all entry start positions (line indices)
    entry_starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = re.match(r'^  - name:\s*(.+?)\s*$', line)
        if m:
            entry_starts.append((i, m.group(1).strip('"').strip("'")))

    # Process in reverse so line insertions don't shift indices
    for idx in range(len(entry_starts) - 1, -1, -1):
        start_line, entry_name = entry_starts[idx]
        if entry_name not in patches:
            continue

        fe = patches[entry_name]
        contents = fe.get('contents', [])
        source_ref = fe.get('source_ref', '')

        # Find the last "owned" line of this entry
        # Owned = indented with 4+ spaces (field lines of this entry)
        last_owned = start_line
        for j in range(start_line + 1, len(lines)):
            stripped = lines[j].strip()
            if not stripped:
                break  # blank line = end of entry
            if stripped.startswith('#'):
                break  # comment = belongs to next entry
            if re.match(r'^  - ', lines[j]):
                break  # next list item
            if re.match(r'^    ', lines[j]) or re.match(r'^  \w', lines[j]):
                last_owned = j
            else:
                break

        # Patch source_ref in-place
        if source_ref:
            found_sr = False
            for j in range(start_line + 1, last_owned + 1):
                if re.match(r'^    source_ref:', lines[j]):
                    lines[j] = f'    source_ref: "{source_ref}"'
                    found_sr = True
                    break
            if not found_sr:
                lines.insert(last_owned + 1, f'    source_ref: "{source_ref}"')
                last_owned += 1

        # Remove existing contents block if present
        contents_start = None
        contents_end = None
        for j in range(start_line + 1, last_owned + 1):
            if re.match(r'^    contents:', lines[j]):
                contents_start = j
            elif contents_start is not None:
                if re.match(r'^      ', lines[j]):
                    contents_end = j
                else:
                    break
        if contents_end is None and contents_start is not None:
            contents_end = contents_start

        if contents_start is not None:
            del lines[contents_start:contents_end + 1]
            last_owned -= (contents_end - contents_start + 1)

        # Insert new contents after last owned line
        if contents:
            new_lines = _format_contents(contents).split('\n')
            for k, cl in enumerate(new_lines):
                lines.insert(last_owned + 1 + k, cl)

    return '\n'.join(lines)


def _append_new_entries(text: str, files: list[dict], original: str) -> str:
    """Append new bios_zip entries (system=None) that aren't in the original."""
    # Parse original to get existing entry names (more reliable than text search)
    existing_data = yaml.safe_load(original) or {}
    existing_names = {f['name'] for f in existing_data.get('files', [])}

    new_entries = []
    for fe in files:
        if fe.get('category') != 'bios_zip' or fe.get('system') is not None:
            continue
        if fe['name'] in existing_names:
            continue
        new_entries.append(fe)

    if not new_entries:
        return text

    lines = []
    for fe in new_entries:
        lines.append(f'\n  - name: {fe["name"]}')
        lines.append(f'    required: {str(fe["required"]).lower()}')
        lines.append(f'    category: bios_zip')
        if fe.get('source_ref'):
            lines.append(f'    source_ref: "{fe["source_ref"]}"')
        if fe.get('contents'):
            lines.append(_format_contents(fe['contents']))

    if lines:
        text = text.rstrip('\n') + '\n' + '\n'.join(lines) + '\n'

    return text


def _format_contents(contents: list[dict]) -> str:
    """Format a contents list as YAML text."""
    lines = ['    contents:']
    for rom in contents:
        lines.append(f'      - name: {rom["name"]}')
        if rom.get('description'):
            lines.append(f'        description: {rom["description"]}')
        if rom.get('size'):
            lines.append(f'        size: {rom["size"]}')
        if rom.get('crc32'):
            lines.append(f'        crc32: "{rom["crc32"]}"')
        if rom.get('sha1'):
            lines.append(f'        sha1: "{rom["sha1"]}"')
        if rom.get('bad_dump'):
            lines.append(f'        bad_dump: true')
    return '\n'.join(lines)


def _backup_and_write_fbneo(path: str, data: dict, hashes: dict) -> None:
    """Write merged FBNeo profile using text-based patching.

    FBNeo profiles have individual ROM entries with archive: field.
    Only patches core_version and appends new ROM entries.
    Existing entries are left untouched (CRC32 changes are rare).
    """
    p = Path(path)
    backup = p.with_suffix('.old.yml')
    shutil.copy2(p, backup)

    original = p.read_text(encoding='utf-8')
    patched = _patch_core_version(original, data.get('core_version', ''))

    # Identify new ROM entries by comparing parsed data keys, not text search
    existing_data = yaml.safe_load(original) or {}
    existing_keys = {
        (f['archive'], f['name'])
        for f in existing_data.get('files', [])
        if f.get('archive')
    }
    new_roms = [
        f for f in data.get('files', [])
        if f.get('archive') and (f['archive'], f['name']) not in existing_keys
    ]

    if new_roms:
        lines = []
        for fe in new_roms:
            lines.append(f'  - name: "{fe["name"]}"')
            lines.append(f'    archive: {fe["archive"]}')
            lines.append(f'    required: {str(fe.get("required", True)).lower()}')
            if fe.get('size'):
                lines.append(f'    size: {fe["size"]}')
            if fe.get('crc32'):
                lines.append(f'    crc32: "{fe["crc32"]}"')
            if fe.get('source_ref'):
                lines.append(f'    source_ref: "{fe["source_ref"]}"')
            lines.append('')
        patched = patched.rstrip('\n') + '\n\n' + '\n'.join(lines)

    p.write_text(patched, encoding='utf-8')
