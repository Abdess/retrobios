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
        _backup_and_write(profile_path, profile)

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
    p = Path(path)
    backup = p.with_suffix('.old.yml')
    shutil.copy2(p, backup)
    with open(p, 'w', encoding='utf-8') as f:
        yaml.dump(
            data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
