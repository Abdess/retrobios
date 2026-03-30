"""Fetch MAME BIOS hashes from mamedev/mame source and merge into profiles.

Sparse clones the MAME repo, parses the source tree for BIOS root sets,
caches results to data/mame-hashes.json, and optionally merges into
emulator profiles that reference mamedev/mame upstream.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .mame_parser import parse_mame_source_tree
from ._hash_merge import compute_diff, merge_mame_profile

log = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[2]
_CACHE_PATH = _ROOT / 'data' / 'mame-hashes.json'
_CLONE_DIR = _ROOT / 'tmp' / 'mame'
_EMULATORS_DIR = _ROOT / 'emulators'
_REPO_URL = 'https://github.com/mamedev/mame.git'
_STALE_HOURS = 24


# ── Cache ────────────────────────────────────────────────────────────


def _load_cache() -> dict[str, Any] | None:
    if not _CACHE_PATH.exists():
        return None
    try:
        with open(_CACHE_PATH, encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _is_stale(cache: dict[str, Any] | None) -> bool:
    if cache is None:
        return True
    fetched_at = cache.get('fetched_at')
    if not fetched_at:
        return True
    try:
        ts = datetime.fromisoformat(fetched_at)
        age = datetime.now(timezone.utc) - ts
        return age.total_seconds() > _STALE_HOURS * 3600
    except (ValueError, TypeError):
        return True


def _write_cache(data: dict[str, Any]) -> None:
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_CACHE_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log.info('cache written to %s', _CACHE_PATH)


# ── Git operations ───────────────────────────────────────────────────


def _run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ['git', *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _sparse_clone() -> None:
    if _CLONE_DIR.exists():
        shutil.rmtree(_CLONE_DIR)
    _CLONE_DIR.parent.mkdir(parents=True, exist_ok=True)

    log.info('sparse cloning mamedev/mame into %s', _CLONE_DIR)
    _run_git([
        'clone',
        '--depth', '1',
        '--filter=blob:none',
        '--sparse',
        _REPO_URL,
        str(_CLONE_DIR),
    ])
    _run_git(
        ['sparse-checkout', 'set', 'src/mame', 'src/devices'],
        cwd=_CLONE_DIR,
    )


def _get_version() -> str:
    # version.cpp is generated at build time, not in the repo.
    # Use GitHub API to get the latest release tag.
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/mamedev/mame/releases/latest',
            headers={'User-Agent': 'retrobios-scraper/1.0',
                     'Accept': 'application/vnd.github.v3+json'},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            tag = data.get('tag_name', '')
            if tag:
                return _parse_version_tag(tag)
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        pass
    return 'unknown'


def _parse_version_tag(tag: str) -> str:
    prefix = 'mame'
    raw = tag.removeprefix(prefix) if tag.startswith(prefix) else tag
    if raw.isdigit() and len(raw) >= 4:
        return f'{raw[0]}.{raw[1:]}'
    return raw




def _get_commit() -> str:
    try:
        result = _run_git(['rev-parse', 'HEAD'], cwd=_CLONE_DIR)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ''


def _cleanup() -> None:
    if _CLONE_DIR.exists():
        log.info('cleaning up %s', _CLONE_DIR)
        shutil.rmtree(_CLONE_DIR)


# ── Profile discovery ────────────────────────────────────────────────


def _find_mame_profiles() -> list[Path]:
    profiles: list[Path] = []
    for path in sorted(_EMULATORS_DIR.glob('*.yml')):
        if path.name.endswith('.old.yml'):
            continue
        try:
            with open(path, encoding='utf-8') as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            upstream = data.get('upstream', '')
            # Only match profiles tracking current MAME (not frozen snapshots
            # which have upstream like "mamedev/mame/tree/mame0139")
            if isinstance(upstream, str) and upstream.rstrip('/') == 'https://github.com/mamedev/mame':
                profiles.append(path)
        except (yaml.YAMLError, OSError):
            continue
    return profiles


# ── Diff formatting ──────────────────────────────────────────────────


def _format_diff(
    profile_path: Path,
    diff: dict[str, Any],
    hashes: dict[str, Any],
    show_added: bool = True,
) -> list[str]:
    lines: list[str] = []
    name = profile_path.stem

    added = diff.get('added', [])
    updated = diff.get('updated', [])
    removed = diff.get('removed', [])
    unchanged = diff.get('unchanged', 0)

    if not added and not updated and not removed:
        lines.append(f'  {name}:')
        lines.append('    no changes')
        return lines

    lines.append(f'  {name}:')

    if show_added:
        bios_sets = hashes.get('bios_sets', {})
        for set_name in added:
            rom_count = len(bios_sets.get(set_name, {}).get('roms', []))
            source_file = bios_sets.get(set_name, {}).get('source_file', '')
            source_line = bios_sets.get(set_name, {}).get('source_line', '')
            ref = f'{source_file}:{source_line}' if source_file else ''
            lines.append(f'    + {set_name}.zip ({ref}, {rom_count} ROMs)')
    elif added:
        lines.append(f'    + {len(added)} new sets available (main profile only)')

    for set_name in updated:
        lines.append(f'    ~ {set_name}.zip (contents changed)')

    oos = diff.get('out_of_scope', 0)
    lines.append(f'    = {unchanged} unchanged')
    if oos:
        lines.append(f'    . {oos} out of scope (not BIOS root sets)')
    return lines


# ── Main ─────────────────────────────────────────────────────────────


def _fetch_hashes(force: bool) -> dict[str, Any]:
    cache = _load_cache()
    if not force and not _is_stale(cache):
        log.info('using cached data from %s', cache.get('fetched_at', ''))
        return cache  # type: ignore[return-value]

    try:
        _sparse_clone()
        bios_sets = parse_mame_source_tree(str(_CLONE_DIR))
        version = _get_version()
        commit = _get_commit()

        data: dict[str, Any] = {
            'source': 'mamedev/mame',
            'version': version,
            'commit': commit,
            'fetched_at': datetime.now(timezone.utc).isoformat(),
            'bios_sets': bios_sets,
        }
        _write_cache(data)
        return data
    finally:
        _cleanup()


def _run(args: argparse.Namespace) -> None:
    hashes = _fetch_hashes(args.force)

    total_sets = len(hashes.get('bios_sets', {}))
    version = hashes.get('version', 'unknown')
    commit = hashes.get('commit', '')[:12]

    if args.json:
        json.dump(hashes, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write('\n')
        return

    print(f'mame-hashes: {total_sets} BIOS root sets from mamedev/mame'
          f' @ {version} ({commit})')
    print()

    profiles = _find_mame_profiles()
    if not profiles:
        print('  no profiles with mamedev/mame upstream found')
        return

    for profile_path in profiles:
        is_main = profile_path.name == 'mame.yml'
        diff = compute_diff(str(profile_path), str(_CACHE_PATH), mode='mame')
        lines = _format_diff(profile_path, diff, hashes, show_added=is_main)
        for line in lines:
            print(line)

        if not args.dry_run:
            updated = diff.get('updated', [])
            added = diff.get('added', []) if is_main else []
            if added or updated:
                merge_mame_profile(
                    str(profile_path),
                    str(_CACHE_PATH),
                    write=True,
                    add_new=is_main,
                )
                log.info('merged into %s', profile_path.name)

    print()
    if args.dry_run:
        print('(dry run, no files modified)')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='mame_hash_scraper',
        description='Fetch MAME BIOS hashes from source and merge into profiles.',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='show diff only, do not modify profiles',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='output raw JSON to stdout',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='re-fetch even if cache is fresh',
    )
    return parser


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s',
    )
    parser = build_parser()
    args = parser.parse_args()
    _run(args)


if __name__ == '__main__':
    main()
