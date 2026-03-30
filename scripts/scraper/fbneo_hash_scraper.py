"""Scrape FBNeo BIOS set hashes from upstream source via sparse clone.

Does NOT inherit BaseScraper (uses git sparse clone, not URL fetch).
Parses BDF_BOARDROM drivers from src/burn/drv/ to extract CRC32/size
for all BIOS ROM sets, then optionally merges into emulator profiles.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import yaml

from scripts.scraper.fbneo_parser import parse_fbneo_source_tree
from scripts.scraper._hash_merge import compute_diff, merge_fbneo_profile

log = logging.getLogger(__name__)

REPO_URL = 'https://github.com/finalburnneo/FBNeo.git'
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CLONE_DIR = REPO_ROOT / 'tmp' / 'fbneo'
CACHE_PATH = REPO_ROOT / 'data' / 'fbneo-hashes.json'
EMULATORS_DIR = REPO_ROOT / 'emulators'
STALE_HOURS = 24


def _is_cache_fresh() -> bool:
    """Check if the JSON cache exists and is less than 24 hours old."""
    if not CACHE_PATH.exists():
        return False
    try:
        data = json.loads(CACHE_PATH.read_text(encoding='utf-8'))
        fetched_at = datetime.fromisoformat(data['fetched_at'])
        return datetime.now(timezone.utc) - fetched_at < timedelta(hours=STALE_HOURS)
    except (json.JSONDecodeError, KeyError, ValueError):
        return False


def _sparse_clone() -> None:
    """Sparse clone FBNeo repo, checking out only src/burn/drv."""
    if CLONE_DIR.exists():
        shutil.rmtree(CLONE_DIR)

    CLONE_DIR.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            'git', 'clone', '--depth', '1', '--filter=blob:none',
            '--sparse', REPO_URL, str(CLONE_DIR),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    subprocess.run(
        ['git', 'sparse-checkout', 'set', 'src/burn/drv', 'src/burner/resource.h'],
        cwd=CLONE_DIR,
        check=True,
        capture_output=True,
        text=True,
    )


def _extract_version() -> tuple[str, str]:
    """Extract version tag and commit SHA from the cloned repo.

    Returns (version, commit_sha). Falls back to resource.h if no tag.
    """
    result = subprocess.run(
        ['git', 'describe', '--tags', '--abbrev=0'],
        cwd=CLONE_DIR,
        capture_output=True,
        text=True,
    )

    # Prefer real version tags over pseudo-tags like "latest"
    version = 'unknown'
    if result.returncode == 0:
        tag = result.stdout.strip()
        if tag and tag != 'latest':
            version = tag
    # Fallback: resource.h
    if version == 'unknown':
        version = _version_from_resource_h()
    # Last resort: use GitHub API for latest real release tag
    if version == 'unknown':
        try:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(
                'https://api.github.com/repos/finalburnneo/FBNeo/tags?per_page=10',
                headers={'User-Agent': 'retrobios-scraper/1.0'},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                import json as json_mod
                tags = json_mod.loads(resp.read())
                for t in tags:
                    if t['name'] != 'latest' and t['name'].startswith('v'):
                        version = t['name']
                        break
        except (urllib.error.URLError, OSError):
            pass

    sha_result = subprocess.run(
        ['git', 'rev-parse', 'HEAD'],
        cwd=CLONE_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    commit = sha_result.stdout.strip()

    return version, commit


def _version_from_resource_h() -> str:
    """Fallback: parse VER_FULL_VERSION_STR from resource.h."""
    resource_h = CLONE_DIR / 'src' / 'burner' / 'resource.h'
    if not resource_h.exists():
        return 'unknown'

    text = resource_h.read_text(encoding='utf-8', errors='replace')
    for line in text.splitlines():
        if 'VER_FULL_VERSION_STR' in line:
            parts = line.split('"')
            if len(parts) >= 2:
                return parts[1]
    return 'unknown'


def _cleanup() -> None:
    """Remove the sparse clone directory."""
    if CLONE_DIR.exists():
        shutil.rmtree(CLONE_DIR)


def fetch_and_cache(force: bool = False) -> dict[str, Any]:
    """Clone, parse, and write JSON cache. Returns the cache dict."""
    if not force and _is_cache_fresh():
        log.info('cache fresh, skipping clone (use --force to override)')
        return json.loads(CACHE_PATH.read_text(encoding='utf-8'))

    try:
        log.info('sparse cloning %s', REPO_URL)
        _sparse_clone()

        log.info('extracting version')
        version, commit = _extract_version()

        log.info('parsing source tree')
        bios_sets = parse_fbneo_source_tree(str(CLONE_DIR))

        cache: dict[str, Any] = {
            'source': 'finalburnneo/FBNeo',
            'version': version,
            'commit': commit,
            'fetched_at': datetime.now(timezone.utc).isoformat(),
            'bios_sets': bios_sets,
        }

        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(
            json.dumps(cache, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8',
        )
        log.info('wrote %d BIOS sets to %s', len(bios_sets), CACHE_PATH)

        return cache
    finally:
        _cleanup()


def _find_fbneo_profiles() -> list[Path]:
    """Find emulator profiles whose upstream references finalburnneo/FBNeo."""
    profiles: list[Path] = []
    for path in sorted(EMULATORS_DIR.glob('*.yml')):
        if path.name.endswith('.old.yml'):
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding='utf-8'))
        except (yaml.YAMLError, OSError):
            continue
        if not data or not isinstance(data, dict):
            continue
        upstream = data.get('upstream', '')
        if isinstance(upstream, str) and 'finalburnneo/fbneo' in upstream.lower():
            profiles.append(path)
    return profiles


def _format_diff(profile_name: str, diff: dict[str, Any], show_added: bool = True) -> str:
    """Format diff for a single profile."""
    lines: list[str] = []
    lines.append(f'  {profile_name}:')

    added = diff.get('added', [])
    updated = diff.get('updated', [])
    oos = diff.get('out_of_scope', 0)

    if not added and not updated:
        lines.append('    no changes')
        if oos:
            lines.append(f'    . {oos} out of scope')
        return '\n'.join(lines)

    if show_added:
        for label in added:
            lines.append(f'    + {label}')
    elif added:
        lines.append(f'    + {len(added)} new ROMs available (main profile only)')
    for label in updated:
        lines.append(f'    ~ {label}')
    lines.append(f'    = {diff["unchanged"]} unchanged')
    if oos:
        lines.append(f'    . {oos} out of scope')

    return '\n'.join(lines)


def run(
    dry_run: bool = False,
    force: bool = False,
    json_output: bool = False,
) -> int:
    """Main entry point for the scraper."""
    cache = fetch_and_cache(force=force)

    version = cache.get('version', 'unknown')
    commit = cache.get('commit', '?')[:12]
    bios_sets = cache.get('bios_sets', {})
    profiles = _find_fbneo_profiles()

    if json_output:
        result: dict[str, Any] = {
            'source': cache.get('source'),
            'version': version,
            'commit': cache.get('commit'),
            'bios_set_count': len(bios_sets),
            'profiles': {},
        }
        for path in profiles:
            diff = compute_diff(str(path), str(CACHE_PATH), mode='fbneo')
            result['profiles'][path.stem] = diff
        print(json.dumps(result, indent=2))
        return 0

    header = (
        f'fbneo-hashes: {len(bios_sets)} BIOS sets '
        f'from finalburnneo/FBNeo @ {version} ({commit})'
    )
    print(header)
    print()

    if not profiles:
        print('  no matching emulator profiles found')
        return 0

    for path in profiles:
        is_main = path.name == 'fbneo.yml'
        diff = compute_diff(str(path), str(CACHE_PATH), mode='fbneo')
        print(_format_diff(path.stem, diff, show_added=is_main))

        if not dry_run and (diff['added'] or diff['updated']):
            is_main = path.name == 'fbneo.yml'
            merge_fbneo_profile(str(path), str(CACHE_PATH), write=True, add_new=is_main)
            log.info('merged changes into %s', path.name)

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Scrape FBNeo BIOS set hashes from upstream source',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='show diff without writing changes',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='force re-clone even if cache is fresh',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        dest='json_output',
        help='output diff as JSON',
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(name)s: %(message)s',
    )

    sys.exit(run(
        dry_run=args.dry_run,
        force=args.force,
        json_output=args.json_output,
    ))


if __name__ == '__main__':
    main()
