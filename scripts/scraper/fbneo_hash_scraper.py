"""Scrape FBNeo BIOS set hashes from upstream source via sparse clone.

Does NOT inherit BaseScraper (uses git sparse clone, not URL fetch).
Parses BDF_BOARDROM drivers from src/burn/drv/ to extract CRC32/size
for all BIOS ROM sets, then optionally merges into emulator profiles.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from core import paths
from core.paths import REPO_ROOT
from model.profiles import source_yaml_paths
from core.artifacts import write_text_atomic
from model.safeparse import yaml_load

from scripts.scraper._hash_merge import (
    compute_diff,
    load_profile,
    merge_fbneo_profile,
    write_fbneo_profile,
)
from scripts.scraper.fbneo_parser import parse_fbneo_source_tree
from scripts.scraper.sparse_clone import fresh_cache, remove_clone, sparse_clone

log = logging.getLogger(__name__)

REPO_URL = "https://github.com/finalburnneo/FBNeo.git"
# One clone per process, for the reason mame_hash_scraper gives.
CLONE_DIR = REPO_ROOT / "tmp" / f"fbneo-{os.getpid()}"
CACHE_PATH = REPO_ROOT / "data" / "fbneo-hashes.json"
EMULATORS_DIR = REPO_ROOT / paths.EMULATORS_DIR
STALE_HOURS = 24


# src/burn/version.h, as the libretro core prints it: "v%x.%x.%x.%02x" of
# the BCD BURN_VERSION, so VER_ALPHA 3 reads 1.0.0.03. FBNeo bumps this file
# without tagging: the last tag (v1.0.0.02) was 9 337 commits behind it.
_VERSION_H = re.compile(
    r"#define\s+VER_MAJOR\s+(\d+)\s+#define\s+VER_MINOR\s+(\d+)\s+"
    r"#define\s+VER_BETA\s+(\d+)\s+#define\s+VER_ALPHA\s+(\d+)"
)


def version_from_header(text: str) -> str:
    """The version src/burn/version.h states."""
    found = _VERSION_H.search(text)
    if not found:
        raise RuntimeError("src/burn/version.h states no VER_MAJOR..VER_ALPHA")
    major, minor, beta, alpha = (int(group) for group in found.groups())
    return f"v{major}.{minor}.{beta}.{alpha:02d}"


def _extract_version() -> str:
    """The version the cloned source states."""
    header = CLONE_DIR / "src" / "burn" / "version.h"
    return version_from_header(header.read_text(encoding="utf-8", errors="replace"))


def fetch_and_cache(force: bool = False) -> dict[str, Any]:
    """Clone, parse, and write JSON cache. Returns the cache dict."""
    fresh = None if force else fresh_cache(CACHE_PATH, STALE_HOURS)
    if fresh is not None:
        log.info("cache fresh, skipping clone (use --force to override)")
        return fresh

    try:
        # src/burn/drv, and in cone mode src/burn/version.h.
        commit = sparse_clone(REPO_URL, CLONE_DIR, ["src/burn/drv"])

        log.info("extracting version")
        version = _extract_version()

        log.info("parsing source tree")
        bios_sets = parse_fbneo_source_tree(str(CLONE_DIR))
        if not bios_sets:
            # An empty read was cached for a day and merged nothing, and
            # the pipeline step reported OK.
            raise RuntimeError(f"no BIOS set read at FBNeo {version} ({commit[:12]})")

        cache: dict[str, Any] = {
            "source": "finalburnneo/FBNeo",
            "version": version,
            "commit": commit,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "bios_sets": bios_sets,
        }

        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(
            str(CACHE_PATH), json.dumps(cache, indent=2, ensure_ascii=False) + "\n"
        )
        log.info("wrote %d BIOS sets to %s", len(bios_sets), CACHE_PATH)

        return cache
    finally:
        remove_clone(CLONE_DIR)


def _find_fbneo_profiles() -> list[Path]:
    """Find emulator profiles whose upstream references finalburnneo/FBNeo."""
    profiles: list[Path] = []
    for path in source_yaml_paths(EMULATORS_DIR):
        try:
            data = yaml_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            # Skipped, a broken fbneo.yml left the list and the refresh
            # reported "no matching emulator profiles found" with exit 0.
            raise RuntimeError(f"cannot read {path}: {exc}") from exc
        if not data or not isinstance(data, dict):
            continue
        upstream = data.get("upstream", "")
        if isinstance(upstream, str) and "finalburnneo/fbneo" in upstream.lower():
            profiles.append(path)
    return profiles


def _format_diff(
    profile_name: str, diff: dict[str, Any], show_added: bool = True
) -> str:
    """Format diff for a single profile."""
    lines: list[str] = []
    lines.append(f"  {profile_name}:")

    added = diff.get("added", [])
    updated = diff.get("updated", [])
    oos = diff.get("out_of_scope", 0)

    if not added and not updated:
        lines.append("    no changes")
        if oos:
            lines.append(f"    . {oos} out of scope")
        return "\n".join(lines)

    if show_added:
        lines.extend(f"    + {label}" for label in added)
    elif added:
        lines.append(f"    + {len(added)} new ROMs available (main profile only)")
    lines.extend(f"    ~ {label}" for label in updated)
    lines.append(f"    = {diff['unchanged']} unchanged")
    if oos:
        lines.append(f"    . {oos} out of scope")

    return "\n".join(lines)


def run(
    dry_run: bool = False,
    force: bool = False,
    json_output: bool = False,
) -> int:
    """Main entry point for the scraper."""
    cache = fetch_and_cache(force=force)

    version = cache.get("version", "unknown")
    commit = cache.get("commit", "?")[:12]
    bios_sets = cache.get("bios_sets", {})
    profiles = _find_fbneo_profiles()

    if json_output:
        result: dict[str, Any] = {
            "source": cache.get("source"),
            "version": version,
            "commit": cache.get("commit"),
            "bios_set_count": len(bios_sets),
            "profiles": {},
        }
        for path in profiles:
            diff = compute_diff(load_profile(path), cache, mode="fbneo")
            result["profiles"][path.stem] = diff
        print(json.dumps(result, indent=2))
        return 0

    header = (
        f"fbneo-hashes: {len(bios_sets)} BIOS sets "
        f"from finalburnneo/FBNeo @ {version} ({commit})"
    )
    print(header)
    print()

    if not profiles:
        print("  no matching emulator profiles found")
        return 0

    for path in profiles:
        is_main = path.name == "fbneo.yml"
        profile = load_profile(path)
        diff = compute_diff(profile, cache, mode="fbneo")
        print(_format_diff(path.stem, diff, show_added=is_main))

        # New entries are never written: the parser knows one line per
        # driver, the struct, while a curated entry cites the RomDesc line of
        # its own ROM. Existing entries, console archives included (the
        # parser keys each board ROM set by the archive GetZipName opens),
        # are refreshed in place.
        if not dry_run and diff["updated"]:
            write_fbneo_profile(path, merge_fbneo_profile(profile, cache, add_new=False))
            log.info("merged changes into %s", path.name)

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Scrape FBNeo BIOS set hashes from upstream source",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show diff without writing changes",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="force re-clone even if cache is fresh",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="output diff as JSON",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s: %(message)s",
    )

    sys.exit(
        run(
            dry_run=args.dry_run,
            force=args.force,
            json_output=args.json_output,
        )
    )


if __name__ == "__main__":
    main()
