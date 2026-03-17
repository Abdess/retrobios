#!/usr/bin/env python3
"""Scan bios/ directory and generate multi-indexed database.json.

Usage:
    python scripts/generate_db.py [--force] [--bios-dir DIR] [--output FILE]

Supports incremental mode via .cache/db_cache.json (mtime-based).
Use --force to rehash all files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

CACHE_DIR = ".cache"
CACHE_FILE = os.path.join(CACHE_DIR, "db_cache.json")
DEFAULT_BIOS_DIR = "bios"
DEFAULT_OUTPUT = "database.json"

SKIP_PATTERNS = {".git", ".github", "__pycache__", ".cache", ".DS_Store", "desktop.ini"}


def compute_hashes(filepath: Path) -> dict:
    """Compute SHA1, MD5, SHA256, CRC32 for a file."""
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    crc = 0

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha1.update(chunk)
            md5.update(chunk)
            sha256.update(chunk)
            crc = zlib.crc32(chunk, crc)

    return {
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "crc32": format(crc & 0xFFFFFFFF, "08x"),
    }


def should_skip(path: Path) -> bool:
    """Check if a path should be skipped. Allows .variants/ directories."""
    for part in path.parts:
        if part in SKIP_PATTERNS:
            return True
        if part.startswith(".") and part != ".variants":
            return True
    return False


def scan_bios_dir(bios_dir: Path, cache: dict, force: bool) -> dict:
    """Scan bios directory and compute hashes, using cache when possible."""
    files = {}
    aliases = {}
    new_cache = {}

    for filepath in sorted(bios_dir.rglob("*")):
        if not filepath.is_file():
            continue
        if should_skip(filepath.relative_to(bios_dir)):
            continue

        rel_path = str(filepath.relative_to(bios_dir.parent))
        stat = filepath.stat()
        mtime = stat.st_mtime
        size = stat.st_size
        cache_key = rel_path

        if not force and cache_key in cache:
            cached = cache[cache_key]
            if cached.get("mtime") == mtime and cached.get("size") == size:
                hashes = {
                    "sha1": cached["sha1"],
                    "md5": cached["md5"],
                    "sha256": cached["sha256"],
                    "crc32": cached["crc32"],
                }
                sha1 = hashes["sha1"]
                if sha1 in files:
                    if sha1 not in aliases:
                        aliases[sha1] = []
                    aliases[sha1].append({"name": filepath.name, "path": rel_path})
                else:
                    entry = {
                        "path": rel_path,
                        "name": filepath.name,
                        "size": size,
                        **hashes,
                    }
                    files[sha1] = entry
                new_cache[cache_key] = {**hashes, "mtime": mtime, "size": size}
                continue

        hashes = compute_hashes(filepath)
        sha1 = hashes["sha1"]
        if sha1 in files:
            if sha1 not in aliases:
                aliases[sha1] = []
            aliases[sha1].append({"name": filepath.name, "path": rel_path})
        else:
            entry = {
                "path": rel_path,
                "name": filepath.name,
                "size": size,
                **hashes,
            }
            files[sha1] = entry
        new_cache[cache_key] = {**hashes, "mtime": mtime, "size": size}

    return files, aliases, new_cache


def build_indexes(files: dict, aliases: dict) -> dict:
    """Build secondary indexes for fast lookup."""
    by_md5 = {}
    by_name = {}
    by_crc32 = {}

    for sha1, entry in files.items():
        by_md5[entry["md5"]] = sha1

        name = entry["name"]
        if name not in by_name:
            by_name[name] = []
        by_name[name].append(sha1)

        by_crc32[entry["crc32"]] = sha1

    # Add alias names to by_name index (aliases have different filenames for same SHA1)
    for sha1, alias_list in aliases.items():
        for alias in alias_list:
            name = alias["name"]
            if name not in by_name:
                by_name[name] = []
            if sha1 not in by_name[name]:
                by_name[name].append(sha1)

    return {
        "by_md5": by_md5,
        "by_name": by_name,
        "by_crc32": by_crc32,
    }


def load_cache(cache_path: str) -> dict:
    """Load cache file if it exists."""
    try:
        with open(cache_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache_path: str, cache: dict):
    """Save cache to disk."""
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(cache, f)


def main():
    parser = argparse.ArgumentParser(description="Generate multi-indexed BIOS database")
    parser.add_argument("--force", action="store_true", help="Force rehash all files")
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR, help="BIOS directory path")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="Output JSON file")
    args = parser.parse_args()

    bios_dir = Path(args.bios_dir)
    if not bios_dir.is_dir():
        print(f"Error: BIOS directory '{bios_dir}' not found", file=sys.stderr)
        sys.exit(1)

    cache = {} if args.force else load_cache(CACHE_FILE)

    print(f"Scanning {bios_dir}/ ...")
    files, aliases, new_cache = scan_bios_dir(bios_dir, cache, args.force)

    if not files:
        print("Warning: No BIOS files found", file=sys.stderr)

    platform_aliases = _collect_all_aliases(files)
    for sha1, name_list in platform_aliases.items():
        for alias_entry in name_list:
            if sha1 not in aliases:
                aliases[sha1] = []
            aliases[sha1].append(alias_entry)

    indexes = build_indexes(files, aliases)
    total_size = sum(entry["size"] for entry in files.values())

    database = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(files),
        "total_size": total_size,
        "files": files,
        "indexes": indexes,
    }

    with open(args.output, "w") as f:
        json.dump(database, f, indent=2)

    save_cache(CACHE_FILE, new_cache)

    alias_count = sum(len(v) for v in aliases.values())
    name_count = len(indexes["by_name"])
    print(f"Generated {args.output}: {len(files)} files, {total_size:,} bytes total")
    print(f"  Name index: {name_count} names ({alias_count} aliases)")
    return 0


def _collect_all_aliases(files: dict) -> dict:
    """Collect alternate filenames from platform YAMLs, core-info, and known aliases.

    Registers alternate names so generate_pack can resolve files stored under different names.
    """
    md5_to_sha1 = {}
    name_to_sha1 = {}
    for sha1, entry in files.items():
        md5_to_sha1[entry["md5"]] = sha1
        name_to_sha1[entry["name"]] = sha1

    aliases = {}

    def _add_alias(name: str, matched_sha1: str):
        if not name or name in name_to_sha1:
            return
        if matched_sha1 not in aliases:
            aliases[matched_sha1] = []
        existing = {a["name"] for a in aliases[matched_sha1]}
        if name not in existing:
            aliases[matched_sha1].append({"name": name, "path": ""})

    platforms_dir = Path("platforms")
    if platforms_dir.is_dir():
        try:
            import yaml
            for config_file in platforms_dir.glob("*.yml"):
                if config_file.name.startswith("_"):
                    continue
                try:
                    with open(config_file) as f:
                        config = yaml.safe_load(f) or {}
                except (yaml.YAMLError, OSError) as e:
                    print(f"Warning: {config_file.name}: {e}", file=sys.stderr)
                    continue

                for sys_id, system in config.get("systems", {}).items():
                    for file_entry in system.get("files", []):
                        name = file_entry.get("name", "")
                        sha1 = file_entry.get("sha1", "")
                        md5 = file_entry.get("md5", "")

                        matched = None
                        if sha1 and sha1 in files:
                            matched = sha1
                        elif md5 and md5 in md5_to_sha1:
                            matched = md5_to_sha1[md5]

                        if matched:
                            _add_alias(name, matched)
        except ImportError:
            pass

    try:
        import sys as _sys
        _sys.path.insert(0, "scripts")
        from scraper.coreinfo_scraper import Scraper as CoreInfoScraper
        ci_reqs = CoreInfoScraper().fetch_requirements()
        for r in ci_reqs:
            basename = r.name
            # Try to match by MD5 or by known canonical names
            matched = None
            if r.md5 and r.md5 in md5_to_sha1:
                matched = md5_to_sha1[r.md5]
            if matched:
                _add_alias(basename, matched)
    except (ImportError, ConnectionError) as e:
        pass

    # Identical content named differently across platforms/cores
    KNOWN_ALIAS_GROUPS = [
        # ColecoVision - all these are the same 8KB BIOS
        ["colecovision.rom", "coleco.rom", "BIOS.col", "bioscv.rom"],
        # Game Boy - DMG boot ROM
        ["gb_bios.bin", "dmg_boot.bin", "dmg_rom.bin", "dmg0_rom.bin"],
        # Game Boy Color - CGB boot ROM
        ["gbc_bios.bin", "cgb_boot.bin", "cgb0_boot.bin", "cgb_agb_boot.bin"],
        # Super Game Boy
        ["sgb_bios.bin", "sgb_boot.bin", "sgb.boot.rom"],
        ["sgb2_bios.bin", "sgb2_boot.bin", "sgb2.boot.rom"],
        ["sgb1.program.rom", "SGB1.sfc/program.rom"],
        ["sgb2.program.rom", "SGB2.sfc/program.rom"],
        # Nintendo DS
        ["bios7.bin", "nds7.bin"],
        ["bios9.bin", "nds9.bin"],
        ["dsi_sd_card.bin", "nds_sd_card.bin"],
        # MSX
        ["MSX.ROM", "MSX.rom", "Machines/Shared Roms/MSX.rom"],
        # NEC PC-98
        ["N88KNJ1.ROM", "n88knj1.rom", "quasi88/n88knj1.rom"],
        # Enterprise
        ["zt19uk.rom", "zt19hfnt.rom", "ep128emu/roms/zt19hfnt.rom"],
        # ZX Spectrum
        ["48.rom", "zx48.rom"],
        # SquirrelJME - all JARs are the same
        ["squirreljme.sqc", "squirreljme.jar", "squirreljme-fast.jar",
         "squirreljme-slow.jar", "squirreljme-slow-test.jar",
         "squirreljme-0.3.0.jar", "squirreljme-0.3.0-fast.jar",
         "squirreljme-0.3.0-slow.jar", "squirreljme-0.3.0-slow-test.jar"],
        # Arcade - FBNeo spectrum
        ["spectrum.zip", "fbneo/spectrum.zip", "spec48k.zip"],
    ]

    for group in KNOWN_ALIAS_GROUPS:
        matched_sha1 = None
        for name in group:
            if name in name_to_sha1:
                matched_sha1 = name_to_sha1[name]
                break
        if not matched_sha1:
            continue
        for name in group:
            _add_alias(name, matched_sha1)

    return aliases


if __name__ == "__main__":
    sys.exit(main() or 0)
