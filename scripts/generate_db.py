#!/usr/bin/env python3
"""Scan bios/ directory and generate multi-indexed database.json.

Usage:
    python scripts/generate_db.py [--force] [--bios-dir DIR] [--output FILE]

Supports incremental mode via .cache/db_cache.json (mtime-based).
Use --force to rehash all files.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    annotate_provenance,
    compute_hashes,
    DEFAULT_PROVENANCE_DIR,
    list_registered_platforms,
    load_provenance_snapshots,
    write_if_changed,
    yaml_load,
)

CACHE_DIR = ".cache"
CACHE_FILE = os.path.join(CACHE_DIR, "db_cache.json")
DEFAULT_BIOS_DIR = "bios"
DEFAULT_OUTPUT = "database.json"

SKIP_PATTERNS = {".git", ".github", "__pycache__", ".cache", ".DS_Store", "desktop.ini"}

# Every digest database.json publishes per file, in the order compute_hashes
# returns them. The schema requires all five, so a cache entry missing any of
# them cannot serve a database entry, and the order is fixed here so a warm
# cache serialises an entry exactly like a fresh hash does.
CACHED_HASHES = ("sha1", "md5", "sha256", "crc32", "adler32")


def should_skip(path: Path) -> bool:
    """Whether a path stays out of the collection.

    Tooling directories and hidden files do. A hidden directory inside the
    collection does not: `.variants/` holds alternate dumps, and an engine
    tree can carry one of its own (C-Dogs SDL reads `data/.wolf3d/`).
    """
    if any(part in SKIP_PATTERNS for part in path.parts):
        return True
    return path.name.startswith(".")


def _canonical_name(filepath: Path) -> str:
    """Get canonical filename, stripping .variants/ hash suffix."""
    name = filepath.name
    if "/.variants/" in str(filepath) or "\\.variants\\" in str(filepath):
        # naomi2.zip.da79eca4 -> naomi2.zip
        parts = name.rsplit(".", 1)
        if (
            len(parts) == 2
            and len(parts[1]) == 8
            and all(c in "0123456789abcdef" for c in parts[1])
        ):
            return parts[0]
    return name


def scan_bios_dir(bios_dir: Path, cache: dict, force: bool) -> tuple[dict, dict, dict]:
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
            fresh = cached.get("mtime") == mtime and cached.get("size") == size
            # Rebuilding the hash dict by hand dropped whichever digest the
            # list forgot, and the entry was then written back to the cache
            # without it, so the loss survived every later run. Requiring the
            # full set instead turns a partial cache entry into a miss, which
            # heals it.
            if fresh and all(name in cached for name in CACHED_HASHES):
                hashes = {name: cached[name] for name in CACHED_HASHES}
                sha1 = hashes["sha1"]
                is_variant = "/.variants/" in rel_path or "\\.variants\\" in rel_path
                if sha1 in files:
                    existing_is_variant = "/.variants/" in files[sha1]["path"]
                    if existing_is_variant and not is_variant:
                        if sha1 not in aliases:
                            aliases[sha1] = []
                        aliases[sha1].append(
                            {"name": files[sha1]["name"], "path": files[sha1]["path"]}
                        )
                        files[sha1] = {
                            "path": rel_path,
                            "name": _canonical_name(filepath),
                            "size": size,
                            **hashes,
                        }
                    else:
                        if sha1 not in aliases:
                            aliases[sha1] = []
                        aliases[sha1].append(
                            {"name": _canonical_name(filepath), "path": rel_path}
                        )
                else:
                    entry = {
                        "path": rel_path,
                        "name": _canonical_name(filepath),
                        "size": size,
                        **hashes,
                    }
                    files[sha1] = entry
                new_cache[cache_key] = {**hashes, "mtime": mtime, "size": size}
                continue

        hashes = compute_hashes(filepath)
        sha1 = hashes["sha1"]
        is_variant = "/.variants/" in rel_path or "\\.variants\\" in rel_path
        if sha1 in files:
            existing_is_variant = "/.variants/" in files[sha1]["path"]
            if existing_is_variant and not is_variant:
                # Non-variant file should be primary over .variants/ file
                if sha1 not in aliases:
                    aliases[sha1] = []
                aliases[sha1].append(
                    {"name": files[sha1]["name"], "path": files[sha1]["path"]}
                )
                files[sha1] = {
                    "path": rel_path,
                    "name": _canonical_name(filepath),
                    "size": size,
                    **hashes,
                }
            else:
                if sha1 not in aliases:
                    aliases[sha1] = []
                aliases[sha1].append(
                    {"name": _canonical_name(filepath), "path": rel_path}
                )
        else:
            entry = {
                "path": rel_path,
                "name": _canonical_name(filepath),
                "size": size,
                **hashes,
            }
            files[sha1] = entry
        new_cache[cache_key] = {**hashes, "mtime": mtime, "size": size}

    return files, aliases, new_cache


def _path_suffixes(rel_path: str) -> list[str]:
    """Every tail of a stored path that can answer a declared destination.

    A destination and the tree meet on a tail, and which tail is unknowable
    from here: one profile writes GC/USA/IPL.bin, another writes the whole
    nand/.../00000000.app.romfs. Indexing only the tail after
    bios/Manufacturer/Console answered the first and never the second, so
    every same-named file collapsed onto one entry.

    The bare filename is left out on purpose. by_name already holds it, and a
    name alone is the weakest evidence there is.

    bios/Nintendo/GameCube/GC/USA/IPL.bin -> GC/USA/IPL.bin, USA/IPL.bin
    """
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    if parts and parts[0] == "bios":
        parts = parts[1:]
    return ["/".join(parts[-depth:]) for depth in range(len(parts), 1, -1)]


def build_indexes(files: dict, aliases: dict) -> dict:
    """Build secondary indexes for fast lookup."""
    by_md5 = {}
    by_name = {}
    by_crc32 = {}
    by_sha256 = {}
    by_path_suffix = {}

    for sha1, entry in files.items():
        by_md5[entry["md5"]] = sha1

        name = entry["name"]
        if name not in by_name:
            by_name[name] = []
        by_name[name].append(sha1)

        by_crc32[entry["crc32"]] = sha1
        by_sha256[entry["sha256"]] = sha1

        # Path suffix index for regional variant resolution
        for suffix in _path_suffixes(entry["path"]):
            if suffix == name:
                continue
            if suffix not in by_path_suffix:
                by_path_suffix[suffix] = []
            if sha1 not in by_path_suffix[suffix]:
                by_path_suffix[suffix].append(sha1)

    # Add alias names to by_name index (aliases have different filenames for same SHA1)
    for sha1, alias_list in aliases.items():
        for alias in alias_list:
            name = alias["name"]
            if name not in by_name:
                by_name[name] = []
            if sha1 not in by_name[name]:
                by_name[name].append(sha1)
            # Also index alias paths in by_path_suffix
            for suffix in _path_suffixes(alias["path"]):
                if suffix == name:
                    continue
                if suffix not in by_path_suffix:
                    by_path_suffix[suffix] = []
                if sha1 not in by_path_suffix[suffix]:
                    by_path_suffix[suffix].append(sha1)

    return {
        "by_md5": by_md5,
        "by_name": by_name,
        "by_crc32": by_crc32,
        "by_sha256": by_sha256,
        "by_path_suffix": by_path_suffix,
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


def _load_gitignored_large_files() -> set[str]:
    """The bios/ paths .gitignore registers as release assets."""
    gitignore = Path(".gitignore")
    if not gitignore.exists():
        return set()
    return {
        line.strip()
        for line in gitignore.read_text().splitlines()
        if line.strip().startswith("bios/")
    }


def _preserve_large_file_entries(files: dict, db_path: str) -> int:
    """Keep the entries of release assets the checkout does not hold.

    Files kept out of git live as assets of the large-files release, and
    .gitignore registers their paths. An entry survives a scan that missed
    its file only under that registered path: a bare name is shared by
    other files (pak0.pk3, history.db), and a path rewritten into the
    download cache is no longer one .gitignore knows, so the manifest
    would send the installer to the repository for it. A fetched asset is
    written back to its registered path.
    """
    from common import fetch_large_file

    registered = _load_gitignored_large_files()
    if not registered:
        return 0

    try:
        with open(db_path) as f:
            existing_db = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0

    # A path the scan just claimed holds known bytes. An older entry naming
    # the same path describes a revision that is no longer there, and keeping
    # it would publish a hash that contradicts the file it points at.
    scanned_paths = {entry.get("path", "") for entry in files.values()}

    count = 0
    for sha1, entry in existing_db.get("files", {}).items():
        path = entry.get("path", "")
        if sha1 in files or path not in registered or path in scanned_paths:
            continue
        cached = fetch_large_file(
            path,
            expected_sha1=entry.get("sha1", ""),
            expected_md5=entry.get("md5", ""),
        )
        if cached and not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.copy2(cached, path)
        files[sha1] = entry
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Generate multi-indexed BIOS database")
    parser.add_argument("--force", action="store_true", help="Force rehash all files")
    parser.add_argument(
        "--bios-dir", default=DEFAULT_BIOS_DIR, help="BIOS directory path"
    )
    parser.add_argument(
        "--output", "-o", default=DEFAULT_OUTPUT, help="Output JSON file"
    )
    parser.add_argument(
        "--provenance-dir",
        default=DEFAULT_PROVENANCE_DIR,
        help="Directory with dump-catalog snapshots",
    )
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

    # Preserve entries for large files stored as release assets (.gitignore)
    preserved = _preserve_large_file_entries(files, args.output)
    if preserved:
        print(f"  Preserved {preserved} large file entries from existing database")

    platform_aliases = _collect_all_aliases(files)
    for sha1, name_list in platform_aliases.items():
        for alias_entry in name_list:
            if sha1 not in aliases:
                aliases[sha1] = []
            aliases[sha1].append(alias_entry)

    snapshots = load_provenance_snapshots(args.provenance_dir)
    provenance_counts = annotate_provenance(files, snapshots)

    indexes = build_indexes(files, aliases)
    total_size = sum(entry["size"] for entry in files.values())

    database = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(files),
        "total_size": total_size,
        "files": files,
        "indexes": indexes,
    }

    new_content = json.dumps(database, indent=2)
    written = write_if_changed(args.output, new_content)

    save_cache(CACHE_FILE, new_cache)

    alias_count = sum(len(v) for v in aliases.values())
    name_count = len(indexes["by_name"])
    status = "Generated" if written else "Unchanged"
    print(f"{status} {args.output}: {len(files)} files, {total_size:,} bytes total")
    print(f"  Name index: {name_count} names ({alias_count} aliases)")
    if provenance_counts:
        matched = sum(1 for e in files.values() if "provenance" in e)
        per_source = ", ".join(
            f"{source} {count}" for source, count in sorted(provenance_counts.items())
        )
        print(f"  Provenance: {matched} files catalog-matched ({per_source})")
    return 0


def _as_list(value: object) -> list[str]:
    """A hash field as lowercase values, whether written alone or as a list."""
    if not value:
        return []
    values = value if isinstance(value, list) else str(value).split(",")
    return [str(v).strip().lower() for v in values if str(v).strip()]


def _primary_names(entries: list) -> set[str]:
    return {str(fe.get("name", "")).lower() for fe in entries if isinstance(fe, dict)}


def _own_aliases(file_entry: dict, primary_names: set[str]) -> list[str]:
    """Aliases that name no other entry of the same profile."""
    name = str(file_entry.get("name", "")).lower()
    return [
        alias for alias in file_entry.get("aliases") or []
        if str(alias).lower() == name or str(alias).lower() not in primary_names
    ]


def _collect_all_aliases(files: dict) -> dict:
    """Collect alternate filenames from platform YAMLs, core-info, and known aliases.

    Registers alternate names so generate_pack can resolve files stored under different names.
    """
    md5_to_sha1 = {}
    name_to_sha1 = {}
    name_count: dict[str, int] = {}
    for sha1, entry in files.items():
        md5_to_sha1[entry["md5"]] = sha1
        name_to_sha1[entry["name"]] = sha1
        name_count[entry["name"]] = name_count.get(entry["name"], 0) + 1

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

            for platform_name in list_registered_platforms(
                str(platforms_dir), include_archived=True
            ):
                config_file = platforms_dir / f"{platform_name}.yml"
                try:
                    with open(config_file) as f:
                        config = yaml_load(f) or {}
                except (yaml.YAMLError, OSError) as e:
                    print(f"Warning: {config_file.name}: {e}", file=sys.stderr)
                    continue

                for sys_id, system in config.get("systems", {}).items():
                    for file_entry in system.get("files", []):
                        name = file_entry.get("name", "")
                        sha1 = file_entry.get("sha1", "")
                        md5 = file_entry.get("md5", "")

                        # A zipped_file entry verifies a ROM INSIDE the
                        # archive, so its hash describes the member and not
                        # the file the name designates. Registering the name
                        # against that hash made d2fdc.zip an alias of a
                        # loose 256-byte state-machine-16.rom, which three
                        # platforms were then served in place of the archive.
                        if file_entry.get("zipped_file"):
                            continue

                        matched = None
                        if sha1 and sha1 in files:
                            matched = sha1
                        elif md5 and md5 in md5_to_sha1:
                            matched = md5_to_sha1[md5]

                        if matched:
                            _add_alias(name, matched)
        except ImportError:
            pass

    # core-info is not read here: it was the only network call of a build
    # that must give the same database offline, and the one name it added
    # (gearcoleco's writer.rom) is a profile entry proven by its sha1, which
    # the profile pass below now registers.

    # Collect aliases from emulator YAMLs (aliases field on file entries)
    emulators_dir = Path("emulators")
    if emulators_dir.is_dir():
        try:
            import yaml

            for emu_file in emulators_dir.glob("*.yml"):
                if emu_file.name.endswith(".old.yml"):
                    continue
                try:
                    with open(emu_file) as f:
                        emu_config = yaml_load(f) or {}
                except (yaml.YAMLError, OSError):
                    continue
                # A profile whose entries name each other (dosbox-x opens
                # MT32_CONTROL.ROM and CM32L_CONTROL.ROM alike, so each entry
                # aliases the other) states that ITS slot takes either name.
                # Indexed globally that became evidence for every emulator:
                # ScummVM's MT-32 slot received the CM-32L ROMs.
                primary_names = _primary_names(emu_config.get("files", []))
                for file_entry in emu_config.get("files", []):
                    entry_name = file_entry.get("name", "")
                    entry_aliases = _own_aliases(file_entry, primary_names)
                    # A profile may accept several revisions: each held one
                    # is designated by the entry, none of them by guess.
                    matched: set[str] = {
                        value for value in _as_list(file_entry.get("sha1"))
                        if value in files
                    }
                    matched |= {
                        md5_to_sha1[value]
                        for value in _as_list(file_entry.get("md5"))
                        if value in md5_to_sha1
                    }
                    if matched:
                        # Proven by content, the profile's own name designates
                        # the file whatever the collection calls it.
                        entry_aliases.insert(0, entry_name)
                    if not entry_aliases:
                        continue
                    if not matched and entry_name and name_count.get(entry_name) == 1:
                        # A name carried by several files names none of them:
                        # quasi88's disk.rom aliases went to whichever
                        # disk.rom the scan met last, a Tandy CoCo ROM.
                        matched = {name_to_sha1[entry_name]}
                    for sha in sorted(matched):
                        for alias_name in entry_aliases:
                            _add_alias(alias_name, sha)
        except ImportError:
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
        [
            "squirreljme.sqc",
            "squirreljme.jar",
            "squirreljme-fast.jar",
            "squirreljme-slow.jar",
            "squirreljme-slow-test.jar",
            "squirreljme-0.3.0.jar",
            "squirreljme-0.3.0-fast.jar",
            "squirreljme-0.3.0-slow.jar",
            "squirreljme-0.3.0-slow-test.jar",
        ],
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
