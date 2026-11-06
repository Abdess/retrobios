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
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    annotate_provenance,
    compute_hashes,
    DEFAULT_PROVENANCE_DIR,
    list_registered_platforms,
    load_provenance_snapshots,
    repository_output_lock,
    require_yaml,
    set_plain_mode,
    source_yaml_paths,
    variant_base_name,
    write_if_changed,
    write_text_atomic,
    yaml_load,
)

# Platform and profile aliases are read from YAML: without pyyaml the
# database lost every one of them and the run still exited 0.
yaml = require_yaml()

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
    if ".variants" in filepath.parts:
        return variant_base_name(filepath.name)
    return filepath.name


def _settled_hashes(
    filepath: Path, cached: dict | None, mtime: float, size: int
) -> dict:
    """The file's digests, computed again when they contradict the cache.

    A forced run rehashes everything, and this host has given a wrong SHA-1
    under load (DSi_Nand_USA.bin read as 834b140f, not ef08ae02). An entry
    whose mtime and size did not move but whose digest did is hashed a
    second time. A second reading that gives the cached value back settles it.
    Two readings that agree against it do not: the host has returned the same
    wrong digest twice in a row (62b100f2 for the same file), and a value
    taken then is cached and read back by every later run. A file rewritten
    in place moves its mtime, so the run stops instead of choosing.
    """
    hashes = compute_hashes(filepath)
    if not cached or cached.get("mtime") != mtime or cached.get("size") != size:
        return hashes
    if cached.get("sha1") in (None, hashes["sha1"]):
        return hashes
    again = compute_hashes(filepath, cache=False)
    print(
        f"  WARNING: {filepath}: sha1 read as {hashes['sha1'][:8]} then "
        f"{again['sha1'][:8]}, cached {cached['sha1'][:8]}",
        file=sys.stderr,
    )
    if again["sha1"] == cached["sha1"]:
        return again
    raise RuntimeError(
        f"{filepath}: read as {again['sha1'][:8]}, cached as {cached['sha1'][:8]}, "
        "with the same mtime and size. Rerun when the host is idle, or "
        f"`touch {filepath}` if its bytes really changed."
    )


def _emulator_tree(path: str) -> bool:
    """Whether a path lies in one emulator's own tree, bios/Other/<emulator>/."""
    parts = path.replace("\\", "/").split("/")
    return len(parts) > 3 and parts[1] == "Other"


def _takes_primary(current: str, candidate: str) -> bool:
    """Whether another copy of the same bytes becomes the content's path.

    A .variants/ copy yields to any other one. A copy in an emulator's own
    tree yields to one filed under its machine: ZEsarUX's sms.rom sorted
    before bios/Sega/Master System/, the resolver set it aside as another
    emulator's file, and Genesis Plus GX got a variant instead of v1.3.
    """
    if "/.variants/" in candidate.replace("\\", "/"):
        return False
    if "/.variants/" in current:
        return True
    return _emulator_tree(current) and not _emulator_tree(candidate)


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
                if sha1 in files:
                    if _takes_primary(files[sha1]["path"], rel_path):
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

        hashes = _settled_hashes(filepath, cache.get(cache_key), mtime, size)
        sha1 = hashes["sha1"]
        if sha1 in files:
            if _takes_primary(files[sha1]["path"], rel_path):
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


def shadowed_alias_index(
    shadowed: list[tuple[str, set[str], list[str]]], by_name: dict
) -> dict[str, list[str]]:
    """Profile aliases that a primary's name keeps out of by_name.

    QUASI88 reads DISK.ROM as n88sub.rom, but DISK.ROM is the MSX disk ROM's
    own name, so by_name never points it at the PC-88 file. The resolver reads
    this index only where the system names a maker and no copy filed under
    that maker answers the name. An entry with no hash designates the content
    its own name holds alone in by_name.
    """
    index: dict[str, set[str]] = {}
    for entry_name, matched, taken in shadowed:
        held = by_name.get(entry_name, [])
        designated = matched or (set(held) if len(held) == 1 else set())
        for alias in taken:
            fresh = designated - set(by_name.get(alias, []))
            if fresh:
                index.setdefault(alias, set()).update(fresh)
    return {alias: sorted(sha1s) for alias, sha1s in sorted(index.items())}


def load_cache(cache_path: str) -> dict:
    """Load cache file if it exists."""
    try:
        with open(cache_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache_path: str, cache: dict) -> None:
    """Save the cache whole or not at all.

    Written in place, a crash while serializing left a truncated file that
    the next run read as empty and rehashed the collection from scratch.
    """
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    write_text_atomic(cache_path, json.dumps(cache))


def _load_gitignored_large_files() -> set[str]:
    """The bios/ paths .gitignore registers as release assets."""
    from largefiles import load_registered_paths

    return set(load_registered_paths(".gitignore"))


def _restore(cached: str, path: str) -> None:
    """Copy a fetched asset to its registered path, whole or not at all.

    An interrupted copy at the final name is a truncated file the next scan
    hashes and publishes. A scratch beside it is swapped in only once full.
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, scratch = tempfile.mkstemp(dir=directory, prefix=".restore-")
    os.close(fd)
    try:
        shutil.copy2(cached, scratch)
        set_plain_mode(scratch)
        os.replace(scratch, path)
    finally:
        if os.path.exists(scratch):
            os.remove(scratch)


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
    except FileNotFoundError:
        return 0
    except json.JSONDecodeError as e:
        # An unreadable database is not an absent one: rewriting it from a
        # checkout without the release assets would drop every entry they
        # hold, and the manifests regenerated from it would omit them.
        raise SystemExit(
            f"{db_path} is not valid JSON ({e}). Restore it from git "
            "or regenerate it on a checkout holding the release assets before "
            "scanning again"
        ) from e

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
            _restore(cached, path)
        files[sha1] = entry
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate multi-indexed BIOS database")
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
    with repository_output_lock(args.output):
        return _generate(args)


def _generate(args: argparse.Namespace) -> int:
    bios_dir = Path(args.bios_dir)
    if not bios_dir.is_dir():
        print(f"Error: BIOS directory '{bios_dir}' not found", file=sys.stderr)
        sys.exit(1)

    # A forced run rehashes every file but keeps the previous digests to
    # check the new ones against.
    cache = load_cache(CACHE_FILE)

    print(f"Scanning {bios_dir}/ ...")
    files, aliases, new_cache = scan_bios_dir(bios_dir, cache, args.force)

    if not files:
        print("Warning: No BIOS files found", file=sys.stderr)

    # Preserve entries for large files stored as release assets (.gitignore)
    preserved = _preserve_large_file_entries(files, args.output)
    if preserved:
        print(f"  Preserved {preserved} large file entries from existing database")

    shadowed: list[tuple[str, set[str], list[str]]] = []
    try:
        platform_aliases = _collect_all_aliases(files, aliases, shadowed)
    except UnreadableSource as exc:
        for source in exc.sources:
            print(f"Error: cannot read {source}", file=sys.stderr)
        print(f"Error: {args.output} not written", file=sys.stderr)
        return 1
    for sha1, name_list in platform_aliases.items():
        for alias_entry in name_list:
            if sha1 not in aliases:
                aliases[sha1] = []
            aliases[sha1].append(alias_entry)

    snapshots = load_provenance_snapshots(args.provenance_dir)
    provenance_counts = annotate_provenance(files, snapshots)

    indexes = build_indexes(files, aliases)
    indexes["by_shadowed_alias"] = shadowed_alias_index(shadowed, indexes["by_name"])
    total_size = sum(entry["size"] for entry in files.values())

    database = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(files),
        "total_size": total_size,
        # The tree these paths belong to: dedup writes _mame_clones.json
        # beside it, and the resolver reads the map there, not at the repo root.
        "bios_dir": os.path.normpath(args.bios_dir),
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


class UnreadableSource(Exception):
    """Platform or profile files that do not parse, named one per line."""

    def __init__(self, sources: list[str]) -> None:
        super().__init__("\n".join(sources))
        self.sources = sources


def _collect_all_aliases(
    files: dict,
    copies: dict | None = None,
    shadowed: list[tuple[str, set[str], list[str]]] | None = None,
) -> dict:
    """Collect alternate filenames from platform YAMLs, core-info, and known aliases.

    Registers alternate names so generate_pack can resolve files stored under different names.
    ``copies`` maps a sha1 to the other files the scan found with that content.
    ``shadowed`` receives, per profile entry, its name, the contents its hashes
    designate and the aliases a primary's name already carries.
    """
    md5_to_sha1 = {}
    name_to_sha1 = {}
    name_count: dict[str, int] = {}
    for sha1, entry in files.items():
        md5_to_sha1[entry["md5"]] = sha1
        name_to_sha1[entry["name"]] = sha1
        name_count[entry["name"]] = name_count.get(entry["name"], 0) + 1
    # The contents held under each name, every copy counted and not only the
    # primary: which copy of identical bytes is primary follows path order.
    # Keyed on primaries alone, project64's 64DD_IPL_v12_JPN.bin stopped
    # naming its content once 64DD_IPL.bin sorted first, and its aliases
    # 64dd_ipl_J.bin and 64DD_IPL_JP.n64 went with it.
    holders: dict[str, set[str]] = {}
    for sha1, entry in files.items():
        holders.setdefault(entry["name"], set()).add(sha1)
    for sha1, copy_list in (copies or {}).items():
        if sha1 in files:
            for copy in copy_list:
                holders.setdefault(copy["name"], set()).add(sha1)

    aliases = {}

    # A name only .variants/ copies carry is not a primary's: those copies are
    # the other revisions of whatever the name designates. Retroarch pins
    # bios_E.sms to v1.3, and with the name refused, Genesis Plus GX got the
    # first variant in index order, a 256 KB BIOS, by the name step.
    named_primaries = {
        entry["name"] for entry in files.values() if "/.variants/" not in entry["path"]
    }

    def _add_alias(name: str, matched_sha1: str) -> None:
        if not name or name in named_primaries:
            return
        if matched_sha1 not in aliases:
            aliases[matched_sha1] = []
        existing = {a["name"] for a in aliases[matched_sha1]}
        if name not in existing:
            aliases[matched_sha1].append({"name": name, "path": ""})

    # A source that does not parse is reported and the run refused: written
    # without it, the database lost every alias the file proves and the
    # command exited 0 (dosbox-x's wqy fonts answered not_found).
    unreadable: list[str] = []
    platforms_dir = Path("platforms")
    if platforms_dir.is_dir():
        for platform_name in list_registered_platforms(
            str(platforms_dir), include_archived=True
        ):
            config_file = platforms_dir / f"{platform_name}.yml"
            try:
                with open(config_file) as f:
                    config = yaml_load(f) or {}
            except (yaml.YAMLError, OSError) as e:
                unreadable.append(f"{config_file}: {e}")
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

    # core-info is not read here: it was the only network call of a build
    # that must give the same database offline, and the one name it added
    # (gearcoleco's writer.rom) is a profile entry proven by its sha1, which
    # the profile pass below now registers.

    # Collect aliases from emulator YAMLs (aliases field on file entries)
    emulators_dir = Path("emulators")
    if emulators_dir.is_dir():
        for emu_file in source_yaml_paths(emulators_dir):
            try:
                with open(emu_file) as f:
                    emu_config = yaml_load(f) or {}
            except (yaml.YAMLError, OSError) as e:
                unreadable.append(f"{emu_file}: {e}")
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
                if shadowed is not None:
                    taken = [
                        alias for alias in entry_aliases
                        if alias != entry_name and alias in named_primaries
                    ]
                    if taken:
                        shadowed.append((entry_name, set(matched), taken))
                if not matched and len(holders.get(entry_name, ())) == 1:
                    # A name carried by several contents names none of them:
                    # quasi88's disk.rom aliases went to whichever
                    # disk.rom the scan met last, a Tandy CoCo ROM.
                    matched = set(holders[entry_name])
                for sha in sorted(matched):
                    for alias_name in entry_aliases:
                        _add_alias(alias_name, sha)

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
        # Nintendo DS. DraStic opens nds_bios_arm9.bin, nds_bios_arm7.bin
        # and nds_firmware.bin and checks their size only: the collection
        # answers those names with its DS dumps.
        ["NDS_Bios7.bin", "bios7.bin", "nds7.bin", "nds_bios_arm7.bin"],
        ["NDS_Bios9.bin", "bios9.bin", "nds9.bin", "nds_bios_arm9.bin"],
        ["NDS_Lite_Firmware.bin", "nds_firmware.bin"],
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

    if unreadable:
        raise UnreadableSource(unreadable)
    return aliases


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
