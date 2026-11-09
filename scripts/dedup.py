"""Deduplicate bios/: keep one canonical file per unique content.

Usage:
    python scripts/dedup.py [--dry-run] [--bios-dir bios]

Two types of deduplication:

1. TRUE DUPLICATES: Same filename in different directories (e.g., naomi.zip
   in both Arcade/ and Sega/Dreamcast/). Keeps one canonical copy, removes
   the others. resolve_local_file finds files by hash, not path.

2. MAME DEVICE CLONES: Different filenames with identical content in the same
   MAME directory (e.g., bbc_m87.zip and bbc_24bbc.zip are identical ZIPs).
   These are NOT aliases: MAME loads each by its unique name. Instead of
   deleting, we create a _mame_clones.json mapping so generate_pack.py can
   pack all names from a single canonical file.

After dedup, run generate_db.py --force to rebuild database indexes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import compute_hashes, require_directory, write_text_atomic

DEFAULT_BIOS_DIR = "bios"

# Directories where deduplication must NOT be applied.
NODEDUP_DIRS = {
    "RPG Maker",
    "ScummVM",
    # A zoneinfo tree is addressed by zone name and its aliases are equal
    # files by design: US/Samoa is Pacific/Midway.
    "tzdata",
    # VICE data is addressed by machine directory: C64, C64DTV and SCPU64
    # share one keymap, C64 and CBM-II one palette. With the copies removed
    # the name step served the C128 keymap to all of them.
    "c64-emu",
    # PinMAME reads a sound-only parent (gts80s) as its own archive, equal
    # byte for byte to the base set. Folding them into the clone map would
    # key gts1.zip twice, once for MAME's set and once for PinMAME's.
    "PinMAME",
    # BBK dictionary ROMs are addressed by model directory, and the OS ROM
    # the A4988 folder needs is the one the gam4980 core is given.
    "BBK",
    # Engine data trees read by path: one sound or one sprite sits under
    # several characters, campaigns or episodes, and each copy is opened
    # where it lies.
    "C-Dogs SDL",
    "Ikemen GO",
    "Theme Hospital",
    "TheXTech",
    # Aleph One opens each scenario's Physics Models and the Splitwolf mod
    # tree its sounds and maps by path: Marathon 2 and Infinity share one
    # Standard.phyA, lwmp/ repeats 182 files across its levels.
    "Bungie",
    "splitwolf",
    # CatacombGL reads each game's folder by name and compares sizes only:
    # the Armageddon and Apocalypse intro shapes SHP1, SHP9 to SHP13 are the
    # Abyss shareware bytes under the retail names, and each game opens
    # its own copy.
    "Softdisk",
    # MAME's support trees (hash, plugins) are read by path as a whole, and
    # two MAME versions share most of their software lists byte for byte.
    "mame",
    # The Tyrian 2.1 distribution ships netset.pcx and tyrset.pcx with the
    # same bytes, and EmuELEC places both names under ports/opentyrian/.
    "opentyrian",
}


def path_priority(path: str) -> tuple:
    """Lower score = better candidate to keep as canonical.

    Prefers: shorter path, non-variant, non-MAME (system-specific over generic).
    """
    parts = Path(path).parts
    is_variant = ".variants" in parts
    is_mame = "MAME" in parts
    is_arcade = "Arcade" in parts
    return (is_variant, is_mame, is_arcade, len(parts), path)


def _in_nodedup_dir(path: str) -> bool:
    parts = Path(path).parts
    return any(nodedup in parts for nodedup in NODEDUP_DIRS)


def _is_mame_dir(path: str) -> bool:
    """Check if a path is in a MAME-specific directory."""
    parts = Path(path).parts
    return "MAME" in parts or "Arcade" in parts


def scan_duplicates(bios_dir: str) -> dict[str, list[str]]:
    """Files grouped by SHA1, excluding no-dedup directories.

    Two equal files have the same size, so only files that share a size are
    read, and for the sha1 alone: hashing the whole tree with every digest
    took 33 s for a scan that reads a quarter of it. A file alone at its
    size is in no group of two and is left out.
    """
    by_size: dict[int, list[str]] = defaultdict(list)
    for root, _dirs, files in os.walk(bios_dir):
        for name in files:
            path = os.path.join(root, name)
            if _in_nodedup_dir(path):
                continue
            by_size[os.path.getsize(path)].append(path)

    sha1_to_paths: dict[str, list[str]] = defaultdict(list)
    for paths in by_size.values():
        if len(paths) < 2:
            continue
        for path in paths:
            sha1_to_paths[compute_hashes(path, frozenset({"sha1"}))["sha1"]].append(path)
    return sha1_to_paths


def _plan_group_removals(
    sha1: str, paths: list[str], mame_clones: dict
) -> list[str]:
    """Decide which copies of one content hash may go.

    Two files with the same content are not automatically interchangeable.
    Same name in different directories is a true duplicate. Different names
    are only collapsible when they are MAME device clones, which is why the
    check is narrowed to zips under a MAME directory: anywhere else each
    name may be the one some emulator looks for.

    Records clone groups in *mame_clones* and returns the paths to remove.
    """
    true_dupes_to_remove: list[str] = []
    # Separate by filename: same name = true duplicate, different name = clone
    by_name: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        by_name[os.path.basename(p)].append(p)

    # True duplicates: same filename in multiple directories
    true_dupes_to_remove = []
    for name, name_paths in by_name.items():
        if len(name_paths) > 1:
            name_paths.sort(key=path_priority)
            true_dupes_to_remove.extend(name_paths[1:])

    # A variant exists to hold a content its primary does not. Once another
    # file holds the same bytes, the copy under .variants/ answers nothing
    # the index does not already know, whatever its name or suffix: the
    # resolver finds the content by hash and writes it under the name the
    # destination asks for.
    remaining = [p for p in paths if p not in true_dupes_to_remove]
    variants = [p for p in remaining if ".variants" in Path(p).parts]
    if variants:
        holders = [p for p in remaining if p not in variants] or [
            min(variants, key=path_priority)
        ]
        true_dupes_to_remove.extend(p for p in variants if p not in holders)

    # Different filenames, same content: need special handling
    unique_names = sorted(by_name.keys())
    if len(unique_names) > 1:
        # Check if these are all in MAME/Arcade dirs AND all ZIPs
        all_mame_zip = all(
            any(_is_mame_dir(p) for p in name_paths)
            for name_paths in by_name.values()
        ) and all(n.endswith(".zip") for n in unique_names)
        if all_mame_zip:
            # MAME device clones: different ZIP names, same ROM content
            # Keep one canonical, remove clones, record in clone map
            canonical_name = min(unique_names, key=len)
            clone_names = sorted(n for n in unique_names if n != canonical_name)
            if clone_names:
                mame_clones[canonical_name] = {
                    "sha1": sha1,
                    "clones": clone_names,
                    "total_copies": sum(len(by_name[n]) for n in clone_names),
                }
                for clone_name in clone_names:
                    for p in by_name[clone_name]:
                        true_dupes_to_remove.append(p)
        else:
            # Non-MAME different names (e.g., 64DD_IPL_US.n64 vs IPL_USA.n64)
            # Keep ALL: each name may be needed by a different emulator
            # Only remove true duplicates (same name in multiple dirs)
            pass

    return true_dupes_to_remove


def deduplicate(bios_dir: str, dry_run: bool = False) -> dict:
    """Remove true duplicates, map MAME device clones.

    True duplicates (same name, different dirs): removes copies.
    MAME clones (different names, same content, same dir): creates mapping.

    Returns dict of {sha1: {"canonical": path, "removed": [paths], "aliases": [names]}}
    """
    # Beside the scanned tree, where get_mame_clone_map() reads it for
    # the real layout. A path relative to the working directory let a
    # scan of a fixture tree rewrite the repository's own map.
    clone_path = os.path.join(
        os.path.dirname(os.path.abspath(bios_dir)), "_mame_clones.json"
    )
    # Read before anything is removed: the map is cumulative, and a run that
    # stopped on an unreadable one after deleting clones would lose them.
    try:
        with open(clone_path) as f:
            previous = json.load(f)
    except FileNotFoundError:
        previous = {}
    except json.JSONDecodeError as e:
        raise SystemExit(
            f"{clone_path} is not valid JSON ({e}). Restore it from git "
            "before deduplicating again"
        ) from e

    sha1_groups = scan_duplicates(bios_dir)
    results = {}
    total_removed = 0
    total_saved = 0
    mame_clones: dict[str, dict] = {}  # canonical_name -> {sha1, clones: [names]}

    for sha1, paths in sorted(sha1_groups.items()):
        if len(paths) <= 1:
            continue

        true_dupes_to_remove = _plan_group_removals(sha1, paths, mame_clones)

        if not true_dupes_to_remove:
            continue

        # Find the best canonical across all paths
        all_paths = [p for p in paths if p not in true_dupes_to_remove]
        if not all_paths:
            # All copies were marked for removal: keep the best one
            all_paths_sorted = sorted(paths, key=path_priority)
            all_paths = [all_paths_sorted[0]]
            true_dupes_to_remove = [p for p in paths if p != all_paths[0]]

        canonical = sorted(all_paths, key=path_priority)[0]
        canonical_name = os.path.basename(canonical)

        all_names = set(os.path.basename(p) for p in paths)
        alias_names = sorted(all_names - {canonical_name})

        size = os.path.getsize(canonical)

        results[sha1] = {
            "canonical": canonical,
            "removed": [],
            "aliases": alias_names,
        }

        for dup in true_dupes_to_remove:
            if dup == canonical:
                continue
            if not os.path.exists(dup):
                continue
            if dry_run:
                print(f"  WOULD REMOVE: {dup}")
            else:
                try:
                    os.remove(dup)
                except OSError as e:
                    print(f"  WARNING: cannot remove {dup}: {e}")
                    continue
                # Clean up empty .variants/ directories
                parent = os.path.dirname(dup)
                if os.path.basename(parent) == ".variants" and not os.listdir(parent):
                    os.rmdir(parent)
            results[sha1]["removed"].append(dup)
            total_removed += 1
            total_saved += size

        if alias_names or true_dupes_to_remove:
            action = "Would remove" if dry_run else "Removed"
            dn = os.path.basename(canonical)
            print(f"  {dn} (keep: {canonical})")
            if true_dupes_to_remove:
                print(f"    {action} {len(true_dupes_to_remove)} copies")
            if alias_names:
                print(f"    MAME clones: {alias_names}")

    # Clean up empty directories
    if not dry_run:
        empty_cleaned = 0
        for root, dirs, files in os.walk(bios_dir, topdown=False):
            if not files and not dirs and root != bios_dir:
                os.rmdir(root)
                empty_cleaned += 1

    prefix = "Would remove" if dry_run else "Removed"
    print(f"\n{prefix}: {total_removed} files")
    print(
        f"Space {'to save' if dry_run else 'saved'}: {total_saved / 1024 / 1024:.1f} MB"
    )
    if not dry_run and empty_cleaned:
        print(f"Cleaned {empty_cleaned} empty directories")

    if mame_clones:
        # A group is only visible while both copies are on disk, and this run
        # has just deleted the clone. Writing only what was seen this time
        # therefore erases every mapping an earlier run recorded, and the
        # canonical zip stops answering to the names it stands in for. The
        # older entries stay valid: their canonical file is still here.
        if not dry_run:
            if isinstance(previous, dict):
                merged = dict(previous)
                merged.update(mame_clones)
                mame_clones = collapse_clone_chains(merged)
        if dry_run:
            print(f"\nWould write MAME clone map: {clone_path}")
            print(
                f"  {len(mame_clones)} canonical ZIPs with "
                f"{sum(len(v['clones']) for v in mame_clones.values())} clones"
            )
        else:
            write_text_atomic(clone_path, json.dumps(mame_clones, indent=2, sort_keys=True))
            print(f"\nWrote MAME clone map: {clone_path}")
            print(
                f"  {len(mame_clones)} canonical ZIPs with "
                f"{sum(len(v['clones']) for v in mame_clones.values())} clones"
            )

    return results


def collapse_clone_chains(clone_map: dict[str, dict]) -> dict[str, dict]:
    """Point every clone at a canonical archive that still exists.

    The map is cumulative. When a later run finds that a canonical archive is
    itself a byte-identical copy of another and removes it, the entry that
    named it as canonical would send its clones to a file that is gone:
    sys68k_cpu21a pointed at sys68k_cpu21 after sys68k_cpu21 became a clone
    of sys68k_cpu20. Each such entry's clones move to the final canonical.
    """
    owner = {
        clone: canonical
        for canonical, entry in clone_map.items()
        for clone in entry.get("clones", [])
    }

    def final(name: str) -> str:
        seen = {name}
        while name in owner:
            name = owner[name]
            if name in seen:
                raise ValueError(f"clone map loops through {name}")
            seen.add(name)
        return name

    collapsed: dict[str, dict] = {}
    for canonical, entry in clone_map.items():
        target = final(canonical)
        kept = collapsed.setdefault(target, {**clone_map.get(target, entry), "clones": []})
        names = set(kept["clones"]) | set(entry.get("clones", []))
        if target != canonical:
            names.add(canonical)
        names.discard(target)
        kept["clones"] = sorted(names)
        kept["total_copies"] = len(kept["clones"])
    return collapsed


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Deduplicate bios/ directory")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without deleting"
    )
    parser.add_argument(
        "--bios-dir", default=DEFAULT_BIOS_DIR,
        help="BIOS collection directory (default: %(default)s)",
    )
    args = parser.parse_args()
    require_directory(args.bios_dir)

    print(f"Scanning {args.bios_dir}/ for duplicates...")
    if args.dry_run:
        print("(DRY RUN)\n")

    deduplicate(args.bios_dir, dry_run=args.dry_run)

    if not args.dry_run:
        print("\nRun 'python scripts/generate_db.py --force' to rebuild database.")


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
