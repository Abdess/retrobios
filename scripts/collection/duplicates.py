"""Which files of bios/ hold the same content, and which of those copies may go."""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path

from collection.scan import primary_rank
from core.hashing import compute_hashes
from model.nodedup import in_nodedup_dir


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
            if in_nodedup_dir(path):
                continue
            by_size[os.path.getsize(path)].append(path)

    sha1_to_paths: dict[str, list[str]] = defaultdict(list)
    for paths in by_size.values():
        if len(paths) < 2:
            continue
        for path in paths:
            sha1_to_paths[compute_hashes(path, frozenset({"sha1"}))["sha1"]].append(path)
    return sha1_to_paths


def plan_group_removals(
    sha1: str, paths: list[str], mame_clones: dict, bios_dir: str
) -> list[str]:
    """Decide which copies of one content hash may go.

    Two files with the same content are not automatically interchangeable.
    Same name in different directories is a true duplicate. Different names
    are only collapsible when they are MAME device clones, which is why the
    check is narrowed to zips under a MAME directory: anywhere else each
    name may be the one some emulator looks for.

    Records clone groups in *mame_clones* and returns the paths to remove.
    """
    def rank(path: str) -> tuple:
        return primary_rank(Path(path), Path(bios_dir))

    # Separate by filename: same name = true duplicate, different name = clone
    by_name: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        by_name[os.path.basename(p)].append(p)

    # True duplicates: same filename in multiple directories
    true_dupes_to_remove: list[str] = []
    for name_paths in by_name.values():
        if len(name_paths) > 1:
            name_paths.sort(key=rank)
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
            min(variants, key=rank)
        ]
        true_dupes_to_remove.extend(p for p in variants if p not in holders)

    # Different filenames, same content. Outside a MAME directory each name
    # may be needed by a different emulator (64DD_IPL_US.n64, IPL_USA.n64)
    # and all are kept. Zips that all sit under MAME/Arcade are device
    # clones: one canonical stays, the clones go and the clone map records them.
    unique_names = sorted(by_name.keys())
    all_mame_zip = all(
        any(_is_mame_dir(p) for p in name_paths) for name_paths in by_name.values()
    ) and all(n.endswith(".zip") for n in unique_names)
    if len(unique_names) > 1 and all_mame_zip:
        canonical_name = min(unique_names, key=len)
        clone_names = [n for n in unique_names if n != canonical_name]
        mame_clones[canonical_name] = {
            "sha1": sha1,
            "clones": clone_names,
            "total_copies": sum(len(by_name[n]) for n in clone_names),
        }
        true_dupes_to_remove.extend(p for n in clone_names for p in by_name[n])

    return true_dupes_to_remove
