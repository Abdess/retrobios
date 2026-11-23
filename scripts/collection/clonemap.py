"""Merging and writing the MAME clone map _mame_clones.json."""

from __future__ import annotations

import json

from core.artifacts import write_text_atomic


def record_clone_map(
    mame_clones: dict[str, dict], previous: dict, clone_path: str, dry_run: bool
) -> dict[str, dict]:
    """Write the clone map, merged with what earlier runs recorded, and return it."""
    # A group is only visible while both copies are on disk, and this run
    # has just deleted the clone. Writing only what was seen this time
    # therefore erases every mapping an earlier run recorded, and the
    # canonical zip stops answering to the names it stands in for. The
    # older entries stay valid: their canonical file is still here.
    if dry_run:
        return mame_clones
    if previous:
        merged = dict(previous)
        merged.update(mame_clones)
        mame_clones = collapse_clone_chains(merged)
    write_text_atomic(clone_path, json.dumps(mame_clones, indent=2, sort_keys=True))
    return mame_clones


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
