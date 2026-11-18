"""Romset recipes: the (member, crc32) lists profiles and imported DATs give per archive."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


Recipe = list[tuple[str, str]]


def load_dat_recipes(path: str | Path) -> dict[str, dict[str, Recipe]]:
    """Recipes imported from MAME or FBNeo DATs.

    A DAT documents every set of one emulator version, where profiles only
    document the few hundred the collection curates by hand. Labels are
    prefixed so an identification says which DAT decided it.
    """
    target = Path(path)
    if target.is_dir():
        merged: dict[str, dict[str, Recipe]] = {}
        for snapshot_file in sorted(target.glob("*.json")):
            merged = merge_recipes(merged, load_dat_recipes(snapshot_file))
        return merged
    snapshot_path = target
    if not snapshot_path.is_file():
        return {}
    with snapshot_path.open(encoding="utf-8") as handle:
        snapshot = json.load(handle)
    source = snapshot.get("source", "dat")
    # A recipe shared by several versions is stored once under the earliest.
    # The label therefore reads "unchanged since", not "is this version".
    recipes: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for entry in snapshot.get("entries", []):
        archive = entry.get("name", "")
        members = entry.get("members", []) or []
        recipe = [
            (str(member["name"]), str(member.get("crc32") or "").lower())
            for member in members
            if member.get("name") is not None
        ]
        if not archive or not recipe or not all(crc for _name, crc in recipe):
            continue
        label = f"{source}:{entry.get('dat', 'unnamed')}"
        recipes[archive][label] = recipe
    return dict(recipes)


def merge_recipes(*sources: dict[str, dict[str, Recipe]]) -> dict[str, dict[str, Recipe]]:
    """Combine recipe sets, keeping every label distinct."""
    merged: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for source in sources:
        for archive, per_label in source.items():
            merged[archive].update(per_label)
    return dict(merged)


def collect_recipes(profiles: dict) -> dict[str, dict[str, Recipe]]:
    """Map each archive name to one recipe per profile that documents it.

    A recipe is only usable when every member carries a CRC32: the pool is
    addressed by content, so a member without one cannot be located.
    """
    recipes: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for profile_name, profile in sorted(profiles.items()):
        for entry in profile.get("files", []) or []:
            contents = entry.get("contents")
            archive = entry.get("name", "")
            if not contents or not archive:
                continue
            recipe = [
                (str(member["name"]), str(member.get("crc32") or "").lower())
                for member in contents
                if member.get("name") is not None
            ]
            if recipe and all(crc for _name, crc in recipe):
                recipes[archive][profile_name] = recipe
    return dict(recipes)
