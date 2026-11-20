"""Romset recipes: the (member, crc32) lists profiles and imported DATs give per archive."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from romrecipes.ledger import ARCHIVES_FILE

Recipe = list[tuple[str, str]]


def usable_recipe(members: list[dict]) -> Recipe | None:
    """The (name, crc32) list of named members, None when it is empty or a
    member lacks a crc32: the pool is addressed by content, so a member
    without one cannot be located."""
    recipe = [
        (str(member["name"]), str(member.get("crc32") or "").lower())
        for member in members
        if member.get("name") is not None
    ]
    return recipe if recipe and all(crc for _name, crc in recipe) else None


def load_dat_recipes(path: str | Path) -> dict[str, dict[str, Recipe]]:
    """Recipes imported from MAME or FBNeo DATs.

    A DAT documents every set of one emulator version, where profiles only
    document the few hundred the collection curates by hand. Labels are
    prefixed so an identification says which DAT decided it.
    """
    target = Path(path)
    if target.is_dir():
        merged: dict[str, dict[str, Recipe]] = {}
        for source, snapshot in dat_snapshots(target):
            merged = merge_recipes(merged, _snapshot_recipes(source, snapshot))
        return merged
    if not target.is_file():
        return {}
    return _snapshot_recipes(*_read_snapshot(target))


def _read_snapshot(path: Path) -> tuple[str, dict]:
    with path.open(encoding="utf-8") as handle:
        snapshot = json.load(handle)
    return str(snapshot.get("source", path.stem)), snapshot


def dat_snapshots(recipes_dir: Path) -> Iterator[tuple[str, dict]]:
    """(source, snapshot) of every DAT snapshot under ``recipes_dir``.

    archives.json sits beside them and records the collection's archives,
    not a DAT's sets.
    """
    for path in sorted(recipes_dir.glob("*.json")):
        if path.name != ARCHIVES_FILE.name:
            yield _read_snapshot(path)


def _snapshot_recipes(source: str, snapshot: dict) -> dict[str, dict[str, Recipe]]:
    # A recipe shared by several versions is stored once under the earliest.
    # The label therefore reads "unchanged since", not "is this version".
    recipes: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for entry in snapshot.get("entries", []):
        archive = entry.get("name", "")
        recipe = usable_recipe(entry.get("members", []) or [])
        if not archive or recipe is None:
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
    """Map each archive name to one usable recipe per profile that documents it."""
    recipes: dict[str, dict[str, Recipe]] = defaultdict(dict)
    for profile_name, profile in sorted(profiles.items()):
        for entry in profile.get("files", []) or []:
            contents = entry.get("contents")
            archive = entry.get("name", "")
            if not contents or not archive:
                continue
            recipe = usable_recipe(contents)
            if recipe is not None:
                recipes[archive][profile_name] = recipe
    return dict(recipes)
