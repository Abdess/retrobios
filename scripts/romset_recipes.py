#!/usr/bin/env python3
"""Identify and reconstruct arcade romset archives from their recipes.

A profile's ``contents:`` block is a recipe: the member names and CRC32s one
emulator version expects inside an archive. TorrentZip makes archive bytes a
function of that recipe alone, so a recipe plus the ROM bytes reproduces the
archive exactly.

Two questions follow, and this module answers both:

``--identify``
    Which version does an archive the collection holds correspond to? The
    recipe that rebuilds it byte for byte names it.

``--missing``
    A platform pins a container MD5 the collection does not have. If some
    recipe plus ROMs already present reproduces that MD5, the archive is
    constructible rather than absent.

Reconstruction is only possible when the pinned archive is itself TorrentZip.
An archive whose bytes carry metadata unrelated to its contents cannot be
derived from ROMs by anyone, and is reported as such rather than guessed at.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    load_database,
    load_emulator_profiles,
    load_platform_config,
    list_registered_platforms,
)
from torrentzip import build_torrentzip, is_torrentzip

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


class AtomPool:
    """ROM bytes in the collection, addressed by CRC32.

    Members are located once and read on demand: arcade sample sets reach
    hundreds of megabytes and a whole-pool preload buys nothing.
    """

    def __init__(self, bios_dir: Path):
        self._index: dict[str, tuple[Path, str]] = {}
        # A recipe is built once: identification and reconstruction ask for the
        # same archives, and every build re-reads and re-deflates its ROMs.
        self._built: dict[tuple[tuple[str, str], ...], bytes | None] = {}
        self.unreadable: list[str] = []
        for archive in sorted(bios_dir.rglob("*.zip")):
            try:
                with zipfile.ZipFile(archive) as handle:
                    for info in handle.infolist():
                        if not info.is_dir():
                            self._index.setdefault(
                                f"{info.CRC:08x}", (archive, info.filename)
                            )
            except (OSError, zipfile.BadZipFile) as exc:
                self.unreadable.append(f"{archive}: {exc}")

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, crc32: str) -> bool:
        return crc32.lower() in self._index

    def read(self, crc32: str) -> bytes:
        archive, member = self._index[crc32.lower()]
        with zipfile.ZipFile(archive) as handle:
            return handle.read(member)

    def build(self, recipe: Recipe) -> bytes | None:
        """Return the TorrentZip bytes for *recipe*, or None if incomplete."""
        key = tuple(recipe)
        if key not in self._built:
            if all(crc in self for _name, crc in recipe):
                self._built[key] = build_torrentzip(
                    [(name, self.read(crc)) for name, crc in recipe]
                )
            else:
                self._built[key] = None
        return self._built[key]


def identify_archive(
    path: Path, recipes: dict[str, Recipe], pool: AtomPool
) -> str | None:
    """Return the recipe label that reproduces *path* byte for byte."""
    original = path.read_bytes()
    for label, recipe in sorted(recipes.items()):
        blob = pool.build(recipe)
        if blob is not None and blob == original:
            return label
    return None


def reconstruct(
    target_md5: str, recipes: dict[str, Recipe], pool: AtomPool
) -> tuple[str, bytes] | None:
    """Return the (label, bytes) whose TorrentZip build matches *target_md5*."""
    target = target_md5.lower()
    for label, recipe in sorted(recipes.items()):
        blob = pool.build(recipe)
        if blob is not None and hashlib.md5(blob).hexdigest() == target:
            return label, blob
    return None


def platform_targets(platforms_dir: str) -> dict[str, set[str]]:
    """Container MD5s the platforms pin, per archive name.

    ``zipped_file`` entries pin an inner ROM instead of the container, so
    their MD5 is not an archive hash and is skipped.
    """
    targets: dict[str, set[str]] = defaultdict(set)
    for name in list_registered_platforms(platforms_dir, include_archived=True):
        config = load_platform_config(name, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []) or []:
                archive = entry.get("name", "")
                if not archive.endswith(".zip") or entry.get("zipped_file"):
                    continue
                for value in str(entry.get("md5") or "").split(","):
                    value = value.strip().lower()
                    if len(value) == 32:
                        targets[archive].add(value)
    return dict(targets)


def _is_archive(path: Path) -> bool:
    """Whether *path* is a readable ZIP.

    A name index entry can be an alias: ``d2fdc.zip`` names a loose Apple II
    ROM, not an archive. Recipes only describe archives.
    """
    try:
        with zipfile.ZipFile(path):
            return True
    except (OSError, zipfile.BadZipFile):
        return False


def _local_paths(archive: str, db: dict) -> list[Path]:
    matches = db["indexes"]["by_name"].get(archive) or []
    if isinstance(matches, str):
        matches = [matches]
    paths = [Path(db["files"][sha1]["path"]) for sha1 in matches if sha1 in db["files"]]
    return [path for path in paths if path.is_file() and _is_archive(path)]


def identify_report(
    recipes: dict[str, dict[str, Recipe]], pool: AtomPool, db: dict
) -> dict:
    """Label every archive the collection holds with the version it matches."""
    identified: list[dict] = []
    unidentified: list[dict] = []
    for archive, per_profile in sorted(recipes.items()):
        for path in _local_paths(archive, db):
            label = identify_archive(path, per_profile, pool)
            record = {
                "archive": archive,
                "path": str(path),
                "torrentzip": is_torrentzip(path),
            }
            if label:
                record["recipe"] = label
                identified.append(record)
            else:
                record["candidates"] = sorted(per_profile)
                unidentified.append(record)
    return {"identified": identified, "unidentified": unidentified}


def missing_report(
    recipes: dict[str, dict[str, Recipe]],
    pool: AtomPool,
    db: dict,
    platforms_dir: str,
) -> dict:
    """Pinned archives the collection lacks, split by why they are absent."""
    have = set(db["indexes"]["by_md5"])
    constructible: list[dict] = []
    no_recipe: list[dict] = []
    unreproducible: list[dict] = []
    for archive, pinned in sorted(platform_targets(platforms_dir).items()):
        per_profile = recipes.get(archive, {})
        for target in sorted(pinned - have):
            if not per_profile:
                no_recipe.append({"archive": archive, "md5": target})
                continue
            found = reconstruct(target, per_profile, pool)
            if found:
                label, blob = found
                constructible.append(
                    {
                        "archive": archive,
                        "md5": target,
                        "recipe": label,
                        "size": len(blob),
                    }
                )
            else:
                usable = [
                    label
                    for label, recipe in per_profile.items()
                    if all(crc in pool for _name, crc in recipe)
                ]
                unreproducible.append(
                    {
                        "archive": archive,
                        "md5": target,
                        "recipes_tried": sorted(usable),
                        "reason": (
                            "no recipe reproduces this MD5; the pinned archive is "
                            "not TorrentZip or follows a recipe not documented here"
                            if usable
                            else "ROMs for every documented recipe are missing"
                        ),
                    }
                )
    return {
        "constructible": constructible,
        "unreproducible": unreproducible,
        "no_recipe": no_recipe,
    }


def write_reconstructions(
    entries: list[dict],
    recipes: dict[str, dict[str, Recipe]],
    pool: AtomPool,
    bios_dir: Path,
    db: dict,
) -> list[str]:
    """Write each constructible archive beside its set, as a variant."""
    written: list[str] = []
    for entry in entries:
        archive = entry["archive"]
        recipe = recipes[archive][entry["recipe"]]
        blob = pool.build(recipe)
        if blob is None:
            continue
        siblings = _local_paths(archive, db)
        parent = siblings[0].parent if siblings else bios_dir
        destination = parent / ".variants" / f"{archive}.{entry['md5'][:8]}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(blob)
        written.append(str(destination))
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identify", action="store_true", help="label local archives")
    parser.add_argument(
        "--missing", action="store_true", help="attempt pinned archives we lack"
    )
    parser.add_argument(
        "--write", action="store_true", help="write reconstructions to .variants/"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--bios-dir", default="bios")
    parser.add_argument("--platforms-dir", default="platforms")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--db", default="database.json")
    parser.add_argument(
        "--dat-recipes",
        default="recipes",
        help="recipe snapshot file, or a directory of them",
    )
    args = parser.parse_args()

    if not args.identify and not args.missing:
        args.identify = args.missing = True

    db = load_database(args.db)
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    profile_recipes = collect_recipes(profiles)
    dat_recipes = load_dat_recipes(args.dat_recipes)
    recipes = merge_recipes(profile_recipes, dat_recipes)
    pool = AtomPool(Path(args.bios_dir))

    result: dict = {
        "recipes": sum(len(v) for v in recipes.values()),
        "profile_recipes": sum(len(v) for v in profile_recipes.values()),
        "dat_recipes": sum(len(v) for v in dat_recipes.values()),
        "archives_with_recipes": len(recipes),
        "atoms": len(pool),
    }
    if pool.unreadable:
        result["unreadable_archives"] = pool.unreadable
    if args.identify:
        result["identify"] = identify_report(recipes, pool, db)
    if args.missing:
        result["missing"] = missing_report(recipes, pool, db, args.platforms_dir)
        if args.write:
            result["written"] = write_reconstructions(
                result["missing"]["constructible"], recipes, pool,
                Path(args.bios_dir), db,
            )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    print(
        f"{result['archives_with_recipes']} archives documentees par "
        f"{result['recipes']} recettes "
        f"({result['profile_recipes']} de profils, {result['dat_recipes']} de DAT), "
        f"{result['atoms']} atomes ROM disponibles"
    )
    if not result["dat_recipes"]:
        print(
            "  Aucune recette DAT: importer avec "
            "`python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289`"
        )
    for problem in result.get("unreadable_archives", []):
        print(f"  UNREADABLE: {problem}")

    if args.identify:
        ident = result["identify"]
        print(
            f"\nIdentification: {len(ident['identified'])} archives reproduites "
            f"par une recette, {len(ident['unidentified'])} non identifiees"
        )
        print(
            "  L'etiquette est la plus ancienne version produisant ces octets: "
            "une recette inchangee depuis 0.190 est comptee la, pas a sa version "
            "d'origine."
        )
        by_recipe: dict[str, int] = defaultdict(int)
        for record in ident["identified"]:
            by_recipe[record["recipe"]] += 1
        for label, count in sorted(by_recipe.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {label}: {count}")
        for record in ident["unidentified"][:10]:
            print(f"  UNIDENTIFIED: {record['path']}")

    if args.missing:
        gap = result["missing"]
        print(
            f"\nArchives epinglees absentes: "
            f"{len(gap['constructible'])} reconstructibles, "
            f"{len(gap['unreproducible'])} irreproductibles, "
            f"{len(gap['no_recipe'])} sans recette"
        )
        for record in gap["constructible"]:
            print(
                f"  BUILDABLE: {record['archive']} md5={record['md5'][:8]} "
                f"via {record['recipe']} ({record['size']} octets)"
            )
        for path in result.get("written", []):
            print(f"  WROTE: {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
