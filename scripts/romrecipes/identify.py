"""Which recipe rebuilds a held archive, and which pinned archives the collection lacks but can rebuild."""

from __future__ import annotations

import hashlib
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

from core.torrentzip import is_torrentzip
from romrecipes.pins import container_entries
from romrecipes.pool import AtomPool
from romrecipes.romsets import Recipe


def identify_archive(
    path: Path, recipes: dict[str, Recipe], pool: AtomPool
) -> str | None:
    """Return the recipe label that reproduces *path* byte for byte.

    Equal bytes need equal (name, crc32) members, which the archive's
    central directory gives without inflating anything: building every
    recipe at DEFLATE level 9 first took 94 s and 1 GB at pipeline step 1c.
    """
    held = _member_list(path)
    if held is None:
        return None
    original = path.read_bytes()
    md5, size = hashlib.md5(original).hexdigest(), len(original)
    for label, recipe in sorted(recipes.items()):
        if sorted((name, crc.lower()) for name, crc in recipe) != held:
            continue
        if pool.digest(recipe) == (md5, size):
            return label
    return None


def _member_list(path: Path) -> list[tuple[str, str]] | None:
    """Sorted (name, crc32) of an archive's members, from its directory."""
    try:
        with zipfile.ZipFile(path) as archive:
            return sorted(
                (info.filename, format(info.CRC, "08x"))
                for info in archive.infolist() if not info.is_dir()
            )
    except (zipfile.BadZipFile, OSError) as exc:
        print(f"  UNREADABLE: {path}: {exc}", file=sys.stderr)
        return None


def reconstruct(
    target_md5: str, recipes: dict[str, Recipe], pool: AtomPool
) -> tuple[str, bytes] | None:
    """Return the (label, bytes) whose TorrentZip build matches *target_md5*."""
    target = target_md5.lower()
    for label, recipe in sorted(recipes.items()):
        known = pool.digest(recipe)
        if known is not None and known[0] == target:
            blob = pool.build(recipe)
            if blob is not None and hashlib.md5(blob).hexdigest() == target:
                return label, blob
    return None


def platform_targets(platforms_dir: str) -> dict[str, set[str]]:
    """Container MD5s the platforms pin, per archive name."""
    targets: dict[str, set[str]] = defaultdict(set)
    for _platform, entry in container_entries(platforms_dir):
        archive = entry.get("name", "")
        if not archive.endswith(".zip"):
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
                            "no recipe reproduces this MD5: the pinned archive is "
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
