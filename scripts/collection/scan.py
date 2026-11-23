"""The walk of bios/: each collection file's digests, and which copy of a content is primary."""

from __future__ import annotations

import sys
from pathlib import Path

from core.collectionfiles import collection_files
from core.hashing import compute_hashes
from resolve.localfile import variant_base_name

# Every digest database.json publishes per file, in the order compute_hashes
# returns them. The schema requires all five, so a cache entry missing any of
# them cannot serve a database entry, and the order is fixed here so a warm
# cache serialises an entry exactly like a fresh hash does.
CACHED_HASHES = ("sha1", "md5", "sha256", "crc32", "adler32")


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


def primary_rank(path: Path, bios_dir: Path) -> tuple:
    """Rank of one copy of a content, the lowest being its path in the index.

    A .variants/ copy yields to any other one. A copy in an emulator's own
    tree, bios/Other/<emulator>/, yields to one filed under its machine:
    ZEsarUX's sms.rom sorted before bios/Sega/Master System/, the resolver
    set it aside as another emulator's file, and Genesis Plus GX got a
    variant instead of v1.3. Equal copies follow the walk's order. The scan
    and the dedup both read this rank, so the copy the dedup keeps is the
    one the index names.
    """
    parts = path.relative_to(bios_dir).parts
    return (".variants" in parts, len(parts) > 2 and parts[0] == "Other", parts)


def _add_scanned(
    files: dict[str, dict],
    aliases: dict[str, list[dict]],
    filepath: Path,
    rel_path: str,
    size: int,
    hashes: dict,
    root: Path,
) -> None:
    """Record a scanned file as its content's primary, or as an alias of it."""
    sha1 = hashes["sha1"]
    entry = {
        "path": rel_path,
        "name": _canonical_name(filepath),
        "size": size,
        **hashes,
    }
    if sha1 not in files:
        files[sha1] = entry
    elif primary_rank(Path(rel_path), root) < primary_rank(Path(files[sha1]["path"]), root):
        aliases.setdefault(sha1, []).append(
            {"name": files[sha1]["name"], "path": files[sha1]["path"]}
        )
        files[sha1] = entry
    else:
        aliases.setdefault(sha1, []).append({"name": entry["name"], "path": rel_path})


def _cached_hashes(cached: dict | None, mtime: float, size: int) -> dict | None:
    """The cache's digests of a file that has not changed since."""
    if cached is None:
        return None
    fresh = cached.get("mtime") == mtime and cached.get("size") == size
    # Rebuilding the hash dict by hand dropped whichever digest the
    # list forgot, and the entry was then written back to the cache
    # without it, so the loss survived every later run. Requiring the
    # full set instead turns a partial cache entry into a miss, which
    # heals it.
    if fresh and all(name in cached for name in CACHED_HASHES):
        return {name: cached[name] for name in CACHED_HASHES}
    return None


def scan_bios_dir(bios_dir: Path, cache: dict, force: bool) -> tuple[dict, dict, dict]:
    """Scan bios directory and compute hashes, using cache when possible."""
    files: dict[str, dict] = {}
    aliases: dict[str, list[dict]] = {}
    new_cache = {}
    root = Path(bios_dir.name)

    for filepath in collection_files(bios_dir):
        rel_path = str(filepath.relative_to(bios_dir.parent))
        stat = filepath.stat()
        mtime = stat.st_mtime
        size = stat.st_size
        cache_key = rel_path

        hashes = None if force else _cached_hashes(cache.get(cache_key), mtime, size)
        if hashes is None:
            hashes = _settled_hashes(filepath, cache.get(cache_key), mtime, size)
        _add_scanned(files, aliases, filepath, rel_path, size, hashes, root)
        new_cache[cache_key] = {**hashes, "mtime": mtime, "size": size}

    return files, aliases, new_cache
