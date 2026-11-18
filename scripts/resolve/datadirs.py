"""Finding a declared file inside the cached data directories."""

from __future__ import annotations

import filecmp
import os
from collections.abc import Callable

from resolve.content import adler32_fits, content_fits, name_match_size_ok


def _resolve_in_data_dirs(
    names_to_try: list[str],
    data_dir_registry: dict,
    verdict: Callable[[str], str],
) -> tuple[tuple[str, str] | None, str | None]:
    """Look for one of these names in the cached data directories.

    Returns the first candidate whose content satisfies the entry, and
    separately the first that answered to the name but contradicted it: a
    name match alone never decides, so the caller reports the contradiction
    rather than shipping the file.
    """
    mismatch: str | None = None
    for dd_entry in data_dir_registry.values():
        cache_dir = dd_entry.get("local_cache", "")
        if not cache_dir or not os.path.isdir(cache_dir):
            continue
        for try_name in names_to_try:
            candidate = os.path.join(cache_dir, try_name)
            if os.path.isfile(candidate):
                status = verdict(candidate)
                if status != "hash_mismatch":
                    return (candidate, status), mismatch
                mismatch = mismatch or candidate
        # The declared path may not be where the cache put it, so the tree
        # is searched for the bare filename, case-insensitively, in the order
        # a walk meets it.
        basename_targets = {
            (n.rsplit("/", 1)[-1] if "/" in n else n).casefold()
            for n in names_to_try
        }
        index = _data_dir_basenames(cache_dir)
        found = sorted(
            (order, path)
            for target in basename_targets
            for order, path in index.get(target, ())
        )
        for _order, candidate in found:
            status = verdict(candidate)
            if status != "hash_mismatch":
                return (candidate, status), mismatch
            mismatch = mismatch or candidate
    return None, mismatch


def _data_dir_tail(
    dest_hint: str, data_dir_registry: dict, file_entry: dict, db: dict
) -> str | None:
    """The cached data-directory file at the destination's own tail.

    The full destination first, then without its leading segment, never
    down to the bare name. A shortened tail two caches hold with different
    bytes proves nothing. The size and Adler-32 the code checks still bound
    the file, as on every name or path step without a hash.
    """
    parts = dest_hint.split("/")
    for start in range(min(2, len(parts) - 1)):
        tail = "/".join(parts[start:])
        hits = [
            os.path.join(cache_dir, tail)
            for cache_dir in (
                dd_entry.get("local_cache", "") for dd_entry in data_dir_registry.values()
            )
            if cache_dir and os.path.isfile(os.path.join(cache_dir, tail))
        ]
        if start and any(
            not filecmp.cmp(hits[0], other, shallow=False) for other in hits[1:]
        ):
            continue
        for candidate in hits:
            if name_match_size_ok(
                file_entry, os.path.getsize(candidate)
            ) and adler32_fits(file_entry, candidate, db) and content_fits(
                file_entry, candidate
            ):
                return candidate
    return None


# Basename index per data-directory cache. Walking the whole tree again for
# every unresolved name made resolution O(names x tree) on each pack build.
_data_dir_index: dict[str, dict[str, list[tuple[int, str]]]] = {}


def _data_dir_basenames(cache_dir: str) -> dict[str, list[tuple[int, str]]]:
    """Casefolded basename -> (walk order, path) of every file in a cache.

    Keyed by the tree's identity as well as its path: a refresh swaps in a
    new directory under the same name, and an index of the old one named
    files that were gone.
    """
    try:
        stat = os.stat(cache_dir)
    except OSError:
        return {}
    key = f"{os.path.realpath(cache_dir)}:{stat.st_dev}:{stat.st_ino}"
    if key not in _data_dir_index:
        index: dict[str, list[tuple[int, str]]] = {}
        order = 0
        for root, _dirs, fnames in os.walk(cache_dir):
            for fname in fnames:
                index.setdefault(fname.casefold(), []).append((order, os.path.join(root, fname)))
                order += 1
        _data_dir_index[key] = index
    return _data_dir_index[key]


def forget_data_dir_index() -> None:
    """Drop the basename indexes, after a data directory was refreshed."""
    _data_dir_index.clear()
