"""Where a file lands inside a pack.

Two files may not claim the same destination, and a destination may
not sit inside another file's path: a pack that cannot be extracted
on Windows is not a pack."""

from __future__ import annotations

from common import sanitize_pack_path
def _path_parents(dest: str) -> list[str]:
    """Return all parent directory segments of a path."""
    parts = dest.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]

def _has_path_conflict(dest: str, seen_files: set[str], seen_parents: set[str]) -> bool:
    """Check if dest conflicts with existing paths (file vs directory).

    Returns True if adding dest would create an impossible extraction:
    - A parent of dest is already a file (e.g., adding X/Y when X is a file)
    - dest itself is already used as a directory (e.g., adding X when X/Y exists)
    """
    for parent in _path_parents(dest):
        if parent in seen_files:
            return True
    if dest in seen_parents:
        return True
    return False

def _register_path(dest: str, seen_files: set[str], seen_parents: set[str]) -> None:
    """Track a file path and its parent directories."""
    seen_files.add(dest)
    for parent in _path_parents(dest):
        seen_parents.add(parent)

def _flat(arcname: str, prefix: str, flatten: bool) -> str:
    """Strip base_destination prefix from ZIP arcname when flattening."""
    if flatten and prefix and arcname.startswith(prefix + "/"):
        return arcname[len(prefix) + 1:]
    return arcname

def _resolve_destination(
    file_entry: dict, pack_structure: dict | None, standalone: bool
) -> str:
    """Resolve the ZIP destination path for a file entry."""
    # 1. standalone_path override
    if standalone and file_entry.get("standalone_path"):
        rel = file_entry["standalone_path"]
    # 2. path field
    elif file_entry.get("path"):
        rel = file_entry["path"]
    # 3. name fallback
    else:
        rel = file_entry.get("name", "")

    rel = sanitize_pack_path(rel)

    # Prepend pack_structure prefix
    if pack_structure:
        mode_key = "standalone" if standalone else "libretro"
        prefix = pack_structure.get(mode_key, "")
        if prefix:
            rel = f"{prefix}/{rel}"

    return rel
