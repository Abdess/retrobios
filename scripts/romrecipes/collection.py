"""Where a database.json path lands on disk: under the folder that holds the BIOS tree."""

from __future__ import annotations

from pathlib import Path


def collection_root(bios_dir: Path) -> Path:
    """The folder database paths (``bios/...``) are relative to: *bios_dir*'s parent."""
    return bios_dir.resolve().parent


def on_disk(root: Path, path: str) -> Path:
    """The file a database *path* names under *root*. An absolute path stays as written."""
    return root / path
