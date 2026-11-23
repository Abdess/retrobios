"""Which files under bios/ belong to the collection."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

SKIP_PATTERNS = {".git", ".github", "__pycache__", ".cache", ".DS_Store", "desktop.ini"}


def should_skip(path: Path) -> bool:
    """Whether a path stays out of the collection.

    Tooling directories and hidden files do. A hidden directory inside the
    collection does not: `.variants/` holds alternate dumps, and an engine
    tree can carry one of its own (C-Dogs SDL reads `data/.wolf3d/`).
    """
    if any(part in SKIP_PATTERNS for part in path.parts):
        return True
    return path.name.startswith(".")


def collection_files(bios_dir: Path) -> Iterator[Path]:
    """Every file of the collection under *bios_dir*, in walk order.

    The database scan and the dedup both read this walk. The dedup walked
    every file and ranked a copy under `bios/.cache/` with the others: it
    could keep that copy, which no index names, and delete the indexed one.
    """
    for path in sorted(bios_dir.rglob("*")):
        if path.is_file() and not should_skip(path.relative_to(bios_dir)):
            yield path
