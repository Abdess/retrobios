"""The checksum list of the pack files a release publishes."""

from __future__ import annotations

from pathlib import Path

from core.hashing import file_digest
from model.releaserecord import PACK_SUFFIX

SUMS = "SHA256SUMS.txt"


def published_packs(directory: Path) -> list[Path]:
    """The pack files a release uploads from a directory: whole packs and parts."""
    stem = PACK_SUFFIX.removesuffix(".zip")
    return sorted(
        path for path in Path(directory).glob(f"*{stem}*.zip") if path.is_file()
    )


def write_sums(directory: Path) -> Path | None:
    """Write SHA256SUMS.txt over the published packs, in `sha256sum` form.

    Returns its path, or None when the directory holds no pack.
    """
    lines = [
        f"{file_digest(path, 'sha256')}  {path.name}" for path in published_packs(directory)
    ]
    if not lines:
        return None
    sums = Path(directory) / SUMS
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sums
