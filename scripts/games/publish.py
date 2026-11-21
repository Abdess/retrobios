"""The rendered games index compared with install/games/ on disk, and written there."""

from __future__ import annotations

from pathlib import Path

from core.artifacts import write_text_atomic


def pending(files: dict[Path, str], output: Path) -> tuple[list[Path], list[Path]]:
    """(files whose text would change, published files no longer generated)."""
    stale = sorted(p for p in output.rglob("*.json") if p not in files) if output.is_dir() else []
    changed = [p for p, t in files.items() if not p.exists() or p.read_text(encoding="utf-8") != t]
    return changed, stale


def write(files: dict[Path, str], changed: list[Path], stale: list[Path]) -> None:
    """Remove the stale files and write the changed ones."""
    for path in stale:
        path.unlink()
    for path in changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(str(path), files[path])
