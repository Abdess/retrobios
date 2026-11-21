"""What a run writes on the drive of its BIOS folder, and the free space it is held against."""
from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path

from installer.datadirs import data_space_bytes
from installer.host_fs import _nearest_folder


def bytes_written(files: Iterable[dict],
                  data_states: list[tuple[dict, tuple[Path, dict[str, dict], int]]]) -> int:
    """The files a run puts in place, missing or replaced, and the data
    trees it rebuilds beside them (data_space_bytes). The line plan, the
    screen's plan and the run's refusal hold this one number against the
    free space: the plans counted the files absent alone, and a run they
    said nothing of stopped for space right after Enter."""
    return sum(entry.get("size", 0) for entry in files) + data_space_bytes(data_states)


def free_space(bios_path: Path) -> int | None:
    """The bytes free on the drive that holds bios_path, read at its nearest
    existing folder since it may not exist yet. None when it cannot be told."""
    try:
        return shutil.disk_usage(_nearest_folder(bios_path)).free
    except OSError:
        return None
