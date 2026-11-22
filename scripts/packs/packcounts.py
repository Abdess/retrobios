"""The counts each full platform pack hands the pipeline's consistency check."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class PackCounts:
    """What a built pack holds, by the builder's own count.

    ``ok`` and ``total`` are the platform's declared files judged in the
    pack's verification mode, ``core_files`` what the pack takes from the
    cores' profiles, and ``unsafe_excluded`` the files left out because the
    frontend would reject their hash. ``trees`` names the archive members the
    build took from its data directories, which verify does not credit.
    """

    archive: str
    ok: int
    total: int
    core_files: int
    unsafe_excluded: int
    trees: tuple[str, ...]


def pack_counts(
    archive: str, file_status: dict[str, str], core_files: int, trees: list[str],
) -> PackCounts:
    """A pack's counts from the verdict of each declared file and its tree members."""
    statuses = list(file_status.values())
    return PackCounts(
        archive=archive,
        ok=statuses.count("ok"),
        total=len(statuses),
        core_files=core_files,
        unsafe_excluded=statuses.count("excluded"),
        trees=tuple(trees),
    )


def write_pack_counts(path: str, packs: list[tuple[str, list[str], PackCounts]]) -> None:
    """Each pack's printed label, registry ids and counts, as a JSON list."""
    Path(path).write_text(json.dumps(
        [{"label": label, "platforms": platforms, **asdict(counts)}
         for label, platforms, counts in packs],
        indent=1, sort_keys=True,
    ))


def read_pack_counts(path: str) -> list[dict]:
    """The packs a build recorded with write_pack_counts."""
    packs = json.loads(Path(path).read_text())
    if not isinstance(packs, list):
        raise ValueError(f"{path} is not a list of packs")
    return packs
