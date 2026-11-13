"""Files whose bytes contradict the identity they are stored under.

The collection is indexed by content, so one sha1 keeps one path. A file
copied into a second system's directory under a second name therefore becomes
invisible: the index answers with whichever path was recorded, and every
consumer of that name is served bytes belonging to another machine. That is
how the Amiga Kickstart came to be served as a Saturn cartridge firmware, and
nothing in the pipeline could see it, because on paper both names resolved.

This walks the tree rather than the index, groups by content, and reports a
group whose paths sit under different manufacturers. A dump legitimately
shared by two systems of the same maker is common, one shared across makers
almost never is.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# A manufacturer directory holding files that genuinely belong to several
# machines, where a shared dump says nothing about a misfiling.
SHARED_TREES = frozenset({"Arcade", "Other"})

# One dump, two machines that really did share it. Each entry names the makers
# whose directories may hold it and the reason they do, so a crossing that is
# not on this list, or a further copy under a third maker, is a finding rather
# than noise.
KNOWN_SHARED: dict[str, tuple[frozenset[str], str]] = {
    "45bedc4cbdeac66c7df59e9e599195c778d86a92": (
        frozenset({"Coleco", "Microsoft"}),
        "ColecoVision BIOS, carried by MSX emulators for their ColecoVision "
        "machine",
    ),
    "286b2e1fb21cc79851da01666db6c0b0e88f25e3": (
        frozenset({"Infocom", "ZC"}),
        "one soundfont shipped by two interpreters",
    ),
}

CHUNK = 1 << 20


@dataclass
class Duplicate:
    """One content, stored under paths that disagree about what it is."""

    sha1: str
    size: int
    paths: list[str]
    manufacturers: list[str]

    @property
    def names(self) -> list[str]:
        return sorted({Path(p).name for p in self.paths})


def _manufacturer(path: Path, root: Path) -> str:
    """The vendor directory a path sits under, relative to the scanned root."""
    parts = path.relative_to(root).parts
    return parts[0] if len(parts) > 1 else ""


def _sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(bios_dir: str = "bios") -> list[Duplicate]:
    """Group the tree by content and keep the groups that cross makers.

    Only files that share a size can share a content, so a size held by one
    file is never read: hashing the whole tree read 18 GB on every pipeline.
    """
    by_size: dict[int, list[Path]] = {}
    root = Path(bios_dir)
    for path in sorted(root.rglob("*")):
        if path.is_file():
            by_size.setdefault(path.stat().st_size, []).append(path)
    by_content: dict[str, list[Path]] = {}
    for paths in by_size.values():
        if len(paths) < 2:
            continue
        for path in paths:
            by_content.setdefault(_sha1(path), []).append(path)

    found: list[Duplicate] = []
    for sha1, paths in by_content.items():
        if len(paths) < 2:
            continue
        makers = {_manufacturer(p, root) for p in paths} - SHARED_TREES
        if sha1 in KNOWN_SHARED and makers <= KNOWN_SHARED[sha1][0]:
            continue
        names = {p.name for p in paths}
        if len(makers) > 1 and len(names) > 1:
            found.append(
                Duplicate(
                    sha1=sha1,
                    size=paths[0].stat().st_size,
                    paths=[str(p) for p in paths],
                    manufacturers=sorted(makers),
                )
            )
    return sorted(found, key=lambda d: d.paths[0])


def format_duplicate(duplicate: Duplicate) -> str:
    """One line naming the content and every identity it answers to."""
    return (
        f"{duplicate.sha1[:12]} ({duplicate.size} bytes) is stored as "
        + " and as ".join(duplicate.paths)
    )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Report one content stored under identities that disagree.",
    )
    parser.add_argument(
        "--bios-dir", default="bios",
        help="BIOS collection directory (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--strict", action="store_true", help="exit non-zero when any is found"
    )
    args = parser.parse_args()
    from common import work_from_repo_root  # noqa: PLC0415

    work_from_repo_root(args, parser, ["bios_dir"])
    from common import require_directory  # noqa: PLC0415

    require_directory(args.bios_dir)

    duplicates = scan(args.bios_dir)
    if args.json:
        import json

        print(
            json.dumps(
                [
                    {
                        "sha1": d.sha1,
                        "size": d.size,
                        "paths": d.paths,
                        "manufacturers": d.manufacturers,
                    }
                    for d in duplicates
                ],
                indent=2,
            )
        )
    else:
        for duplicate in duplicates:
            print(f"  {format_duplicate(duplicate)}")
        print(f"\n{len(duplicates)} contents stored under contradicting identities.")

    return 1 if (duplicates and args.strict) else 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
