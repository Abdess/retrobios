"""Files whose bytes contradict the identity they are stored under.

The collection is indexed by content, so one sha1 keeps one path. A file
copied into a second system's directory under a second name therefore becomes
invisible: the index answers with whichever path was recorded, and every
consumer of that name is served bytes belonging to another machine. That is
how the Amiga Kickstart came to be served as a Saturn cartridge firmware, and
nothing in the pipeline could see it, because on paper both names resolved.

This walks the tree rather than the index, groups by content, and reports a
group whose paths sit under different manufacturers. A dump legitimately
shared by two systems of the same maker is common; one shared across makers
almost never is.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# A manufacturer directory holding files that genuinely belong to several
# machines, where a shared dump says nothing about a misfiling.
SHARED_TREES = frozenset({"Arcade", "Other"})

# One dump, two machines that really did share it. Each entry names the reason,
# so a crossing that is not on this list is a finding rather than noise.
KNOWN_SHARED = {
    "5ea7c2b824672e914525d1d5c419d71b84a426a2": "ZX Spectrum 48K ROM, which the "
    "Enterprise and the FBNeo Spectrum driver run as well",
    "16375d42ea109b47edded7a16028de7fdb3013a1": "ZX Spectrum 128K ROM, under both "
    "Sinclair spellings and the Enterprise Spectrum mode",
    "45bedc4cbdeac66c7df59e9e599195c778d86a92": "ColecoVision BIOS, carried by MSX "
    "emulators for their ColecoVision machine",
    "b2e1955d957a475de2411770452eff4ea19f4cee": "Odyssey 2 and Videopac are one "
    "machine sold under two names",
    "0d2ef6e67322f48f4b7e08d8bbe68827e2074561": "Oric Microdisc ROM, the Oric being "
    "a Tangerine machine",
    "0334b35f164089df7b2a82d46fa0ec6e43fafa90": "ZX81 overlay, the TS1500 being the "
    "same machine for Timex",
    "286b2e1fb21cc79851da01666db6c0b0e88f25e3": "one soundfont shipped by two "
    "interpreters",
    "a439fbb390da38cada95a7cbb1d6ca199cd66ef8": "Roland CM-32L control ROM, kept a "
    "second time in the DOSBox mt32-roms tree",
    "b083518fffb7f66b03c23b7eb4f868e62dc5a987": "Roland MT-32 control ROM, same",
    "289cc298ad532b702461bfc738009d9ebe8025ea": "Roland CM-32L PCM ROM, same",
    "f6b1eebc4b2d200ec6d3d21d51325d5b48c60252": "Roland MT-32 PCM ROM, same",
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
    """Group the tree by content and keep the groups that cross makers."""
    by_content: dict[str, list[Path]] = {}
    root = Path(bios_dir)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        by_content.setdefault(_sha1(path), []).append(path)

    found: list[Duplicate] = []
    for sha1, paths in by_content.items():
        if len(paths) < 2:
            continue
        if sha1 in KNOWN_SHARED:
            continue
        makers = {_manufacturer(p, root) for p in paths} - SHARED_TREES
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
        description="Report one content stored under identities that disagree.",
    )
    parser.add_argument("--bios-dir", default="bios")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--strict", action="store_true", help="exit non-zero when any is found"
    )
    args = parser.parse_args()

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
    raise SystemExit(main())
