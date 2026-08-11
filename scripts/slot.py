"""One file per slot: keep the BIOS a core would actually load.

A slot is a (system, region) pair holding several interchangeable BIOS. Region
filtering narrows a pack to one territory; a system can still ship three US
PlayStation BIOS that differ only by revision, which is what leaves the choice
open in the frontend.

The winner is only ever taken from an ordered search list the core's code
actually walks, recorded as `search_rank:` on the file entry: rank 1 is tried
first, and the first file found wins. PicoDrive's biosfiles_us/eu/jp arrays are
the shape this describes.

`priority:` is deliberately not read. Its meaning is disputed: the field
reference calls it a tie-breaker where higher wins, while DuckStation's own
selection compares the numbers the other way, and its values rank PS2 images
above the plain PlayStation BIOS. Selecting on it dropped scph5501, the very
file most US setups load.

Where no ordered list is declared, the group is reported undecidable and every
candidate is kept: picking one would be the arbitrary selection this exists to
remove, and it could discard the file the core would have loaded.
"""

from __future__ import annotations

BIOS_CATEGORY = "bios"


def build_slot_index(profiles: dict) -> dict[str, dict]:
    """Map a file key to its slot metadata, keyed by path then name."""
    index: dict[str, dict] = {}
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files") or []:
            if not isinstance(f, dict):
                continue
            if f.get("category", BIOS_CATEGORY) != BIOS_CATEGORY:
                continue
            name = f.get("name", "")
            path = f.get("path") or ""
            for key in {path, name} - {""}:
                entry = index.setdefault(
                    key, {"rank": None, "emulators": []}
                )
                rank = f.get("search_rank")
                if rank is not None:
                    current = entry["rank"]
                    entry["rank"] = (
                        rank if current is None else min(current, rank)
                    )
                if emu_name not in entry["emulators"]:
                    entry["emulators"].append(emu_name)
    return index


def lookup_slot(index: dict[str, dict], destination: str, name: str) -> dict | None:
    """Look a candidate up, trying the destination then its suffixes then name."""
    if destination:
        entry = index.get(destination)
        if entry:
            return entry
        parts = destination.split("/")
        for i in range(1, len(parts)):
            entry = index.get("/".join(parts[i:]))
            if entry:
                return entry
    return index.get(name)


def resolve_slot_drops(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
) -> tuple[set[str], list[str]]:
    """Destinations to skip, and the groups no declared order can decide.

    Returns (drops, undecidable). A group is decided only when every candidate
    declares a search rank and exactly one holds the first rank; anything else
    keeps every candidate.
    """
    keep: set[str] = set()
    drop: set[str] = set()
    undecidable: list[str] = []

    for group_id, members in groups.items():
        candidates: list[tuple[str, int | None]] = []
        for destination, name in members:
            entry = lookup_slot(index, destination, name)
            if entry is None:
                keep.add(destination)
                continue
            candidates.append((destination, entry["rank"]))

        if len(candidates) < 2:
            keep.update(dest for dest, _p in candidates)
            continue

        # Every candidate must carry a rank: a set where some members are
        # unranked cannot be ordered, and dropping the unranked ones would
        # discard exactly the file the core may load.
        if any(p is None for _d, p in candidates):
            undecidable.append(group_id)
            keep.update(dest for dest, _p in candidates)
            continue

        best = min(p for _d, p in candidates)
        winners = [dest for dest, p in candidates if p == best]
        if len(winners) != 1:
            undecidable.append(group_id)
            keep.update(dest for dest, _p in candidates)
            continue

        keep.add(winners[0])
        drop.update(dest for dest, _p in candidates if dest != winners[0])

    return drop - keep, sorted(undecidable)
