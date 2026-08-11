"""One file per slot: keep the BIOS a core would actually load.

A slot is a (system, region) pair holding several interchangeable BIOS. Region
filtering narrows a pack to one territory; a system can still ship three US
PlayStation BIOS that differ only by revision, which is what leaves the choice
open in the frontend.

The winner is only ever taken from the preference order the core's own code
applies, recorded as `priority:` on the file entry, lowest first. DuckStation
keeps the image whose priority is lower (bios.cpp, FindBIOSImageInDirectory)
and its table de-prioritizes by raising the number: the buggy launch console
sits at 50 and PS2 images at 100, while scph5501 sits at 5. A core that walks
an ordered search list, as PicoDrive does with biosfiles_us/eu/jp, maps onto
the same field as 1, 2, 3.

Every candidate of a group must carry one. A set where some members are
unranked cannot be ordered, and dropping the unranked ones would discard
exactly the file the core may load. Where the order is not declared the group
is reported undecidable and every candidate is kept: picking one would be the
arbitrary selection this exists to remove.

The scale is only meaningful inside one system's candidate set. Profiles that
cover the same system must rank on the same scale.
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
                    key, {"rank": None, "regions": set(), "emulators": []}
                )
                entry["regions"] |= {str(r) for r in (f.get("region") or [])}
                rank = f.get("priority")
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
    declares a priority and exactly one holds the lowest; anything else keeps
    every candidate.
    """
    keep: set[str] = set()
    drop: set[str] = set()
    undecidable: list[str] = []

    # A slot is a system AND a declared region: the Japanese and American
    # PlayStation BIOS are not alternatives to each other, and comparing their
    # ranks across regions would pick one territory's file for another's.
    tiers: dict[tuple[str, tuple[str, ...]], list[tuple[str, int | None]]] = {}
    for group_id, members in groups.items():
        for destination, name in members:
            entry = lookup_slot(index, destination, name)
            if entry is None:
                keep.add(destination)
                continue
            tier = tuple(sorted(entry["regions"]))
            tiers.setdefault((group_id, tier), []).append(
                (destination, entry["rank"])
            )

    for (group_id, tier), candidates in tiers.items():
        if len(candidates) < 2:
            keep.update(dest for dest, _p in candidates)
            continue

        # Every candidate must carry a rank: a set where some members are
        # unranked cannot be ordered, and dropping the unranked ones would
        # discard exactly the file the core may load.
        if any(p is None for _d, p in candidates):
            undecidable.append(f"{group_id}|{','.join(tier)}" if tier else group_id)
            keep.update(dest for dest, _p in candidates)
            continue

        best = min(p for _d, p in candidates)
        winners = [dest for dest, p in candidates if p == best]
        if len(winners) != 1:
            undecidable.append(f"{group_id}|{','.join(tier)}" if tier else group_id)
            keep.update(dest for dest, _p in candidates)
            continue

        keep.add(winners[0])
        drop.update(dest for dest, _p in candidates if dest != winners[0])

    return drop - keep, sorted(undecidable)
