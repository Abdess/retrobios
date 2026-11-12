"""One file per slot: keep the BIOS a core would actually load.

A slot is a (system, region) pair holding several interchangeable BIOS. Region
filtering narrows a pack to one territory, but a system can still ship three US
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

The scale is only meaningful inside one emulator's candidate set. When two
profiles rank the same file differently (pcsx1 walks scph1001 first while
DuckStation prefers scph5501), the pack serves both cores, so neither order
may win: the file is marked conflicting and its group stays undecidable.
The same holds when one profile ranks a file and another declares it with no
rank: the second core reads it by its own rule, which no rank expresses.
"""

from __future__ import annotations

from alternatives import set_keys

BIOS_CATEGORY = "bios"


def platform_slot_index(
    config: dict, profiles: dict, target_cores: set[str] | None = None
) -> dict[str, dict]:
    """The slot index of the emulators a platform runs, nothing else.

    Built over every profile, DuckStation, ePSXe and Rustation ranked the
    PlayStation BIOS of RomM, whose cores rank none of them, and
    `--one-per-slot` dropped four images RomM declares.
    """
    return {
        key: merge_claims(by_emu)
        for key, by_emu in platform_slot_claims(config, profiles, target_cores).items()
    }


def platform_slot_claims(
    config: dict, profiles: dict, target_cores: set[str] | None = None
) -> dict[str, dict[str, dict]]:
    """What each emulator a platform runs declares at each key, unmerged."""
    from common import resolve_platform_cores  # noqa: PLC0415

    cores = resolve_platform_cores(config, profiles, target_cores=target_cores)
    return slot_claims({n: profiles[n] for n in cores if n in profiles})


def slot_claims(profiles: dict) -> dict[str, dict[str, dict]]:
    """Per key (path, standalone path, name), what each emulator declares there.

    Each claim holds the ranks the emulator gives the key in declaration
    order, None for an entry without one, the regions, and the set keys.
    The install manifest carries these unmerged, so the installer merges
    them over the cores a board runs as build_slot_index merges them here.
    """
    claims: dict[str, dict[str, dict]] = {}
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
            # Keyed by the standalone layout too, as build_region_index is.
            for key in {path, f.get("standalone_path") or "", name} - {""}:
                claim = claims.setdefault(key, {}).setdefault(
                    emu_name, {"ranks": [], "regions": set(), "sets": set()}
                )
                claim["regions"] |= {str(r) for r in (f.get("region") or [])}
                claim["sets"] |= set(set_keys(emu_name, f))
                claim["ranks"].append(f.get("priority"))
    return claims


def merge_claims(by_emulator: dict[str, dict]) -> dict:
    """One key's slot metadata, merged over the emulators claiming it.

    Two ranks that differ make the key conflicting. So does an emulator
    that declares the key without a rank beside one that ranks it: a core
    that declares the file without a rank loads it by a rule of its own.
    Genesis Plus GX opens bios_CD_U.bin by name for a US disc, and
    PicoDrive's rank 4 for it would let its rank-3 file replace it.
    """
    ranks = {r for claim in by_emulator.values() for r in claim["ranks"] if r is not None}
    ranked_by = {e for e, claim in by_emulator.items()
                 if any(r is not None for r in claim["ranks"])}
    unranked_by = {e for e, claim in by_emulator.items() if None in claim["ranks"]}
    return {
        "rank": min(ranks) if ranks else None,
        "conflict": len(ranks) > 1 or bool(ranked_by and unranked_by - ranked_by),
        "regions": {r for claim in by_emulator.values() for r in claim["regions"]},
        "emulators": sorted(by_emulator),
        "sets": {k for claim in by_emulator.values() for k in claim["sets"]},
    }


def build_slot_index(profiles: dict) -> dict[str, dict]:
    """Map a file key to its slot metadata, keyed by path then name."""
    return {key: merge_claims(by_emu) for key, by_emu in slot_claims(profiles).items()}


def slot_lookup_keys(destination: str, name: str) -> list[str]:
    """The keys lookup_slot tries, in its order."""
    keys: list[str] = []
    if destination:
        parts = destination.split("/")
        keys += ["/".join(parts[i:]) for i in range(len(parts))]
    return [*keys, name]


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
    held: set[str] | None = None,
) -> tuple[set[str], list[str]]:
    """Destinations to skip, and the groups no declared order can decide.

    Returns (drops, undecidable). A group is decided only when every candidate
    declares a priority and exactly one holds the lowest. Anything else keeps
    every candidate. ``held`` names the destinations the collection holds: a
    candidate it lacks ships nothing, so it neither wins nor displaces one.
    """
    keep: set[str] = set()
    drop: set[str] = set()
    undecidable: list[str] = []

    # A slot is a system AND a declared region: the Japanese and American
    # PlayStation BIOS are not alternatives to each other, and comparing their
    # ranks across regions would pick one territory's file for another's.
    bucketed: dict[tuple[str, tuple[str, ...]], list[tuple[str, int | None, frozenset]]] = {}
    for group_id, members in groups.items():
        for destination, name in members:
            if held is not None and destination not in held:
                continue
            entry = lookup_slot(index, destination, name)
            if entry is None:
                keep.add(destination)
                continue
            tier = tuple(sorted(entry["regions"]))
            rank = None if entry.get("conflict") else entry["rank"]
            bucketed.setdefault((group_id, tier), []).append(
                (destination, rank, frozenset(entry.get("sets") or ()))
            )
    # A rank orders the members of one set: px68k-sdl ranks its IPL and its
    # font ROM lists each from 1, and the two never compete. Candidates are
    # compared when they share a set, and those in no set among themselves.
    tiers: dict[tuple[str, tuple[str, ...], int], list[tuple[str, int | None]]] = {}
    for (group_id, tier), found in bucketed.items():
        for part, component in enumerate(_by_shared_set(found)):
            tiers[(group_id, tier, part)] = component

    for (group_id, tier, _part), candidates in tiers.items():
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


def _by_shared_set(
    found: list[tuple[str, int | None, frozenset]],
) -> list[list[tuple[str, int | None]]]:
    """The candidates of one tier split where no set links them."""
    parent = list(range(len(found)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first_of: dict[object, int] = {}
    for i, (_dest, _rank, sets) in enumerate(found):
        for key in sets or {None}:
            if key in first_of:
                parent[root(i)] = root(first_of[key])
            else:
                first_of[key] = i
    parts: dict[int, list[tuple[str, int | None]]] = {}
    for i, (dest, rank, _sets) in enumerate(found):
        parts.setdefault(root(i), []).append((dest, rank))
    return list(parts.values())
