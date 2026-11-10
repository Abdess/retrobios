"""Entries a core accepts in place of one another.

A profile writes ``group:`` on the entries of one search list. Yabause tries
saturn_bios.bin, sega_101.bin, then mpr-17933.bin and loads the first it
finds (libretro.c:1035-1049): it needs one of them and none in particular.
The requirement belongs to the set, in the profile's ``groups:`` map, and a
member's ``required`` is derived from the sets it is in: true when one of
them is required. A fallback two machine models share (pom2's apple2.rom)
then needs no value of its own. ``priority`` keeps the order the code reads
the members in.

Holding one member fills the set, so the other members are not missing. A
set nobody holds is one gap, reported under its first member with the set's
requirement, never one gap per member. A --required-only build keeps one
member of a required set, the first the code would load among those held.
Every reader goes through this module so that verify, the gap report, the
packs and the manifests agree.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Sequence
from dataclasses import dataclass

_UNRANKED = 1 << 30


def groups_of(entry: dict) -> tuple[str, ...]:
    """The sets an entry belongs to: one name, a list for a file two machine
    models both fall back on, or a map from set to the entry's rank there."""
    value = entry.get("group")
    if not value:
        return ()
    values = value if isinstance(value, (list, dict)) else [value]
    return tuple(str(v) for v in values if v)


def rank_in(entry: dict, group: str) -> int | None:
    """The rank of an entry in one of its sets: the map's value when the
    entry ranks differently in each (pom2's apple2.rom is second for the ][
    and third at boot), else its priority."""
    value = entry.get("group")
    if isinstance(value, dict) and isinstance(value.get(group), int):
        return value[group]
    priority = entry.get("priority")
    return priority if isinstance(priority, int) else None


def set_requirements(profile: dict) -> dict[str, bool]:
    """The requirement of each set the profile declares."""
    declared = profile.get("groups") or {}
    return {
        str(name): bool((spec or {}).get("required", True))
        for name, spec in declared.items()
    }


def derive_member_requirements(profile: dict) -> None:
    """Write on each member the requirement its sets give it.

    Read once when a profile is loaded, so every reader sees ``required``
    as it always has. A member is required when one of its sets is.
    """
    requirements = set_requirements(profile)
    for entry in profile.get("files") or []:
        if not isinstance(entry, dict):
            continue
        names = groups_of(entry)
        if names and "required" not in entry:
            entry["required"] = any(requirements.get(n, True) for n in names)


def required_groups(entry: dict, profile: dict) -> list[str]:
    """The required sets of its profile an entry is a member of."""
    requirements = set_requirements(profile)
    return [n for n in groups_of(entry) if requirements.get(n, True)]


def set_fields(entry: dict, profile: dict) -> dict:
    """What a --required-only build reads on a core file to keep one member
    of a set: the entry's required sets, each with its rank there."""
    sets = required_groups(entry, profile)
    if not sets:
        return {}
    return {"required_groups": {group: rank_in(entry, group) for group in sets}}


def set_keys(owner: Hashable, entry: dict) -> tuple[tuple, ...]:
    """The keys of an entry's sets, scoped to its owner (a profile, or a
    profile under one build)."""
    return tuple((owner, group) for group in groups_of(entry))


def slot_set_keys(owner: Hashable, entries: Iterable[dict]) -> tuple[tuple, ...]:
    """The sets the entries on one destination belong to. A destination has
    one outcome however many versions it lists, so its versions' sets are
    settled together."""
    keys: list[tuple] = []
    for entry in entries:
        keys.extend(k for k in set_keys(owner, entry) if k not in keys)
    return tuple(keys)


def _rank(rank: int | None, position: int) -> tuple[int, int]:
    return (rank if isinstance(rank, int) else _UNRANKED, position)


@dataclass
class Standing:
    """The member kept as the one gap of the sets nobody holds."""

    others: list[str]
    required: bool


def settle_sets(
    members: Sequence[tuple[tuple[tuple, ...], dict, bool]],
    set_required: Callable[[tuple], bool] = lambda _key: True,
) -> tuple[set[int], dict[int, Standing]]:
    """Which unheld members are excused, and which one stands for its set.

    ``members`` lists ``(set keys, entry, fills)`` in the order the profile
    declares them, where ``fills`` says the member is held (or answered by a
    declaration that reports it). Returns the positions to leave out of a
    report and, for each set no member fills, the position kept as its one
    gap with the names of the others and the set's requirement. A member
    fills or not on its own: a held one is never excused, and an unheld one
    stays reported when it stands for at least one unfilled set.
    """
    by_set: dict[tuple, list[int]] = {}
    for position, (keys, _entry, _fills) in enumerate(members):
        for key in keys:
            by_set.setdefault(key, []).append(position)

    standing: dict[int, Standing] = {}
    for key, positions in by_set.items():
        if any(members[p][2] for p in positions):
            continue
        first = min(positions, key=lambda p: _rank(rank_in(members[p][1], key[1]), p))
        held_up = standing.setdefault(first, Standing([], False))
        held_up.required = held_up.required or set_required(key)
        for p in positions:
            name = str(members[p][1].get("name", ""))
            if p != first and name not in held_up.others:
                held_up.others.append(name)

    excused = {
        position
        for position, (keys, _entry, fills) in enumerate(members)
        if keys and not fills and position not in standing
    }
    return excused, standing


def required_only_spares(
    entries: Sequence[dict],
    owner: Callable[[dict], Hashable],
    held: Callable[[dict], bool],
    gone: Callable[[dict], bool] = lambda _entry: False,
    sets: Callable[[dict], dict[str, int | None]] = lambda e: e.get("required_groups") or {},
) -> set[int]:
    """The ids of the held members a --required-only build leaves out.

    ``sets`` maps the required sets of an entry to its rank in each: a core
    file of a platform pack carries them as ``required_groups``.

    A required set needs one file: the build keeps the member the code
    would load first among those it holds and still carries (``gone`` says
    a region filter took it), by ``priority`` then declaration order, and
    drops the others. A member of an optional set is not touched here,
    nor one that another required set of its own still needs.
    """
    candidates: dict[tuple, list[tuple[tuple[int, int], int]]] = {}
    for position, entry in enumerate(entries):
        if not held(entry) or gone(entry):
            continue
        for group, rank in sets(entry).items():
            candidates.setdefault((owner(entry), group), []).append(
                (_rank(rank, position), position)
            )
    kept: set[int] = set()
    members: set[int] = set()
    for ranked in candidates.values():
        members.update(position for _rank_key, position in ranked)
        kept.add(min(ranked)[1])
    return {id(entries[p]) for p in members - kept}


def core_file_spares(
    entries: Sequence[dict], gone: Callable[[dict], bool] = lambda _entry: False,
) -> set[int]:
    """The core files of a platform pack a --required-only build leaves out.

    A set the platform declares a member of is carried by that declaration,
    so its other members are spares. Otherwise one held member per required
    set stays, as in an emulator pack. Read by the builder, the manifest
    and verify alike.
    """
    answered = {id(e) for e in entries if e.get("set_declared")}
    # An archive under the core's own folder is read before the same name
    # at the root (Kronos), so archive units rank first among equals.
    rest = sorted(
        (e for e in entries if id(e) not in answered),
        key=lambda e: not e.get("archive"),
    )
    return answered | required_only_spares(
        rest,
        owner=lambda e: e.get("source_profile") or e.get("profile") or "",
        held=lambda e: e.get("in_repo", True) is not False,
        gone=gone,
    )

