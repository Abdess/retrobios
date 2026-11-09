"""Entries a core accepts in place of one another.

A profile writes ``group:`` on the entries of one search list. Yabause tries
saturn_bios.bin, sega_101.bin, then mpr-17933.bin and loads the first it
finds (libretro.c:1035-1049): it needs one of them and none in particular.
``required`` on a member states the set's requirement, and ``priority`` keeps
the order the code reads them in.

Holding one member fills the set, so the other members are not missing. A
set nobody holds is one gap, reported under its first member, never one gap
per member. Every reader settles sets through ``settle_sets`` so that verify,
the gap report and the packs agree on what is missing.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterable, Sequence

_UNRANKED = 1 << 30


def groups_of(entry: dict) -> tuple[str, ...]:
    """The sets an entry belongs to: one name, or a list for a file two
    machine models both fall back on."""
    value = entry.get("group")
    if not value:
        return ()
    values = value if isinstance(value, list) else [value]
    return tuple(str(v) for v in values if v)


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


def _rank(entry: dict, position: int) -> tuple[int, int]:
    priority = entry.get("priority")
    return (priority if isinstance(priority, int) else _UNRANKED, position)


def settle_sets(
    members: Sequence[tuple[tuple[tuple, ...], dict, bool]],
) -> tuple[set[int], dict[int, list[str]]]:
    """Which unheld members are excused, and which one stands for its set.

    ``members`` lists ``(set keys, entry, fills)`` in the order the profile
    declares them, where ``fills`` says the member is held (or answered by a
    declaration that reports it). Returns the positions to leave out of a
    report and, for each set no member fills, the position kept as its one
    gap with the names of the others. A member fills or not on its own: a
    held one is never excused, and an unheld one stays reported when it
    stands for at least one unfilled set.
    """
    by_set: dict[tuple, list[int]] = {}
    for position, (keys, _entry, _fills) in enumerate(members):
        for key in keys:
            by_set.setdefault(key, []).append(position)

    standing: dict[int, list[str]] = {}
    for positions in by_set.values():
        if any(members[p][2] for p in positions):
            continue
        first = min(positions, key=lambda p: _rank(members[p][1], p))
        names = standing.setdefault(first, [])
        for p in positions:
            name = str(members[p][1].get("name", ""))
            if p != first and name not in names:
                names.append(name)

    excused = {
        position
        for position, (keys, _entry, fills) in enumerate(members)
        if keys and not fills and position not in standing
    }
    return excused, standing
