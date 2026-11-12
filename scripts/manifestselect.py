"""What an install manifest records about each file so the installer can narrow it.

The installer runs without the profiles or the database, yet a narrowed
install must hold the same files as a pack built with the same narrowing.
Each entry therefore carries the platform systems it belongs to and, when
the code selects it by territory, its regions and the groups in which it
competes. The installer replays region.resolve_region_drops over them.

The pack's `--system X` keeps the platform's declarations under X and every
core extra owned by X, then groups regions over the declarations it kept and
over every core extra of the platform. A group membership is therefore either
unconditional (a core extra) or present only when the declaring system is
kept (a platform declaration), and the manifest records the two apart.
"""

from __future__ import annotations

from dataclasses import dataclass

import region as region_mod
import slot as slot_mod
from common import _norm_system_id, sanitize_pack_path
from packextras import (
    _kept,
    _serving_system_ids,
    extra_region_groups,
    extra_region_key,
    system_spellings,
)


def _dest(entry: dict) -> str:
    return sanitize_pack_path(entry.get("destination", entry.get("name", "")))


@dataclass(frozen=True)
class SelectionIndex:
    """System and region facts for one platform, as the pack builder reads them."""

    region_index: dict[str, dict]
    competing: frozenset[str]
    systems_by_dest: dict[str, frozenset[str]]
    declared_by: dict[str, frozenset[str]]
    extra_groups: dict[str, frozenset[str]]
    slots: dict[str, dict]

    @classmethod
    def build(
        cls,
        region_groups: dict[str, list[tuple[str, str]]],
        region_index: dict[str, dict],
        pack_systems: dict[str, dict],
        extras: list[dict],
        required_only: bool = False,
        extras_prefix: str = "",
        slot_claims: dict[str, dict[str, dict]] | None = None,
    ) -> SelectionIndex:
        by_norm: dict[str, set[str]] = {}
        for sys_id in pack_systems:
            by_norm.setdefault(_norm_system_id(sys_id), set()).add(sys_id)

        declared_by: dict[str, set[str]] = {}
        for sys_id, system in pack_systems.items():
            for file_entry in _kept(system.get("files", []), required_only):
                dest = _dest(file_entry)
                if dest:
                    declared_by.setdefault(dest, set()).add(sys_id)

        owned_by: dict[str, set[str]] = {}
        extra_groups: dict[str, set[str]] = {}
        spellings = system_spellings(pack_systems)
        for extra in extras:
            # Keyed as platform_region_groups keys it (extra_region_key).
            dest = extra_region_key(extra, extras_prefix)
            if not dest:
                continue
            extra_groups.setdefault(dest, set()).update(
                extra_region_groups(extra, spellings)
            )
            # A profile system the platform does not have is no system the
            # pack's --system accepts: it would offer what the pack refuses.
            for sys_id in _serving_system_ids(extra):
                owned_by.setdefault(dest, set()).update(
                    by_norm.get(_norm_system_id(sys_id), ())
                )

        systems_by_dest = {
            dest: frozenset(declared_by.get(dest, set()) | owned_by.get(dest, set()))
            for dest in set(declared_by) | set(owned_by)
        }
        return cls(
            region_index,
            frozenset(
                dest for members in region_groups.values() for dest, _name in members
            ),
            systems_by_dest,
            {dest: frozenset(ids) for dest, ids in declared_by.items()},
            {dest: frozenset(ids) for dest, ids in extra_groups.items()},
            _slot_fields(region_groups, slot_claims or {}),
        )

    def fields(self, dest: str, name: str) -> dict:
        """What an entry carries for the installer's selection.

        `systems` drives --system. A regional entry adds its regions,
        `region_groups` it always competes in as a core extra, and
        `region_system_groups` it competes in only when that platform system
        is kept, and `priority` the rank the code searches it at. An entry that never competes carries no region field: an
        untagged file always survives a region filter.
        """
        out: dict = {}
        systems = self.systems_by_dest.get(dest)
        if systems:
            out["systems"] = sorted(systems)
        if dest not in self.competing:
            return out
        if dest in self.slots:
            out["slot"] = self.slots[dest]
        regions = region_mod.lookup_regions(self.region_index, dest, name)
        if not regions:
            return out
        out["regions"] = sorted(regions)
        always = self.extra_groups.get(dest)
        if always:
            out["region_groups"] = sorted(always)
        declared = self.declared_by.get(dest)
        if declared:
            out["region_system_groups"] = sorted(declared)
        # The code's search rank decides whether a world file may withdraw
        # this one when no region matches.
        priority = region_mod.lookup_priority(self.region_index, dest, name)
        if priority is not None:
            out["priority"] = priority
        return out


def _slot_fields(
    region_groups: dict[str, list[tuple[str, str]]],
    claims: dict[str, dict[str, dict]],
) -> dict[str, dict]:
    """Per destination, the groups it competes in for a slot and the claims
    at each key slot.lookup_slot would try.

    Only a group where some emulator ranks a member can drop a file, so
    only its members are written, each with all its groups. A key whose
    claims equal the previous one's answers the same and is left out. A
    destination no emulator claims is never dropped, and carries nothing.
    """
    names: dict[str, list[str]] = {}
    for members in region_groups.values():
        for dest, name in members:
            if name not in names.setdefault(dest, []):
                names[dest].append(name)
    keyed: dict[str, list[str]] = {}
    for dest, found in names.items():
        keys: list[str] = []
        for name in found:
            keys += [k for k in slot_mod.slot_lookup_keys(dest, name)
                     if k in claims and k not in keys]
        if keys:
            keyed[dest] = keys

    def ranked(dest: str) -> bool:
        return any(rank is not None for key in keyed.get(dest, ())
                   for claim in claims[key].values() for rank in claim["ranks"])

    # Each time a group lists the destination: two cores filing one file in
    # a group make two candidates of one rank, which no order separates.
    groups: dict[str, list[str]] = {}
    for group_id, members in region_groups.items():
        for dest, _name in members:
            groups.setdefault(dest, []).append(group_id)
    # Every group of such a destination: one where it stays keeps it.
    written: set[str] = set()
    for members in region_groups.values():
        if any(ranked(member) for member, _name in members):
            written.update(member for member, _name in members if member in keyed)
    fields: dict[str, dict] = {}
    for dest in sorted(written):
        kept: list[dict] = []
        for key in keyed[dest]:
            by_emulator = {
                emulator: {
                    "ranks": claim["ranks"],
                    **({"regions": sorted(claim["regions"])} if claim["regions"] else {}),
                    **({"sets": sorted(g for _owner, g in claim["sets"])}
                       if claim["sets"] else {}),
                }
                for emulator, claim in sorted(claims[key].items())
            }
            if not kept or kept[-1] != by_emulator:
                kept.append(by_emulator)
        fields[dest] = {"groups": sorted(groups[dest]), "keys": kept}
    return fields
