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
from common import _norm_system_id, sanitize_pack_path
from packextras import _extra_system_ids, _kept, extra_region_groups


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

    @classmethod
    def build(
        cls,
        region_groups: dict[str, list[tuple[str, str]]],
        region_index: dict[str, dict],
        pack_systems: dict[str, dict],
        extras: list[dict],
        required_only: bool = False,
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
        for extra in extras:
            dest = _dest(extra)
            if not dest:
                continue
            extra_groups.setdefault(dest, set()).update(extra_region_groups(extra))
            # A profile system the platform does not have is no system the
            # pack's --system accepts: it would offer what the pack refuses.
            for sys_id in _extra_system_ids(extra):
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
