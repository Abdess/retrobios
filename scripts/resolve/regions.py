"""Region-ordered selection of the files a platform's cores declare."""

from __future__ import annotations

from model.profiles import lists_files
from model.region import WORLD, normalize_declared, rank
from resolve.slot import lookup_slot


def platform_region_index(
    config: dict, profiles: dict, target_cores: set[str] | None = None
) -> dict[str, dict]:
    """The region index of the emulators a platform runs, nothing else.

    Built over every profile, an emulator foreign to the platform voided the
    filter: Pizza Boy SC, an Android app, declares bios_CD_E.bin without a
    region, so the Genesis Plus GX and PicoDrive tags never counted and
    `--region us` kept both CD BIOSes in the RetroArch pack.
    """
    from resolve.cores import resolve_platform_cores

    cores = resolve_platform_cores(config, profiles, target_cores=target_cores)
    return build_region_index({n: profiles[n] for n in cores if n in profiles})


def build_region_index(profiles: dict) -> dict[str, dict]:
    """Build a region lookup from emulator profiles.

    Keyed by the entry's path when present, by name otherwise.  Untagged
    declarations are recorded as ambiguity evidence: if the same lookup key is
    both tagged and untagged, filtering keeps it instead of inventing a region.
    """
    index: dict[str, dict] = {}
    for emu_name, profile in sorted(profiles.items()):
        if not lists_files(profile):
            continue
        for f in profile.get("files") or []:
            if not isinstance(f, dict):
                continue
            try:
                regions = normalize_declared(f.get("region"))
            except ValueError as exc:
                raise ValueError(
                    f"{emu_name}: {f.get('name', '?')}: {exc}"
                ) from exc
            name = f.get("name", "")
            path = f.get("path") or ""
            # Path-keyed so same-named entries stay separate (Dolphin declares
            # three IPL.bin), name-keyed so a candidate identified by name alone
            # sees the union and is never dropped on ambiguity. The standalone
            # layout is a path of its own: GC/EUR/IPL.bin fell through to the
            # bare name and its five-region union, and was never reduced.
            # An alias is another name the core reads for the same file:
            # scph5552.bin, the name beetle_psx also opens for its European
            # BIOS, stayed in a --region jp pack once scph5502.bin went.
            aliases = {str(a) for a in f.get("aliases") or []}
            priority = f.get("priority")
            for key in {path, f.get("standalone_path") or "", name, *aliases} - {""}:
                entry = index.setdefault(
                    key,
                    {"regions": set(), "has_untagged": False, "emulators": [],
                     "priorities": set()},
                )
                entry["regions"] |= regions
                entry["priorities"].add(priority if isinstance(priority, int) else None)
                if not regions:
                    entry["has_untagged"] = True
                if emu_name not in entry["emulators"]:
                    entry["emulators"].append(emu_name)
    return index


def lookup_regions(index: dict[str, dict], destination: str, name: str) -> set[str]:
    """Look a candidate file up in the region index.

    Tried in lookup_slot's order: the full destination, then progressively
    shorter path suffixes, then the bare name. Suffix matching bridges a
    platform entry whose destination carries an extra prefix to the profile
    entry that declares the region.
    """
    entry = lookup_slot(index, destination, name)
    if not entry or entry.get("has_untagged"):
        return set()
    return set(entry["regions"])


def lookup_priority(index: dict[str, dict], destination: str, name: str) -> int | None:
    """The search rank the code gives a candidate, lower first.

    None when no entry declares one, or when two declarations disagree: a
    rank in doubt cannot decide what to drop.
    """
    entry = lookup_slot(index, destination, name)
    priorities = (entry or {}).get("priorities", set())
    if len(priorities) != 1:
        return None
    return next(iter(priorities))


def _competing_ranks(
    members: list[tuple[str, str]],
    index: dict[str, dict],
    requested: list[str],
) -> list[tuple[int, str]]:
    """Rank the members of a group that compete regionally.

    Files with no declared region, and files declared world, are excluded: they
    never compete and never drop.
    """
    ranked: list[tuple[int, str]] = []
    for destination, name in members:
        regions = lookup_regions(index, destination, name)
        if not regions or WORLD in regions:
            continue
        ranked.append((rank(regions, requested), destination))
    return ranked


# Marks the group of a file no system names (extra_region_groups and the
# emulator-mode grouping both build it).
FILE_GROUP = ":file:"


def resolve_region_drops(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
    requested: list[str],
    held: set[str] | None = None,
) -> set[str]:
    """Destinations to skip for a requested region priority list.

    Per group, an exact/parent regional match beats other regional candidates.
    A world candidate beats unmatched regional fallbacks the code does not
    search before it, while untagged files always survive.  If neither a requested nor a world candidate exists, all
    regional candidates survive so filtering can never empty a group.

    ``held`` names the destinations the collection holds. A match it lacks
    never displaces a held file: the American BIOS stays in a Japanese pack
    when the Japanese one is missing, and the missing one stays reported.
    """
    if not requested:
        return set()

    keep: set[str] = set()
    drop: set[str] = set()
    for group_id, members in groups.items():
        if FILE_GROUP in group_id:
            # A file no system names competes with nothing: it drops nothing,
            # and keeping it would veto the group that does decide for the
            # same path. Dolphin's GC/EUR/IPL.bin, alone as a core extra,
            # kept what the GameCube group dropped for --region us. A system
            # holding one file still keeps it: a group is never emptied.
            continue
        regional: list[tuple[int, str]] = []
        world: set[str] = set()
        untagged: set[str] = set()
        for destination, name in members:
            regions = lookup_regions(index, destination, name)
            if not regions:
                untagged.add(destination)
            elif WORLD in regions:
                world.add(destination)
            else:
                regional.append((rank(regions, requested), destination))

        keep |= untagged | world
        if not regional:
            continue
        matched = [(r, destination) for r, destination in regional if r < len(requested)]
        winners, rivals = matched, world
        if held is not None:
            # A missing file answers the request but takes no held file's
            # place: only held files decide what gives way.
            winners = [(r, d) for r, d in matched if d in held]
            rivals = world & held
        if winners:
            best = min(r for r, _destination in winners)
            keep |= {
                destination for r, destination in matched
                if r == best or (r < best and destination not in (held or ()))
            }
            drop |= {destination for _r, destination in regional if destination not in keep}
        elif rivals:
            # A world file beats an unmatched regional one, unless the code
            # provably looks for the regional one first: DuckStation ranks its
            # PS1 images 5 to 50 and its world PS2 images 100, so a request
            # for Brazil would otherwise leave it only the PS2 fallbacks.
            world_ranks = [
                lookup_priority(index, destination, name)
                for destination, name in members
                if destination in rivals
            ]
            ranked = [rank for rank in world_ranks if rank is not None]
            known = len(ranked) == len(world_ranks)
            best_world = min(ranked) if known and ranked else None
            for _r, destination in regional:
                name = next(n for d, n in members if d == destination)
                ours = lookup_priority(index, destination, name)
                if best_world is not None and ours is not None and ours < best_world:
                    keep.add(destination)
                else:
                    drop.add(destination)
        else:
            # Preserve every unmatched candidate as a visible fallback.
            keep |= {destination for _r, destination in regional}
    return drop - keep


def fallback_groups(
    groups: dict[str, list[tuple[str, str]]],
    index: dict[str, dict],
    requested: list[str],
) -> list[str]:
    """Group IDs where no candidate matched, so the whole group was kept.

    A world file, or one that declares no region at all, answers every
    region: the C64 kernal VICE loads by default is untagged, and a group
    holding it beside a Japanese and a Swedish kernal does have a BIOS for
    North America. A file no system claims is a group of its own and keeps
    nothing as a fallback: Dolphin's GC/EUR/IPL.bin named the GameCube as
    lacking a North American BIOS the pack carries.
    """
    if not requested:
        return []
    out: list[str] = []
    for group_id, members in groups.items():
        if ":file:" in group_id:
            continue
        ranked = _competing_ranks(members, index, requested)
        served = any(
            not regions or WORLD in regions
            for regions in (
                lookup_regions(index, destination, name)
                for destination, name in members
            )
        )
        if ranked and not served and min(r for r, _ in ranked) == len(requested):
            out.append(group_id)
    return sorted(out)
