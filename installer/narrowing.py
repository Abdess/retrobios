"""Narrowing a file list to a board, cores, regions, systems and one file per slot."""
from __future__ import annotations

from collections.abc import Callable, Collection, Iterable

from installer.constants import (
    AREA_TERRITORIES,
    FILE_GROUP,
    OTHER_SYSTEMS,
    REGIONS,
    REGION_ALIASES,
    WORLD_REGION,
    _REGION_PARENT,
)
from installer.cores import SYSTEM_KEY_FILES, SYSTEM_SHORT_NAMES, did_you_mean, entry_systems
from installer.embedded import _name_key
from installer.manifest import _COPY_FIELDS
from installer.paths import _entry_key


def _for_cores(entry: dict, chosen: set[str]) -> dict | None:
    """The copy of a core file the chosen cores read, or None.

    A destination holds one file. When several cores read it and disagree
    on its content, the manifest carries the first core's copy and the
    others as alternatives, in the order the pack builder tries them: a
    pack built without the first core carries the next one's copy.
    """
    if chosen.intersection(entry.get("cores") or []):
        return entry
    for alternative in entry.get("alternatives", []):
        if chosen.intersection(alternative["cores"]):
            kept = {
                k: v for k, v in entry.items()
                if k not in _COPY_FIELDS
                and k not in ("alternatives", "slot_choices", "declared_choices")
            }
            kept.update((k, alternative[k]) for k in _COPY_FIELDS if k in alternative)
            return kept
    return None


def _settle_slot(
    entry: dict,
    chosen: set[str],
    kept_system: Callable[[str], bool] | None = None,
) -> dict:
    """A platform file as a pack built for the chosen cores carries it.

    Where a core's own source contradicts the platform and the frontend only
    checks the path, the pack serves the core's copy: the first of
    `slot_choices` naming a chosen core decides. Otherwise the platform
    answers, through the first of `declared_choices` whose systems remain.
    """
    declared = entry.get("declared_choices")
    if declared is None:
        return entry
    platform_copy = next(
        (c for c in declared
         if kept_system is None or any(kept_system(s) for s in c["systems"])),
        declared[0],
    )
    copy = next(
        (c for c in entry.get("slot_choices", []) if chosen.intersection(c["cores"])),
        None,
    )
    if copy is None or "sha1" not in copy:
        copy = platform_copy
    kept = {
        k: v for k, v in entry.items()
        if k not in _COPY_FIELDS
        and k not in ("slot_choices", "declared_choices", "declared_copy")
    }
    kept.update((k, copy[k]) for k in _COPY_FIELDS if k in copy and k != "cores")
    kept["cores"] = None
    if copy is not platform_copy and copy.get("sha1") != platform_copy.get("sha1"):
        # What the platform checks here, for the `declared` event.
        kept["declared_copy"] = {k: platform_copy[k] for k in _COPY_FIELDS
                                 if k in platform_copy and k != "cores"}
    return kept


def _filter_by_target(
    files: list[dict], target_cores: list[str]
) -> list[dict]:
    """Keep the platform's files, and the core files the given cores read."""
    chosen = set(target_cores)
    result: list[dict] = []
    for f in files:
        if f.get("cores") is None:
            result.append(_settle_slot(f, chosen))
            continue
        kept = _for_cores(f, chosen)
        if kept is not None:
            result.append(kept)
    return result


def designated_cores(
    manifest: dict, names: list[str], target: str | None = None
) -> set[str]:
    """The cores a list of names designates, the way the pack builder reads it.

    A target list, or a core found installed, names a core the buildbot's
    way (`mednafen_psx`), and a file names the profile that reads it
    (`beetle_psx`). `core_names` gives each profile its other names. A core
    only the platform's RetroArch downloader brings runs on the boards
    `downloaded_cores` gives it: Batocera's bcm2711 list names its own
    amiberry, and the buildbot's amiberry core is no download there.
    """
    wanted = set(names)
    chosen = set(wanted)
    for profile, aliases in (manifest.get("core_names") or {}).items():
        if wanted.intersection(aliases):
            chosen.add(profile)
    if target is not None:
        chosen -= {
            profile for profile, boards in (manifest.get("downloaded_cores") or {}).items()
            if target not in boards
        }
    return chosen


def offered_here(
    manifest: dict, entry: dict, cores: set[str], target: str | None
) -> set[str]:
    """The cores a board reads this file for.

    A roms folder can offer a core on some boards only (ROCKNIX writes
    uae4arm for roms/amiga under the devices it builds it for): on another
    board, that core reads nothing there, even when the board runs it for
    another folder. `offered_boards` gives those boards.
    """
    offered = manifest.get("offered_boards") or {}
    if target is None or not offered:
        return cores
    tree = {"roms": "roms", None: "install"}.get(entry.get("root"))
    if tree is None:
        return cores
    dest = str(entry.get("dest", ""))
    return {
        core for core in cores
        if not any(
            place["root"] == tree and dest.startswith(place["folder"] + "/")
            and target not in place["boards"]
            for place in offered.get(core) or []
        )
    }


def narrow_to_cores(
    manifest: dict,
    names: list[str],
    files: list[dict] | None = None,
    omitted: list[dict] | None = None,
    declared_by_info: Collection[str] = (),
    target: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """Keep what the named cores read, as a pack built for them carries.

    A file a core loads stays when that core is named. A file of the
    platform's own list stays when one of its systems does: a system goes
    when none of the cores `system_cores` gives it is named, and a system
    it does not list stays whatever is named. A dropped system's file gives
    way to the first named core claiming its destination. A manifest without
    the two maps keeps the platform's list whole and matches cores by name.
    A destination in `declared_by_info`, what the .info of an installed core
    no profile describes declares, stays whatever is named. `target` is the
    board the names are the list of.
    """
    cores = designated_cores(manifest, names, target)
    reach = manifest.get("system_cores") or {}
    info_dests = {dest.casefold() for dest in declared_by_info}

    def kept_system(system: str) -> bool:
        return system not in reach or bool(cores.intersection(reach[system]))

    displaced: list[dict] = []

    def kept(entries: list[dict]) -> list[dict]:
        result: list[dict] = []
        for entry in entries:
            if str(entry.get("dest", "")).casefold() in info_dests:
                result.append(_for_cores(entry, cores) or _settle_slot(entry, cores))
                continue
            if entry.get("cores") is not None:
                here = offered_here(manifest, entry, cores, target)
                copy = _for_cores(entry, here)
                if copy is not None:
                    result.append(copy)
                    continue
                # None of the cores served here is named: a named core that
                # wants the slot and has nothing held is a file left out.
                claim = next(
                    (c for c in entry.get("absent_claims", [])
                     if here.intersection(c.get("cores") or [])),
                    None,
                )
                if claim is not None:
                    displaced.append({"dest": entry["dest"], **claim})
                continue
            # The systems declaring the file, where they are fewer than the
            # ones reading it.
            systems = entry.get("declared_in") or entry_systems(entry)
            if not systems or any(kept_system(s) for s in systems):
                result.append(_settle_slot(entry, cores, kept_system))
                continue
            # The system is dropped, which frees its destination for the
            # first named core claiming it, as in a pack built for them.
            copy = _for_cores(entry, cores)
            if copy is not None:
                result.append(copy)
        return result

    files = manifest.get("files", []) if files is None else files
    omitted = manifest.get("omitted_files", []) if omitted is None else omitted
    kept_files = kept(files)
    return kept_files, kept(omitted) + displaced


def canonical_region(raw: str) -> str:
    """One region name or alias, spelled the way manifests spell it."""
    key = raw.strip().lower()
    key = REGION_ALIASES.get(key, key)
    if key not in REGIONS:
        import difflib

        close = difflib.get_close_matches(key, [*REGION_ALIASES, *REGIONS], n=3, cutoff=0.5)
        hint = f" Close matches: {', '.join(close)}." if close else ""
        raise ValueError(
            f"unknown region: {raw.strip()}.{hint} "
            f"Short forms: {', '.join(REGION_ALIASES)}. Regions: "
            f"{', '.join(sorted(REGIONS))}"
        )
    return key


def _region_comparable(a: str, b: str) -> bool:
    return (
        a == b
        or _REGION_PARENT.get(a) == b
        or _REGION_PARENT.get(b) == a
        or a in AREA_TERRITORIES.get(b, ())
        or b in AREA_TERRITORIES.get(a, ())
    )


def _region_rank(file_regions: set[str], requested: list[str]) -> int:
    for index, wanted in enumerate(requested):
        if any(_region_comparable(wanted, region) for region in file_regions):
            return index
    return len(requested)


def region_drops(
    entries: list[dict],
    requested: list[str],
    systems: list[str] | None = None,
    held: set[str] | None = None,
) -> set[str]:
    """Destinations a region priority list withdraws, as _entry_key spells them.

    The pack builder's rule (region.resolve_region_drops), replayed over the
    groups the manifest records. Per group, the best-ranked regional file
    stays. A world file beats unmatched regional ones the code does not search
    before it (`priority`, lower first). When nothing matches and no world
    file exists, every regional file stays, so a group is never emptied. A
    file with no region never competes and always stays.

    A core extra competes whatever systems are chosen, while a platform's own
    declaration competes only when its system is kept, as in the pack.

    ``held`` names the destinations the manifest can install. A match it
    lacks never displaces a held file: the American BIOS stays under
    --region japan when the Japanese one is missing. A group named after a
    single file (FILE_GROUP) competes with nothing and keeps nothing.
    """
    if not requested:
        return set()
    kept_systems = set(systems) if systems else None
    groups: dict[str, list[tuple[set, str, int | None]]] = {}
    for entry in entries:
        regions = entry.get("regions")
        if not regions:
            continue
        joined = list(entry.get("region_groups") or [])
        joined += [
            group for group in entry.get("region_system_groups") or []
            if kept_systems is None or group in kept_systems
        ]
        priority = entry.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool):
            priority = None
        for group in joined:
            groups.setdefault(group, []).append((set(regions), _entry_key(entry), priority))
    keep: set[str] = set()
    drop: set[str] = set()
    for group_id, members in groups.items():
        if FILE_GROUP in group_id:
            continue
        world = {dest for regions, dest, _p in members if WORLD_REGION in regions}
        ranks = {dest: priority for _regions, dest, priority in members}
        regional = [
            (_region_rank(regions, requested), dest)
            for regions, dest, _p in members
            if WORLD_REGION not in regions
        ]
        keep |= world
        if not regional:
            continue
        matched = [(rank, dest) for rank, dest in regional if rank < len(requested)]
        winners, rivals = matched, world
        if held is not None:
            winners = [(rank, dest) for rank, dest in matched if dest in held]
            rivals = world & held
        if winners:
            best = min(rank for rank, _dest in winners)
            keep |= {
                dest for rank, dest in matched
                if rank == best or (rank < best and dest not in (held or ()))
            }
            drop |= {dest for _rank, dest in regional if dest not in keep}
        elif rivals:
            world_ranks = [ranks[dest] for dest in rivals]
            known_ranks = [rank for rank in world_ranks if rank is not None]
            best_world = min(known_ranks) if len(known_ranks) == len(world_ranks) else None
            for _rank, dest in regional:
                ours = ranks[dest]
                if best_world is not None and ours is not None and ours < best_world:
                    keep.add(dest)
                else:
                    drop.add(dest)
        else:
            keep |= {dest for _rank, dest in regional}
    return drop - keep


def narrow(
    files: list[dict],
    omitted: list[dict],
    systems: list[str],
    cores: list[str],
    regions: list[str],
) -> tuple[list[dict], list[dict]]:
    """Keep what the chosen systems, cores and regions need.

    A core choice keeps the platform's own list and narrows only the files
    cores load, the rule --target already follows. Regions are then decided
    the way the pack builder decides them under --system: over the chosen
    systems' declarations and every core extra. The system filter comes last.
    """
    if cores:
        files = _filter_by_target(files, cores)
        omitted = _filter_by_target(omitted, cores)
    if regions:
        # The builder's held set: what the collection serves. An omission
        # answers the request but takes no installable file's place, unless
        # the builder holds it (held: true) and only this download lacks it:
        # the pack drops the fallback it displaces, and so does this.
        held = {_entry_key(f) for f in files} | {
            _entry_key(o) for o in omitted if o.get("held")
        }
        dropped = region_drops(files + omitted, regions, systems, held)
        files = [f for f in files if _entry_key(f) not in dropped]
        omitted = [o for o in omitted if _entry_key(o) not in dropped]
    if systems:
        wanted = set(systems)
        files = [f for f in files if _chosen(f, wanted)]
        omitted = [o for o in omitted if _chosen(o, wanted)]
    return files, omitted


def _chosen(entry: dict, wanted: set[str]) -> bool:
    systems = entry_systems(entry)
    if not systems:
        return OTHER_SYSTEMS in wanted
    return bool(wanted & set(systems))


def _merged_slot(claims: dict) -> tuple[int | None, tuple, frozenset]:
    """One key's rank, regions and sets over the emulators claiming it, as
    the pack builder merges them (slot.merge_claims). Two ranks that differ,
    or a rank beside an emulator declaring the file without one, leave the
    file unranked: neither order may win for a pack serving both cores."""
    ranks = {rank for claim in claims.values() for rank in claim.get("ranks", [])
             if rank is not None}
    ranked_by = {name for name, claim in claims.items()
                 if any(rank is not None for rank in claim.get("ranks", []))}
    unranked_by = {name for name, claim in claims.items() if None in claim.get("ranks", [])}
    conflict = len(ranks) > 1 or bool(ranked_by and unranked_by - ranked_by)
    regions = tuple(sorted({r for claim in claims.values() for r in claim.get("regions", [])}))
    sets = frozenset((name, group) for name, claim in claims.items()
                     for group in claim.get("sets", []))
    return (None if conflict or not ranks else min(ranks)), regions, sets


def slot_drops(entries: list[dict], held: set[str],
               reach: Collection[str] | None = None) -> set[str]:
    """Destinations --one-per-slot withdraws, as _entry_key spells them.

    The pack builder's rule (slot.resolve_slot_drops), replayed over the
    `slot` each entry records. A slot is a group and the regions the code
    selects the file for, split where no set links its files. In a slot of
    two files or more, the one ranked first by `priority:` (lower first)
    stays and the others go, and only when every file of it is ranked and
    one ranks best: otherwise every file stays. `held` names what the run
    can install, as for the regions. `reach` is the cores of the board: the
    claims of the others are no part of its order.
    """
    bucketed: dict[tuple[str, tuple], list[tuple[str, int | None, frozenset]]] = {}
    keep: set[str] = set()
    for entry in entries:
        slot = entry.get("slot")
        key = _entry_key(entry)
        if not isinstance(slot, dict) or key not in held:
            continue
        # One lookup per name the groups list the file under (`also`).
        for chain in [slot, *slot.get("also", [])]:
            merged = None
            for claims in chain.get("keys", []):
                here = {name: claim for name, claim in claims.items()
                        if reach is None or name in reach}
                if here:
                    merged = _merged_slot(here)
                    break
            if merged is None:
                keep.add(key)
                continue
            rank, regions, sets = merged
            for group in chain.get("groups", []):
                bucketed.setdefault((group, regions), []).append((key, rank, sets))
    drop: set[str] = set()
    for found in bucketed.values():
        for candidates in _linked_by_set(found):
            if len(candidates) < 2 or any(rank is None for _key, rank in candidates):
                keep.update(key for key, _rank in candidates)
                continue
            best = min(rank for _key, rank in candidates if rank is not None)
            winners = [key for key, rank in candidates if rank == best]
            if len(winners) != 1:
                keep.update(key for key, _rank in candidates)
                continue
            keep.add(winners[0])
            drop.update(key for key, _rank in candidates if key != winners[0])
    return drop - keep


def _linked_by_set(found: list[tuple[str, int | None, frozenset]]
                   ) -> list[list[tuple[str, int | None]]]:
    """The files of one slot split where no set links them: a rank orders
    the members of one set, and files in no set are compared together."""
    parent = list(range(len(found)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first_of: dict[object, int] = {}
    for i, (_key, _rank, sets) in enumerate(found):
        for set_key in sets or {None}:
            if set_key in first_of:
                parent[root(i)] = root(first_of[set_key])
            else:
                first_of[set_key] = i
    parts: dict[int, list[tuple[str, int | None]]] = {}
    for i, (key, rank, _sets) in enumerate(found):
        parts.setdefault(root(i), []).append((key, rank))
    return list(parts.values())


def one_per_slot(files: list[dict], omitted: list[dict],
                 reach: Collection[str] | None = None) -> tuple[list[dict], list[dict]]:
    """The files and omissions --one-per-slot keeps. What the builder holds
    and this download lacks (held: true) displaces a file as in the pack."""
    held = {_entry_key(f) for f in files} | {_entry_key(o) for o in omitted if o.get("held")}
    dropped = slot_drops(files + omitted, held, reach)
    return ([f for f in files if _entry_key(f) not in dropped],
            [o for o in omitted if _entry_key(o) not in dropped])


def truth_lists(manifest: dict, files: list[dict],
                omitted: list[dict]) -> tuple[list[dict], list[dict]]:
    """What --source truth installs: the files the emulator profiles prove a
    core reads, as `generate_pack.py --source truth` packs them. The full
    list marks what that list lacks (truth: false) and carries what only it
    holds (truth_files, truth_omitted)."""
    return ([f for f in files if f.get("truth", True)] + list(manifest.get("truth_files") or []),
            [o for o in omitted if o.get("truth", True)]
            + list(manifest.get("truth_omitted") or []))


def standalone_entries(manifest: dict, layouts: dict, profile: str) -> list[dict] | None:
    """The files a profile's standalone build reads, as entries of the list:
    None for a profile without one. An item [dest, sha1] takes its download
    from the copy of the list with that content."""
    if profile not in layouts:
        return None
    copies = {
        copy["sha1"]: copy
        for entry in [*manifest.get("files", []), *(manifest.get("truth_files") or [])]
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]
        if copy.get("sha1") and (copy.get("repo_path") or copy.get("release_asset"))
    }
    result: list[dict] = []
    for item in layouts[profile]:
        if isinstance(item, list):
            dest, sha1 = item
            copy = copies[sha1]
            result.append({"dest": dest, **{k: copy[k] for k in _COPY_FIELDS
                                            if k in copy and k != "cores"},
                           "cores": [profile]})
        else:
            result.append({**item, "cores": [profile]})
    return result


def standalone_layout(manifest: dict, layouts: dict, profiles: list[str],
                      files: list[dict], omitted: list[dict]
                      ) -> tuple[list[dict], list[dict]]:
    """--emulator with --standalone: the platform's own files of the systems
    the emulators run, and beside them each emulator's standalone build, in
    profile order, first at a destination wins, as `generate_pack.py
    --emulator --standalone` packs them."""
    built: dict[str, dict] = {}
    for profile in sorted(profiles):
        for entry in standalone_entries(manifest, layouts, profile) or []:
            built.setdefault(_entry_key(entry), entry)
    own = [entry for entry in files
           if entry.get("cores") is None and _entry_key(entry) not in built]
    return own + list(built.values()), [o for o in omitted if o.get("cores") is None]


# What --find reads a hash as, by its length in hex digits.
FIND_KINDS = {40: "sha1", 64: "sha256", 32: "md5", 8: "crc32"}


def find_by_hash(files: list[dict], value: str) -> tuple[str, list[dict], bool]:
    """The entries of a list whose content has this hash: the kind read
    from its length, the matches, each at its destination with the copy
    that has it, and whether the list records that kind at all."""
    value = value.strip().lower()
    kind = FIND_KINDS.get(len(value), "")
    matches: list[dict] = []
    recorded = False
    seen: set[tuple[str, str]] = set()
    for entry in files:
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]:
            if kind in copy:
                recorded = True
            if str(copy.get(kind, "")).lower() != value:
                continue
            found = dict(entry)
            for field in ("alternatives", "slot_choices", "declared_choices", "declared_copy"):
                found.pop(field, None)
            found.update((k, copy[k]) for k in _COPY_FIELDS if k in copy)
            if (_entry_key(found), found.get("sha1", "")) not in seen:
                seen.add((_entry_key(found), found.get("sha1", "")))
                matches.append(found)
    return kind, matches, recorded


def recorded_axes(files: list[dict], omitted: Iterable[dict] = ()) -> frozenset:
    """What a file list lets --system, --core and --region narrow by: its
    systems, its cores, its regions. A list from an older release records
    none. The MinUI family's records cores and regions and no system: all
    three were refused on it, by a remedy that fetched the same list."""
    entries = [*files, *omitted]
    systems = any("systems" in entry for entry in entries)
    if not systems and not any("regions" in entry for entry in entries):
        # Systems and regions came in one release: a list with neither is
        # older, its cores read by nothing that narrows.
        return frozenset()
    # A current list records the regions of the files a region selects, and
    # none when it has no such file: --region then keeps every file, as the
    # pack built with it does.
    axes = {"regions", *(["systems"] if systems else [])}
    if any(copy.get("cores") for entry in files
           for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]):
        axes.add("cores")
    return frozenset(axes)


def records_selection(files: list[dict]) -> bool:
    """Whether a manifest records anything narrowing reads. Older ones do not."""
    return bool(recorded_axes(files))


def available_choices(files: list[dict], omitted: list[dict]) -> dict[str, list[str]]:
    """The systems, cores and regions a manifest lets one narrow to."""
    systems = {s for e in files + omitted for s in entry_systems(e)}
    ordered = sorted(systems)
    if any(not entry_systems(f) for f in files):
        ordered.append(OTHER_SYSTEMS)
    cores = {
        c for f in files
        for copy in [f, *f.get("alternatives", []), *f.get("slot_choices", [])]
        for c in (copy.get("cores") or [])
    }
    regions = {
        r for e in files + omitted for r in (e.get("regions") or [])
        if r != WORLD_REGION
    }
    return {
        "systems": ordered,
        "cores": sorted(cores),
        "regions": sorted(regions),
    }


def choosable_cores(files: list[dict], omitted: list[dict],
                    systems: Collection[str] = ()) -> list[str]:
    """The cores a choice is made among, for the files a run keeps once
    the save entries it cannot place and the game data --no-game-data cuts
    are left out, of the systems chosen (every system for none). Cores on
    the screen and c in line mode list these and count "N of M" out of
    them: the screen listed the whole file list's 189 where the run
    accepted 181."""
    if systems:
        files, omitted = narrow(files, omitted, list(systems), [], [])
    return available_choices(files, omitted)["cores"]


def core_files(files: list[dict], core: str) -> list[dict]:
    """The files one core adds to the platform's own: what line mode's
    Cores question and the screen's Cores rows size."""
    return _filter_by_target([entry for entry in files if entry.get("cores") is not None],
                             [core])


def resolve_choices(
    values: list[str], known: list[str], label: str,
    aliases: dict[str, str] | None = None,
    holders: dict[str, list[str]] | None = None,
) -> list[str]:
    """Names given on the command line, matched without regard to case.

    Each value is one name or a comma-separated list. A whole value that is
    itself a name wins over splitting it: Recalbox names one system
    `msx1,msx2,msxturbor`. An unknown name is refused, never ignored, since
    carrying on would install something other than what was asked.
    aliases maps another name of a known one to it, as Batocera's `psx`
    stands for sony-playstation. A known name always wins over an alias.
    holders maps a system the list files under other ids to those ids
    (key_file_holders): an unknown name for it is answered with them.
    """
    aliases = {alias: name for alias, name in (aliases or {}).items() if name in known}
    by_lower = {name.lower(): name for name in known}
    for alias, name in aliases.items():
        by_lower.setdefault(alias.lower(), name)
    # Spelled as the site writes it (Sony PlayStation), a name is still one
    # name when no other one reads the same once case and spacing go.
    by_key: dict[str, str | None] = {}
    for name in known:
        key = _name_key(name)
        by_key[key] = None if key in by_key else name
    for alias, name in aliases.items():
        by_key.setdefault(_name_key(alias), name)
    chosen: list[str] = []
    unknown: list[str] = []
    for value in values:
        value = value.strip()
        tokens = [value] if value.lower() in by_lower else value.split(",")
        for token in (t.strip() for t in tokens):
            if not token:
                continue
            picked = by_lower.get(token.lower()) or by_key.get(_name_key(token))
            if picked is None:
                unknown.append(token)
            elif picked not in chosen:
                chosen.append(picked)
    if unknown:
        if not known:
            raise ValueError(f"unknown {label}: {', '.join(unknown)}. This list records none.")
        listing = {"system": "--list-systems", "emulator": "--list-emulators"}.get(
            label, "--list-cores")
        hints, inside_from = aliases, 4
        held = holders or {}
        stands_for: dict[str, str] = {}
        notes = ""
        if label == "system":
            # gba is the end of nintendo-gba: three letters are enough here.
            hints = {**{short: name for short, name in SYSTEM_SHORT_NAMES.items()
                        if name in known}, **aliases}
            inside_from = 3
            stands_for = {_name_key(system): system for system in held}
            for short, name in SYSTEM_SHORT_NAMES.items():
                if name in held:
                    stands_for.setdefault(_name_key(short), name)
            named = dict.fromkeys(
                stands_for[_name_key(token)] for token in unknown
                if _name_key(token) in stands_for)
            notes = "".join(
                f"This list files {SYSTEM_KEY_FILES[system]} under "
                f"{', '.join(held[system])}. " for system in named)
        meant = {key: held[system] for key, system in stands_for.items()}
        raise ValueError(
            f"unknown {label}: {', '.join(unknown)}. {notes}"
            f"{did_you_mean(unknown, known, listing, hints, inside_from, meant)}"
        )
    if values and not chosen:
        raise ValueError(f"--{label} needs at least one name")
    return chosen


def resolve_regions(values: list[str]) -> list[str]:
    """A region priority list, best first, from names or aliases."""
    chosen: list[str] = []
    for value in values:
        for token in value.split(","):
            if token.strip():
                region = canonical_region(token)
                if region not in chosen:
                    chosen.append(region)
    if values and not chosen:
        raise ValueError("--region needs at least one region")
    return chosen


def parse_selection(text: str, count: int, ordered: bool = False) -> list[int]:
    """Numbers typed at a prompt: `3`, `1,4`, `2-5`, or `all`, 1-based.

    Returned sorted, or in the typed order when the order is a priority.
    """
    if text.strip().lower() in ("all", "*"):
        return list(range(1, count + 1))
    chosen: list[int] = []
    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue
        low, sep, high = token.partition("-")
        try:
            start = int(low)
            end = int(high) if sep else start
        except ValueError:
            raise ValueError(f"not a number or range: {token}") from None
        if start > end or start < 1 or end > count:
            raise ValueError(f"out of range: {token} (1-{count})")
        for number in range(start, end + 1):
            if number not in chosen:
                chosen.append(number)
    return chosen if ordered else sorted(chosen)
