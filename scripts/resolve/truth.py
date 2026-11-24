"""Platform truth generation and diffing.

Generates ground-truth YAML from emulator profiles for gap analysis,
and diffs truth against scraped platform data to find divergences.
"""

from __future__ import annotations

import copy
import logging
import os

from resolve.launches import PlatformLaunches
from resolve.standalone import platform_layouts, platform_launches
from resolve.cores import resolve_platform_cores
from resolve.reconcile import contradicts, shares_hash
from model.alternatives import groups_of
from core.hashing import HASH_FIELDS, compute_hashes, declared_hashes, parse_hash_list
from resolve.entryscope import (
    filter_files_by_mode,
    installed_with_emulator,
)
from resolve.truthsystems import (
    _SystemMap,
    _brought,
    _cover,
    _enrich_hashes,
    _has_exploitable_data,
    _platform_entries,
    _require_by_slot,
    _serialize_systems,
    _sizes_clash,
)


# Notes on how the model settled two cores: a caller that has no use for
# them (check_freshness) silences this logger, never the text it writes.
log = logging.getLogger(__name__)

_CONFLICTS_SHOWN: set[tuple[str, ...]] = set()


def _serialize_source_ref(sr: object) -> str:
    """Convert a source_ref value to a clean string for serialization."""
    if isinstance(sr, str):
        return sr
    if isinstance(sr, dict):
        parts = [f"{k}: {v}" for k, v in sr.items()]
        return "; ".join(parts)
    return str(sr)


_FILLED_FIELDS = (
    "size",
    "min_size",
    "max_size",
    "path",
    "validation",
    "description",
    "category",
    "hle_fallback",
    "note",
    "aliases",
    "contents",
)
_COPIED_FIELDS = (
    "sha1",
    "md5",
    "sha256",
    "crc32",
    "size",
    "path",
    "description",
    "hle_fallback",
    "category",
    "note",
    "validation",
    "min_size",
    "max_size",
    "aliases",
    "contents",
    "priority",
    "region",
)

def _merge_file_into_system(
    system: dict,
    file_entry: dict,
    emu_name: str,
    db: dict | None,
) -> None:
    """Merge a file entry into a system's file list, deduplicating by name.

    A name is one file across cores, whatever path each core gives it. A
    core that declares the same name under two paths declares two files:
    Dolphin's three IPL.bin differ only by GC/USA, GC/EUR, GC/JAP. Under
    one path or none, its declarations are revisions of one file.
    """
    # A profile states where the code reads a file as `path:` or as
    # `destination:` (redream's dc_bios.bin at dc/boot.bin), as the resolver
    # reads them.
    if not file_entry.get("path") and file_entry.get("destination"):
        file_entry = {**file_entry, "path": file_entry["destination"]}
    files = system.setdefault("files", [])
    existing = _same_file(files, file_entry, emu_name)
    if existing is None:
        files.append(_new_truth_entry(file_entry, emu_name, db))
    else:
        _fold_into(existing, file_entry, emu_name)


def _same_file(files: list[dict], file_entry: dict, emu_name: str) -> dict | None:
    """The entry already standing for this file, if any."""
    name_lower = file_entry["name"].lower()
    path = str(file_entry.get("path") or "").casefold()

    def other_path(f: dict) -> str:
        return str(f.get("path") or "").casefold()

    # A label and a name a core opens are one file only on a shared hash:
    # pcsx_rearmed's hashless scph1001.bin took the md5 of DuckStation's
    # label of that name, another dump.
    labelled = not file_entry.get("_opens_by_name", True)
    same_name = [
        f for f in files
        if f["name"].lower() == name_lower
        and (labelled == (not f.get("_named_by", True)) or _shares_hash(f, file_entry))
    ]
    return (
        next((f for f in same_name if path and other_path(f) == path), None)
        # Another core's file of the same name is the same file unless their
        # contents disagree: beebem's 16 KB BBC BIOS.rom and np2kai's PC-98
        # bios.rom merged, and the export wrote the BBC md5 over Recalbox's.
        or next(
            (f for f in same_name
             if emu_name not in f.get("_cores", ()) and not _contents_disagree(f, file_entry)),
            None,
        )
        # Revisions one core accepts under one name and no path fill one
        # slot. Across cores, contents that disagree are two files: fMSX's
        # 16640-byte RS232.ROM took blueMSX's 8192 size beside its own md5,
        # a record no file satisfies.
        or next(
            (f for f in same_name
             if (not path or not other_path(f))
             and (emu_name in f.get("_cores", ()) or not _contents_disagree(f, file_entry))),
            None,
        )
    )


def _shares_hash(a: dict, b: dict) -> bool:
    return shares_hash(declared_hashes(a), declared_hashes(b))


def _contents_disagree(a: dict, b: dict) -> bool:
    """A hash both declare without a value in common, or no size both admit."""
    return contradicts(declared_hashes(a), declared_hashes(b)) or _sizes_clash(a, b)


def _fold_into(existing: dict, file_entry: dict, emu_name: str) -> None:
    """Add one core's declaration to the entry that already stands for it."""
    revision = emu_name in existing.get("_cores", ())
    existing["_cores"] = existing.get("_cores", set()) | {emu_name}
    if file_entry.get("_opens_by_name", True):
        existing["_named_by"] = existing.get("_named_by", set()) | {emu_name}
    existing["_brought_by"] = existing.get("_brought_by", set()) | _brought(file_entry, emu_name)
    sr = file_entry.get("source_ref")
    if sr is not None:
        sr_key = _serialize_source_ref(sr)
        existing["_source_refs"] = existing.get("_source_refs", set()) | {sr_key}
    else:
        existing.setdefault("_source_refs", set())
    if groups_of(file_entry):
        _fold_set_member(existing, file_entry, emu_name)
    elif file_entry.get("required"):
        existing["required"] = True
        # Which cores need it: `required` above is the union, true when
        # any core needs it, and a package of one core must not read it.
        existing["_required_by"] = existing.get("_required_by", set()) | {emu_name}
    elif file_entry.get("required") is not None:
        existing.setdefault("required", file_entry["required"])
    _merge_hashes(existing, file_entry, emu_name, revision)
    # Merge non-hash data fields if existing lacks them.
    # A core that creates an entry without size/path/validation may be
    # enriched by a sibling core that has those fields.
    for field in _FILLED_FIELDS:
        if file_entry.get(field) is not None and existing.get(field) is None:
            existing[field] = file_entry[field]
    _merge_priority(existing, file_entry.get("priority"))
    _merge_region(existing, file_entry.get("region"))


def _fold_set_member(entry: dict, file_entry: dict, emu_name: str) -> None:
    """A core that takes this file as one of a set needs the set, not it.

    Yabause loads the first of saturn_bios.bin, sega_101.bin and
    mpr-17933.bin it finds. None of the three is required on its own, so
    the core stays out of `required` and `_required_by`, and `_one_of`
    names it with `one_of_required` saying whether its set is required.
    """
    entry["_one_of"] = entry.get("_one_of", set()) | {emu_name}
    if file_entry.get("required", True):
        entry["one_of_required"] = True
    else:
        entry.setdefault("one_of_required", False)


def _merge_region(existing: dict, theirs: str | list | None) -> None:
    """The regions every reader selects the file for, the pack's own rule.

    region.build_region_index takes the union of the tags and keeps a file
    untagged as soon as one reader declares it without a region. The first
    tag used to win: psxonpsp660.bin came out japan from pcsx_rearmed while
    SwanStation tags it world and beetle_psx not at all.
    """
    if existing.get("_region_void"):
        return
    if not theirs:
        existing.pop("region", None)
        existing["_region_void"] = True
        return
    ours = existing.get("region") or []
    ours = ours if isinstance(ours, list) else [ours]
    added = [r for r in (theirs if isinstance(theirs, list) else [theirs]) if r not in ours]
    existing["region"] = [*ours, *added]


def _merge_hashes(
    existing: dict, file_entry: dict, emu_name: str, revision: bool = False
) -> None:
    """Fold one declaration's hashes into the entry.

    A core that lists several revisions under one name accepts each of them
    (dosbox's MT-32 control ROMs, raze's GRP versions): ``revision`` keeps
    the union. Two cores that disagree keep the first value and are reported.
    """
    for h in HASH_FIELDS:
        theirs = file_entry.get(h, "")
        ours = existing.get(h, "")
        if not theirs:
            continue
        if not ours:
            existing[h] = theirs
            existing.setdefault("_hash_by", {})[h] = emu_name
            continue
        # A field holds one value, a list or a comma-joined string (mesence
        # names twelve BS-X dumps in one sha256): compared value by value.
        t_list, o_list = parse_hash_list(theirs), parse_hash_list(ours)
        if revision:
            added = [v for v in t_list if v not in o_list]
            if added:
                existing[h] = [*o_list, *added]
            continue
        if not set(t_list) & set(o_list):
            # The value kept is one revision among those the cores accept:
            # it pairs an entry, it never overrules one (checked_hashes).
            existing["hash_conflict"] = sorted({*existing.get("hash_conflict", ()), h})
            # Once per process: a run over every platform met the same pair
            # once per platform and opened its output on six copies.
            key = (file_entry["name"], h, str(ours), str(theirs), emu_name)
            if key not in _CONFLICTS_SHOWN:
                _CONFLICTS_SHOWN.add(key)
                # Both cores and which value stays: naming only the second
                # core sent the reader through ten profiles for the first.
                first = existing.get("_hash_by", {}).get(h, "an earlier core")
                log.warning(
                    "WARNING: hash conflict for %s: %s %s (%s) kept, %s (%s) "
                    "left out of the model",
                    file_entry["name"], h, ours, first, theirs, emu_name,
                )


def _merge_priority(existing: dict, theirs: int | None) -> None:
    """Search order is a fact of the code, so it travels with the entry.

    The best rank any core gives it is kept and the disagreement is recorded
    beside it, the way slot.py already does: the rank says how early to read
    the file, the conflict says the order cannot decide which single file to
    keep.
    """
    if theirs is None:
        return
    ours = existing.get("priority")
    if ours is None:
        existing["priority"] = theirs
        return
    if ours != theirs:
        existing["priority_conflict"] = True
    existing["priority"] = min(ours, theirs)


def _new_truth_entry(file_entry: dict, emu_name: str, db: dict | None) -> dict:
    entry: dict = {"name": file_entry["name"]}
    grouped = bool(groups_of(file_entry))
    if file_entry.get("required") is not None and not grouped:
        entry["required"] = file_entry["required"]
    for field in _COPIED_FIELDS:
        val = file_entry.get(field)
        if val is not None:
            entry[field] = val
    # Strip empty string hashes (profile says "" when hash is unknown)
    for h in HASH_FIELDS:
        if entry.get(h) == "":
            del entry[h]
    # Normalize CRC32: strip 0x prefix, lowercase
    crc = entry.get("crc32")
    if isinstance(crc, str):
        entry["crc32"] = crc.removeprefix("0x").lower()
    if not file_entry.get("region"):
        entry["_region_void"] = True
    entry["_cores"] = {emu_name}
    entry["_required_by"] = {emu_name} if file_entry.get("required") and not grouped else set()
    if grouped:
        _fold_set_member(entry, file_entry, emu_name)
    entry["_named_by"] = {emu_name} if file_entry.get("_opens_by_name", True) else set()
    entry["_brought_by"] = _brought(file_entry, emu_name)
    sr = file_entry.get("source_ref")
    entry["_source_refs"] = {_serialize_source_ref(sr)} if sr is not None else set()
    if db:
        _enrich_hashes(entry, db)
    # Which core gave each hash, for the conflict warning. Dropped before
    # the model is written.
    entry["_hash_by"] = {h: emu_name for h in HASH_FIELDS if entry.get(h)}
    return entry


def _fold_data_directory_readers(
    systems: dict,
    profiles: dict,
    cores: list[str],
    launches: PlatformLaunches,
    platform_name: str,
    data_registry: dict,
) -> None:
    """Count a core that reads a data directory among the readers of its files.

    LRPS2 reads pcsx2/resources/GameIndex.yaml from its data directory and
    declares no file entry for it, so the entry other cores build for that
    path named armsx2 and yaps2 alone: RetroArch's System.dat line, which
    describes LRPS2's copy, was paired with armsx2's revision and nothing
    said the cores disagree. The copy in the directory's cache is what the
    reader reads, so its hashes fold in as that core's declaration and a
    different value marks hash_conflict. Only entries other cores already
    build are touched: a directory's other files are not BIOS entries.
    """
    by_path: dict[str, list[dict]] = {}
    for sys_data in systems.values():
        for entry in sys_data.get("files", []):
            by_path.setdefault(entry.get("path") or entry.get("name", ""), []).append(entry)
    if not by_path:
        return
    for emu_name in cores:
        for view, standalone in platform_layouts(
            emu_name, profiles[emu_name], launches
        ):
            trees = [
                tree for tree in filter_files_by_mode(
                    [t for t in view.get("data_directories") or [] if isinstance(t, dict)],
                    standalone,
                )
                if tree.get("ref") in data_registry
            ]
            for tree in trees:
                cache = data_registry[tree["ref"]].get("local_cache", "")
                if not cache or not os.path.isdir(cache):
                    continue
                # Below the build's own folder, as the emulator pack lays the
                # tree out: PPSSPP's assets sit under PPSSPP/, not at the root.
                structure = (profiles[emu_name].get("pack_structure") or {}).get(
                    "standalone" if standalone else "libretro", ""
                )
                prefix = "/".join(
                    part.strip("/") for part in (structure, str(tree.get("destination") or ""))
                    if part and part.strip("/")
                )
                prefix = f"{prefix}/" if prefix else ""
                if prefix and any(
                    str(f.get("path") or "").startswith(prefix)
                    for f in view.get("files") or [] if isinstance(f, dict)
                ):
                    # The profile names what it reads in the tree: yaps2
                    # lists its resources, pcee2 lists patches.zip alone
                    # (its build compiles GameIndex.yaml and the shaders in).
                    continue
                installed = installed_with_emulator(tree, platform_name)
                for path, entries in by_path.items():
                    if not path.startswith(prefix):
                        continue
                    copy_path = os.path.join(cache, path[len(prefix):])
                    if not os.path.isfile(copy_path):
                        continue
                    held = compute_hashes(copy_path, frozenset({"sha1", "md5", "crc32"}))
                    declaration = {
                        "name": os.path.basename(path),
                        "required": bool(tree.get("required", False)),
                        "source_ref": tree.get("source_ref"),
                        **held,
                        "_opens_by_name": True,
                        "_brought": None if installed else (
                            f"{emu_name}:{'standalone' if standalone else 'libretro'}"
                        ),
                    }
                    for entry in entries:
                        if emu_name not in entry.get("_cores", set()):
                            _fold_into(entry, dict(declaration), emu_name)


def generate_platform_truth(
    platform_name: str,
    config: dict,
    registry_entry: dict,
    profiles: dict[str, dict],
    db: dict | None = None,
    target_cores: set[str] | None = None,
    *,
    data_registry: dict,
) -> dict:
    """Generate ground-truth system data for a platform from emulator profiles.

    Args:
        platform_name: platform identifier
        config: loaded platform config (via load_platform_config), has cores,
                systems, standalone_cores with inheritance resolved
        registry_entry: registry metadata for hash_type, verification_mode, etc.
        profiles: all loaded emulator profiles
        db: optional database for hash enrichment
        target_cores: optional hardware target core filter
        data_registry: the data directory registry (_data_dirs.yml) of the
                caller's platforms directory

    Returns a dict with platform metadata, systems, and per-file details
    including which cores reference each file.
    """
    # The layout rule verify and the pack builder apply: truth guessed its
    # own from the profile type where the platform names no standalone
    # emulator, and kept files the pack never carries.
    launches = platform_launches(config, profiles)

    resolved = resolve_platform_cores(config, profiles, target_cores)

    # Build mapping: profile system ID -> platform system ID
    # Three strategies, tried in order:
    # 1. File-based: if the scraped platform already has this file, use its system
    # 2. Exact match: profile system ID == platform system ID
    # 3. Normalized match: strip manufacturer prefix + separators
    mapping = _SystemMap.of(config, db)

    systems: dict[str, dict] = {}
    unattributed: dict[str, int] = {}
    cores_profiled: set[str] = set()
    cores_unprofiled: set[str] = set()
    # Track which cores contribute to each system
    system_cores: dict[str, dict[str, set[str]]] = {}

    for emu_name in sorted(resolved):
        profile = profiles.get(emu_name)
        if not profile:
            cores_unprofiled.add(emu_name)
            continue
        cores_profiled.add(emu_name)

        on_platform = {
            mapping.map_sys_id(sid) for sid in profile.get("systems", [])
        } & mapping.platform_sys_ids
        for fe in _platform_entries(emu_name, profile, launches, platform_name):
            sys_targets = mapping.targets(fe, profile, on_platform)
            if not sys_targets:
                unattributed[emu_name] = unattributed.get(emu_name, 0) + 1
                continue
            for position, sys_id in enumerate(sys_targets):
                system = systems.setdefault(sys_id, {})
                _merge_file_into_system(
                    system, fe if position == 0 else copy.deepcopy(fe), emu_name, db
                )
                _cover(system_cores, sys_id, "profiled", emu_name)

    # Ensure all systems of resolved cores have entries (even with 0 files).
    # This documents that the system is covered: the core was analyzed and
    # needs no external files for this system. Sorted: the set's order is
    # the hash seed's, and it decided where each empty system was written.
    for emu_name in sorted(cores_profiled):
        profile = profiles[emu_name]
        for prof_sid in profile.get("systems", []):
            sys_id = mapping.map_sys_id(prof_sid)
            systems.setdefault(sys_id, {})
            _cover(system_cores, sys_id, "profiled", emu_name)

    # Track unprofiled cores per system based on profile system lists
    for emu_name in cores_unprofiled:
        for sys_id in systems:
            _cover(system_cores, sys_id, "unprofiled", emu_name)

    _fold_data_directory_readers(
        systems, profiles, sorted(cores_profiled), launches, platform_name,
        data_registry,
    )

    for sys_data in systems.values():
        _require_by_slot(sys_data.get("files", []))

    # Drop files with no exploitable data AFTER all cores have contributed.
    # A file declared by one core without hash/size/path may be enriched by
    # another core that has the same entry with data, so the filter must run
    # once at the end, not per-core at creation time.
    for sys_data in systems.values():
        files_list = sys_data.get("files", [])
        if files_list:
            sys_data["files"] = [fe for fe in files_list if _has_exploitable_data(fe)]

    _serialize_systems(systems, system_cores)

    return {
        "platform": platform_name,
        "generated": True,
        "systems": systems,
        "_coverage": {
            "cores_resolved": len(resolved),
            "cores_profiled": len(cores_profiled),
            "cores_unprofiled": sorted(cores_unprofiled),
            # Entries of multi-system cores no system of this platform can
            # be said to own: counted, never filed under a guess.
            "unattributed": dict(sorted(unattributed.items())),
        },
    }
