"""Platform truth generation and diffing.

Generates ground-truth YAML from emulator profiles for gap analysis,
and diffs truth against scraped platform data to find divergences.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

from common import (
    OUTER_ROOTS,
    _norm_system_id,
    load_data_dir_registry,
    platform_layouts,
    resolve_platform_cores,
    standalone_set as platform_standalone_set,
)
from alternatives import groups_of
from hashing import compute_hashes
from validation import (
    filter_files_by_mode,
    installed_with_emulator,
    opens_by_name,
    read_from_system_dir,
    unread_on,
)



_CONFLICTS_SHOWN: set[tuple[str, ...]] = set()

def _serialize_source_ref(sr: object) -> str:
    """Convert a source_ref value to a clean string for serialization."""
    if isinstance(sr, str):
        return sr
    if isinstance(sr, dict):
        parts = [f"{k}: {v}" for k, v in sr.items()]
        return "; ".join(parts)
    return str(sr)


def _enrich_hashes(entry: dict, db: dict) -> None:
    """Fill the hashes a profile omits from the record its own hash names.

    The record is found by sha1, then md5, then crc32 with the size when the
    profile gives one. Never by name: a file in bios/ under the same name may
    not be the bytes the source code expects. An entry listing several
    accepted values for a hash is left as is.
    """
    for h in ("sha1", "md5", "crc32"):
        if isinstance(entry.get(h), list):
            return

    files_db = db.get("files", {})
    indexes = db.get("indexes", {})

    record = None

    # Anchor 1: SHA1 (strongest)
    sha1 = entry.get("sha1")
    if sha1 and isinstance(sha1, str):
        record = files_db.get(sha1)

    # Anchor 2: MD5 (strong)
    if record is None:
        md5 = entry.get("md5")
        if md5 and isinstance(md5, str):
            by_md5 = indexes.get("by_md5", {})
            ref = by_md5.get(md5.lower())
            if ref:
                ref_sha1 = ref if isinstance(ref, str) else (ref[0] if ref else None)
                if ref_sha1:
                    record = files_db.get(ref_sha1)

    # Anchor 3: CRC32 (32-bit, collisions theoretically possible).
    # Require size match when profile has a size to guard against collisions.
    if record is None:
        crc = entry.get("crc32")
        if crc and isinstance(crc, str):
            by_crc32 = indexes.get("by_crc32", {})
            ref = by_crc32.get(crc.lower())
            if ref:
                ref_sha1 = ref if isinstance(ref, str) else (ref[0] if ref else None)
                if ref_sha1:
                    candidate = files_db.get(ref_sha1)
                    if candidate is not None:
                        profile_size = entry.get("size")
                        if not profile_size or candidate.get("size") == profile_size:
                            record = candidate

    if record is None:
        return

    # Copy sibling hashes and size from the anchored record.
    for field in ("sha1", "md5", "sha256", "crc32"):
        if not entry.get(field) and record.get(field):
            entry[field] = record[field]
    if not entry.get("size") and record.get("size"):
        entry["size"] = record["size"]


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
_HASH_FIELDS = ("sha1", "md5", "sha256", "crc32")


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


def _require_by_slot(files: list[dict]) -> None:
    """A core that requires a name an entry answers for requires the entry.

    Merged by name, one core's alternatives land in several entries. Ymir
    reads sega_101.bin, mpr-17933.bin or saturn_bios.bin, so the sega_101.bin
    entry carries those aliases. kronos, yabause and yabasanshiro open
    saturn_bios.bin first and sega_101.bin as a fallback: they sat in that
    entry's _cores, out of its _required_by, while their saturn_bios.bin entry
    had them requiring it, and a platform line paired through the alias read
    them as optional. A core already among the entry's readers that requires
    one of its aliases, as another entry of the system, is one of its
    requirers. No reader is added.
    """
    required_by_name: dict[str, set[str]] = {}
    for entry in files:
        required_by_name.setdefault(entry["name"].lower(), set()).update(
            entry.get("_required_by", ())
        )
    for entry in files:
        # Only the aliases: entries sharing the entry's own name are other
        # files that name already kept apart (pak0.pak under each game).
        names = {str(alias).lower() for alias in entry.get("aliases") or ()}
        names.discard(entry["name"].lower())
        requirers = set().union(*(required_by_name.get(n, set()) for n in names))
        added = (requirers & entry.get("_cores", set())) - entry.get("_required_by", set())
        if added:
            entry["_required_by"] = entry.get("_required_by", set()) | added
            entry["required"] = True


def _brought(file_entry: dict, emu_name: str) -> set[str]:
    """The core and build that need the file brought, empty when the
    emulator installs it. An entry read without layer (a test, a caller of
    its own) is brought by its core's libretro build."""
    brought = file_entry.get("_brought", f"{emu_name}:libretro")
    return {brought} if brought else set()


def _shares_hash(a: dict, b: dict) -> bool:
    return any(
        _declared(a, field) & _declared(b, field)
        for field in ("sha1", "md5", "sha256", "crc32")
    )


def _declared(entry: dict, field: str) -> set[str]:
    """The values an entry declares for a hash field, one or a list."""
    value = entry.get(field)
    values = value if isinstance(value, list) else [value]
    return {str(v).lower() for v in values if v}


def _contents_disagree(a: dict, b: dict) -> bool:
    """A hash both declare without a value in common, or no size both admit."""
    for field in ("sha1", "md5", "sha256", "crc32"):
        ours, theirs = _declared(a, field), _declared(b, field)
        if ours and theirs and not ours & theirs:
            return True
    return _sizes_clash(a, b)


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
    for h in _HASH_FIELDS:
        theirs = file_entry.get(h, "")
        ours = existing.get(h, "")
        if not theirs:
            continue
        if not ours:
            existing[h] = theirs
            existing.setdefault("_hash_by", {})[h] = emu_name
            continue
        t_list = theirs if isinstance(theirs, list) else [theirs]
        o_list = ours if isinstance(ours, list) else [ours]
        if revision:
            known = {str(v).lower() for v in o_list}
            added = [v for v in t_list if str(v).lower() not in known]
            if added:
                existing[h] = [*o_list, *added]
            continue
        if not {str(v).lower() for v in t_list} & {str(v).lower() for v in o_list}:
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
                print(
                    f"WARNING: hash conflict for {file_entry['name']}: "
                    f"{h} {ours} ({first}) kept, {theirs} ({emu_name}) "
                    "left out of the model",
                    file=sys.stderr,
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
    for h in _HASH_FIELDS:
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
    entry["_hash_by"] = {h: emu_name for h in _HASH_FIELDS if entry.get(h)}
    return entry


def _has_exploitable_data(entry: dict) -> bool:
    """Check if an entry has any data beyond its name that can drive verification.

    Applied AFTER merging all cores so entries benefit from enrichment by
    sibling cores before being judged empty.
    """
    return bool(
        any(entry.get(h) for h in ("sha1", "md5", "sha256", "crc32"))
        or entry.get("path")
        or entry.get("size")
        or entry.get("min_size")
        or entry.get("max_size")
        or entry.get("validation")
        or entry.get("contents")
    )


def _system_dir_files(profile: dict, standalone: bool) -> list[dict]:
    """Entries of the build the platform runs, read from the system directory.

    An entry the platform's launchers leave outside the BIOS tree
    (``unplaced``) is not, nor one placed below its roms or an emulator
    folder (``root``): the platform has no file of its own there.
    """
    return [
        f for f in filter_files_by_mode(profile.get("files", []), standalone=standalone)
        if read_from_system_dir(f) and not f.get("unplaced") and f.get("root") not in OUTER_ROOTS
    ]


def _archives_not_members(files: list[dict]) -> list[dict]:
    """A profile's entries with the members of each archive folded into it.

    fbneo declares bubsys.zip as the ROMs it holds, each carrying
    `archive: bubsys.zip`. The platform reads the archive, never a member:
    as loose files the members were added to RetroArch's System.dat, and
    the 480-byte boot.bin was filed under the Dreamcast by its bare name.
    The archive stands in their place with the members as its contents,
    the shape a profile that declares the archive itself already has.
    """
    out: list[dict] = []
    archives: dict[tuple[str, str], dict] = {}
    for fe in files:
        archive = fe.get("archive")
        if not archive:
            out.append(fe)
            continue
        key = (archive, fe.get("system", ""))
        entry = archives.get(key)
        if entry is None:
            entry = {"name": archive, "category": "bios_zip", "contents": [],
                     "_brought": None}
            if fe.get("system"):
                entry["system"] = fe["system"]
            if fe.get("source_ref") is not None:
                entry["source_ref"] = fe["source_ref"]
            archives[key] = entry
            out.append(entry)
        if fe.get("required"):
            entry["required"] = True
        # The archive is brought when one member is: gngeo_data.zip, every
        # member of it installed by make install, is not a file to copy.
        if "_brought" not in fe:
            entry.pop("_brought", None)
        elif "_brought" in entry and entry["_brought"] is None:
            entry["_brought"] = fe["_brought"]
        entry["contents"].append({
            field: fe[field]
            for field in ("name", "size", "crc32", "sha1", "md5")
            if fe.get(field) is not None
        })
    return out


def _sizes(entry: dict) -> tuple[set[int] | None, int | None, int | None]:
    """The sizes an entry admits: exact values, then a min and a max."""
    raw = entry.get("size")
    values = raw if isinstance(raw, list) else [raw]
    exact = {int(v) for v in values if isinstance(v, int) and not isinstance(v, bool)}
    low, high = entry.get("min_size"), entry.get("max_size")
    return (exact or None,
            low if isinstance(low, int) else None,
            high if isinstance(high, int) else None)


def _sizes_clash(a: dict, b: dict) -> bool:
    """No size both entries admit, lists and ranges included."""
    exact_a, low_a, high_a = _sizes(a)
    exact_b, low_b, high_b = _sizes(b)

    def fits(value: int, low: int | None, high: int | None) -> bool:
        return (low is None or value >= low) and (high is None or value <= high)

    if exact_a and exact_b:
        return not exact_a & exact_b
    if exact_a:
        return not any(fits(v, low_b, high_b) for v in exact_a)
    if exact_b:
        return not any(fits(v, low_a, high_a) for v in exact_b)
    return False


def _identity(entry: dict, db: dict | None) -> dict:
    """The entry with the hashes and size the database knows for its hash."""
    probe = {k: entry[k] for k in ("sha1", "md5", "crc32", "size") if entry.get(k)}
    if db and probe and not any(isinstance(v, list) for v in probe.values()):
        _enrich_hashes(probe, db)
    return {**entry, **{k: v for k, v in probe.items() if not entry.get(k)}}


def _identity_values(entry: dict) -> set[str]:
    """Every hash an identity declares."""
    values: set[str] = set()
    for field in ("sha1", "md5", "sha256", "crc32"):
        values |= _declared(entry, field)
    return values


def _declaration_verdict(entry: dict, declaration: dict, db: dict | None) -> str:
    """same, other or undecided: can a platform declaration be this file?

    A shared hash proves it. Sizes no value of which agrees refute it, as
    name_match_size_ok refutes a candidate. Two hashes at one size are two
    revisions of one slot, as slots.py reads them, so they refute nothing.
    The size the database holds for a declared hash counts as declared:
    Batocera's BK BASIC10.ROM names only an md5, of a 24576-byte file, and
    clk's 16 KB Oric basic10.rom was filed under the BK beside it.
    """
    ours, theirs = _identity(entry, db), _identity(declaration, db)
    if _identity_values(ours) & _identity_values(theirs):
        return "same"
    if _sizes_clash(ours, theirs):
        return "other"
    return "undecided"


_REPO_PLATFORMS = Path(__file__).resolve().parent.parent / "platforms"


def _fold_data_directory_readers(
    systems: dict,
    profiles: dict,
    cores: list[str],
    standalone_set: set[str],
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
            emu_name, profiles[emu_name], standalone_set
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
                installed = platform_name in (tree.get("installed_on") or [])
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
    data_registry: dict | None = None,
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
        data_registry: the data directory registry (_data_dirs.yml), read
                from the repository's platforms/ when not given

    Returns a dict with platform metadata, systems, and per-file details
    including which cores reference each file.
    """
    # The layout rule verify and the pack builder apply: truth guessed its
    # own from the profile type where the platform names no standalone
    # emulator, and kept files the pack never carries.
    standalone_set = platform_standalone_set(config)

    resolved = resolve_platform_cores(config, profiles, target_cores)

    # Build mapping: profile system ID -> platform system ID
    # Three strategies, tried in order:
    # 1. File-based: if the scraped platform already has this file, use its system
    # 2. Exact match: profile system ID == platform system ID
    # 3. Normalized match: strip manufacturer prefix + separators
    platform_sys_ids = set(config.get("systems", {}).keys())

    # Every platform declaration of a name, in the platform's order. The
    # last one used to win, whatever the content.
    declared_by_name: dict[str, list[tuple[str, dict]]] = {}
    for psid, sys_data in config.get("systems", {}).items():
        for fe in sys_data.get("files", []):
            fname = fe.get("name", "").lower()
            if fname:
                declared_by_name.setdefault(fname, []).append((psid, fe))

    # Normalized ID -> platform system ID. Walked in the platform's order,
    # not the set's: two IDs normalizing alike went to whichever the hash
    # seed put last.
    norm_to_platform: dict[str, str] = {}
    for psid in config.get("systems", {}):
        norm_to_platform.setdefault(_norm_system_id(psid), psid)

    def _map_sys_id(profile_sid: str) -> str:
        """Map a profile system ID to the platform's system ID."""
        if profile_sid in platform_sys_ids:
            return profile_sid
        return norm_to_platform.get(_norm_system_id(profile_sid), profile_sid)

    def _attribute(fe: dict, own: str | None, on_platform: set[str]) -> list[str]:
        """The platform systems an entry belongs to, [] when nothing decides.

        A declaration of the same name settles the system only when it can
        be the same file: a shared hash, or no contradicting size. fmsx's
        16 KB DISK.ROM is not quasi88's 2 KB disk.rom, and dosbox's SC-55
        ROM1.BIN is not galaksija's. The same content declared under two
        systems is filed under both.
        """
        verdicts = [
            (psid, _declaration_verdict(fe, decl, db))
            for psid, decl in declared_by_name.get(fe.get("name", "").lower(), [])
        ]
        same = sorted({psid for psid, v in verdicts if v == "same"})
        undecided = sorted({psid for psid, v in verdicts if v == "undecided"})
        if own is not None:
            mapped = _map_sys_id(own)
            if any(psid == mapped and v != "other" for psid, v in verdicts):
                return [mapped]
            if same:
                return same
            if len(undecided) == 1:
                return undecided
            return [mapped]
        if same:
            return same
        if len(undecided) == 1:
            return undecided
        if undecided:
            ours = [psid for psid in undecided if psid in on_platform]
            return ours if len(ours) == 1 else []
        return [next(iter(on_platform))] if len(on_platform) == 1 else []

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

        # The pack's rule (validation.deliverable), per build: a file the
        # emulator installs is kept and marked, one the launcher never opens
        # is left out.
        filtered = _archives_not_members([
            {
                **fe,
                "_opens_by_name": opens_by_name(fe, profile, standalone),
                "_brought": None if installed_with_emulator(fe, platform_name)
                else f"{emu_name}:{'standalone' if standalone else 'libretro'}",
            }
            for view, standalone in platform_layouts(emu_name, profile, standalone_set)
            for fe in _system_dir_files(view, standalone)
            if not unread_on(fe, platform_name)
        ])

        on_platform = {
            _map_sys_id(sid) for sid in profile.get("systems", [])
        } & platform_sys_ids
        for fe in filtered:
            profile_sid = fe.get("system", "")
            sys_ids = profile.get("systems", [])
            if profile_sid:
                own: str | None = profile_sid
            elif len(sys_ids) == 1:
                own = sys_ids[0]
            elif not sys_ids:
                # A profile that names no system: a platform declaration of
                # the same file files it, and the placeholder takes only a
                # name the platform does not declare. mess2015's hiscore.dat
                # beside the arcade one put an "unknown" section in System.dat.
                own = None
            else:
                # A multi-system profile's entry without a system is filed by
                # the platform's own declaration of the same file, or the one
                # profile system the platform has. Otherwise it is not filed:
                # the first system was a guess, and CLK's Apple, Mac, ZX and
                # Amiga ROMs went to RomM as Amstrad CPC firmware.
                own = None
            sys_targets = _attribute(fe, own, on_platform)
            if not sys_ids and not profile_sid and not sys_targets \
                    and fe.get("name", "").lower() not in declared_by_name:
                sys_targets = [_map_sys_id("unknown")]
            if not sys_targets:
                unattributed[emu_name] = unattributed.get(emu_name, 0) + 1
                continue
            for position, sys_id in enumerate(sys_targets):
                system = systems.setdefault(sys_id, {})
                _merge_file_into_system(
                    system, fe if position == 0 else copy.deepcopy(fe), emu_name, db
                )
                sys_cov = system_cores.setdefault(
                    sys_id,
                    {
                        "profiled": set(),
                        "unprofiled": set(),
                    },
                )
                sys_cov["profiled"].add(emu_name)

    # Ensure all systems of resolved cores have entries (even with 0 files).
    # This documents that the system is covered: the core was analyzed and
    # needs no external files for this system. Sorted: the set's order is
    # the hash seed's, and it decided where each empty system was written.
    for emu_name in sorted(cores_profiled):
        profile = profiles[emu_name]
        for prof_sid in profile.get("systems", []):
            sys_id = _map_sys_id(prof_sid)
            systems.setdefault(sys_id, {})
            sys_cov = system_cores.setdefault(
                sys_id,
                {
                    "profiled": set(),
                    "unprofiled": set(),
                },
            )
            sys_cov["profiled"].add(emu_name)

    # Track unprofiled cores per system based on profile system lists
    for emu_name in cores_unprofiled:
        for sys_id in systems:
            sys_cov = system_cores.setdefault(
                sys_id,
                {
                    "profiled": set(),
                    "unprofiled": set(),
                },
            )
            sys_cov["unprofiled"].add(emu_name)

    _fold_data_directory_readers(
        systems, profiles, sorted(cores_profiled), standalone_set, platform_name,
        load_data_dir_registry(str(_REPO_PLATFORMS)) if data_registry is None
        else data_registry,
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

    # Convert sets to sorted lists for serialization
    for sys_id, sys_data in systems.items():
        for fe in sys_data.get("files", []):
            fe.pop("_hash_by", None)
            fe.pop("_region_void", None)
            fe["_cores"] = sorted(fe.get("_cores", set()))
            fe["_required_by"] = sorted(fe.get("_required_by", set()))
            one_of = fe.pop("_one_of", None)
            if one_of:
                fe["one_of"] = sorted(one_of)
            fe["_named_by"] = sorted(fe.get("_named_by", set()))
            fe["_brought_by"] = sorted(fe.get("_brought_by", set()))
            if not fe["_brought_by"]:
                fe["bundled"] = True
            fe["_source_refs"] = sorted(fe.get("_source_refs", set()))
        # Add per-system coverage
        cov = system_cores.get(sys_id, {})
        sys_data["_coverage"] = {
            "cores_profiled": sorted(cov.get("profiled", set())),
            "cores_unprofiled": sorted(cov.get("unprofiled", set())),
        }

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


# Platform truth diffing


def _path_tail(value: object) -> str:
    return str(value or "").replace("\\", "/").casefold()


def _hash_mismatch(t_entry: dict, s_entry: dict) -> dict | None:
    """The first hash field the export would correct, by the export's rule.

    contradicted_hashes is the one decision: a hash the code does not check
    contradicts nothing (checked_hashes), and a platform md5 that is a
    composite of a zip's members is no container md5 (comparable).
    """
    from exporter.baseline import contradicted_hashes

    fields = contradicted_hashes(t_entry, s_entry)
    if not fields:
        return None
    h = fields[0]
    return {
        "name": s_entry["name"],
        "hash_type": h,
        f"truth_{h}": t_entry.get(h, ""),
        f"scraped_{h}": s_entry.get(h, ""),
        "truth_cores": list(t_entry.get("_cores", [])),
    }


def _diff_system(truth_sys: dict, scraped_sys: dict) -> dict:
    """Compare files between truth and scraped for a single system.

    Entries are paired by pair_entries, the rule export_native applies. Two
    rules had diverged, and diff_truth flagged a hash the export did not
    correct while the export corrected hashes the diff never named. An entry
    never answers for two.
    """
    from exporter.baseline import _is_placeholder, is_label, pair_entries, platform_declares

    truth_files = [
        fe for fe in truth_sys.get("files", [])
        if fe.get("name") and not fe["name"].startswith("_")
        and not _is_placeholder(fe["name"])
    ]
    scraped_files = scraped_sys.get("files", [])

    missing: list[dict] = []
    hash_mismatch: list[dict] = []
    required_mismatch: list[dict] = []
    extra_phantom: list[dict] = []
    extra_unprofiled: list[dict] = []

    pairs = pair_entries(truth_files, scraped_files)
    claimed = set(pairs.values())
    for t_index, t_entry in enumerate(truth_files):
        s_position = pairs.get(t_index)
        if s_position is None:
            if (not is_label(t_entry) and not t_entry.get("bundled")
                    and not platform_declares(t_entry, scraped_files)):
                missing.append(
                    {
                        "name": t_entry["name"],
                        "destination": t_entry.get("path") or t_entry["name"],
                        "cores": list(t_entry.get("_cores", [])),
                        "source_refs": list(t_entry.get("_source_refs", [])),
                    }
                )
            continue
        s_entry = scraped_files[s_position]
        mismatch = _hash_mismatch(t_entry, s_entry)
        if mismatch:
            mismatch["destination"] = s_entry.get("destination") or s_entry["name"]
            hash_mismatch.append(mismatch)
        t_req = t_entry.get("required")
        s_req = s_entry.get("required")
        if t_entry.get("one_of_required") and not t_req:
            # Needed as one of a set: no value of its own to compare.
            t_req = None
        if t_req is not None and s_req is not None and t_req != s_req:
            required_mismatch.append(
                {
                    "name": s_entry["name"],
                    "destination": s_entry.get("destination") or s_entry["name"],
                    "truth_required": t_req,
                    "scraped_required": s_req,
                }
            )

    # A scraped entry no truth entry describes, by path, name or hash.
    unmatched_scraped = {
        position: s_entry
        for position, s_entry in enumerate(scraped_files)
        if position not in claimed
        and not any(platform_declares(t, [s_entry]) for t in truth_files)
    }

    # Scraped files not in truth -> extra
    coverage = truth_sys.get("_coverage", {})
    has_unprofiled = bool(coverage.get("cores_unprofiled"))
    # An archive declared once per ROM it holds (zipped_file) is still one
    # file.
    seen_extra: set[tuple[str, str]] = set()
    for s_key, s_entry in unmatched_scraped.items():
        key = (s_entry["name"].lower(), _path_tail(s_entry.get("destination")))
        if key in seen_extra:
            continue
        seen_extra.add(key)
        # The destination tells apart two declarations of one name: the
        # report listed six `hiscore.dat` to add beside one to drop.
        entry = {
            "name": s_entry["name"],
            "destination": s_entry.get("destination") or s_entry["name"],
        }
        if has_unprofiled:
            extra_unprofiled.append(entry)
        else:
            extra_phantom.append(entry)

    result: dict = {}
    if missing:
        result["missing"] = missing
    if hash_mismatch:
        result["hash_mismatch"] = hash_mismatch
    if required_mismatch:
        result["required_mismatch"] = required_mismatch
    if extra_phantom:
        result["extra_phantom"] = extra_phantom
    if extra_unprofiled:
        result["extra_unprofiled"] = extra_unprofiled
    return result


def _has_divergences(sys_div: dict) -> bool:
    """Check if a system divergence dict contains any actual divergences."""
    return bool(sys_div)


def _update_summary(summary: dict, sys_div: dict) -> None:
    """Update summary counters from a system divergence dict."""
    summary["total_missing"] += len(sys_div.get("missing", []))
    summary["total_extra_phantom"] += len(sys_div.get("extra_phantom", []))
    summary["total_extra_unprofiled"] += len(sys_div.get("extra_unprofiled", []))
    summary["total_hash_mismatch"] += len(sys_div.get("hash_mismatch", []))
    summary["total_required_mismatch"] += len(sys_div.get("required_mismatch", []))


def diff_platform_truth(truth: dict, scraped: dict) -> dict:
    """Compare truth YAML against scraped YAML, returning divergences.

    System IDs are matched using normalized forms (via _norm_system_id) to
    handle naming differences between emulator profiles and scraped platforms
    (e.g. 'sega-game-gear' vs 'sega-gamegear').
    """
    truth_systems = truth.get("systems", {})
    scraped_systems = scraped.get("systems", {})

    summary = {
        "systems_compared": 0,
        "systems_fully_covered": 0,
        "systems_partially_covered": 0,
        "systems_uncovered": 0,
        "total_missing": 0,
        "total_extra_phantom": 0,
        "total_extra_unprofiled": 0,
        "total_hash_mismatch": 0,
        "total_required_mismatch": 0,
    }

    divergences: dict[str, dict] = {}
    uncovered_systems: list[str] = []

    # Build normalized-ID lookup for truth systems
    norm_to_truth: dict[str, str] = {}
    for sid in truth_systems:
        norm_to_truth[_norm_system_id(sid)] = sid

    # Match scraped systems to truth via normalized IDs
    matched_truth: set[str] = set()

    for s_sid in sorted(scraped_systems):
        norm = _norm_system_id(s_sid)
        t_sid = norm_to_truth.get(norm)

        if t_sid is None:
            # Also try exact match (in case normalization is lossy)
            if s_sid in truth_systems:
                t_sid = s_sid
            else:
                uncovered_systems.append(s_sid)
                summary["systems_uncovered"] += 1
                continue

        matched_truth.add(t_sid)
        summary["systems_compared"] += 1
        sys_div = _diff_system(truth_systems[t_sid], scraped_systems[s_sid])

        if _has_divergences(sys_div):
            divergences[s_sid] = sys_div
            _update_summary(summary, sys_div)
            summary["systems_partially_covered"] += 1
        else:
            summary["systems_fully_covered"] += 1

    # Truth systems not matched by any scraped system: all files missing
    for t_sid in sorted(truth_systems):
        if t_sid in matched_truth:
            continue
        summary["systems_compared"] += 1
        sys_div = _diff_system(truth_systems[t_sid], {"files": []})
        if _has_divergences(sys_div):
            divergences[t_sid] = sys_div
            _update_summary(summary, sys_div)
            summary["systems_partially_covered"] += 1
        else:
            summary["systems_fully_covered"] += 1

    result: dict = {"summary": summary}
    if divergences:
        result["divergences"] = divergences
    if uncovered_systems:
        result["uncovered_systems"] = uncovered_systems
    return result
