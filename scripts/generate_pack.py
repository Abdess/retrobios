#!/usr/bin/env python3
"""Generate platform-specific BIOS ZIP packs.

Usage:
    python scripts/generate_pack.py --platform retroarch [--output-dir dist/]
    python scripts/generate_pack.py --all [--output-dir dist/]

Reads platform YAML config + database.json -> creates ZIP with correct
file layout for each platform. Handles inheritance, shared groups, variants,
and 3-tier storage (embedded/external/user_provided).
"""

from __future__ import annotations

import sys

# The README's first command. Under 3.8 it stopped on a SyntaxError that read
# like a damaged file. The build needs 3.9, as pipeline.py says.
if sys.version_info < (3, 9):
    sys.exit(f"generate_pack.py needs Python 3.9 or newer, this is {sys.version.split()[0]}")

from collections.abc import Callable, Iterable, Iterator

from artifacts import _build_timestamp, set_plain_mode
import argparse
import contextlib
import functools
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, os.path.dirname(__file__))
from alternatives import core_file_spares, settle_sets, slot_set_keys
from common import resolve_platform_cores as _platform_cores
from common import (
    ROMS_ROOT,
    TARGET_KEY,
    _core_key,
    content_folder_boards,
    OUTER_ROOTS,
    outer_layout,
    installed_data_refs,
    platform_arg,
    require_directory,
    target_listing_line,
    suggest_names,
    system_index,
    require_platform,
    load_target_config,
    archive_entry,
    profiles_for_systems,
    write_text_atomic,
    archive_is_optional,
    artifact_lock,
    repository_output_lock,
    ArtifactLockBusy,
    build_target_cores_cache,
    build_zip_contents_index,
    compute_hashes,
    expand_directory_entries,
    filter_systems_by_target,
    group_identical_platforms,
    list_emulator_profiles,
    list_platform_system_ids,
    platform_system_names,
    resolve_system_arg,
    print_platform_listing,
    select_systems,
    platform_scope_systems,
    system_scope_error,
    canonical_target_name,
    platform_files_target,
    list_registered_platforms,
    list_release_pack_platforms,
    list_system_ids,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    without_profile_blind,
    MANUFACTURER_PREFIXES,
    _norm_system_id,
    require_yaml,
    ProfileSelectionError,
    core_system_dirs,
    declared_root,
    downloadable_on,
    downloaded_only_profiles,
    list_available_targets,
    entry_serves_systems,
    entry_system_ids,
    platform_layouts,
    sanitize_pack_path,
    select_emulator_profiles,
    standalone_set,
    system_core_reach,
    upstream_profile_index,
    yaml_load,
)
import packresolve
from refresh_data_dirs import cache_lock, hold_data_dirs
import region as region_mod
from manifestselect import SelectionIndex
import slot as slot_mod
import slots
import split_pack
from gamedata import GAME_DATA, GameDataCut, is_game_data, platform_game_data, without_game_data
from deterministic_zip import _FIXED_DATE_TIME
from largefiles import asset_name, load_registered_paths, published_asset_name
from nativemode import (
    digest_algorithm,
    hash_mismatch_excludes_file,
    reads_file_contents,
)
from validation import (
    baseline_verdict,
    existence_discrepancy,
    destination_owners,
    validated_choice,
    agnostic_substitute,
    _build_validation_index,
    _parse_validation,
    deliverable,
    read_from_system_dir,
    with_archive_members,
    extra_alternatives,
)

yaml = require_yaml()

DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB_FILE = "database.json"
DEFAULT_OUTPUT_DIR = "dist"
DEFAULT_BIOS_DIR = "bios"



# Formats that are already compressed: deflating them again took 28 s of the
# RetroArch build for 2.1 GB of members and saved 9.6 MB (0.45 %), 16 GB and
# about 72 MB across all packs. Measured per extension on the 2026-10-20
# packs; .pk3 (3 %), .jpg (6 %), .avi (44 %) and .jar (60 %) still shrink
# and stay deflated. Chosen by name alone, so a pack stays a function of its
# inputs.
_STORED_EXTENSIONS = frozenset({".7z", ".chd", ".ogg", ".pk4", ".png", ".zip"})


def _member_compression(arcname: str) -> int:
    """ZIP_STORED for a member whose format is already compressed."""
    if os.path.splitext(arcname)[1].lower() in _STORED_EXTENSIONS:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


class PackRecord:
    """A pack build kept in memory: the paths it writes, no archive.

    ``members`` is every path written, ``files`` the ones the build counts as
    the profile's files (archives and loose files, not trees or notes), and
    ``trees`` the members a platform pack takes from its data directories.
    The pipeline builds every emulator pack and every narrowed platform pack
    this way and compares them with what verify credits, without reading or
    compressing a byte.
    """

    def __init__(self) -> None:
        self.members: list[str] = []
        self.files: list[str] = []
        self.trees: list[str] = []
        # The collection file each copied member comes from: a split part
        # writes a file only where the full pack writes the same bytes.
        self.sources: dict[str, str] = {}


def _add_pack_member(
    zf: zipfile.ZipFile | PackRecord, source_path: str, arcname: str
) -> None:
    """Add a file to the pack with metadata that does not depend on the build.

    ZipFile.write copies the source file's mtime into the member. For a file
    this build just produced in tmp/ that is the wall clock, and for a file
    from the collection it is whenever the clone was checked out, so a pack
    rebuilt from identical inputs differed from the last one although every
    byte of content matched: 348 members of the Recalbox pack moved between
    two consecutive builds. The content is streamed rather than read whole,
    because some members are firmware images of several hundred megabytes.
    """
    if isinstance(zf, PackRecord):
        zf.members.append(arcname)
        zf.sources[arcname] = source_path
        return
    info = zipfile.ZipInfo(filename=arcname, date_time=_FIXED_DATE_TIME)
    info.compress_type = _member_compression(arcname)
    # The executable bit is the one permission worth carrying: the RetroDECK
    # pack ships the two Voxatron engine binaries, and a user who extracts
    # them at 644 cannot run them. Git records the bit, so reading it from
    # the source keeps the pack the same from any clone. Nothing else about
    # the source's mode reaches the archive.
    stat_result = os.stat(source_path)
    mode = 0o755 if stat_result.st_mode & 0o111 else 0o644
    info.external_attr = (0o100000 | mode) << 16
    size = stat_result.st_size
    info.file_size = size
    with open(source_path, "rb") as source, zf.open(
        info, "w", force_zip64=size >= 1 << 31
    ) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)


def _write_generated_member(
    zf: zipfile.ZipFile | PackRecord, arcname: str, text: str
) -> None:
    """Write a pack member the builder composes rather than copies.

    READMEs, instruction notes and the manifest are produced at build time,
    so writestr would stamp them with the wall clock and give the same pack
    a different hash on every run. Pinning them to the epoch the archive
    rebuilder already uses makes a pack a function of its inputs alone.
    """
    if isinstance(zf, PackRecord):
        zf.members.append(arcname)
        return
    info = zipfile.ZipInfo(filename=arcname, date_time=_FIXED_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, text)


def _narrowings(
    source: str,
    regions: list[str] | None,
    target_name: str | None,
    one_per_slot: bool,
    required_only: bool,
    standalone: bool = False,
    no_game_data: bool = False,
) -> list[tuple[str, str]]:
    """Every dimension that narrows a pack, as (filename tag, plain label).

    The pack name and the pack README are both built from this list, so a new
    way of narrowing a pack cannot reach users nameless or unannounced. Order
    is the filename order and must not change: it is what existing archives
    are called.
    """
    applied: list[tuple[str, str]] = []
    if source == "platform":
        applied.append(("_Platform", "only what the platform declares"))
    elif source == "truth":
        applied.append(("_Truth", "only what emulator profiles require"))
    if regions:
        pretty = ", ".join(
            " ".join(w.title() for w in slug.split("-")) for slug in regions
        )
        applied.append(
            (f"_{region_mod.region_tag(regions)}", f"region priority {pretty}")
        )
    if target_name:
        applied.append(
            (f"_{_target_tag(target_name)}", f"cores available on {target_name}")
        )
    if one_per_slot:
        applied.append(("_OnePerSlot", "one BIOS per system and region"))
    if standalone:
        applied.append(("_Standalone", "standalone mode files only"))
    if required_only:
        applied.append(("_Required", "required files only"))
    if no_game_data:
        applied.append(("_NoGameData", "firmware only, game data left out"))
    return applied


@contextlib.contextmanager
def _writing_pack(zip_path: str) -> Iterator[zipfile.ZipFile]:
    """A pack written beside its final name, swapped in once complete.

    Opened on the final name, a rebuild truncated the previous pack at once,
    and a build that raised half way still wrote a central directory: a
    readable ZIP holding part of the files, which the run then checked and
    summed as the pack.
    """
    directory = os.path.dirname(zip_path) or "."
    fd, scratch = tempfile.mkstemp(
        prefix=f".{os.path.basename(zip_path)}.", suffix=".partial", dir=directory
    )
    os.close(fd)
    try:
        with zipfile.ZipFile(scratch, "w", zipfile.ZIP_DEFLATED) as zf:
            yield zf
        set_plain_mode(scratch)
        os.replace(scratch, zip_path)
    except BaseException:
        Path(scratch).unlink(missing_ok=True)
        raise


def _target_tag(target_name: str) -> str:
    """Filename tag for a hardware target.

    Without it a targeted pack takes the same name as the full one and
    overwrites it.
    """
    return "".join(
        part.title() for part in re.split(r"[-_\s]+", target_name.strip()) if part
    )


def _platform_target(
    platform_name: str, target: str | None, platforms_dir: str
) -> str | None:
    """The target as this platform files it, the name its artifacts carry.

    Named once for the whole run, a target two platforms file differently
    (rpi4: Batocera's bcm2711, Recalbox's rpi4_64) kept the typed name under
    --all and took the platform's own under --platform, so --verify-packs
    looked for a pack the --all build had named otherwise. A platform that
    does not file the target is packed whole under --all, and its name
    claims no narrowing: BizHawk_..._Switch_BIOS_Pack.zip was the full pack.
    """
    if not target or not platform_files_target(platform_name, target, platforms_dir):
        return None
    return canonical_target_name([platform_name], target, platforms_dir)


def _system_tag(system_filter: list[str] | None) -> str:
    """Filename tag for a pack limited to some systems, empty for all."""
    if not system_filter:
        return ""
    display_parts = []
    for sid in system_filter:
        s = sid.lower().replace("_", "-")
        for prefix in MANUFACTURER_PREFIXES:
            if s.startswith(prefix):
                s = s[len(prefix) :]
                break
        display_parts.append("_".join(p.title() for p in s.split("-") if p))
    return "_" + _bounded_join(display_parts, system_filter)


# A system list long enough to push a pack name past this falls back to the
# first system, a count and a digest of the list.
MAX_SYSTEM_TAG_BYTES = 120


def _bounded_join(parts: list[str], keys: list[str]) -> str:
    """Parts joined while they fit, else the first, a count and a digest.

    Thirty systems joined made a 261-byte file name and the ZIP could not
    be opened. The digest keeps two different selections apart. The joiner
    is one no part holds: with "_", sega-dreamcast + arcade and
    sega-dreamcast-arcade both named Dreamcast_Arcade, and the second build
    replaced the first.
    """
    joined = "+".join(parts)
    if len(joined.encode("utf-8")) <= MAX_SYSTEM_TAG_BYTES:
        return joined
    digest = hashlib.sha1("\n".join(sorted(keys)).encode("utf-8")).hexdigest()[:8]
    return f"{parts[0]}_and_{len(parts) - 1}_more_{digest}"


_UNSAFE_IN_NAME = re.compile(r'[/\\:*?"<>|]')


def _name_part(text: str, space: str = "") -> str:
    """A display name made safe to stand in a file name.

    'FinalBurn Neo (CPS-1/CPS-2)' named a directory that did not exist, and a
    Windows user cannot write ':' or '?' either.
    """
    return _UNSAFE_IN_NAME.sub("-", text.replace(" ", space))


def _platform_pack_stem(
    group_platforms: list[str], representative: str, platforms_dir: str
) -> str:
    """Platform part of a pack name, version included.

    A group of identical platforms shares one pack named after all of them,
    and the builder and --verify-packs both read the name from here.
    """
    rep_cfg = load_platform_config(representative, platforms_dir)
    version = rep_cfg.get("version", rep_cfg.get("dat_version", ""))
    version_tag = f"_{_name_part(str(version))}" if version else ""
    return platform_pack_prefix(group_platforms, representative, platforms_dir) + version_tag


def platform_pack_prefix(
    group_platforms: list[str], representative: str, platforms_dir: str
) -> str:
    """Platform part of a pack name without the version.

    The site reads a pack's version back by removing this prefix: a version
    may hold an underscore (AmberELEC prerelease-20261019_1835).
    """
    if len(group_platforms) <= 1:
        rep_cfg = load_platform_config(representative, platforms_dir)
        return _name_part(rep_cfg.get("platform", representative), "_")
    names = [
        load_platform_config(p, platforms_dir).get("platform", p)
        for p in group_platforms
    ]
    return "_".join(_name_part(n) for n in names)


def platform_list_version(config: dict, platform: str) -> str:
    """The version of the list a platform's YAML transcribes: the release
    tag the scraper read, or for a list kept on a branch with no release,
    the date of the commit it pinned. load_platform_config never passes a
    parent's version to a child, Lakka is not RetroArch v1.22.2.

    The installer compares it with the version a machine runs, so a missing
    value is refused rather than written as a stand-in.
    """
    version = str(config.get("version") or "").strip()
    if not version:
        raise ValueError(
            f"{platform}: the platform YAML records no version of its own"
        )
    return version


# What the builder writes into a platform pack beside the files it carries.
PACK_DOCUMENTS = ("README.txt", "manifest.json")


def pack_markers(
    platform_name: str, target_name: str | None, platforms_dir: str
) -> tuple[str, ...]:
    """The empty files a pack carries for the systems it is unzipped on,
    as named before flattening: the .nomedia of a pack for Android."""
    from common import list_available_targets

    names = [t["name"] for t in list_available_targets(platform_name, platforms_dir)]
    return (MEDIA_MARKER,) if lands_on_android(names, target_name) else ()


def core_data_trees(
    config: dict,
    profiles: dict[str, dict],
    platform_name: str,
    data_registry: dict | None,
    target_cores: set[str] | None = None,
) -> list[dict]:
    """The data directories the platform's cores read, as tree references.

    A profile's ``data_directories`` reach the pack of every platform that
    runs the core as a libretro core, below the system directory it hands
    the core (and the build's own folder, ``pack_structure``), as the
    emulator pack lays them out. Left out: a tree the platform's package
    installs, for this core or another reading the same tree
    (``installed_data_refs``), one the build bundles or the platform never
    opens (``deliverable``), and one whose registry entry names the
    platforms it serves (``for_platforms``) without this one. A standalone build reads its data below its own folder, which a
    tree's destination does not describe, so its trees stay out, as does a
    tree read beside the content (``load_from``).

    Each reference carries the profile's systems (``source_systems``, as a
    core extra does), which --system and --split narrow on.
    """
    if not data_registry:
        return []
    installed = installed_data_refs(platform_name)
    handed = standalone_set(config)
    # Relative to base_destination, which the members are written under. A
    # platform with none writes its BIOS folder into every destination, and
    # the trees go there as the core extras do.
    root = declared_root(config)
    trees: list[dict] = []
    seen: dict[tuple[str, str], int] = {}
    for core in sorted(_platform_cores(config, profiles, target_cores)):
        profile = profiles[core]
        if all(standalone for _view, standalone in platform_layouts(core, profile, handed)):
            continue
        declared = [t for t in profile.get("data_directories") or [] if isinstance(t, dict)]
        directories = core_system_dirs(core, profile, handed)
        structure = str((profile.get("pack_structure") or {}).get("libretro") or "")
        for tree in deliverable(declared, False, platform_name):
            if not read_from_system_dir(tree):
                continue
            ref = str(tree.get("ref") or "")
            entry = data_registry.get(ref)
            if entry is None or ref in installed:
                continue
            allowed = entry.get("for_platforms")
            if allowed and platform_name not in allowed:
                continue
            for directory in [""] if directories is None else directories:
                destination = prefixed_destination("/".join(
                    part.strip("/")
                    for part in (directory, structure, str(tree.get("destination") or ""))
                    if part.strip("/")
                ), root) or root
                if (ref, destination) in seen:
                    # One tree, read by a second core: the manifest says both
                    # (tree_readers), the pack writes it once.
                    first = trees[seen[(ref, destination)]]
                    if core not in first["readers"]:
                        first["readers"].append(core)
                    continue
                seen[(ref, destination)] = len(trees)
                trees.append({
                    "ref": ref,
                    "destination": destination,
                    "required": tree.get("required"),
                    "core": core,
                    "readers": [core],
                    "source_systems": entry_system_ids(tree, profile),
                })
    return trees


def _in_data_cache(path: str, data_registry: dict | None) -> bool:
    """Whether a resolved file lies in one of the data directory caches."""
    real = os.path.realpath(path)
    return any(
        real.startswith(os.path.realpath(entry["local_cache"]) + os.sep)
        for entry in (data_registry or {}).values()
        if entry.get("local_cache")
    )


def _tree_references(
    pack_systems: dict, core_trees: Iterable[dict],
) -> Iterator[tuple[tuple[str, ...], dict]]:
    """(systems, reference) for each tree a pack carries: those its systems
    declare, then those its cores read."""
    for sys_id, system in sorted(pack_systems.items()):
        for dd in system.get("data_directories", []):
            yield (sys_id,), dd
    for tree in core_trees:
        yield tuple(tree["source_systems"]), tree


def _data_directory_members(
    pack_systems: dict,
    data_registry: dict | None,
    platform_name: str,
    base_dest: str,
    case_insensitive: bool,
    seen_destinations: set,
    seen_lower: set,
    seen_parents: set,
    refs_out: dict | None = None,
    required_only: bool = False,
    core_trees: Iterable[dict] = (),
    reclaim: dict[str, str] | None = None,
) -> Iterator[tuple[str, str]]:
    """Yield (source, destination) for the cached data directories a
    platform's systems declare, then those its cores read (``core_trees``,
    from core_data_trees).

    ``reclaim`` maps a destination already taken to the cache file it was
    resolved to: the manifest found the platform's entry there and cannot
    list it as a file, so the tree yields it once more and the installer
    gets it from the tree's archive.

    ``refs_out``, when given, maps each yielded destination to
    (registry key, system ids, directory destination, whether the core
    needs the tree), for the manifest.

    These are not BIOS and carry no hash of their own: they are whole
    trees an emulator reads, refreshed from upstream, so what ships is
    whatever the cache holds. The pack and the install manifest both read
    this, the first to write the files and the second to count them.
    ``required_only`` leaves out a tree declared ``required: false``, one the
    core runs without, as it leaves out such a file.
    """
    # Data directories from _data_dirs.yml
    for systems, dd in _tree_references(pack_systems, core_trees):
        ref_key = dd.get("ref", "")
        if not ref_key or not data_registry or ref_key not in data_registry:
            continue
        needed = dd.get("required") is not False
        if required_only and not needed:
            continue
        if ref_key in installed_data_refs(platform_name):
            continue
        entry = data_registry[ref_key]
        allowed = entry.get("for_platforms")
        if allowed and platform_name not in allowed:
            continue
        local_path = entry.get("local_cache", "")
        if not local_path or not os.path.isdir(local_path):
            print(
                f"  WARNING: data directory '{ref_key}' not cached at {local_path} (run refresh_data_dirs.py)"
            )
            _MISSING_DATA_DIRS.add(ref_key)
            continue
        dd_dest = dd.get("destination", "")
        if base_dest and dd_dest:
            dd_prefix = f"{base_dest}/{dd_dest}"
        elif base_dest:
            dd_prefix = base_dest
        else:
            dd_prefix = dd_dest
        # Held while the caller writes what is yielded: a refresh swapping
        # the tree waits until the walk is done.
        with cache_lock(local_path, shared=True):
            for root, _dirs, filenames in os.walk(local_path):
                for fname in filenames:
                    src = os.path.join(root, fname)
                    rel = os.path.relpath(src, local_path)
                    full = f"{dd_prefix}/{rel}" if dd_prefix else rel
                    if reclaim and full in reclaim and (
                        os.path.normpath(reclaim[full]) == os.path.normpath(src)
                    ):
                        del reclaim[full]
                        if refs_out is not None:
                            refs_out[full] = (ref_key, systems, dd_prefix, needed)
                        yield src, full
                        continue
                    if full in seen_destinations or (
                        full.lower() in seen_lower and case_insensitive
                    ):
                        continue
                    if _has_path_conflict(full, seen_destinations, seen_parents):
                        continue
                    seen_destinations.add(full)
                    _register_path(full, seen_destinations, seen_parents)
                    if case_insensitive:
                        seen_lower.add(full.lower())
                    if refs_out is not None:
                        refs_out[full] = (ref_key, systems, dd_prefix, needed)
                    yield src, full


def _pack_data_directories(
    zf: zipfile.ZipFile | PackRecord,
    pack_systems: dict,
    data_registry: dict | None,
    platform_name: str,
    base_dest: str,
    flatten: bool,
    case_insensitive: bool,
    seen_destinations: set,
    seen_lower: set,
    seen_parents: set,
    required_only: bool = False,
    core_trees: Iterable[dict] = (),
) -> int:
    """Add the data directories to the pack. Returns how many files went in."""
    added = 0
    for src, full in _data_directory_members(
        pack_systems, data_registry, platform_name, base_dest,
        case_insensitive, seen_destinations, seen_lower, seen_parents,
        required_only=required_only, core_trees=core_trees,
    ):
        _add_pack_member(zf, src, _flat(full, base_dest, flatten))
        if isinstance(zf, PackRecord):
            zf.trees.append(_flat(full, base_dest, flatten))
        added += 1
    return added


def _case_twin_pairs(
    twins: list[str], seen_destinations: set[str], base_dest: str, flatten: bool,
) -> list[tuple[str, str]]:
    """Each spelling left out, with the spelling the pack holds."""
    held = {
        _flat(dest, base_dest, flatten).lower(): _flat(dest, base_dest, flatten)
        for dest in seen_destinations
    }
    return sorted({(twin, held[twin.lower()]) for twin in twins if twin.lower() in held})


def _report_pack_counts(
    zip_path: str,
    file_status: dict,
    total_files: int,
    core_count: int,
    source: str,
    verification_mode: str,
    tree_count: int = 0,
) -> None:
    """Print the line the pipeline's consistency check reads.

    The check compares these counts against what verify.py reports for
    the same platform, so the wording is a contract: parse_pack_counts
    in pipeline.py matches on it.
    """
    files_ok = sum(1 for s in file_status.values() if s == "ok")
    files_untested = sum(1 for s in file_status.values() if s == "untested")
    files_excluded = sum(1 for s in file_status.values() if s == "excluded")
    files_miss = sum(1 for s in file_status.values() if s == "missing")
    total_checked = len(file_status)

    parts = [f"{files_ok}/{total_checked} files OK"]
    if files_untested:
        parts.append(f"{files_untested} untested")
    if files_excluded:
        parts.append(f"{files_excluded} unsafe excluded")
    if files_miss:
        parts.append(f"{files_miss} missing")
    if source == "platform":
        print(
            f"  {zip_path}: {total_files} files packed (platform baseline only), "
            f"{', '.join(parts)} [{verification_mode}]"
        )
    elif source == "truth":
        print(
            f"  {zip_path}: {total_files} files packed (ground truth only), "
            f"{core_count} from emulator profiles [{verification_mode}]"
        )
    else:
        baseline = total_files - core_count - tree_count
        trees = f"{tree_count} in core data trees + " if tree_count else ""
        print(
            f"  {zip_path}: {total_files} files packed ({baseline} baseline + "
            f"{trees}{core_count} from cores), {', '.join(parts)} [{verification_mode}]"
        )

def _select_variants(
    config: dict,
    pack_systems: dict,
    emulators_dir: str,
    db: dict,
    base_dest: str,
    emu_profiles: dict | None,
    target_cores: set[str] | None,
    source: str,
    regions: list[str] | None,
    one_per_slot: bool,
    required_only: bool = False,
    undeclared: list[dict] | None = None,
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    slot_overrides: dict[str, str] | None = None,
) -> tuple[set, list, list]:
    """Which regional and slot alternatives this pack leaves out.

    Both reductions are decided once, over the platform baseline and the
    core extras together: deciding them separately is how the report and
    the pack came to withdraw different files for the same request.
    Returns the destinations to drop, the groups kept only as a
    fallback, and the slots no profile puts in order.
    """
    region_drops: set[str] = set()
    region_fallbacks: list[str] = []
    # One grouping for both passes: a file judged in its own system by one
    # pass must not land in every system of its profile for the other.
    region_groups: dict[str, list[tuple[str, str]]] = {}
    held: set[str] = set()
    if regions or one_per_slot:
        region_groups, _extra_dests = platform_region_groups(
            config,
            pack_systems,
            emulators_dir,
            db,
            base_dest,
            emu_profiles,
            target_cores=target_cores,
            include_extras=(source != "platform"),
            include_all=(source == "truth"),
            required_only=required_only,
            held_out=held,
            undeclared=undeclared,
            zip_contents=zip_contents,
            data_registry=data_registry,
            slot_overrides=slot_overrides,
        )
    if regions:
        region_index = region_mod.platform_region_index(
            config, emu_profiles or {}, target_cores
        )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions, held
        )
        region_fallbacks = region_mod.fallback_groups(
            region_groups, region_index, regions
        )

    slot_undecidable: list[str] = []
    if one_per_slot:
        slot_groups = {
            sys_id: [(d, n) for d, n in members if d not in region_drops]
            for sys_id, members in region_groups.items()
        }
        slot_drops, slot_undecidable = slot_mod.resolve_slot_drops(
            slot_groups,
            slot_mod.platform_slot_index(config, emu_profiles or {}, target_cores),
            held,
        )
        region_drops = region_drops | slot_drops
        if slot_undecidable:
            print(
                f"  {len(slot_undecidable)} slot(s) with no declared order: "
                f"every candidate kept"
            )

    return region_drops, region_fallbacks, slot_undecidable


def _platform_pack_name(
    platform_name: str,
    platforms_dir: str,
    narrowings: list[tuple[str, str]],
    system_filter: list[str] | None,
    pack_name: str | None = None,
) -> str:
    """File name of a platform pack: stem, narrowing tags, system tag.

    A caller naming the pack itself (a --split part) is taken at its word.
    """
    if pack_name:
        return pack_name
    stem = _platform_pack_stem([platform_name], platform_name, platforms_dir)
    tags = "".join(tag for tag, _label in narrowings)
    return f"{stem}{tags}_BIOS_Pack{_system_tag(system_filter)}.zip"


def _matches_an_alternative(fe: dict, local_path: str, profiles: dict) -> bool:
    """Whether the copy is another version the same profile accepts there.

    A profile lists every version its code takes under one name (each GRP
    of Raze's table, eduke32's demo and retail NWINTER.GRP). The extra
    carries the first, and the held copy matching a sibling is no mismatch.
    """
    siblings = extra_alternatives(fe, profiles)
    if len(siblings) < 2:
        return False
    # A sibling the code takes without a check (Raze's "BLOOD: Unknown
    # Version") accepts whatever copy fills the slot.
    if any(not _parse_validation(entry.get("validation")) for entry in siblings):
        return True
    actual = compute_hashes(local_path, frozenset({"sha1", "md5", "crc32"}))
    for entry in siblings:
        for algorithm in ("sha1", "md5", "crc32"):
            declared = entry.get(algorithm)
            values = declared if isinstance(declared, list) else [declared]
            if any(v and str(v).lower() == actual.get(algorithm, "") for v in values):
                return True
    return False


def _report_left_out(cut: GameDataCut, systems: set[str], cores: bool) -> None:
    """Name the game data a --no-game-data build left out, and why.

    ``systems`` limits the platform layer to the systems this pack covers,
    and ``cores`` says whether this pack collected the core files itself:
    a split part does not, its run names them once.
    """
    kept = [
        item for item in cut.left_out
        if (item.layer == "platform" and item.system in systems)
        or (item.layer == "core" and cores)
    ]
    for line in GameDataCut(cut.config, cut.profiles, kept).report_lines():
        print(f"  {line}")


def generate_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    required_only: bool = False,
    system_filter: list[str] | None = None,
    precomputed_extras: list[dict] | None = None,
    extras_only: bool = False,
    source: str = "full",
    flatten: bool = True,
    regions: list[str] | None = None,
    target_name: str | None = None,
    one_per_slot: bool = False,
    offline: bool | None = None,
    pack_name: str | None = None,
    no_game_data: bool = False,
    record: PackRecord | None = None,
    within: dict[str, str] | None = None,
) -> str | None:
    """Generate a ZIP pack for a platform.

    ``no_game_data`` leaves out the platform's entries categorized as game
    data and the cores' ``category: game_data`` files, and names each one.

    ``pack_name`` replaces the derived file name: a split part is named after
    its group, and a name built from every system of a hundred-system group
    is longer than a file name can be.

    ``record`` builds the pack in memory (PackRecord): no archive is written,
    no external file fetched, and the paths are kept on it.

    ``within`` is the full pack's PackRecord.sources, given to a split part:
    a declared file or core extra is written only where the full pack writes
    the same bytes. A part sees neither the other systems' declarations nor
    their extras, so a path the full pack settles (a file/directory conflict,
    a case twin, a path another system's file takes) was written again.

    Returns the path to the generated ZIP, or None on failure.
    """
    config = load_platform_config(platform_name, platforms_dir)
    if target_name:
        config = {**config, TARGET_KEY: target_name}
    if zip_contents is None:
        zip_contents = {}
    if emu_profiles is None:
        # The pipeline always passes them, but a caller that does not must get the
        # same pack, not one built without validation, slots or agnostic cores.
        emu_profiles = load_emulator_profiles(emulators_dir)
    # Cut from the full config and profiles: the category of a platform
    # entry is read from the profiles' game data entries.
    cut = (
        without_game_data(config, emu_profiles, data_registry, target_cores)
        if no_game_data else None
    )
    if cut is not None:
        config, emu_profiles = cut.config, cut.profiles

    verification_mode = config.get("verification_mode", "existence")
    platform_display = config.get("platform", platform_name)
    base_dest = config.get("base_destination", "")

    narrowings = _narrowings(
        source, regions, target_name, one_per_slot, required_only,
        no_game_data=no_game_data,
    )
    zip_path = os.path.join(
        output_dir,
        _platform_pack_name(
            platform_name, platforms_dir, narrowings, system_filter, pack_name
        ),
    )
    if record is None:
        os.makedirs(output_dir, exist_ok=True)

    # Case-insensitive dedup only for platforms targeting Windows/macOS.
    # Linux-only platforms (Batocera, Recalbox, RetroDECK, Lakka, RomM)
    # are case-sensitive and may have distinct files like DISK.ROM vs disk.rom.
    case_insensitive = config.get("case_insensitive_fs", False)

    total_files = 0
    missing_files = []
    # Core extras whose local copy contradicts the profile hash: packed,
    # reported, and never counted against the platform's own file total.
    core_discrepancies: list[str] = []
    user_provided = []
    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()  # only used when case_insensitive=True
    # Spellings left out as case twins of a packed file, for the README.
    case_twins: list[str] = []
    seen_parents: set[str] = (
        set()
    )  # parent dirs of added files (path conflict detection)
    # Per-destination status.  ``excluded`` means a same-named local payload
    # exists but contradicts the declaration and is intentionally not shipped.
    # It is distinct from a genuine coverage gap (``missing``).
    file_status: dict[str, str] = {}
    file_reasons: dict[str, str] = {}

    # Build emulator-level validation index from the platform's own
    # emulators (same scope as verify.py)
    from common import resolve_platform_cores

    validation_index = {}
    platform_profiles: dict[str, dict] = {}
    if emu_profiles:
        platform_profiles = {
            name: emu_profiles[name]
            for name in resolve_platform_cores(config, emu_profiles)
        }
        validation_index = _build_validation_index(platform_profiles)
    validation_owners = destination_owners(platform_profiles)
    slot_overrides = slots.pack_overrides(
        config, emu_profiles or {}, db, zip_contents, data_registry,
        target_cores=target_cores, source=source,
    )

    pack_systems = platform_scope_systems(
        config, emu_profiles or {}, target_cores, system_filter
    )
    if system_filter and not pack_systems:
        reason = system_scope_error(config, platform_name, system_filter, target_name)
        print(f"  WARNING: {reason}")
        return None
    if extras_only:
        # The part of a split that carries the core extras no platform system
        # owns: the platform's own files and trees went to the other parts.
        pack_systems = {}

    preferred_entries: dict[str, int] = {}
    if source != "truth":
        # Decided among the declarations this pack keeps: a preferred entry
        # that --required-only drops must not silence its required twin, or
        # the destination leaves the pack without a trace (RetroDECK's four
        # Atari 5200 ROMs, optional under atari-400-800 and required under
        # atari-5200). No data directories: the choice is about the baseline.
        preferred_entries = _preferred_entries(
            pack_systems, db, bios_dir, base_dest, required_only,
            zip_contents, offline,
        )

    # Region selection is decided once, over both the platform baseline and the
    # core extras, so the two phases below consult a single set. Grouping uses a
    # dedicated extras pass with an empty seen set: it only needs group
    # membership, never destinations, and a superset of members is the safe
    # direction. Runs only when --region is given.
    # The gap report both extras passes read, computed once: the region
    # grouping and the core complement below ask it the same question.
    undeclared = (
        undeclared_report(
            config, emulators_dir, db, emu_profiles, target_cores,
            include_all=(source == "truth"),
        )
        if source != "platform" and precomputed_extras is None
        else None
    )
    region_drops, region_fallbacks, slot_undecidable = _select_variants(
        config, pack_systems, emulators_dir, db, base_dest, emu_profiles,
        target_cores, source, regions, one_per_slot, required_only,
        undeclared=undeclared, zip_contents=zip_contents,
        data_registry=data_registry, slot_overrides=slot_overrides,
    )

    with (
        contextlib.nullcontext(record) if record is not None
        else _writing_pack(zip_path)
    ) as zf:
      if source != "truth":
        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                if required_only and file_entry.get("required") is False:
                    continue
                dest = sanitize_pack_path(file_entry.get("destination", file_entry["name"]))
                if region_drops and dest in region_drops:
                    continue
                if not dest:
                    # EmuDeck-style entries (system:md5 whitelist, no filename).
                    # Judged as verify judges it: resolved on disk, the md5
                    # list parsed once (case, comma lists).
                    fkey = f"{sys_id}/{file_entry.get('name', '')}"
                    held, held_status = resolve_file(
                        file_entry, db, bios_dir, zip_contents,
                        data_dir_registry=data_registry, offline=offline,
                    )
                    if held_status == "not_found" or not held:
                        file_status[fkey] = "missing"
                    elif baseline_verdict(
                        file_entry, held, held_status, verification_mode,
                        config.get("hash_rule", ""),
                    )[1]:
                        file_status[fkey] = "excluded"
                    else:
                        file_status.setdefault(fkey, "ok")
                    continue
                if base_dest:
                    full_dest = f"{base_dest}/{dest}"
                else:
                    full_dest = dest

                dedup_key = full_dest
                already_packed = dedup_key in seen_destinations or (
                    case_insensitive and dedup_key.lower() in seen_lower
                )

                preferred = preferred_entries.get(dedup_key)
                if preferred is not None and id(file_entry) != preferred:
                    continue

                if _has_path_conflict(full_dest, seen_destinations, seen_parents):
                    # Content ships under the conflicting shape (file vs dir,
                    # e.g. SGB1.sfc). verify.py resolves each declaration on
                    # its own, so this one is counted by what it resolves to:
                    # an unresolved one counted OK had the pack claim a file
                    # verify reports missing.
                    conflict_path, conflict_status = resolve_file(
                        file_entry, db, bios_dir, zip_contents,
                        data_dir_registry=data_registry, offline=offline,
                    )
                    # The verdict of the main path: a zipped_file archive is
                    # judged by the member inside, and a frontend that hashes
                    # one digest accepts a file another declared hash
                    # contradicts, as verify judges it.
                    conflict_status, refusal = baseline_verdict(
                        file_entry, conflict_path, conflict_status, verification_mode,
                        config.get("hash_rule", ""),
                    )
                    if conflict_status == "not_found":
                        file_status[dedup_key] = "missing"
                        file_reasons[dedup_key] = "not found"
                    elif refusal:
                        file_status[dedup_key] = "excluded"
                        file_reasons[dedup_key] = refusal
                    else:
                        file_status.setdefault(dedup_key, "ok")
                    continue

                storage = file_entry.get("storage", "embedded")

                if storage == "user_provided":
                    if already_packed:
                        continue
                    seen_destinations.add(dedup_key)
                    _register_path(dedup_key, seen_destinations, seen_parents)
                    if case_insensitive:
                        seen_lower.add(dedup_key.lower())
                    file_status.setdefault(dedup_key, "ok")
                    instructions = file_entry.get(
                        "instructions", "Please provide this file manually."
                    )
                    instr_name = f"INSTRUCTIONS_{file_entry['name']}.txt"
                    instr_path = (
                        f"{base_dest}/{instr_name}" if base_dest else instr_name
                    )
                    _write_generated_member(
                        zf,
                        _flat(instr_path, base_dest, flatten),
                        f"File needed: {file_entry['name']}\n\n{instructions}\n",
                    )
                    user_provided.append(file_entry["name"])
                    total_files += 1
                    continue

                local_path, status = resolve_declaration(
                    file_entry,
                    db,
                    bios_dir,
                    zip_contents,
                    data_registry,
                    slot_overrides.get(full_dest),
                    offline=offline,
                )

                if status == "external":
                    file_ext = os.path.splitext(file_entry["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(
                        delete=False, suffix=file_ext, dir=packresolve.scratch_dir()
                    ) as tmp:
                        tmp_path = tmp.name

                    # The slot is the platform's file whether the download
                    # arrives or not: verify cannot fetch, and a core file
                    # filling it on a failed download made the two differ.
                    seen_destinations.add(dedup_key)
                    _register_path(dedup_key, seen_destinations, seen_parents)
                    if case_insensitive:
                        seen_lower.add(dedup_key.lower())
                    try:
                        if record is None and download_external(file_entry, tmp_path):
                            extract = file_entry.get("extract", False)
                            if extract and tmp_path.endswith(".zip"):
                                _extract_zip_to_archive(tmp_path, _flat(full_dest, base_dest, flatten), zf)
                            else:
                                _add_pack_member(zf, tmp_path, _flat(full_dest, base_dest, flatten))
                            file_status.setdefault(dedup_key, "ok")
                            total_files += 1
                        else:
                            file_status[dedup_key] = "missing"
                            file_reasons[dedup_key] = "external download failed"
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue

                if status == "not_found":
                    # A filename-agnostic core takes any image of its system,
                    # renamed. Only an existence frontend accepts that.
                    files_db = db.get("files", {})
                    agnostic_path = None
                    agnostic_resolved = False
                    if not reads_file_contents(verification_mode):
                        found = agnostic_substitute(file_entry, sys_id, db, platform_profiles)
                        if found:
                            local_path, agnostic_path = found
                            agnostic_resolved = True

                    if agnostic_resolved and local_path:
                        original_name = os.path.basename(local_path)
                        dest_name = file_entry.get("name", "")
                        if original_name != dest_name and agnostic_path:
                            alt_names = []
                            for _s, _e in files_db.items():
                                _p = _e.get("path", "")
                                if _p.startswith(agnostic_path):
                                    _n = _e.get("name", "")
                                    if _n and _n != original_name:
                                        alt_names.append(_n)
                            readme_text = _build_agnostic_rename_readme(
                                dest_name,
                                original_name,
                                alt_names,
                            )
                            readme_name = f"RENAMED_{dest_name}.txt"
                            readme_full = (
                                f"{base_dest}/{readme_name}"
                                if base_dest
                                else readme_name
                            )
                            if readme_full not in seen_destinations:
                                _write_generated_member(
                                    zf,
                                    _flat(readme_full, base_dest, flatten),
                                    readme_text,
                                )
                                seen_destinations.add(readme_full)
                        status = "agnostic_fallback"
                        # Fall through to normal packing below
                    else:
                        if not already_packed:
                            file_status[dedup_key] = "missing"
                            file_reasons[dedup_key] = "not found"
                        continue

                # The verdict the install manifest reads too: a member missing
                # from a zipped_file archive, or a hash the frontend rejects.
                status, refusal = baseline_verdict(
                    file_entry, local_path, status, verification_mode,
                    config.get("hash_rule", ""),
                )
                if refusal:
                    # An earlier declaration of this path shipped a file this
                    # one refuses: it is in the pack, untested as verify
                    # counts it, not excluded.
                    file_status[dedup_key] = "untested" if already_packed else "excluded"
                    file_reasons[dedup_key] = refusal
                    continue
                if not hash_mismatch_excludes_file(verification_mode) and (
                    status == "hash_mismatch" and local_path
                ):
                    # Existence platforms accept any file at the declared path:
                    # their code never reads the bytes. An upstream hash that
                    # contradicts a local dump is reported, not acted on.
                    file_reasons.setdefault(
                        dedup_key,
                        existence_discrepancy(file_entry, local_path, platform_display),
                    )
                if file_status.get(dedup_key) == "missing":
                    # An earlier declaration of this path found nothing, and this
                    # one fills it, as verify counts it.
                    del file_status[dedup_key]
                    file_reasons.pop(dedup_key, None)
                file_status.setdefault(dedup_key, "ok")

                # Emulator-level validation: informational only for platform packs.
                # Platform verification (existence/md5) is the authority for pack status.
                # Emulator checks are supplementary: logged but don't downgrade.
                # When a discrepancy is found, try to find a file satisfying both.
                if file_status.get(dedup_key) == "ok":
                    local_path, disagreement = validated_choice(
                        file_entry, local_path, db, validation_index, bios_dir,
                        digest_algorithm(verification_mode), dest, validation_owners,
                    )
                    if disagreement:
                        file_reasons.setdefault(
                            dedup_key, f"{platform_display} says OK but {disagreement}"
                        )

                if already_packed:
                    if dedup_key not in seen_destinations:
                        case_twins.append(_flat(full_dest, base_dest, flatten))
                    continue
                if within is not None and not _same_bytes(
                    local_path, within.get(_flat(full_dest, base_dest, flatten))
                ):
                    # The full pack holds another system's file here.
                    continue
                if file_status.get(dedup_key) == "excluded":
                    # An earlier declaration refused the file this one ships.
                    file_status[dedup_key] = "untested"
                seen_destinations.add(dedup_key)
                _register_path(dedup_key, seen_destinations, seen_parents)
                if case_insensitive:
                    seen_lower.add(dedup_key.lower())

                extract = file_entry.get("extract", False)
                flat_dest = _flat(full_dest, base_dest, flatten)
                if extract and local_path.endswith(".zip"):
                    _extract_zip_to_archive(local_path, flat_dest, zf)
                elif local_path.endswith(".zip"):
                    _add_zip_to_pack(local_path, flat_dest, zf, file_entry)
                else:
                    _add_pack_member(zf, local_path, flat_dest)
                total_files += 1

      # Core requirements: files platform's cores need but YAML doesn't declare
      if emu_profiles is None:
          emu_profiles = load_emulator_profiles(emulators_dir)
      if source == "platform":
          core_files = []
      elif precomputed_extras is not None:
          core_files = precomputed_extras
      elif system_filter:
          # The systems asked for, with what their cores need: the split
          # packs get exactly this, and a full pack of one system had none.
          core_files = _extras_for_systems(
              _collect_emulator_extras(
                  config, emulators_dir, db, set(), base_dest, emu_profiles,
                  target_cores=target_cores, include_all=(source == "truth"),
                  undeclared=undeclared,
              ),
              system_filter,
          )
      else:
          core_files = _collect_emulator_extras(
              config,
              emulators_dir,
              db,
              seen_destinations,
              base_dest,
              emu_profiles,
              target_cores=target_cores,
              include_all=(source == "truth"),
              undeclared=undeclared,
          )

      core_count = 0
      save_count = 0
      extra_resolver = ExtraResolver(
          db, bios_dir, zip_contents, data_registry, validation_index,
          validation_owners, offline, profiles=emu_profiles,
      )
      spares = core_file_spares(
          core_files,
          lambda fe: bool(region_drops)
          and extra_region_key(fe, declared_root(config)) in region_drops,
      ) if required_only else set()
      for fe in core_files:
          if required_only and (fe.get("required") is False or id(fe) in spares):
              continue
          dest = sanitize_pack_path(fe.get("destination", fe["name"]))
          if region_drops and extra_region_key(fe, declared_root(config)) in region_drops:
              continue
          if not dest:
              continue
          if fe.get("root") in OUTER_ROOTS:
              # Read below the roms directory or in an emulator folder: the
              # pack is extracted into the BIOS folder and cannot reach
              # them, the installer places these files.
              continue
          # Core extras: _collect_emulator_extras already adjusted
          # destinations for slug-based platforms.  Apply the effective
          # prefix (base_dest, or inferred from YAML when base_dest is
          # empty, as RetroDECK infers "bios"). A file read below the save
          # directory goes to the pack's save folder instead.
          full_dest = extra_full_destination(
              fe, _detect_extras_prefix(config, base_dest)
          )
          if not full_dest:
              continue
          # Taken, a case twin on a case-insensitive filesystem, or a
          # file/directory conflict (SGB1.sfc vs SGB1.sfc/): verify replays
          # the same rule (packextras.hidden_extras).
          block = placement_block(
              full_dest, seen_destinations, seen_lower, seen_parents,
              case_insensitive,
          )
          if block:
              if block == "case_twin" and extra_resolver.resolve(fe, dest)[0]:
                  case_twins.append(_flat(full_dest, base_dest, flatten))
              continue

          # The emulator's own check picks the copy, as for a declared file
          # and in the emulator pack: the name led RetroArch's GC/dsp_rom.bin
          # to Dolphin's obsolete v0.3.1 free ROM, beside Nintendo's coef
          # ROM, a pair Dolphin warns about at every start.
          local_path, status, disagreement = extra_resolver.resolve(fe, dest)
          if not local_path:
              continue
          if disagreement:
              core_discrepancies.append(f"{full_dest}: {disagreement}")
          if status == "hash_mismatch" and not _matches_an_alternative(
              fe, local_path, emu_profiles or {}
          ):
              # The core's declared hash comes from its source, the local dump
              # is what the collection holds. Shipping it keeps the emulator
              # working when the code never reads the hash, and the divergence is
              # reported so it can be resolved at the profile or the dump.
              # file_status tracks platform declarations only, so the report
              # goes to its own list and never moves the pack's own count.
              core_discrepancies.append(
                  f"{full_dest}: declared hash of "
                  f"{fe.get('source_profile') or fe.get('source_emulator', 'core profile')}"
                  " does not match the packed copy"
              )

          flat_dest = _flat(full_dest, base_dest, flatten)
          if within is not None and not _same_bytes(local_path, within.get(flat_dest)):
              continue
          if local_path.endswith(".zip"):
              _add_zip_to_pack(local_path, flat_dest, zf, fe)
          else:
              _add_pack_member(zf, local_path, flat_dest)
          if file_status.get(full_dest) in ("missing", "excluded"):
              source_name = fe.get("source_profile") or fe.get(
                  "source_emulator", "core profile"
              )
              if reads_file_contents(verification_mode):
                  # The frontend hashes what sits at the path, and the core's
                  # copy is not the hash it declares: the file ships for the
                  # core, the platform's own check still fails, as verify says.
                  file_reasons[full_dest] = (
                      "platform-declared hash unavailable; "
                      f"packed the validated {source_name} requirement, "
                      "which the platform check does not accept"
                  )
              else:
                  # An existence frontend is satisfied by any file at the path.
                  file_status[full_dest] = "ok"
                  file_reasons.pop(full_dest, None)
          seen_destinations.add(full_dest)
          _register_path(full_dest, seen_destinations, seen_parents)
          if case_insensitive:
              seen_lower.add(full_dest.lower())
          core_count += 1
          if fe.get("root") == "save":
              save_count += 1
          total_files += 1

      # The trees the cores read follow them as their extras do: by the
      # systems asked for, and those of no system in the part of their own.
      core_trees = (
          [] if source == "platform"
          else core_data_trees(
              config, emu_profiles, platform_name, data_registry, target_cores
          )
      )
      if extras_only:
          owned = list(platform_scope_systems(config, emu_profiles, target_cores))
          core_trees = [t for t in core_trees if not _extras_for_systems([t], owned)]
      elif system_filter:
          core_trees = _extras_for_systems(core_trees, system_filter)
      # Counted apart: the trees a core reads are not on the platform's
      # list. MyMinUI declares nothing and its line read "6944 baseline".
      total_files += _pack_data_directories(
          zf, pack_systems, data_registry, platform_name, base_dest,
          flatten, case_insensitive, seen_destinations, seen_lower,
          seen_parents, required_only=required_only,
      )
      tree_count = _pack_data_directories(
          zf, {}, data_registry, platform_name, base_dest,
          flatten, case_insensitive, seen_destinations, seen_lower,
          seen_parents, required_only=required_only, core_trees=core_trees,
      )
      total_files += tree_count

      # README.txt for users: personalized step-by-step per platform
      num_systems = len(pack_systems)
      _registry_path = Path(platforms_dir) / "_registry.yml"
      _pack_registry: dict = {}
      if _registry_path.exists():
          with open(_registry_path) as _rf:
              _pack_registry = (yaml_load(_rf) or {}).get("platforms", {})
      keeps_case = case_insensitive and any(
          d.get("os") not in CASE_FOLDING_OS
          for d in (_pack_registry.get(platform_name, {}).get("install", {}) or {})
          .get("detect", [])
      )
      if keeps_case and source != "platform" and precomputed_extras is None:
          # The spellings a folded platform counts as declared never reach
          # the extras: collected as the filesystem that keeps case sees
          # them, as the manifest's case_variants are (Mesen-CE's bios.col
          # beside the declared BIOS.col).
          unfolded = _collect_emulator_extras(
              {**config, "case_insensitive_fs": False}, emulators_dir, db, set(),
              base_dest, emu_profiles, target_cores=target_cores,
              include_all=(source == "truth"),
          )
          if system_filter:
              unfolded = _extras_for_systems(unfolded, system_filter)
          prefix = _detect_extras_prefix(config, base_dest)
          unfolded_spares = core_file_spares(
              unfolded,
              lambda fe: bool(region_drops)
              and extra_region_key(fe, declared_root(config)) in region_drops,
          ) if required_only else set()
          for fe in unfolded:
              if required_only and (fe.get("required") is False or id(fe) in unfolded_spares):
                  continue
              if region_drops and extra_region_key(fe, declared_root(config)) in region_drops:
                  continue
              full = extra_full_destination(fe, prefix)
              if (
                  full and full not in seen_destinations and full.lower() in seen_lower
                  and extra_resolver.resolve(
                      fe, sanitize_pack_path(fe.get("destination", fe["name"]))
                  )[0]
              ):
                  case_twins.append(_flat(full, base_dest, flatten))
      readme_text = _build_readme(
          platform_name, platform_display, base_dest, total_files, num_systems,
          source=source,
          contributors=_pack_registry.get(platform_name, {}).get("contributed_by", []),
          regions=regions,
          fallback_systems=region_fallbacks,
          one_per_slot=one_per_slot,
          undecidable_slots=slot_undecidable,
          narrowings=narrowings,
          system_filter=system_filter,
          detect=(
              _pack_registry.get(platform_name, {}).get("install", {}) or {}
          ).get("detect", []),
          standalone_copies=(
              _pack_registry.get(platform_name, {}).get("install", {}) or {}
          ).get("standalone_copies", []),
          launch_folders=len(config.get("core_system_dirs") or {}),
          save_folder=(save_layout(config).in_pack if save_count else ""),
          save_where=(
              save_place(
                  str(_pack_registry.get(platform_name, {}).get("extract_to") or ""),
                  save_layout(config).folder, base_dest,
              ) if save_count else ""
          ),
          save_by_system=bool(save_count and save_layout(config).by_system),
          case_twins=(
              _case_twin_pairs(case_twins, seen_destinations, base_dest, flatten)
              if keeps_case else []
          ),
      )
      _write_generated_member(zf, "README.txt", readme_text)
      for marker in pack_markers(platform_name, target_name, platforms_dir):
          _write_generated_member(
              zf, _flat(f"{base_dest}/{marker}" if base_dest else marker, base_dest, flatten), ""
          )

    _report_pack_counts(
        zip_path, file_status, total_files, core_count, source,
        verification_mode, tree_count=tree_count,
    )
    if cut is not None:
        _report_left_out(
            cut,
            systems=set(pack_systems) if source != "truth" else set(),
            cores=source != "platform" and precomputed_extras is None,
        )


    for key, reason in sorted(file_reasons.items()):
        status = file_status.get(key, "")
        if status == "untested":
            label = "UNTESTED"
        elif status == "excluded":
            label = "EXCLUDED"
        elif status == "missing":
            label = "MISSING"
        else:
            label = "DISCREPANCY"
        print(f"  {label}: {key}: {reason}")
    for name in missing_files:
        print(f"  MISSING: {name}")
    for note in sorted(core_discrepancies):
        print(f"  DISCREPANCY: {note}")
    return zip_path


def _extract_zip_to_archive(
    source_zip: str,
    dest_prefix: str,
    target_zf: zipfile.ZipFile | PackRecord,
) -> None:
    """Extract contents of a source ZIP into target ZIP under dest_prefix."""
    with zipfile.ZipFile(source_zip, "r") as src:
        if isinstance(target_zf, PackRecord):
            target_zf.members.extend(
                f"{dest_prefix}/{name}" if dest_prefix else name
                for name in map(sanitize_pack_path, src.namelist())
                if name and not name.endswith("/")
            )
            target_zf.sources[dest_prefix] = source_zip
            return
        for info in src.infolist():
            if info.is_dir():
                continue
            clean_name = sanitize_pack_path(info.filename)
            if not clean_name:
                continue
            data = src.read(info.filename)
            target_path = f"{dest_prefix}/{clean_name}" if dest_prefix else clean_name
            member = zipfile.ZipInfo(
                filename=target_path, date_time=_FIXED_DATE_TIME
            )
            member.compress_type = _member_compression(target_path)
            member.external_attr = 0o100644 << 16
            target_zf.writestr(member, data)


def _add_zip_to_pack(
    source_zip: str,
    dest_path: str,
    target_zf: zipfile.ZipFile | PackRecord,
    file_entry: dict | None = None,
) -> None:
    """Write a source ZIP into the pack, byte for byte.

    The pack carries the collection's own bytes, so every member hashes to
    the sha1 the install list and the site publish. Rebuilt ZIPs gave about
    1,500 archives another hash than the list: an extracted pack then failed
    `install.py --check`. The collection's bytes are fixed in git, which keeps
    the pack reproducible without a rebuild.
    """
    if isinstance(target_zf, PackRecord):
        target_zf.members.append(dest_path)
        target_zf.sources[dest_path] = source_zip
        return
    _check_zip_members(source_zip)
    _add_pack_member(target_zf, source_zip, dest_path)


def _check_zip_members(source_zip: str) -> None:
    """Refuse an archive whose members fail their own CRC.

    Copied as-is "for verify to flag", a damaged archive went into the pack
    and nothing flagged it.
    """
    try:
        with zipfile.ZipFile(source_zip) as zf:
            bad = zf.testzip()
    except zipfile.BadZipFile as exc:
        raise DamagedArchiveError(
            f"{source_zip}: {exc}; restore it from git or the release before packing"
        ) from exc
    if bad is not None:
        raise DamagedArchiveError(
            f"{source_zip}: member {bad} fails its CRC; "
            "restore it from git or the release before packing"
        )


class DamagedArchiveError(OSError):
    """An archive of the collection whose members fail their own CRC."""


# Emulator/system mode pack generation



def _pack_data_tree(
    zf: zipfile.ZipFile | PackRecord,
    local_cache: str,
    dd_dest: str,
    seen_destinations: set[str],
    seen_parents: set[str],
    seen_lower: set[str],
    packed_at: dict[str, str] | None = None,
) -> int:
    """Write one data directory into an emulator pack, under its shared lock.

    A refresh swaps the tree by rename. Without the lock a walk half done
    read the old tree and wrote files of the new one. ``packed_at`` records
    each member, so a later profile asking for the same bytes there is
    served rather than reported missing.
    """
    added = 0
    with cache_lock(local_cache, shared=True):
        for root, _dirs, filenames in os.walk(local_cache):
            for fname in filenames:
                src = os.path.join(root, fname)
                rel = os.path.relpath(src, local_cache)
                full = f"{dd_dest}/{rel}" if dd_dest else rel
                if full.lower() in seen_lower or _has_path_conflict(
                    full, seen_destinations, seen_parents
                ):
                    continue
                seen_destinations.add(full)
                _register_path(full, seen_destinations, seen_parents)
                seen_lower.add(full.lower())
                _add_pack_member(zf, src, full)
                if packed_at is not None:
                    packed_at[full.lower()] = src
                added += 1
    return added


def _same_bytes(path: str, other: str | None) -> bool:
    if not other:
        return False
    if os.path.realpath(path) == os.path.realpath(other):
        return True
    return compute_hashes(path)["sha1"] == compute_hashes(other)["sha1"]


# A file name holds 255 bytes on every filesystem a pack is written to,
# and the margin leaves room for the split part suffix and a scratch prefix.
MAX_PACK_NAME_BYTES = 200


def _bounded_pack_name(display_names: list[str], keys: list[str], suffix: str) -> str:
    """The emulator pack's file name, its emulators joined while they fit.

    Past the limit the name keeps the first emulator, says how many more the
    pack holds, and carries a digest of the selection so two different
    selections never share a file.
    """
    joined = "_".join(display_names) + suffix
    if len(joined.encode("utf-8")) <= MAX_PACK_NAME_BYTES:
        return joined
    digest = hashlib.sha1("\n".join(sorted(keys)).encode("utf-8")).hexdigest()[:8]
    return f"{display_names[0]}_and_{len(display_names) - 1}_more_{digest}{suffix}"


def generate_emulator_pack(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    required_only: bool = False,
    regions: list[str] | None = None,
    offline: bool | None = None,
    platforms_dir: str | None = None,
    pack_name: str | None = None,
    system_ids: list[str] | None = None,
    final_dir: str | None = None,
    record: PackRecord | None = None,
) -> str | None:
    """Generate a ZIP pack for specific emulator profiles.

    Returns the path, "" when no file is needed (verify --emulator reports
    0/0 OK), None on failure.

    `pack_name` is the caller's own file name: the system pack names its
    archive after the system, and joining 23 SNES emulator names went past
    the 255 bytes a file name may hold. `system_ids` keeps only the entries
    of those systems, as a platform pack narrows core extras. `final_dir`
    is where the caller moves the archive, the path the report names.
    `record` builds the pack in memory instead (PackRecord): nothing is
    written or read, and the paths are kept on it.
    """
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    if zip_contents is None:
        zip_contents = build_zip_contents_index(db)

    try:
        selected = select_emulator_profiles(profile_names, all_profiles, standalone)
    except ProfileSelectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None

    # ZIP naming
    display_names = [_name_part(p.get("emulator", n)) for n, p in selected]
    validation_index = _build_validation_index(dict(selected))
    narrow_tags = "".join(
        tag
        for tag, _label in _narrowings(
            "full", regions, None, False, required_only, standalone
        )
    )
    zip_name = pack_name or _bounded_pack_name(
        display_names, [n for n, _p in selected], f"{narrow_tags}_BIOS_Pack.zip"
    )
    zip_path = os.path.join(output_dir, zip_name)
    if record is None:
        os.makedirs(output_dir, exist_ok=True)

    data_registry = load_data_dir_registry(
        platforms_dir or os.path.join(os.path.dirname(__file__), "..", "platforms")
    )
    region_drops: set[str] = (
        emulator_region_drops(
            selected, standalone, regions, required_only, db,
            zip_contents=zip_contents, data_registry=data_registry,
        )
        if regions
        else set()
    )

    total_files = 0
    data_files = 0
    missing_files = []
    rejected_files: list[str] = []
    discrepancies: list[str] = []
    unsourceable_files: list[str] = []
    instruction_files: list[str] = []
    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()
    seen_parents: set[str] = (
        set()
    )  # parent dirs of added files (path conflict detection)
    seen_hashes: set[str] = set()  # SHA1 dedup for same file, different path
    # Loose file packed at each folded destination, to tell a profile asking
    # for the same file there from one asking for other bytes.
    packed_at: dict[str, str] = {}
    # A destination is missing once, however many profiles ask for it:
    # verify --emulator counts by destination.
    missing_at: set[str] = set()

    def report_missing(name: str, destination: str) -> None:
        if destination not in missing_at:
            missing_at.add(destination)
            missing_files.append(name)

    data_dir_notices: list[str] = []

    with (
        contextlib.nullcontext(record) if record is not None
        else _writing_pack(zip_path)
    ) as zf:
        for emu_name, profile in sorted(selected):
            pack_structure = profile.get("pack_structure")
            files = expand_agnostic_entries(
                expand_directory_entries(
                    deliverable(profile.get("files", []), standalone),
                    db,
                    standalone,
                ),
                emu_name, profile, db, standalone, all_profiles,
            )
            if system_ids:
                files = [
                    fe for fe in files if entry_serves_systems(fe, profile, system_ids)
                ]
            if not files and not profile.get("data_directories"):
                print(f"  No files needed for {profile.get('emulator', emu_name)}")

            archives: set[str] = set()
            for fe in files:
                archive = fe.get("archive")
                if archive:
                    archives.add(archive)

            # What each destination came to, settled by set once the
            # profile is read: a member another member fills is not missing,
            # and a set nobody holds is reported once (alternatives.py). An
            # archive unit is a member like a loose file.
            outcomes: list[tuple[list[dict], bool, Callable[[], None] | None]] = []
            spares = emulator_required_spares(
                emu_name, profile, files, standalone, region_drops, db,
                validation_index, zip_contents, data_registry,
            ) if required_only else set()

            # Pack archives as units
            archive_prefix = profile.get("archive_prefix", "")
            for archive_name in sorted(archives):
                archive_dest = _archive_destination(
                    archive_name, archive_prefix, pack_structure, standalone
                )

                own_entry = archive_entry(archive_name, files)
                if required_only and archive_is_optional(own_entry, archive_name, files):
                    continue
                if archive_dest in spares:
                    continue
                local_path, status = resolve_file(
                    own_entry,
                    db,
                    bios_dir,
                    zip_contents,
                    data_dir_registry=data_registry,
                    offline=offline,
                )
                taken = archive_dest.lower() in seen_lower
                if taken or _has_path_conflict(archive_dest, seen_destinations, seen_parents):
                    # Another profile's file holds this path. The same archive
                    # asked for twice is served. Anything else leaves this
                    # profile without its archive, which used to pass in
                    # silence: a neocdz.zip lacking 000-lo.lo shipped as the
                    # one the second core needs.
                    if not (taken and local_path and _same_bytes(
                        local_path, packed_at.get(archive_dest.lower())
                    )):
                        outcomes.append(([own_entry], False, functools.partial(
                            report_missing, archive_name, archive_dest
                        )))
                    else:
                        outcomes.append(([own_entry], True, None))
                    continue
                if local_path and status not in ("not_found",):
                    if local_path.endswith(".zip"):
                        _add_zip_to_pack(local_path, archive_dest, zf, own_entry)
                    else:
                        _add_pack_member(zf, local_path, archive_dest)
                    seen_destinations.add(archive_dest)
                    _register_path(archive_dest, seen_destinations, seen_parents)
                    seen_lower.add(archive_dest.lower())
                    packed_at[archive_dest.lower()] = local_path
                    total_files += 1
                    if record is not None:
                        record.files.append(archive_dest)
                    outcomes.append(([own_entry], True, None))
                else:
                    outcomes.append(([own_entry], False, functools.partial(
                        report_missing, archive_name, archive_dest
                    )))

            # Pack individual files (skip archive members). The entries of one
            # profile on one destination are the releases the code accepts
            # there (raze's seven SW.GRP): the first one the core accepts
            # fills the slot, as verify --emulator credits it, and the slot
            # has one outcome however many alternatives it lists.
            slots: dict[str, list[dict]] = {}
            for fe in files:
                if required_only and fe.get("required") is False:
                    continue
                if fe.get("archive"):
                    continue
                dest = _resolve_destination(fe, standalone)
                if not dest or dest in spares:
                    continue
                if region_drops and dest in region_drops:
                    continue
                slots.setdefault(dest, []).append(fe)

            for dest, alternatives in slots.items():
                # Name order, first file wins, case folded: verify replays
                # the rule and reports a later profile's file as missing.
                block = placement_block(
                    dest, seen_destinations, seen_lower, seen_parents, True
                )

                provided = next(
                    (fe for fe in alternatives if fe.get("storage") == "user_provided"),
                    None,
                )
                if provided is not None and block:
                    continue
                if provided is not None:
                    # Instructions, not a file: written beside the slot the
                    # user fills, and counted apart from what the pack holds.
                    seen_destinations.add(dest)
                    _register_path(dest, seen_destinations, seen_parents)
                    seen_lower.add(dest.lower())
                    instr = provided.get("instructions", "Please provide this file manually.")
                    folder = dest.rsplit("/", 1)[0] + "/" if "/" in dest else ""
                    _write_generated_member(
                        zf,
                        f"{folder}INSTRUCTIONS_{provided['name']}.txt",
                        f"File needed: {provided['name']}\n\n{instr}\n",
                    )
                    # verify --emulator counts an unsourceable one as such.
                    (unsourceable_files if provided.get("unsourceable") else instruction_files).append(
                        provided["name"]
                    )
                    continue

                chosen: tuple[dict, str, str | None] | None = None
                fallback: tuple[dict, str, str | None] | None = None
                refusal: str | None = None
                refused_path: str | None = None
                for fe in alternatives:
                    local_path, status = resolve_file(
                        {**with_archive_members(fe, files), "source_profile": emu_name},
                        db,
                        bios_dir,
                        zip_contents,
                        dest_hint=fe.get("path", ""),
                        data_dir_registry=data_registry,
                        offline=offline,
                    )
                    if status == "external":
                        chosen = (fe, "", "external")
                        break
                    if status in ("not_found", "user_provided") or not local_path:
                        continue
                    # The file verify --emulator credits is the one shipped:
                    # a dump the core's own check rejects gives way to a held
                    # one it accepts (azahar's otp.bin, dolphin's dsp_rom.bin).
                    better, disagreement = validated_choice(
                        fe, local_path, db, validation_index, bios_dir, None,
                        emulators={emu_name},
                    )
                    if disagreement:
                        reason = disagreement.split(" says ", 1)[-1]
                        refusal = refusal or f"{fe['name']}: {reason}"
                        refused_path = refused_path or local_path
                        continue
                    if better != local_path:
                        chosen = (fe, better, None)
                        break
                    if status == "hash_mismatch":
                        # Not a check the core runs, so the file still serves,
                        # but it is not the dump the profile documents.
                        fallback = fallback or (fe, local_path, "mismatch")
                        continue
                    chosen = (fe, local_path, None)
                    break
                chosen = chosen or fallback

                if block:
                    held = (
                        chosen[1] if chosen is not None and chosen[2] != "external"
                        else None if chosen is not None else refused_path
                    )
                    if chosen is not None or held is not None:
                        if block == "taken" and held and _same_bytes(
                            held, packed_at.get(dest.lower())
                        ):
                            # The file already at this path, asked for twice.
                            outcomes.append((alternatives, True, None))
                            continue
                        outcomes.append((alternatives, False, functools.partial(
                            report_missing, alternatives[0]["name"], dest
                        )))
                        continue

                if chosen is None:
                    if refusal:
                        rejected_files.append(refusal)
                        outcomes.append((alternatives, False, None))
                    elif all(fe.get("unsourceable") for fe in alternatives):
                        outcomes.append((alternatives, False, functools.partial(
                            unsourceable_files.append, alternatives[0]["name"]
                        )))
                    else:
                        outcomes.append((alternatives, False, functools.partial(
                            report_missing, alternatives[0]["name"], dest
                        )))
                    continue

                fe, local_path, how = chosen
                if how == "external":
                    file_ext = os.path.splitext(fe["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(
                        delete=False, suffix=file_ext, dir=packresolve.scratch_dir()
                    ) as tmp:
                        tmp_path = tmp.name
                    try:
                        # Built in memory, nothing is fetched: verify --emulator
                        # cannot fetch either and reports the file missing.
                        if record is None and download_external(fe, tmp_path):
                            _add_pack_member(zf, tmp_path, dest)
                            seen_destinations.add(dest)
                            _register_path(dest, seen_destinations, seen_parents)
                            seen_lower.add(dest.lower())
                            total_files += 1
                            if record is not None:
                                record.files.append(dest)
                            outcomes.append((alternatives, True, None))
                        else:
                            outcomes.append((alternatives, False, functools.partial(
                                missing_files.append, fe["name"]
                            )))
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue
                if how == "mismatch":
                    discrepancies.append(
                        f"{fe['name']}: not the dump the {emu_name} profile declares"
                    )

                # SHA1 dedup: skip if same physical file AND same destination
                # (but allow same file to be packed under different destinations,
                # e.g., IPL.bin in GC/USA/ and GC/EUR/ from same source)
                dedup_key_hash = f"{os.path.realpath(local_path)}:{dest}"
                outcomes.append((alternatives, True, None))
                if dedup_key_hash in seen_hashes:
                    continue
                seen_hashes.add(dedup_key_hash)

                if local_path.endswith(".zip"):
                    _add_zip_to_pack(local_path, dest, zf, fe)
                else:
                    _add_pack_member(zf, local_path, dest)
                seen_destinations.add(dest)
                _register_path(dest, seen_destinations, seen_parents)
                seen_lower.add(dest.lower())
                packed_at[dest.lower()] = local_path
                total_files += 1
                if record is not None:
                    record.files.append(dest)

            excused, _standing = settle_sets([
                (slot_set_keys(emu_name, entries), entries[0], fills)
                for entries, fills, _report in outcomes
            ])
            for position, (_entries, _fills, report) in enumerate(outcomes):
                if report is not None and position not in excused:
                    report()

            # The trees after the files, as in a platform pack: a dump the
            # profile declares wins over the copy a tree bundles at the same
            # path (Dolphin's real dsp_rom.bin over Sys/GC's free one).
            # A tree only one build reads follows that build, like a file.
            for dd in deliverable(
                profile.get("data_directories", []), standalone
            ):
                if required_only and dd.get("required") is False:
                    continue
                ref_key = dd.get("ref", "")
                if not ref_key or not data_registry or ref_key not in data_registry:
                    if ref_key:
                        data_dir_notices.append(ref_key)
                    continue
                entry = data_registry[ref_key]
                local_cache = entry.get("local_cache", "")
                if not local_cache or not os.path.isdir(local_cache):
                    data_dir_notices.append(ref_key)
                    continue
                dd_dest = dd.get("destination", "")
                if pack_structure:
                    mode_key = "standalone" if standalone else "libretro"
                    prefix = pack_structure.get(mode_key, "")
                    if prefix:
                        dd_dest = f"{prefix}/{dd_dest}" if dd_dest else prefix
                data_files += _pack_data_tree(
                    zf, local_cache, dd_dest, seen_destinations, seen_parents, seen_lower,
                    packed_at,
                )

    # Remove empty ZIP (no files packed and no missing = nothing to ship)
    nothing_needed = total_files + data_files == 0 and not (
        missing_files or rejected_files or instruction_files or unsourceable_files
    )
    if record is None and nothing_needed:
        os.unlink(zip_path)
        # What verify --emulator reports as 0/0 OK: no file is needed, so
        # no pack is written and the run succeeds. Printed with the path,
        # the run named a file it had just removed and exited 1.
        print(f"  {', '.join(display_names)}: no file needed, no pack written")
        return ""

    # Report. The members of data trees are counted apart: verify --emulator
    # counts the profile's files, and folding 3500 tree members into the
    # same number made the two impossible to compare.
    missing_count = len(missing_files)
    ok_count = total_files
    parts = [f"{ok_count} files packed"]
    if data_files:
        parts.append(f"{data_files} from data directories")
    if missing_count:
        parts.append(f"{missing_count} missing")
    if rejected_files:
        parts.append(f"{len(rejected_files)} refused by the core")
    if unsourceable_files:
        parts.append(f"{len(unsourceable_files)} unsourceable")
    if instruction_files:
        parts.append(f"{len(instruction_files)} to provide")
    shown = os.path.join(final_dir, zip_name) if final_dir else zip_path
    print(f"  {shown}: {', '.join(parts)}")
    for name in missing_files:
        print(f"  MISSING: {name}")
    for name in unsourceable_files:
        print(f"  UNSOURCEABLE: {name}")
    for name in instruction_files:
        print(f"  TO PROVIDE: {name} (instructions in the pack)")
    for line in rejected_files:
        print(f"  REFUSED: {line}")
    for line in discrepancies:
        print(f"  DISCREPANCY: {line}")
    for ref in sorted(set(data_dir_notices)):
        print(
            f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)"
        )
    _MISSING_DATA_DIRS.update(data_dir_notices)

    return (
        zip_path
        if total_files + data_files > 0 or missing_files or rejected_files or instruction_files
        or unsourceable_files
        else None
    )


def generate_system_pack(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    required_only: bool = False,
    regions: list[str] | None = None,
    offline: bool | None = None,
    platforms_dir: str | None = None,
) -> str | None:
    """Generate a ZIP pack for all emulators supporting given system IDs.

    Returns the path, "" when no file is needed, None on failure.
    """
    profiles = load_emulator_profiles(emulators_dir)
    matching = profiles_for_systems(profiles, system_ids, standalone)

    if not matching:
        all_systems: set[str] = set()
        for p in profiles.values():
            all_systems.update(p.get("systems", []))
        if standalone:
            print(
                f"No standalone emulators found for system(s): {', '.join(system_ids)}",
                file=sys.stderr,
            )
        else:
            print(
                f"No emulators found for system(s): {', '.join(system_ids)}",
                file=sys.stderr,
            )
        # --list-systems merges spellings that differ in case or separator:
        # the hint counted 579 spellings for the 532 lines it prints.
        print(suggest_names(system_ids, sorted(all_systems), "--list-systems",
                            listed=len(system_index(profiles))),
              file=sys.stderr)
        return None

    # Named like the platform's --system tag: one spelling of a system is
    # one file name, and one selection.
    sys_display = _bounded_join(
        [_system_display_name(sid) for sid in system_ids], list(system_ids)
    )
    # Built in a scratch directory: under its emulator name in output_dir it
    # overwrote, then carried away, an --emulator pack already there.
    os.makedirs(output_dir, exist_ok=True)
    # Every dimension goes through the one list: keeping only the region
    # tag made --system X --required-only overwrite the pack built without it.
    tags = "".join(
        tag
        for tag, _label in _narrowings(
            "full", regions, None, False, required_only, standalone=standalone
        )
    )
    # The selection mode is part of the name: `--system sega-triforce`
    # and `--emulator triforce` both wrote Triforce_BIOS_Pack.zip, and
    # the second run replaced the first without a word.
    final_name = f"{sys_display}_System{tags}_BIOS_Pack.zip"
    scratch = tempfile.mkdtemp(prefix=".system-", dir=output_dir)
    try:
        result = generate_emulator_pack(
            matching,
            emulators_dir,
            db,
            bios_dir,
            scratch,
            standalone,
            zip_contents,
            required_only=required_only,
            regions=regions,
            offline=offline,
            platforms_dir=platforms_dir,
            pack_name=final_name,
            system_ids=system_ids,
            final_dir=output_dir,
        )
        if not result:
            return result
        new_path = os.path.join(output_dir, final_name)
        os.replace(result, new_path)
        return new_path
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _system_display_name(system_id: str) -> str:
    """Convert system ID to display name for ZIP naming."""
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    parts = s.split("-")
    return "_".join(p.title() for p in parts if p)


def _group_systems_by_manufacturer(
    systems: dict[str, dict],
    db: dict,
    bios_dir: str,
) -> dict[str, list[str]]:
    """Group system IDs by manufacturer for --split --group-by manufacturer."""
    from common import derive_manufacturer

    groups: dict[str, list[str]] = {}
    for sid, sys_data in systems.items():
        mfr = derive_manufacturer(sid, sys_data)
        groups.setdefault(mfr, []).append(sid)
    return groups


def generate_split_packs(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    group_by: str = "system",
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    required_only: bool = False,
    source: str = "full",
    regions: list[str] | None = None,
    target_name: str | None = None,
    one_per_slot: bool = False,
    offline: bool | None = None,
    no_game_data: bool = False,
    records: dict[str, PackRecord] | None = None,
) -> list[str]:
    """Generate split packs (one ZIP per system or manufacturer).

    The parts add up to the full pack: each is built against the full pack's
    own placement (``within``). ``records`` builds the parts in memory, keyed
    by part name, with no archive written.
    """
    config = load_platform_config(platform_name, platforms_dir)
    # The split directory carries the same tags as the packs inside it, or two
    # differently narrowed runs write into one another.
    split_tags = "".join(
        tag
        for tag, _label in _narrowings(
            source, regions, target_name, one_per_slot, required_only,
            no_game_data=no_game_data,
        )
    )
    # Two groupings write different files. Without the tag they accumulate in
    # one directory under one SHA256SUMS.txt.
    group_tag = "" if group_by == "system" else f"_By{group_by.title()}"
    # The parts carry the version, so the directory does too: a rescrape that
    # moves the version would otherwise leave the old parts beside the new
    # under one SHA256SUMS.txt.
    # Named by the stem the full pack reads: assembled here by hand, a '/' in
    # a version nested the directory where the check never looked for it.
    part_prefix = (
        f"{_platform_pack_stem([platform_name], platform_name, platforms_dir)}{split_tags}"
    )
    split_dir = os.path.join(output_dir, f"{part_prefix}{group_tag}_Split")
    if records is None:
        os.makedirs(split_dir, exist_ok=True)

    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)
    narrowing = {
        "emulators_dir": emulators_dir, "zip_contents": zip_contents,
        "data_registry": data_registry, "emu_profiles": emu_profiles,
        "target_cores": target_cores, "required_only": required_only,
        "source": source, "regions": regions, "target_name": target_name,
        "one_per_slot": one_per_slot, "offline": offline,
        "no_game_data": no_game_data,
    }
    full = PackRecord()
    with contextlib.redirect_stdout(io.StringIO()):
        generate_pack(
            platform_name, platforms_dir, db, bios_dir, split_dir,
            record=full, **narrowing,
        )

    def part(pack_name: str, **scope: object) -> str | None:
        record = PackRecord() if records is not None else None
        zip_path = generate_pack(
            platform_name, platforms_dir, db, bios_dir, split_dir,
            pack_name=pack_name, record=record, within=full.sources,
            **scope, **narrowing,
        )
        if record is not None and zip_path:
            records[pack_name] = record
        return zip_path
    # The systems a core of the target runs: a part per declared system sent
    # each one the target drops to a refusal naming it as unknown.
    systems = platform_scope_systems(config, emu_profiles, target_cores)

    if group_by == "manufacturer":
        groups = _group_systems_by_manufacturer(systems, db, bios_dir)
    else:
        groups = {_system_display_name(sid): [sid] for sid in systems}

    # Pre-compute core extras once (expensive: scans 260+ emulator profiles)
    # then distribute per group based on emulator system overlap
    base_dest = config.get("base_destination", "")
    # Each part cuts the platform's own entries from the full profiles. The
    # extras are collected once here, already without the cores' game data.
    cut = (
        without_game_data(config, emu_profiles, data_registry, target_cores)
        if no_game_data else None
    )
    if source == "platform":
        all_extras = []
    elif emu_profiles:
        all_extras = _collect_emulator_extras(
            cut.config if cut else config, emulators_dir, db, set(), base_dest,
            cut.profiles if cut else emu_profiles,
            target_cores=target_cores, include_all=(source == "truth"),
        )
    else:
        all_extras = []
    if cut is not None and source != "platform":
        _report_left_out(cut, systems=set(), cores=True)
    results = []
    for group_name, group_system_ids in sorted(groups.items()):
        group_extras = _extras_for_systems(all_extras, group_system_ids)
        zip_path = part(
            f"{part_prefix}_{_name_part(group_name, '_')}_BIOS_Pack.zip",
            system_filter=group_system_ids, precomputed_extras=group_extras,
        )
        if zip_path:
            results.append(zip_path)

    # Extras whose system the platform does not declare, or that name none,
    # belong to no group: they go in a part of their own, or the parts would
    # not add up to the full pack (4507 of RetroArch's 5430 were left out).
    distributed = {
        id(fe)
        for fe in _extras_for_systems(
            all_extras, [s for ids in groups.values() for s in ids]
        )
    }
    undistributed = [fe for fe in all_extras if id(fe) not in distributed]
    if undistributed:
        zip_path = part(
            f"{part_prefix}_Other_Cores_BIOS_Pack.zip",
            precomputed_extras=undistributed, extras_only=True,
        )
        if zip_path:
            results.append(zip_path)

    return results


def _entry_for_file(candidates: list[dict], held: dict) -> dict:
    """The declaration a held file answers when several share its name.

    BBKEmu declares 8.BIN once per model. The last one won, and the A4980
    dump went to the A4988 folder. The declared hash decides, then the
    destination the collection's own path ends with, then the last one.
    """
    def declared(fe: dict, key: str) -> set[str]:
        value = fe.get(key)
        values = value if isinstance(value, list) else str(value or "").split(",")
        return {str(v).strip().lower() for v in values if str(v).strip()}

    for fe in candidates:
        if any(
            str(held.get(key, "")).lower() in declared(fe, key)
            for key in ("sha1", "md5", "sha256", "crc32")
            if held.get(key)
        ):
            return fe
    held_paths = [str(held.get("path", ""))] + [str(p) for p in held.get("paths") or []]
    for fe in candidates:
        tail = str(fe.get("path") or fe.get("destination") or "").lower()
        if tail and any(path.lower().endswith("/" + tail) for path in held_paths):
            return fe
    return candidates[-1]


def generate_md5_pack(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    output_dir: str,
    zip_contents: dict | None = None,
    platform_name: str | None = None,
    platforms_dir: str | None = None,
    emulator_name: str | None = None,
    emulators_dir: str | None = None,
    standalone: bool = False,
) -> str | None:
    """Build a pack from an explicit list of hashes with layout context."""
    files_db = db.get("files", {})
    if zip_contents is None:
        zip_contents = {}

    plat_file_index: dict[str, list[dict]] = {}
    base_dest = ""
    plat_display = "Custom"
    if platform_name and platforms_dir:
        config = load_platform_config(platform_name, platforms_dir)
        base_dest = config.get("base_destination", "")
        plat_display = config.get("platform", platform_name)
        for _sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                plat_file_index.setdefault(fe.get("name", "").lower(), []).append(fe)

    emu_display = ""
    if emulator_name and emulators_dir:
        profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
        # The same gate as --emulator, unknown names included: a typo or a
        # buildbot name gave a generic pack in the layout of no emulator. A
        # core with no standalone build has no standalone layout either.
        try:
            (_name, profile), = select_emulator_profiles(
                [emulator_name], profiles, standalone
            )
        except ProfileSelectionError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return None
        emu_display = profile.get("emulator", emulator_name)
        for fe in profile.get("files", []):
            plat_file_index.setdefault(fe.get("name", "").lower(), []).append(fe)
            for alias in fe.get("aliases", []):
                plat_file_index.setdefault(alias.lower(), []).append(fe)

    context_name = plat_display if platform_name else (emu_display or "Custom")
    # The selection mode is part of the name, as for --system: BizHawk is
    # both a platform and a profile display name, and the two layouts
    # (Firmware/ under the platform, the profile's paths under the core)
    # wrote one file, the second run replacing the first without a word.
    mode_part = "_Emulator" if emulator_name and not platform_name else ""
    # --standalone changes the destination layout, so a run with it must not
    # take the name of a run without it.
    custom_tags = "".join(
        tag
        for tag, _label in _narrowings(
            "full", None, None, False, False, standalone=standalone
        )
    )
    # The hash list is what chooses the content: two lists under one name
    # overwrote each other in the same output directory.
    selection = hashlib.sha1(
        "\n".join(sorted(f"{kind}:{value.lower()}" for kind, value in hashes)).encode()
    ).hexdigest()[:8]
    zip_name = (
        f"{_name_part(context_name, '_')}{mode_part}_Custom_{selection}{custom_tags}"
        "_BIOS_Pack.zip"
    )
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    packed: list[tuple[str, str]] = []
    not_in_repo: list[tuple[str, str]] = []
    not_in_db: list[str] = []
    seen: set[str] = set()

    with _writing_pack(zip_path) as zf:
        for hash_type, hash_val in hashes:
            sha1 = sha1_for_hash(hash_type, hash_val, db)
            if not sha1:
                not_in_db.append(hash_val)
                continue

            entry = files_db[sha1]
            name = entry.get("name", "")
            aliases = entry.get("aliases") or []
            paths = entry.get("paths") or []

            dest = name
            matched_fe = None
            for lookup_name in [name] + aliases:
                if lookup_name.lower() in plat_file_index:
                    matched_fe = _entry_for_file(
                        plat_file_index[lookup_name.lower()], entry
                    )
                    break

            if matched_fe:
                if emulator_name:
                    # Laid out as the emulator pack lays it out: its path and
                    # its standalone_path, which --standalone has to reach.
                    dest = _resolve_destination(matched_fe, standalone)
                else:
                    dest = matched_fe.get("destination", matched_fe.get("name", name))
            elif paths:
                dest = paths[0]

            if base_dest and not dest.startswith(base_dest):
                full_dest = f"{base_dest}/{dest}"
            else:
                full_dest = dest

            if full_dest in seen:
                continue
            seen.add(full_dest)

            fe_for_resolve = {"name": name, "sha1": sha1, "md5": entry.get("md5", "")}
            local_path, status = resolve_file(
                fe_for_resolve, db, bios_dir, zip_contents
            )

            if status == "not_found" or not local_path:
                not_in_repo.append((name, hash_val))
                continue

            _add_pack_member(zf, local_path, full_dest)
            packed.append((name, hash_val))

    total = len(hashes)
    print(f"\nPacked {len(packed)}/{total} requested files")
    for name, h in packed:
        print(f"  PACKED: {name} ({h[:16]}...)")
    for name, h in not_in_repo:
        print(f"  NOT IN REPO: {name} ({h[:16]}...)")
    for h in not_in_db:
        print(f"  NOT IN DB: {h}")

    if not packed:
        if os.path.exists(zip_path):
            os.unlink(zip_path)
        return None
    return zip_path


def _json_artifact_kind(path: Path) -> str | None:
    """"manifest" for an install manifest, "targets" for a per-target core
    list, None for anything else. The two share their file names: install.py
    fetches install/<platform>.json and install/targets/<platform>.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    if "manifest_version" in data:
        return "manifest"
    if all(v is None or isinstance(v, list) for v in data.values()):
        return "targets"
    return None


def _refuse_mixed_output(output_dir: str, writing: str) -> None:
    """Stop before one kind of installer JSON overwrites the other.

    Both are named <platform>.json, so --manifest-targets aimed at install/
    replaced install/retroarch.json, the file every installer downloads, with
    a target table, and the reverse replaced a target list by a manifest.
    """
    directory = Path(output_dir)
    if not directory.is_dir():
        return
    other = "targets" if writing == "manifest" else "manifest"
    held = sorted(
        p.name for p in directory.glob("*.json") if _json_artifact_kind(p) == other
    )
    if not held:
        return
    what = {
        "manifest": "install manifests (install/ in the repository)",
        "targets": "per-target core lists (install/targets/ in the repository)",
    }
    flag = "--manifest" if writing == "manifest" else "--manifest-targets"
    print(
        f"ERROR: {output_dir} holds {what[other]}: {', '.join(held[:3])}"
        f"{', ...' if len(held) > 3 else ''}. {flag} writes {what[writing]} under the "
        f"same file names; pass the --output-dir that holds those instead.",
        file=sys.stderr,
    )
    sys.exit(1)


def generate_target_manifests(targets_dir: str, output_dir: str) -> None:
    """Convert target YAMLs to installer JSON manifests."""
    os.makedirs(output_dir, exist_ok=True)
    targets_path = Path(targets_dir)
    if not targets_path.is_dir():
        print(f"No targets directory at {targets_dir}", file=sys.stderr)
        return
    count = 0
    for yml_file in sorted(targets_path.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        result = target_list(yml_file)
        out_path = Path(output_dir) / f"{yml_file.stem}.json"
        write_text_atomic(out_path, json.dumps(result, indent=2, sort_keys=True) + "\n")
        count += 1
        print(f"  {yml_file.stem}: {len(result)} targets")
    print(f"Generated {count} target manifest(s) in {output_dir}")


def target_list(yml_file: Path) -> dict[str, list[str] | dict | None]:
    """A platform's cores per hardware target, as install/targets/ publishes
    them and a pack carries them: aliases included, overrides applied."""
    targets_path = yml_file.parent
    with open(yml_file) as f:
        data = yaml_load(f) or {}
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        raise ValueError(f"{yml_file}: targets must be a mapping")

    # The pack builder accepts the aliases declared in _overrides.yml, so
    # --target switch works there. Emitting only canonical names left the
    # installer rejecting the same word and, worse, carrying on with every
    # file instead: the user asked for a filter and got the full pack.
    overrides_path = targets_path / "_overrides.yml"
    alias_map: dict[str, list[str]] = {}
    platform_overrides: dict = {}
    if overrides_path.is_file():
        with open(overrides_path) as f:
            all_overrides = yaml_load(f) or {}
        platform_overrides = (
            all_overrides.get(yml_file.stem, {}).get("targets", {}) or {}
        )
        for tname, ovr in platform_overrides.items():
            names = [a for a in (ovr or {}).get("aliases", []) if isinstance(a, str)]
            if names:
                alias_map[tname] = names

    result: dict[str, list[str] | dict | None] = {}
    for target_name, target_info in targets.items():
        if not isinstance(target_name, str) or not target_name:
            raise ValueError(f"{yml_file}: target names must be non-empty strings")
        if not isinstance(target_info, dict):
            raise ValueError(f"{yml_file}: target {target_name!r} must be a mapping")
        cores = target_info.get("cores")
        if cores is None:
            result[target_name] = None
            continue
        if (
            not isinstance(cores, list)
            or any(not isinstance(core, str) or not core for core in cores)
            or len(cores) != len(set(cores))
        ):
            raise ValueError(
                f"{yml_file}: target {target_name!r} cores must be unique "
                "non-empty strings"
            )
        # The builder's own reading, overrides included: a list published
        # another way makes the installer serve what the pack does not.
        # An empty list is a board with no core, not one with every core.
        resolved = load_target_config(
            yml_file.stem, target_name, str(targets_path.parent)
        )
        listed = None if resolved is None else sorted(resolved)
        images = target_info.get("images")
        # The image names a card's board file holds (Batocera writes
        # anbernic-rg35xx-plus for the h700 target): the installer reads
        # the board of a card prepared on a computer through them.
        result[target_name] = (
            {"cores": listed, "images": images}
            if images and listed is not None else listed
        )

    for target_name, names in alias_map.items():
        if target_name not in result:
            continue
        for alias in names:
            if alias in result:
                raise ValueError(
                    f"{yml_file}: alias {alias!r} collides with a target name"
                )
            # An alias names the board, not its images.
            held = result[target_name]
            result[alias] = held["cores"] if isinstance(held, dict) else held
    return result


def _resolve_systems(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Turn --system into the platform's system ids, before any work.

    With --platform the platform's own names count too (Batocera's psx), the
    mapping the install manifest carries. With --all each name must be one
    of our ids some platform declares. Checked inside the build, a typo cost
    the lock and a refresh of every data directory first, then ended on a
    WARNING and exit 1, and a list with one known name ignored the others.
    """
    if not args.system or not (args.platform or args.all):
        return
    if args.platform:
        config = load_platform_config(args.platform, args.platforms_dir)
        systems = list(config.get("systems", {}))
        listing = f"--platform {args.platform} --list-systems"
    else:
        config = None
        systems = sorted({
            sid
            for name in list_registered_platforms(args.platforms_dir)
            for sid in load_platform_config(name, args.platforms_dir).get("systems", {})
        })
        listing = "--platform <name> --list-systems"
    try:
        args.system_ids = resolve_system_arg(args.system, systems, config, listing)
    except ValueError as exc:
        parser.error(f"--system {args.system}: {exc}")


def _platforms_with_systems(
    args: argparse.Namespace,
    platforms: list[str],
    system_filter: list[str],
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
) -> list[str]:
    """The platforms a --system list leaves a system to pack, before any lock.

    Under --all a platform without one is out of scope, as a platform
    without the target is: `--all --system sony-playstation-2` built every
    PS2 pack and exited 1 on MiSTer, which has no PS2. Under --platform the
    request is refused here, with its reason.
    """
    kept = []
    for name in platforms:
        config = load_platform_config(name, args.platforms_dir)
        tc = target_cores_cache.get(name) if args.target else None
        if platform_scope_systems(config, emu_profiles, tc, system_filter):
            kept.append(name)
            continue
        if not args.all:
            reason = system_scope_error(config, name, system_filter, args.target)
            print(f"ERROR: {reason}", file=sys.stderr)
            sys.exit(1)
        declared = select_systems(config.get("systems", {}), system_filter)
        reason = (
            system_scope_error(config, name, system_filter, args.target)
            if declared and args.target
            else f"no system {', '.join(system_filter)}"
        )
        print(f"INFO: Skipping {name}: {reason}")
    if not kept:
        where = f" on target {args.target}" if args.target else ""
        print(f"ERROR: no platform packed here runs {', '.join(system_filter)}{where}",
              file=sys.stderr)
        sys.exit(1)
    return kept


def _refuse_for_verify_packs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """What --verify-packs cannot be combined with, refused before any lock.

    These lived in the --all-variants checks, which return at once without
    that flag: --verify-packs --manifest or --split went through, and a run
    with neither --platform nor --all failed after locking the directory.
    """
    if not args.verify_packs:
        return
    if args.manifest:
        parser.error("--verify-packs is incompatible with --manifest")
    if not (args.platform or args.all):
        parser.error("--verify-packs requires --platform or --all")
    # The check that follows the build reads the full pack's name.
    for flag, given in (
        ("--system", args.system),
        ("--one-per-slot", args.one_per_slot),
        ("--split", args.split),
    ):
        if given:
            parser.error(f"{flag} is incompatible with --verify-packs")


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate argument combinations and mutual exclusion rules."""
    _refuse_for_verify_packs(args, parser)
    has_platform = bool(args.platform)
    has_all = args.all
    has_emulator = bool(args.emulator)
    has_system = bool(args.system)
    has_from_md5 = bool(args.from_md5 or getattr(args, "from_md5_file", None))

    if args.from_md5 and getattr(args, "from_md5_file", None):
        parser.error("--from-md5 and --from-md5-file are mutually exclusive")
    if has_from_md5 and has_all:
        parser.error("--from-md5 requires --platform or --emulator, not --all")
    if has_from_md5 and has_system:
        parser.error("--from-md5 and --system are mutually exclusive")
    if has_from_md5 and args.split:
        parser.error("--split and --from-md5 are mutually exclusive")

    # --platform/--all and --system can combine (system filters within platform)
    # --emulator is exclusive with everything else
    if has_emulator and (has_platform or has_all or has_system):
        parser.error(
            "--emulator is mutually exclusive with --platform, --all, and --system"
        )
    if has_platform and has_all:
        parser.error("--platform and --all are mutually exclusive")
    if not (has_platform or has_all or has_emulator or has_system or has_from_md5):
        parser.error("Specify --platform, --all, --emulator, --system, or --from-md5")
    if args.standalone and not (
        has_emulator or (has_system and not has_platform and not has_all)
    ):
        parser.error(
            "--standalone requires --emulator or --system (without --platform)"
        )
    if args.split and not (has_platform or has_all):
        parser.error("--split requires --platform or --all")
    if args.split and has_emulator:
        parser.error("--split is incompatible with --emulator")
    if args.group_by is not None and not args.split:
        parser.error("--group-by requires --split")
    if args.target and not (has_platform or has_all):
        parser.error("--target requires --platform or --all")
    if args.target and has_emulator:
        parser.error("--target is incompatible with --emulator")
    if args.manifest and not (has_platform or has_all):
        parser.error("--manifest requires --platform or --all")
    if args.manifest and has_emulator:
        parser.error("--manifest is incompatible with --emulator")
    if args.manifest and args.split:
        parser.error("--manifest is incompatible with --split")
    if getattr(args, "region", None) and has_from_md5:
        parser.error("--region and --from-md5 are mutually exclusive")
    # A mode either applies a narrowing flag or refuses it. Swallowing one
    # answers about an artifact the caller did not ask for, and the name on
    # disk then asserts a narrowing the contents do not carry.
    # --source and --group-by default to None so a typed default value is
    # seen: compared with "full", `--emulator X --source full` went through.
    source_given = getattr(args, "source", None) is not None
    if source_given and (has_emulator or (has_system and not has_platform)):
        parser.error("--source requires --platform or --all")
    if has_from_md5:
        for flag, given in (
            ("--manifest", args.manifest),
            ("--target", args.target),
            ("--required-only", args.required_only),
            ("--source", source_given),
        ):
            if given:
                parser.error(f"{flag} is incompatible with --from-md5")
    if has_system and (has_platform or has_all):
        if args.manifest:
            parser.error("--system is incompatible with --manifest")
        if args.split:
            parser.error("--system is incompatible with --split")

    # Game data is categorized against a platform's list and the cores it
    # runs: a pack of one emulator or of a system's emulators has neither.
    if getattr(args, "no_game_data", False) and not (has_platform or has_all):
        parser.error("--no-game-data requires --platform or --all")
    if getattr(args, "no_game_data", False) and has_from_md5:
        parser.error("--no-game-data is incompatible with --from-md5")
    if getattr(args, "one_per_slot", False):
        if has_from_md5:
            parser.error("--one-per-slot and --from-md5 are mutually exclusive")
        if args.manifest:
            parser.error("--one-per-slot is incompatible with --manifest")
        if has_emulator:
            parser.error("--one-per-slot is incompatible with --emulator")
        if has_system:
            parser.error("--one-per-slot is incompatible with --system")


def _write_manifest_if_changed(path: str, manifest: dict) -> None:
    """Write manifest JSON only if content (excluding timestamp) changed."""
    new_json = json.dumps(manifest, indent=2)
    if os.path.exists(path):
        with open(path) as f:
            try:
                old = json.load(f)
            except (json.JSONDecodeError, OSError):
                old = None
        if old is not None:
            # Compare everything except the generated timestamp
            old_cmp = {k: v for k, v in old.items() if k != "generated"}
            new_cmp = {k: v for k, v in manifest.items() if k != "generated"}
            if old_cmp == new_cmp:
                return  # no content change, keep existing timestamp
    write_text_atomic(path, new_json)


def _run_manifest_mode(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    db: dict,
    zip_contents: dict,
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
) -> None:
    """Generate JSON manifests instead of ZIP packs."""
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    os.makedirs(args.output_dir, exist_ok=True)
    registry: dict = {}
    if os.path.exists(registry_path):
        with open(registry_path) as _rf:
            registry = yaml_load(_rf) or {}

    variants = ALL_VARIANTS if args.all_variants else ((args.source, args.required_only),)

    failed: list[str] = []
    for source, required_only in variants:
        for group_platforms, representative in groups:
            print(f"\nGenerating manifest for {representative} [source={source}]...")
            tc = target_cores_cache.get(representative) if args.target else None
            if _skip_empty_truth(args, source, representative, emu_profiles, tc, failed):
                continue
            try:
                manifest = generate_manifest(
                    representative,
                    args.platforms_dir,
                    db,
                    args.bios_dir,
                    registry_path,
                    emulators_dir=args.emulators_dir,
                    zip_contents=zip_contents,
                    emu_profiles=emu_profiles,
                    target_cores=tc,
                    source=source,
                    regions=getattr(args, "regions", None),
                    target_name=_platform_target(
                        representative, args.target, args.platforms_dir
                    ),
                    offline=args.offline,
                    required_only=required_only,
                    no_game_data=getattr(args, "no_game_data", False),
                )
                narrow_suffix = "".join(
                    tag.lower()
                    for tag, _label in _narrowings(
                        source,
                        getattr(args, "regions", None),
                        _platform_target(representative, args.target, args.platforms_dir),
                        False,
                        required_only,
                        no_game_data=getattr(args, "no_game_data", False),
                    )
                )
                out_path = os.path.join(
                    args.output_dir,
                    f"{representative}{narrow_suffix}.json",
                )
                _write_manifest_if_changed(out_path, manifest)
                print(
                    f"  {out_path}: {manifest['total_files']} files, "
                    f"{manifest['total_size']} bytes, "
                    f"{manifest['total_omitted']} safely omitted"
                )
                # Create aliases for grouped platforms (e.g., lakka -> retroarch)
                for alias_plat in group_platforms:
                    if alias_plat != representative:
                        alias_path = os.path.join(
                            args.output_dir,
                            f"{alias_plat}{narrow_suffix}.json",
                        )
                        alias_manifest = dict(manifest)
                        alias_manifest["platform"] = alias_plat
                        alias_cfg = load_platform_config(alias_plat, args.platforms_dir)
                        alias_manifest["display_name"] = alias_cfg.get(
                            "platform", alias_plat
                        )
                        alias_manifest["version"] = platform_list_version(
                            alias_cfg, alias_plat
                        )
                        alias_manifest["base_destination"] = alias_cfg.get(
                            "base_destination", ""
                        )
                        alias_registry = registry.get("platforms", {}).get(alias_plat, {})
                        alias_install = alias_registry.get("install", {})
                        alias_manifest["detect"] = alias_install.get("detect", [])
                        # Placed and completed as the representative's are:
                        # copied raw, an alias's copies named no source.
                        alias_manifest["standalone_copies"] = _standalone_copies(
                            alias_install.get("standalone_copies", []),
                            {name: emu_profiles[name]
                             for name in _platform_cores(alias_cfg, emu_profiles)},
                            manifest["files"],
                        )
                        _write_manifest_if_changed(alias_path, alias_manifest)
                        print(f"  {alias_path}: alias of {representative}")
            except (FileNotFoundError, OSError, yaml.YAMLError) as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                failed.append(representative)

    # A platform whose manifest could not be built has none, and install.py
    # serves whatever an older run left there: that is a failed run.
    if failed:
        print(f"ERROR: no manifest for {', '.join(sorted(set(failed)))}", file=sys.stderr)
        sys.exit(1)


@contextlib.contextmanager
def _pack_output_lock(output_dir: str, exclusive: bool = True) -> Iterator[None]:
    """Hold the output directory for the duration of a pack run, and the
    repository's fixed outputs when it is one of them (install/)."""
    try:
        with artifact_lock(output_dir, exclusive=exclusive), \
                repository_output_lock(output_dir) if exclusive else contextlib.nullcontext():
            yield
    except ArtifactLockBusy as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


def _baseline_shortfall(excluded: int, absent: int) -> list[str]:
    """Why a verified pack holds fewer baseline files than the platform declares."""
    parts = []
    if excluded:
        parts.append(f"{excluded} unsafe excluded")
    if absent:
        parts.append(f"{absent} not in the collection")
    return parts


def _run_verify_packs(args: argparse.Namespace) -> None:
    """Verify each pack in the output directory against its platform.

    Delegates to verify_pack_against_platform so the command answers the same
    question the pipeline asks: baseline files, core extras and structure. A
    second implementation here answered a narrower one and reported OK while
    the core extras went unchecked.
    """
    verify_db = load_database(args.db)

    if args.platform:
        platforms = [args.platform]
    elif args.all:
        # The packs --all builds: a platform without release_pack has no pack
        # to check, and its absence from the directory is no failure.
        platforms = list_release_pack_platforms(args.platforms_dir)
    else:
        raise ValueError("--verify-packs requires --platform or --all")

    # The target is checked as the build checks it: a mistyped one, or one
    # the platform does not publish, was dropped and the full pack verified
    # under it, `all OK` for a pack no build had made.
    target_cores_cache: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores_cache, platforms = build_target_cores_cache(
                platforms, args.target, args.platforms_dir, is_all=args.all
            )
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    all_ok = True
    verify_regions = getattr(args, "regions", None)
    verify_profiles = load_emulator_profiles(args.emulators_dir)
    verify_data_registry = load_data_dir_registry(args.platforms_dir)
    # After an --all-variants build every variant is named, so none of the
    # six packs the run wrote passes unmentioned.
    expected = _expected_pack_names(
        platforms,
        args.platforms_dir,
        verify_regions,
        args.target,
        ALL_VARIANTS if args.all_variants else (("full", False),),
        no_game_data=getattr(args, "no_game_data", False),
    )
    on_disk = (
        set(os.listdir(args.output_dir)) if os.path.isdir(args.output_dir) else set()
    )

    verified = 0
    failing: list[str] = []
    for platform_name in platforms:
        found = sorted(expected[platform_name] & on_disk)
        verified += len(found)
        if not found:
            # Naming a platform is asking about its pack: FAIL, with the
            # command that builds it. With --all, a platform whose pack was
            # not built is out of scope and skipped.
            if args.platform:
                print(
                    f"  {platform_name}: FAIL (no pack in {args.output_dir}; build it with "
                    f"python scripts/generate_pack.py --platform {platform_name} "
                    f"--output-dir {args.output_dir})"
                )
                all_ok = False
                failing.append(f"{platform_name} (no pack)")
            else:
                print(f"  {platform_name}: SKIP (no pack in {args.output_dir})")
            continue
        tc = target_cores_cache.get(platform_name)
        # A group pack and a pack built for the platform alone can both be
        # present, and each one is a pack of this platform.
        for pack_name in found:
            variant = _pack_variant(pack_name)
            if variant is None:
                # One BIOS per slot: the slot choice is not replayed here.
                print(
                    f"  {platform_name} [{pack_name}]: hashes checked during the build; "
                    "one per slot by design, so not compared to the platform's full list"
                )
                continue
            source, required_only = variant
            zip_path = os.path.join(args.output_dir, pack_name)
            result = verify_pack_against_platform(
                zip_path,
                platform_name,
                args.platforms_dir,
                db=verify_db,
                emulators_dir=args.emulators_dir,
                emu_profiles=verify_profiles,
                regions=verify_regions,
                data_registry=verify_data_registry,
                target_cores=tc,
                source=source,
                required_only=required_only,
                no_game_data=getattr(args, "no_game_data", False),
            )
            (ok, _checked, _present, errors, bl_checked, bl_present,
             core_checked, core_present, bl_excluded, bl_absent) = result
            # These explain a baseline short of its total: a dump whose hash
            # the frontend refuses is left out on purpose, and a file the
            # collection does not hold cannot be packed (verify reports it).
            shortfall = ", ".join(_baseline_shortfall(bl_excluded, bl_absent))
            excluded = f" ({shortfall})" if shortfall else ""
            counts = (
                f"{bl_present}/{bl_checked} baseline{excluded}, "
                f"{core_present}/{core_checked} cores"
            )
            if ok:
                print(f"  {platform_name} [{pack_name}]: OK ({counts})")
            else:
                print(f"  {platform_name} [{pack_name}]: FAIL ({counts}, {len(errors)} errors)")
                for err in errors:
                    print(f"    {err}")
                all_ok = False
                failing.append(f"{platform_name} ({pack_name})")

    if failing:
        # Named at the end, where the log is read, and on stderr, as the
        # build path does: a failing pack sat among its own error lines.
        print(
            f"ERROR: packs failed verification: {', '.join(failing)}",
            file=sys.stderr,
        )
    elif verified:
        print(f"Verified {verified} pack{'s' if verified != 1 else ''}: all OK")
    if not verified:
        # Every platform skipped is no check at all: a mistyped or purged
        # output directory read as a passed integrity check.
        print(f"ERROR: no pack to verify in {args.output_dir}", file=sys.stderr)
        all_ok = False
    if not all_ok:
        sys.exit(1)


# The source x required combinations --all-variants builds, in build order.
ALL_VARIANTS: tuple[tuple[str, bool], ...] = (
    ("full", False), ("full", True),
    ("platform", False), ("platform", True),
    ("truth", False), ("truth", True),
)


def _pack_label(source: str, required_only: bool) -> str:
    """The variant tag pipeline.parse_pack_counts reads after a pack name."""
    return f"[source={source}, required]" if required_only else f"[source={source}]"


def _truth_layer_is_empty(
    platform: str, platforms_dir: str, emu_profiles: dict, target_cores: set[str] | None
) -> bool:
    """Whether a platform runs no core a profile describes.

    MiSTer declares `cores: []`: its truth pack held nothing, passed its
    check and was published under a name claiming a content.
    """
    config = load_platform_config(platform, platforms_dir)
    return not _platform_cores(config, emu_profiles or {}, target_cores=target_cores)


def _skip_empty_truth(
    args: argparse.Namespace,
    source: str,
    representative: str,
    emu_profiles: dict,
    tc: set[str] | None,
    failed: list[str],
) -> bool:
    """Leave out a truth pack that would be empty, refuse it when asked for."""
    if source != "truth" or not _truth_layer_is_empty(
        representative, args.platforms_dir, emu_profiles, tc
    ):
        return False
    if args.all_variants:
        print(f"  {representative}: no core profile, no truth pack")
    else:
        print(
            f"ERROR: {representative} runs no core a profile describes; "
            "a truth pack would hold nothing",
            file=sys.stderr,
        )
        failed.append(representative)
    return True


def _produced(split: bool, zip_path: str | None, zip_paths: list[str] | None) -> bool:
    """Whether the build wrote what the run asked for."""
    return bool(zip_paths if split else zip_path)


def _run_platform_packs(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    db: dict,
    zip_contents: dict,
    data_registry: dict | None,
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
    system_filter: list[str] | None,
) -> None:
    """Generate ZIP packs for platform groups and verify."""
    variants = ALL_VARIANTS if args.all_variants else ((args.source, args.required_only),)
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    # Per pack, the systems each of its files is for, written into its
    # manifest.json once the pack is verified (pack_systems).
    systems_for: dict[str, dict] = {}
    # The packs this run writes, the only ones it verifies and rewrites.
    built: set[str] = set()

    failed: list[str] = []
    for source, required_only in variants:
        for group_platforms, representative in groups:
            aliases = [p for p in group_platforms if p != representative]
            if aliases:
                all_names = [
                    load_platform_config(p, args.platforms_dir).get("platform", p)
                    for p in group_platforms
                ]
                label = " / ".join(all_names)
                print(f"\nGenerating pack for {label} {_pack_label(source, required_only)}...")
            else:
                print(f"\nGenerating pack for {representative} {_pack_label(source, required_only)}...")

            zip_path = None
            zip_paths: list = []
            tc = target_cores_cache.get(representative) if args.target else None
            named_target = _platform_target(representative, args.target, args.platforms_dir)
            if _skip_empty_truth(args, source, representative, emu_profiles, tc, failed):
                continue
            try:
                if args.split:
                    zip_paths = generate_split_packs(
                        representative,
                        args.platforms_dir,
                        db,
                        args.bios_dir,
                        args.output_dir,
                        group_by=args.group_by,
                        emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents,
                        data_registry=data_registry,
                        emu_profiles=emu_profiles,
                        target_cores=tc,
                        required_only=required_only,
                        source=source,
                        regions=getattr(args, "regions", None),
                        target_name=named_target,
                        one_per_slot=args.one_per_slot,
                        offline=args.offline,
                        no_game_data=getattr(args, "no_game_data", False),
                    )
                    print(f"  Split into {len(zip_paths)} packs")
                else:
                    # A group's pack is written under the group's name from
                    # the start: built under the representative's and then
                    # renamed, it overwrote and carried away a
                    # `--platform retroarch` pack already in the directory,
                    # and os.rename refused an existing target on Windows.
                    group_name = None
                    if aliases:
                        narrow_tags = "".join(
                            tag
                            for tag, _label in _narrowings(
                                source,
                                getattr(args, "regions", None),
                                named_target,
                                args.one_per_slot,
                                required_only,
                                no_game_data=getattr(args, "no_game_data", False),
                            )
                        )
                        stem = _platform_pack_stem(
                            group_platforms, representative, args.platforms_dir
                        )
                        group_name = (
                            f"{stem}{narrow_tags}_BIOS_Pack"
                            f"{_system_tag(system_filter)}.zip"
                        )
                    zip_path = generate_pack(
                        representative,
                        args.platforms_dir,
                        db,
                        args.bios_dir,
                        args.output_dir,
                        emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents,
                        data_registry=data_registry,
                        emu_profiles=emu_profiles,
                        target_cores=tc,
                        required_only=required_only,
                        system_filter=system_filter,
                        source=source,
                        regions=getattr(args, "regions", None),
                        target_name=named_target,
                        one_per_slot=args.one_per_slot,
                        offline=args.offline,
                        pack_name=group_name,
                        no_game_data=getattr(args, "no_game_data", False),
                    )
            except (FileNotFoundError, OSError, yaml.YAMLError) as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                failed.append(representative)
            else:
                # A builder that declined (no system left under the target)
                # produced nothing: the run must say so, not verify whatever
                # the output directory already held and exit 0.
                if not _produced(args.split, zip_path, zip_paths):
                    failed.append(representative)
                    continue
                built.update(
                    os.path.relpath(path, args.output_dir)
                    for path in ([zip_path] if zip_path else zip_paths)
                )
                if zip_path and not system_filter:
                    # The install list of the same choices names each file's
                    # systems: the pack records them, so a pack alone (a
                    # handheld without Wi-Fi) can be narrowed by system.
                    board_list = Path(args.platforms_dir) / "targets" / f"{representative}.yml"
                    systems_for[os.path.basename(zip_path)] = pack_systems(generate_manifest(
                        representative, args.platforms_dir, db, args.bios_dir,
                        registry_path, emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents, emu_profiles=emu_profiles,
                        target_cores=tc, source=source,
                        regions=getattr(args, "regions", None), target_name=named_target,
                        offline=args.offline, required_only=required_only,
                        data_registry=data_registry,
                        no_game_data=getattr(args, "no_game_data", False),
                    ), target_list(board_list) if board_list.is_file() else None)

    print("\nVerifying packs and generating manifests...")
    skip_conf = bool(system_filter or args.split)
    all_ok = verify_and_finalize_packs(
        args.output_dir,
        db,
        platforms_dir=args.platforms_dir,
        emulators_dir=args.emulators_dir,
        built=built,
        pack_systems_by_name=systems_for,
        skip_conformance=skip_conf,
        data_registry=data_registry,
        regions=getattr(args, "regions", None),
        target_name=args.target,
        no_game_data=getattr(args, "no_game_data", False),
    )
    if args.split:
        for entry in os.listdir(args.output_dir):
            sub = os.path.join(args.output_dir, entry)
            if os.path.isdir(sub) and entry.endswith("_Split"):
                ok = verify_and_finalize_packs(
                    sub,
                    db,
                    platforms_dir=args.platforms_dir,
                    emulators_dir=args.emulators_dir,
                    built={
                        os.path.basename(name) for name in built
                        if os.path.dirname(name) == entry
                    },
                    skip_conformance=True,
                    data_registry=data_registry,
                    regions=getattr(args, "regions", None),
                )
                all_ok = all_ok and ok
    if failed:
        # Verification only sees the ZIPs that exist, so a pack that was never
        # written does not fail it.
        print(f"ERROR: no pack for {', '.join(sorted(set(failed)))}", file=sys.stderr)
        sys.exit(1)
    if not all_ok:
        sys.exit(1)


def _refuse_for_all_variants(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Flags --all-variants would override, or modes that never read it."""
    if not args.all_variants:
        return
    # It builds the six source x required combinations itself: a --source
    # or --required-only beside it would be overridden, and the modes that
    # build one pack (emulator, system, hashes) never read it.
    for flag, given in (
        ("--source", args.source is not None),
        ("--required-only", args.required_only),
        ("--no-game-data", getattr(args, "no_game_data", False)),
        ("--emulator", args.emulator),
        ("--from-md5", args.from_md5 or args.from_md5_file),
    ):
        if given:
            parser.error(f"{flag} is incompatible with --all-variants")
    if args.system and not (args.platform or args.all):
        parser.error("--all-variants requires --platform or --all")


def _refuse_refresh_data(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Only the platform pack path refreshes the data directories.

    Elsewhere the cache on disk was packed as it stood, and --offline wins
    over the refresh without a word.
    """
    if args.refresh_data and args.no_refresh_data:
        parser.error("--refresh-data is incompatible with --no-refresh-data")
    for name, given in (("--refresh-data", args.refresh_data),
                        ("--no-refresh-data", args.no_refresh_data)):
        if not given:
            continue
        for flag, on in (
            ("--offline", args.offline),
            ("--emulator", args.emulator),
            ("--system", args.system and not (args.platform or args.all)),
            ("--from-md5", args.from_md5 or args.from_md5_file),
        ):
            if on:
                parser.error(f"{name} is incompatible with {flag}")


def _refuse_unapplied_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Refuse every flag the requested mode would not apply.

    A mode applies a narrowing flag or refuses it: a swallowed flag answers
    about an artifact the caller did not name. Run before any quick-exit
    mode, since --verify-packs and --manifest-targets return early.
    """
    # Parsed before the quick-exit modes: --verify-packs returns early and
    # still needs the region priority list to narrow its expectation.
    args.regions = []
    if args.region:
        try:
            args.regions = region_mod.parse_requested(args.region)
        except ValueError as exc:
            parser.error(str(exc))
        if args.manifest_targets:
            parser.error("--region is incompatible with --manifest-targets")
    if args.one_per_slot and args.manifest_targets:
        parser.error("--one-per-slot is incompatible with --manifest-targets")
    _refuse_refresh_data(args, parser)

    _refuse_for_all_variants(args, parser)
    mode = next(
        (
            name for name, on in (
                ("--manifest-targets", args.manifest_targets),
                ("--verify-packs", args.verify_packs and not args.all_variants),
                ("--list-platforms", args.list),
                ("--list-emulators", args.list_emulators),
                ("--list-systems", args.list_systems),
                ("--list-targets", args.list_targets),
            ) if on
        ),
        None,
    )
    if mode is None:
        return
    given = _given_flags(args)
    for flag in sorted(given - QUICK_MODE_FLAGS[mode] - {mode}):
        parser.error(f"{flag} is incompatible with {mode}")


# What each mode that returns early reads. Anything else given beside it is
# refused: the mode would answer about an artifact the caller did not name.
QUICK_MODE_FLAGS: dict[str, set[str]] = {
    # Checks packs already on disk against the platform's own list, narrowed
    # by region and target and by nothing else.
    "--verify-packs": {
        "--platform", "--all", "--target", "--region", "--no-game-data",
    },
    # One manifest per hardware target, from the target files themselves.
    "--manifest-targets": set(),
    "--list-platforms": set(),
    "--list-emulators": set(),
    "--list-systems": {"--platform"},
    "--list-targets": {"--platform"},
}


def _given_flags(args: argparse.Namespace) -> set[str]:
    """Flags that select or narrow what a run produces, as typed."""
    flags = {
        "--platform": args.platform,
        "--all": args.all,
        "--emulator": args.emulator,
        "--system": args.system,
        "--standalone": args.standalone,
        "--split": args.split,
        "--group-by": args.group_by is not None,
        "--manifest": args.manifest,
        "--manifest-targets": args.manifest_targets,
        "--verify-packs": args.verify_packs,
        "--all-variants": args.all_variants,
        "--from-md5": args.from_md5,
        "--from-md5-file": args.from_md5_file,
        "--required-only": args.required_only,
        "--no-game-data": getattr(args, "no_game_data", False),
        "--source": args.source is not None,
        "--target": args.target,
        "--region": args.region,
        "--one-per-slot": args.one_per_slot,
        "--list-platforms": args.list,
        "--list-emulators": args.list_emulators,
        "--list-systems": args.list_systems,
        "--list-targets": args.list_targets,
        "--refresh-data": args.refresh_data,
        "--no-refresh-data": args.no_refresh_data,
    }
    return {flag for flag, on in flags.items() if on}


# Data directories a pack needed and the cache did not hold. The pack is
# written without them, so the run cannot exit as if it were complete: a
# refresh refused by a quota left the PPSSPP pack with 2 files, exit 0.
_MISSING_DATA_DIRS: set[str] = set()


def main() -> None:
    # One run's account: tests call main() repeatedly in one process, and a
    # notice left by an earlier run failed a later one that missed nothing.
    _MISSING_DATA_DIRS.clear()
    with contextlib.ExitStack() as held:
        try:
            _main(held)
        except DamagedArchiveError as exc:
            # Emulator, system and hash modes have no per-platform loop to
            # report it: the run stops with the file to restore.
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
    if _MISSING_DATA_DIRS:
        print(
            "ERROR: packs written without data directories that are not cached: "
            f"{', '.join(sorted(_MISSING_DATA_DIRS))} (run refresh_data_dirs.py)",
            file=sys.stderr,
        )
        sys.exit(1)


def _main(held: contextlib.ExitStack) -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate platform BIOS ZIP packs")
    parser.add_argument(
        "--platform", "-p", type=platform_arg,
        help="Platform name (e.g., retroarch)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Generate the release packs (release_pack in the registry), or with"
        " --manifest the install manifests of every platform",
    )
    parser.add_argument(
        "--emulator", "-e", help="Emulator profile name(s), comma-separated"
    )
    parser.add_argument("--system", "-s", help="System ID(s), comma-separated")
    parser.add_argument("--standalone", action="store_true", help="Use standalone mode")
    parser.add_argument(
        "--list-emulators", action="store_true", help="List available emulators"
    )
    parser.add_argument(
        "--list-systems", action="store_true", help="List available systems"
    )
    parser.add_argument(
        "--platforms-dir", default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument("--db", default=DEFAULT_DB_FILE, help="Path to database.json")
    parser.add_argument(
        "--bios-dir", default=DEFAULT_BIOS_DIR,
        help="BIOS collection directory (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir", "-o", default=DEFAULT_OUTPUT_DIR,
        help="directory the packs and manifests go to (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="No network at all: data directories and release assets come "
        "from the cache only, so a gitignored file never fetched is missing "
        "(--no-refresh-data keeps the trees as cached and still fetches assets)",
    )
    parser.add_argument(
        "--refresh-data",
        action="store_true",
        help="Force re-download all data directories",
    )
    parser.add_argument(
        "--no-refresh-data",
        action="store_true",
        help="Pack the data directories as cached, still fetching release assets",
    )
    # install.py's name. --list stays for the scripts that already type it.
    parser.add_argument(
        "--list-platforms", "--list", dest="list", action="store_true",
        help="List available platforms",
    )
    parser.add_argument(
        "--required-only",
        action="store_true",
        help="Only include required files, skip optional",
    )
    parser.add_argument(
        "--no-game-data",
        action="store_true",
        help="Leave out game data (the platform's entries a core reads as a "
        "game's files, and the cores' game data files): firmware only",
    )
    parser.add_argument(
        "--source",
        choices=["platform", "truth", "full"],
        default=None,
        help="File source: platform (YAML only), truth (emulator profiles), full "
             "(both, the default)",
    )
    parser.add_argument(
        "--all-variants",
        action="store_true",
        help="Generate all 6 source x required combinations",
    )
    parser.add_argument(
        "--split", action="store_true", help="Generate one ZIP per system/manufacturer"
    )
    parser.add_argument(
        "--group-by",
        choices=["system", "manufacturer"],
        default=None,
        help="Grouping for --split (default: system)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region",
        help="Region priority list, best first (e.g. us,eu,jp)",
    )
    parser.add_argument(
        "--one-per-slot",
        action="store_true",
        help="Keep one BIOS per system and region where the core declares an order",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--from-md5",
        help="Hash(es) to look up or pack, comma-separated: CRC32, MD5, SHA-1 or SHA-256",
    )
    parser.add_argument(
        "--from-md5-file",
        help="File with hashes, one per line, alone or beside a file name as md5sum writes it",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Output JSON manifests instead of ZIP packs",
    )
    parser.add_argument(
        "--manifest-targets",
        action="store_true",
        help="Convert target YAMLs to installer JSON",
    )
    parser.add_argument(
        "--verify-packs",
        action="store_true",
        help="Extract and verify pack integrity (path + hash)",
    )
    args = parser.parse_args()
    from verify import work_from_repo_root

    work_from_repo_root(
        args, parser,
        ["db", "platforms_dir", "bios_dir", "output_dir", "emulators_dir", "from_md5_file"],
    )
    packresolve.set_offline(bool(args.offline))
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    require_directory(args.bios_dir)

    _refuse_unapplied_flags(args, parser)
    _refuse_for_verify_packs(args, parser)
    # Quick-exit modes: --verify-packs alone = verify existing packs only
    # Combined with --all-variants, generation runs first then verify
    if args.verify_packs and not args.all_variants:
        # The check resolves core files against data/ like the build did,
        # and a refresh swapping a tree mid-check would judge another tree.
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
        with _pack_output_lock(args.output_dir, exclusive=False):
            _run_verify_packs(args)
        return
    if args.manifest_targets:
        _refuse_mixed_output(args.output_dir, "targets")
        with _pack_output_lock(args.output_dir):
            generate_target_manifests(
                os.path.join(args.platforms_dir, "targets"), args.output_dir
            )
        return
    if args.list:
        print_platform_listing(args.platforms_dir)
        return
    if args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
        return
    if args.list_systems:
        if args.platform:
            list_platform_system_ids(args.platform, args.platforms_dir)
        else:
            list_system_ids(args.emulators_dir)
        return
    if args.list_targets:
        if not args.platform:
            parser.error("--list-targets requires --platform")
        from common import list_available_targets

        targets = list_available_targets(args.platform, args.platforms_dir)
        if not targets:
            print(f"No targets configured for platform '{args.platform}'")
            return
        for t in targets:
            print(target_listing_line(t))
        return

    _validate_args(args, parser)
    _resolve_systems(args, parser)
    # Unset until every refusal has run, so a typed default value is seen.
    args.source = args.source or "full"
    args.group_by = args.group_by or "system"

    # Hash lookup / pack mode
    # A platform run may refresh the trees below, under the exclusive lock:
    # it takes the shared ones after that. Every other mode reads them now.
    if not (args.platform or args.all) or args.offline or args.no_refresh_data:
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
    has_from_md5 = bool(args.from_md5 or getattr(args, "from_md5_file", None))
    if has_from_md5:
        try:
            hashes = (
                parse_hash_input(args.from_md5)
                if args.from_md5
                else parse_hash_file(args.from_md5_file)
            )
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
        except OSError as exc:
            print(f"ERROR: --from-md5-file {args.from_md5_file}: {exc.strerror}", file=sys.stderr)
            sys.exit(1)
        if not hashes:
            print(
                f"ERROR: no hash in the input. Accepted: {ACCEPTED_HASHES}",
                file=sys.stderr,
            )
            sys.exit(1)
        db = load_database(args.db)
        if not args.platform and not args.emulator:
            # A lookup that found nothing is an answer a script must see.
            if lookup_hashes(
                hashes, db, args.bios_dir, args.emulators_dir, args.platforms_dir
            ):
                sys.exit(1)
            return
        zip_contents = build_zip_contents_index(db)
        with _pack_output_lock(args.output_dir):
            result = generate_md5_pack(
                hashes=hashes,
                db=db,
                bios_dir=args.bios_dir,
                output_dir=args.output_dir,
                zip_contents=zip_contents,
                platform_name=args.platform,
                platforms_dir=args.platforms_dir,
                emulator_name=args.emulator,
                emulators_dir=args.emulators_dir,
                standalone=getattr(args, "standalone", False),
            )
        if not result:
            sys.exit(1)
        return

    db = load_database(args.db)
    zip_contents = build_zip_contents_index(db)

    # Emulator mode
    if args.emulator:
        names = [n.strip() for n in args.emulator.split(",") if n.strip()]
        with _pack_output_lock(args.output_dir):
            built = generate_emulator_pack(
                names,
                args.emulators_dir,
                db,
                args.bios_dir,
                args.output_dir,
                args.standalone,
                zip_contents,
                required_only=args.required_only,
                regions=getattr(args, "regions", None),
                offline=args.offline,
                platforms_dir=args.platforms_dir,
            )
        if built is None:
            sys.exit(1)
        return

    # System mode (standalone, without platform context)
    if args.system and not args.platform and not args.all:
        system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
        with _pack_output_lock(args.output_dir):
            built = generate_system_pack(
                system_ids,
                args.emulators_dir,
                db,
                args.bios_dir,
                args.output_dir,
                args.standalone,
                zip_contents,
                required_only=args.required_only,
                regions=getattr(args, "regions", None),
                offline=args.offline,
                platforms_dir=args.platforms_dir,
            )
        if built is None:
            sys.exit(1)
        return

    system_filter = getattr(args, "system_ids", None)

    # Platform mode
    if args.all and args.manifest:
        # Install manifests cover every registered platform: the installer
        # serves each one, with or without a release pack.
        platforms = list_registered_platforms(args.platforms_dir)
    elif args.all:
        # A release publishes the packs the registry marks release_pack and
        # nothing else: a pack built for another platform is one nobody uploads.
        platforms = list_release_pack_platforms(args.platforms_dir)
        if not platforms:
            parser.error("no registered platform has release_pack: true")
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    # A mistyped target is refused before the output lock and the data
    # directory refresh: checked after them, `--target swich` waited on a
    # pipeline's caches before saying the target does not exist.
    target_cores_cache: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores_cache, platforms = build_target_cores_cache(
                platforms,
                args.target,
                args.platforms_dir,
                is_all=args.all,
            )
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    emu_profiles = load_emulator_profiles(args.emulators_dir)
    if system_filter:
        platforms = _platforms_with_systems(
            args, platforms, system_filter, emu_profiles, target_cores_cache
        )
    platforms = without_profile_blind(
        platforms,
        [
            flag for flag, given in (
                ("--region", getattr(args, "regions", None)),
                ("--one-per-slot", getattr(args, "one_per_slot", False)),
                ("--no-game-data", getattr(args, "no_game_data", False)),
            ) if given
        ],
        args.platforms_dir,
        emu_profiles,
        target_cores_cache if args.target else None,
        args.all,
    )

    data_registry = load_data_dir_registry(args.platforms_dir)
    # The output directory is claimed before the data directory refresh: a
    # refresh waits for every run that holds a cache, so a second build
    # during a pipeline sat silent for hours instead of being refused.
    with _pack_output_lock(args.output_dir):
        if data_registry and not args.offline and not args.no_refresh_data:
            from refresh_data_dirs import load_registry, refresh_all

            registry = load_registry(os.path.join(args.platforms_dir, "_data_dirs.yml"))
            results = refresh_all(registry, force=args.refresh_data)
            updated = sum(1 for v in results.values() if v)
            if updated:
                print(f"Refreshed {updated} data director{'ies' if updated > 1 else 'y'}")
            failed = sorted(k for k, v in results.items() if v is None)
            if failed:
                print(f"WARNING: data directory refresh failed: {', '.join(failed)}")
        if data_registry:
            hold_data_dirs(held, data_registry)

        groups = group_identical_platforms(
            platforms, args.platforms_dir, target_cores_cache if args.target else None
        )

        if args.manifest:
            _refuse_mixed_output(args.output_dir, "manifest")
            _run_manifest_mode(
                args, groups, db, zip_contents, emu_profiles, target_cores_cache
            )
        else:
            _run_platform_packs(
                args,
                groups,
                db,
                zip_contents,
                data_registry,
                emu_profiles,
                target_cores_cache,
                system_filter,
            )
    if not args.manifest and args.verify_packs:
        with _pack_output_lock(args.output_dir, exclusive=False):
            _run_verify_packs(args)


# Manifest generation (JSON inventory for install.py)

@functools.lru_cache(maxsize=None)
def _registered(repo_root: str) -> frozenset[str]:
    """The paths a repository's .gitignore registers as release assets, read
    by the parser the fetcher and the release check use, once per root."""
    return frozenset(load_registered_paths(os.path.join(repo_root, ".gitignore")))


def _is_release_asset(local_path: str, repo_root: str) -> bool:
    """Whether the installer fetches this file from the large-files release.

    The repository serves every committed file from its raw URL. Only the
    files kept out of git live as release assets, and .gitignore is the
    ledger of those. Size is not the criterion: a committed file over 50 MB
    is still served by the repository, and announcing it as a release asset
    sends the installer to an asset nobody uploaded.
    """
    return _repo_relative(local_path, repo_root) in _registered(repo_root)


def _repo_relative(local_path: str, repo_root: str) -> str:
    try:
        return os.path.relpath(local_path, repo_root)
    except ValueError:
        return ""


def _release_asset_name(local_path: str, repo_root: str) -> str:
    """The large-files asset install.py downloads for a gitignored file.

    The name GitHub serves, not the one uploaded: a space in the path came
    back as a 404 for an installer asking for it verbatim.
    """
    return published_asset_name(
        asset_name(_repo_relative(local_path, repo_root), sorted(_registered(repo_root)))
    )


def _get_repo_path(sha1: str, db: dict) -> str:
    """Get the repo path for a file by SHA1 lookup."""
    entry = db.get("files", {}).get(sha1, {})
    return entry.get("path", "")


# The database the index was built from, held so its identity stays its own.
_DB_SHA1_BY_PATH: list[tuple[dict, dict[str, str]]] = []


def _db_sha1_by_path(db: dict) -> dict[str, str]:
    """Path -> sha1 of the database, built once per database."""
    if _DB_SHA1_BY_PATH and _DB_SHA1_BY_PATH[0][0] is db:
        return _DB_SHA1_BY_PATH[0][1]
    index = {
        os.path.normpath(entry["path"]): sha1
        for sha1, entry in db.get("files", {}).items()
        if entry.get("path")
    }
    _DB_SHA1_BY_PATH[:] = [(db, index)]
    return index


# The hashes a manifest entry records, and each file's once verified.
_MANIFEST_HASHES = frozenset({"sha1", "sha256"})
_STABLE_HASHES: dict[tuple, dict] = {}


def _placed_copies(copies: list[dict], dests: list[str]) -> list[dict]:
    """Each standalone copy with the path this manifest gives its file.

    The registry names one path per file for every platform (one anchor),
    while each manifest places the file its own way: EmuDeck installs
    aes_keys.txt at the root and Batocera prod.keys under switch/, so the
    installer looked for Citra/sysdata/aes_keys.txt, found nothing and
    copied nothing. `file` stays as written, since it also lays out a custom
    emulator root. `source` says where the installed file is.
    """
    by_name: dict[str, list[str]] = {}
    for dest in dests:
        by_name.setdefault(dest.rsplit("/", 1)[-1].casefold(), []).append(dest)
    placed: list[dict] = []
    for copy in copies:
        wanted = copy.get("file")
        if not wanted or wanted in dests:
            placed.append(copy)
            continue
        tail = [d for d in dests if d.endswith("/" + wanted)]
        if tail:
            # The file whose path carries the least on top of the tail.
            shortest = min(len(d) for d in tail)
            tail = [d for d in tail if len(d) == shortest]
        else:
            tail = by_name.get(wanted.rsplit("/", 1)[-1].casefold(), [])
        placed.append({**copy, "source": tail[0]} if len(tail) == 1 else copy)
    return placed


# data_root keys of the profiles, as the copy targets name each system.
_DATA_ROOT_SYSTEMS = {"linux": "linux", "macos": "darwin", "windows": "windows",
                      "android": "android"}


def _data_root_target(system: str, text: str) -> str | None:
    """A profile's data_root on one system as a copy target, or None when it
    names no place a run can find: a folder beside an executable, a working
    directory, a folder picked in the app. Of `A, else B` the alternative
    under the home is kept, the default the registry's targets write.
    """
    for choice in (part.strip() for part in text.split(", else ")):
        if "<" in choice:
            continue
        if system == "windows" and re.match(r"^%[A-Za-z0-9_()]+%/", choice):
            return choice.replace("/", "\\")
        if system == "android" and choice.startswith("Android/data/"):
            return "$EXTERNAL_STORAGE/" + choice
        if system in ("linux", "darwin"):
            if choice.startswith("~/"):
                return "$HOME/" + choice[2:]
            if choice.startswith("$HOME/"):
                return choice
    return None


def _one_content(held: list[str], entries: dict[str, dict], emulator: str) -> list[str]:
    """The one dest a copy reads when every held dest carries the same bytes.

    Unchanged when the contents differ: the name then designates nothing.
    """
    if len({entries[dest].get("sha1") for dest in held}) != 1:
        return held
    own = [dest for dest in held if emulator in (entries[dest].get("cores") or ())]
    return [min(own or held, key=lambda dest: (dest.count("/"), len(dest), dest))]


def _profile_copies(
    profiles: dict[str, dict], dests: list[str], declared: list[dict],
    entries: dict[str, dict] | None = None,
) -> list[dict]:
    """The standalone copies the emulator profiles document: each file with
    a standalone_path, into the data_root of each system that names a place.

    The registry's list was kept by hand for eight emulators, while the
    profiles give the folder of 61 with the code that builds it: a machine
    with standalone Cemu only got none of its keys. A target the registry
    already gives for the same name is left to it, and a file the manifest
    does not carry, or carries under the save directory, has no source. A
    file found by content (found_by) sits wherever the folder the user set
    for the scan points: Amiberry reads its ROMs from rom_path, which
    amiberry.conf moves, so its name under data_root proves nothing.
    ``entries`` maps each dest to its manifest entry: one file carried at
    two paths with the same bytes is one source, the copy whose cores name
    the emulator, else the shortest path. DuckStation's ps2_scph50006.bin
    sits at the BIOS root and under pcsx2/bios/ for the libretro PS2 cores.
    """
    from fnmatch import fnmatch  # noqa: PLC0415

    taken: list[tuple[str, str, str, bool]] = []
    for copy in declared:
        name = copy.get("pattern") or PurePosixPath(copy.get("file", "")).name
        for system, targets in (copy.get("targets") or {}).items():
            taken += [(system, target, name, "pattern" in copy) for target in targets]

    def covered(system: str, target: str, name: str) -> bool:
        return any(
            system == t_system and target == t_target
            and (fnmatch(name, t_name) if is_pattern else name == t_name)
            for t_system, t_target, t_name, is_pattern in taken
        )

    by_tail: dict[str, list[str]] = {}
    for dest in dests:
        parts = dest.split("/")
        for start in range(len(parts)):
            by_tail.setdefault("/".join(parts[start:]), []).append(dest)
    copies: list[dict] = []
    for profile_name in sorted(profiles):
        profile = profiles[profile_name]
        roots = {
            _DATA_ROOT_SYSTEMS[key]: target
            for key, value in (profile.get("data_root") or {}).items()
            if key in _DATA_ROOT_SYSTEMS and isinstance(value, dict)
            and (target := _data_root_target(_DATA_ROOT_SYSTEMS[key], value.get("path", "")))
        }
        if not roots:
            continue
        for entry in profile.get("files", []):
            standalone = entry.get("standalone_path")
            if (not standalone or standalone.endswith("/") or entry.get("mode") == "libretro"
                    or entry.get("type") == "directory" or entry.get("found_by") == "content"):
                continue
            held = by_tail.get(entry.get("path") or entry["name"], [])
            if len(held) > 1 and entries is not None:
                held = _one_content(held, entries, profile_name)
            if len(held) != 1:
                continue
            source = held[0]
            where = PurePosixPath(standalone)
            placed: dict[str, list[str]] = {}
            for system, root in roots.items():
                sep = "\\" if system == "windows" else "/"
                target = root if str(where.parent) == "." else (
                    root + sep + str(where.parent).replace("/", sep))
                if not covered(system, target, where.name):
                    placed[system] = [target]
            if not placed:
                continue
            copy = {"file": source, "targets": placed}
            if where.name != PurePosixPath(source).name:
                copy["as"] = where.name
            copies.append(copy)
    return copies


def _standalone_copies(
    declared: list[dict], profiles: dict[str, dict], manifest_files: list[dict],
) -> list[dict]:
    """A manifest's standalone copies: the registry's, placed where this
    manifest puts each file, then the ones the profiles document. A platform
    whose registry entry declares none gets none."""
    if not declared:
        return []
    kept = [entry for entry in manifest_files if entry.get("root") != "save"]
    dests = [entry["dest"] for entry in kept]
    entries = {entry["dest"]: entry for entry in kept}
    return _placed_copies(declared, dests) + _profile_copies(profiles, dests, declared, entries)


def _stable_hashes(local_path: str, db: dict) -> dict:
    """The file's hashes, held against the scan that built the database.

    A manifest entry is what every installer downloads and checks against.
    Under load this host has hashed a 252 MB DSi NAND to a sha1 no file
    holds, twice and the same way, so recomputing alone proves nothing: the
    database scanned the same path, and a manifest that disagrees with it is
    refused rather than published.
    """
    stat = os.stat(local_path)
    expected = _db_sha1_by_path(db).get(os.path.normpath(local_path))
    # Keyed by what was checked, the sha1 this database expects there, never
    # by id(db): a database freed and replaced at the same address answered
    # with hashes verified against the first one.
    key = (os.path.normpath(local_path), stat.st_size, stat.st_mtime_ns, expected)
    known = _STABLE_HASHES.get(key)
    if known is not None:
        # Verified against the scan once: twelve manifests name a file up
        # to a dozen times, and rehashing it each time spent 163 s of 218.
        return known
    hashes = compute_hashes(local_path, _MANIFEST_HASHES)
    for _attempt in range(2):
        if expected is None or hashes["sha1"] == expected:
            _STABLE_HASHES[key] = hashes
            return hashes
        # Read from disk again: the cached digest is the one in doubt, and a
        # retry through the cache answered with it without a second read.
        hashes = compute_hashes(local_path, _MANIFEST_HASHES, cache=False)
    raise RuntimeError(
        f"{local_path}: sha1 {hashes['sha1']} contradicts the database scan "
        f"({expected}). Rehash the file or regenerate database.json"
    )


def _manifest_entry(
    local_path: str | None,
    dest: str,
    cores: list[str] | None,
    db: dict,
    repo_root: str,
    selection_fields: dict,
) -> tuple[dict | None, int]:
    """The download record of a resolved file, and the size it occupies.

    The installer fetches by hash, so the entry records the copy this
    repository holds: an upstream hash carried by no local file resolves to
    no URL. An entry needs somewhere to be fetched from, and a file the
    database does not index (a data directory, a copy added since the last
    scan, a hash computed wrong) has neither a repo path nor a release
    asset. None then, so the caller records an omission instead of a dead
    entry that makes the installer refuse the whole manifest.
    `selection_fields` carries what the installer narrows on.
    """
    sha1 = ""
    sha256 = ""
    file_size = 0
    if local_path and os.path.exists(local_path):
        file_size = os.path.getsize(local_path)
        hashes = _stable_hashes(local_path, db)
        sha1 = hashes["sha1"]
        sha256 = hashes["sha256"]
    repo_path = _get_repo_path(sha1, db) if sha1 else ""
    is_release_asset = _is_release_asset(local_path or "", repo_root)
    if not repo_path and not is_release_asset:
        return None, file_size
    entry: dict = {
        "dest": dest,
        "sha1": sha1,
        "sha256": sha256,
        "size": file_size,
        "repo_path": repo_path,
        "cores": cores,
        **selection_fields,
    }
    if is_release_asset:
        entry["storage"] = "release"
        entry["release_asset"] = _release_asset_name(local_path, repo_root)
    # The installer writes what it downloads with the umask's mode, but a program
    # (RetroDECK's pico8, vox) has to stay runnable. The git mode cannot say:
    # hundreds of MAME archives carry an execute bit nothing reads.
    if local_path and _is_program(local_path):
        entry["executable"] = True
    return entry, file_size


_PROGRAM_MAGIC = (
    b"\x7fELF",
    b"#!",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


def _is_program(path: str) -> bool:
    """An ELF or Mach-O binary, or a script with an interpreter line."""
    with open(path, "rb") as handle:
        head = handle.read(4)
    return any(head.startswith(magic) for magic in _PROGRAM_MAGIC)


def _attach_claims(
    entry: dict,
    claims: list[dict],
    db: dict,
    bios_dir: str,
    zip_contents: dict | None,
    offline: bool | None,
    required_only: bool,
    validation_index: dict | None,
    owners: dict | None,
    dest: str,
    manifest_dest: str,
    repo_root: str,
    data_registry: dict | None = None,
) -> None:
    """Every other core that reads this destination, in the order the builder
    meets them: a pack built without the earlier cores, or without the
    platform system that declares the file, carries the first remaining
    one's copy.

    A claim joins the copy just before it when the bytes agree and starts an
    alternative otherwise. It never joins an earlier copy, which would let it
    win over a core the builder tries first. Only a core's first claim can
    win: its later ones are reached only when that one is. A platform entry
    names no core, so its first claim always starts an alternative.
    """
    claimed = set(entry["cores"] or [])
    for claim in claims:
        claim_emu = claim.get("source_profile") or claim.get("source_emulator", "")
        if not claim_emu or claim_emu in claimed:
            continue
        claimed.add(claim_emu)
        if required_only and claim.get("required") is False:
            continue
        claim_path, claim_status = resolve_file(
            claim, db, bios_dir, zip_contents,
            dest_hint=claim.get("destination", ""),
            data_dir_registry=data_registry, offline=offline,
        )
        if claim_status in ("not_found", "external", "user_provided") or not claim_path:
            # Nothing held for this core: narrowed to it without the cores
            # served above, the slot is a file left out (installer replays it).
            systems = _extra_system_ids(claim)
            entry.setdefault("absent_claims", []).append({
                "name": str(claim.get("name") or ""),
                "system": systems[0] if systems else "",
                "required": bool(claim.get("required", True)),
                "reason": (
                    claim_status
                    if claim_status in ("not_found", "external", "user_provided")
                    else "not_found"
                ),
                "cores": [claim_emu],
            })
            continue
        claim_path, _ = validated_choice(
            claim, claim_path, db, validation_index or {}, bios_dir, None,
            claim.get("layout_path") or dest, owners,
        )
        copy, _size = _manifest_entry(
            claim_path, manifest_dest, [claim_emu], db, repo_root, {}
        )
        if copy is None:
            continue
        alternatives = entry.setdefault("alternatives", [])
        last = alternatives[-1] if alternatives else entry
        if last["cores"] is not None and copy["sha1"] == last["sha1"]:
            if claim_emu not in last["cores"]:
                last["cores"].append(claim_emu)
            continue
        del copy["dest"]
        alternatives.append(copy)
    if not entry.get("alternatives"):
        entry.pop("alternatives", None)


def _record_slot_choices(
    entry: dict,
    choices: list[tuple[str, str | None]],
    declarations: list[tuple[list[str], dict, str]],
    settle: Callable[[dict, str, str, str | None], tuple[str | None, str]],
    dest: str,
    db: dict,
    repo_root: str,
) -> None:
    """Record what a pack built for fewer cores serves at a platform destination.

    `slot_choices` lists, in the order slots decides, the cores whose claim
    settles the slot and the copy it serves, a choice without a copy leaving
    the platform's answer. `declared_choices` is the platform's answer by the
    declaring systems that remain, in the order the builder takes them.
    Nothing is recorded where every narrowing gets the entry's own copy.
    """

    def download(file_entry: dict, sys_id: str, override: str | None) -> dict | None:
        local_path, _status = settle(file_entry, sys_id, dest, override)
        if local_path is None:
            return None
        copy, _size = _manifest_entry(local_path, dest, None, db, repo_root, {})
        if copy is None:
            return None
        return {k: v for k, v in copy.items() if k not in ("dest", "cores")}

    declared: list[dict] = []
    for systems, file_entry, sys_id in declarations:
        copy = download(file_entry, sys_id, None)
        if copy is None:
            # An omission is not a copy the installer can switch to.
            return
        if declared and declared[-1]["sha1"] == copy["sha1"]:
            declared[-1]["systems"].extend(systems)
        else:
            declared.append({**copy, "systems": list(systems)})
    _systems, first, first_sys = declarations[0]
    recorded: list[dict] = []
    seen: set[str] = set()
    for emulator, path in choices:
        if emulator in seen:
            continue
        seen.add(emulator)
        copy = {} if path is None else download(first, first_sys, path)
        if copy is None:
            return
        if recorded and recorded[-1].get("sha1") == copy.get("sha1"):
            recorded[-1]["cores"].append(emulator)
        else:
            recorded.append({**copy, "cores": [emulator]})
    while recorded and "sha1" not in recorded[-1]:
        recorded.pop()
    if not recorded and len(declared) == 1:
        return
    if recorded:
        entry["slot_choices"] = recorded
    entry["declared_choices"] = declared


def _manifest_core_entries(
    core_files: list,
    config: dict,
    db: dict,
    bios_dir: str,
    base_dest: str,
    repo_root: str,
    zip_contents: dict | None,
    offline: bool | None,
    region_drops: set,
    case_insensitive: bool,
    seen_destinations: set,
    seen_lower: set,
    seen_parents: set,
    manifest_files: list,
    omitted_by_destination: dict,
    record_omission: Callable[..., None],
    pack_only_sizes: list[int],
    selection: SelectionIndex,
    required_only: bool = False,
    validation_index: dict | None = None,
    owners: dict | None = None,
    data_registry: dict | None = None,
    profiles: dict | None = None,
) -> int:
    """Add the files a platform's cores need but its list does not name.

    The installer fetches by hash, so an entry records the copy this
    repository holds rather than the value the profile declares: an
    upstream hash carried by no local file leaves the entry with no URL.
    Returns the bytes added.
    """
    total_size = 0
    extras_pfx = _detect_extras_prefix(config, base_dest)
    resolver = ExtraResolver(
        db, bios_dir, zip_contents, data_registry, validation_index or {},
        owners, offline, profiles=profiles,
    )
    spares = core_file_spares(
        core_files,
        lambda fe: bool(region_drops)
        and extra_region_key(fe, declared_root(config)) in region_drops,
    ) if required_only else set()
    for fe in core_files:
        if required_only and (fe.get("required") is False or id(fe) in spares):
            continue
        dest = sanitize_pack_path(fe.get("destination", fe["name"]))
        if not dest:
            continue
        region_key = extra_region_key(fe, declared_root(config))
        if region_drops and region_key in region_drops:
            continue
        full_dest = extra_full_destination(fe, extras_pfx)
        if not full_dest:
            continue
        save_root = fe.get("root") == "save"

        if (
            case_insensitive
            and full_dest not in seen_destinations
            and full_dest.lower() in seen_lower
        ):
            # One file under two spellings: BlastEm opens 32X_M_BIOS.bin and
            # PicoDrive 32X_M_BIOS.BIN. The second core's claim joins the
            # entry kept, or a pack built without the first core loses the
            # file the installer would still have to place. Collisions are
            # rare, so the entry is looked up only when one happens.
            folded = (
                save_manifest_dest(fe) if save_root
                else _manifest_dest_of(full_dest, base_dest)
            ).lower()
            held = next(
                (e for e in manifest_files
                 if e["dest"].lower() == folded
                 and (e.get("root") == "save") == save_root),
                None,
            )
            if held is not None and held.get("cores") is not None:
                _attach_claims(
                    held, [fe], db, bios_dir, zip_contents, offline, required_only,
                    validation_index, owners, dest, held["dest"], repo_root,
                    data_registry,
                )
            continue

        if placement_block(
            full_dest, seen_destinations, seen_lower, seen_parents,
            case_insensitive,
        ):
            continue

        # The builder's own lookup (ExtraResolver): the data directories, the
        # copy the emulator accepts, and the size its code checks. Without
        # the data directories blueMSX's MSX2P.rom named a different dump
        # than the one its pack carried.
        local_path, status, _disagreement = resolver.resolve(fe, dest)
        if not local_path:
            source_emu = fe.get("source_profile") or fe.get("source_emulator", "")
            if not _claim_platform_omission(
                omitted_by_destination.get(full_dest), source_emu
            ):
                systems = _extra_system_ids(fe)
                record_omission(
                    full_dest, fe, systems[0] if systems else "", status, _claim_cores(fe),
                )
            continue

        source_emu = fe.get("source_profile") or fe.get("source_emulator", "")

        # Manifest dests are relative to base_destination. Keep the inferred
        # extras prefix when it is an internal layout dir (RetroDECK bios/).
        # A file read below the save directory is written relative to the
        # directory the core is handed, and says so (save_entry_fields).
        outer_root = fe.get("root") if fe.get("root") in OUTER_ROOTS else None
        if save_root:
            manifest_dest = save_manifest_dest(fe)
        elif outer_root:
            # Relative to the roms or emulators folder the entry names.
            manifest_dest = dest
        else:
            manifest_dest = _manifest_dest_of(full_dest, base_dest)

        entry, file_size = _manifest_entry(
            local_path, manifest_dest, [source_emu] if source_emu else [],
            db, repo_root,
            selection.fields(region_key, fe.get("name", "")),
        )
        if entry is not None and save_root:
            entry.update(save_entry_fields(fe))
        elif entry is not None and outer_root:
            entry["root"] = outer_root
        if entry is None:
            if not _claim_platform_omission(
                omitted_by_destination.get(full_dest), source_emu
            ):
                systems = _extra_system_ids(fe)
                record_omission(
                    full_dest, fe, systems[0] if systems else "", "not_found",
                    _claim_cores(fe),
                )
            if file_size:
                pack_only_sizes.append(file_size)
            continue

        if is_game_data(fe) and all(
            is_game_data(claim) for claim in fe.get("other_claims", [])
        ):
            entry["category"] = GAME_DATA
        _attach_claims(
            entry, fe.get("other_claims", []), db, bios_dir, zip_contents,
            offline, required_only, validation_index, owners, dest,
            manifest_dest, repo_root, data_registry,
        )

        manifest_files.append(entry)
        displaced = omitted_by_destination.pop(full_dest, None)
        if displaced and displaced.get("cores"):
            # A core that wants this slot and has nothing held: a pack built
            # without the cores served here leaves the slot to it, missing,
            # and the installer narrowing to those cores has to say so too.
            entry.setdefault("absent_claims", []).append(
                {k: v for k, v in displaced.items() if k not in ("dest", "held")}
            )
        total_size += file_size
        seen_destinations.add(full_dest)
        _register_path(full_dest, seen_destinations, seen_parents)
        if case_insensitive:
            seen_lower.add(full_dest.lower())

    return total_size


def _manifest_dest_of(full_dest: str, base_dest: str) -> str:
    """A pack destination as the manifest writes it, below base_destination."""
    if base_dest and full_dest.startswith(f"{base_dest}/"):
        return full_dest[len(base_dest) + 1:]
    return full_dest


def _claim_platform_omission(held: dict | None, emulator: str) -> bool:
    """Record a core's claim on a destination the platform already omits.

    The platform's own omission stands while one of its declaring systems
    does. A pack built without them falls to the first core claiming the
    path, as for a file present. Overwriting the record lost the platform's
    claim: a target without that core dropped an omission its pack reports.
    """
    if held is None or held.get("cores") is not None:
        return False
    if emulator:
        claims = held.setdefault("alternatives", [])
        if {"cores": [emulator]} not in claims:
            claims.append({"cores": [emulator]})
    return True


def _manifest_selection(
    config: dict,
    pack_systems: dict,
    emulators_dir: str,
    db: dict,
    base_dest: str,
    emu_profiles: dict,
    target_cores: set[str] | None,
    source: str,
    required_only: bool,
    regions: list[str] | None,
    undeclared: list[dict] | None = None,
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    slot_overrides: dict[str, str] | None = None,
) -> tuple[set[str], SelectionIndex, set[str]]:
    """Destinations a region list removes, the groups the installer replays,
    and the destinations the builder holds.

    Grouped as the pack groups them, so a region the installer applies to
    the full manifest withdraws what `--region` withdraws from the pack.
    """
    extras: list[dict] = []
    held: set[str] = set()
    region_groups, _extra_dests = platform_region_groups(
        config,
        pack_systems,
        emulators_dir,
        db,
        base_dest,
        emu_profiles,
        target_cores=target_cores,
        include_extras=(source != "platform"),
        include_all=(source == "truth"),
        required_only=required_only,
        extras_out=extras,
        held_out=held,
        undeclared=undeclared,
        zip_contents=zip_contents,
        data_registry=data_registry,
        slot_overrides=slot_overrides,
    )
    region_index = region_mod.platform_region_index(
        config, emu_profiles, target_cores
    )
    drops = (
        region_mod.resolve_region_drops(region_groups, region_index, regions, held)
        if regions
        else set()
    )
    return drops, SelectionIndex.build(
        region_groups, region_index, pack_systems, extras, required_only,
        extras_prefix=declared_root(config),
    ), held


def _claim_cores(fe: dict) -> list[str]:
    """The cores an extra and the claims folded onto it name: an omission
    names every core reading the file, as a list built for one of them
    would."""
    names = {
        claim.get("source_profile") or claim.get("source_emulator", "")
        for claim in (fe, *fe.get("other_claims", []))
    }
    return sorted(name for name in names if name)


def _record_absent(
    absent: list[dict],
    config: dict,
    base_dest: str,
    region_drops: set,
    required_only: bool,
    seen_destinations: set,
    omitted_by_destination: dict,
    record_omission: Callable[..., None],
) -> None:
    """A file a core needs that the collection does not hold is an omission.

    Left out of both lists, DevilutionX's diabdat.mpq and dhewm3's
    pak000-004 reached no safety notice: the installer said everything
    was verified and the game refused to start.
    """
    extras_pfx = _detect_extras_prefix(config, base_dest)
    for fe in absent:
        if required_only and fe.get("required") is False:
            continue
        dest = sanitize_pack_path(fe.get("destination", fe.get("name", "")))
        if not dest or (
            region_drops and extra_region_key(fe, declared_root(config)) in region_drops
        ):
            continue
        full_dest = extra_full_destination(fe, extras_pfx)
        if not full_dest or full_dest in seen_destinations:
            continue
        source_emu = fe.get("source_profile") or fe.get("source_emulator", "")
        held = omitted_by_destination.get(full_dest)
        if held is not None:
            # Another core reads the same missing file there (Raze and
            # EDuke32 both open NAPALM.GRP): one omission names them all.
            claimed = held.get("cores")
            if (held.get("reason") == "not_found" and claimed and source_emu
                    and source_emu not in claimed):
                held["cores"] = sorted([*claimed, source_emu])
            continue
        systems = _extra_system_ids(fe)
        record_omission(
            full_dest, fe, systems[0] if systems else "", "not_found",
            [source_emu] if source_emu else [],
        )


# What a manifest's roms_directory and emulators_directory carry: the BIOS
# folder's name, for the roms root its place relative to the BIOS folder
# (romfolders roms_root.from_bios), and for emulator folders the places the
# launcher searches, the one a missing folder is created at, and the config
# file whose key moves a folder.
MANIFEST_OUTER_FIELDS = ("bios_folder", "from_bios", "searched", "default", "config")


def _record_unplaceable(
    unplaceable: list[dict],
    record_omission: Callable[..., None],
    config: dict,
    profiles: dict[str, dict],
) -> None:
    """Held by the collection, nowhere to put it on this platform.

    Said in the manifest, where RomM's DOSBox Pure ROMs were simply absent.
    One place read by several cores is one omission naming them all.
    """
    # The emulator's own folder is the one the platform installs the name
    # it lists into: RetroPie puts amiberry 5.7.2 and 6.3.3, one per board,
    # both in $md_inst of its amiberry package.
    platform_names = {
        str(c) for key in ("cores", "standalone_cores")
        if isinstance(config.get(key), list) for c in config[key]
    }

    def folder(profile: str) -> str:
        names = {profile, *map(str, (profiles.get(profile) or {}).get("cores") or [])}
        return min(names & platform_names, default=profile)

    grouped: dict[str, tuple[dict, list[str]]] = {}
    for u in unplaceable:
        where = u.get("path") or u.get("name", "")
        # The profile key, the name a target's core list and the
        # installer's narrowing match: the display name matched none.
        core = u.get("profile") or u.get("emulator", "")
        if u.get("unplaced"):
            key = f"emulator:{folder(core)}:{where}"
        elif u.get("root") in OUTER_ROOTS:
            key = f"{u['root']}:{where}"
        elif u.get("root") == "save":
            key = f"save:{save_manifest_dest(u)}"
        else:
            key = where
        held, cores = grouped.setdefault(key, (u, []))
        if core and core not in cores:
            cores.append(core)
        if u.get("required", True) and not held.get("required", True):
            grouped[key] = ({**held, "required": True}, cores)
    for key, (u, cores) in grouped.items():
        record_omission(
            # Keyed apart from the BIOS tree's paths, which a file read below
            # the save directory or in the emulator's folder can repeat.
            key, u, u.get("system") or "",
            u.get("unplaceable", "no_platform_slug"), sorted(cores),
        )


# Systems whose default filesystems fold case (NTFS, APFS, HFS+).
CASE_FOLDING_OS = frozenset({"windows", "darwin"})


def system_titles(*entry_lists: Iterable[dict]) -> dict[str, str]:
    """The name a person reads for each system the entries carry.

    Batocera names PlayStation `psx` and the installer showed
    `sony-playstation (psx)`: neither is what a beginner looks for. The
    title is the one the site prints, so a system reads the same on its
    page and in the installer. A system the site cannot name is left out,
    and the installer shows its id: the site build refuses such a system,
    so only a test fixture reaches here with one.
    """
    from siterender import system_name

    ids = {
        sys_id
        for entries in entry_lists for entry in entries
        for sys_id in entry.get("systems") or []
    }
    titles: dict[str, str] = {}
    for sys_id in sorted(ids):
        try:
            titles[sys_id] = system_name(sys_id)
        except KeyError:
            continue
    return titles


def generate_manifest(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    source: str = "full",
    regions: list[str] | None = None,
    target_name: str | None = None,
    offline: bool | None = None,
    required_only: bool = False,
    data_registry: dict | None = None,
    fold_case: bool | None = None,
    no_game_data: bool = False,
) -> dict:
    """Generate a JSON manifest for a platform (same resolution as generate_pack).

    Returns a dict ready for JSON serialization with file inventory,
    install hints, and download metadata. ``fold_case`` overrides the
    platform's ``case_insensitive_fs``, for the case variants below.

    A file that is a game's data, not firmware, carries ``"category":
    "game_data"``, so the installer can leave it out as the builder does
    under ``no_game_data``. Firmware carries no category.
    """
    config = load_platform_config(platform_name, platforms_dir)
    if fold_case is not None:
        config = {**config, "case_insensitive_fs": fold_case}
    if target_name:
        config = {**config, TARGET_KEY: target_name}
    if zip_contents is None:
        zip_contents = {}
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)
    if data_registry is None:
        data_registry = load_data_dir_registry(platforms_dir)
    full_profiles = emu_profiles
    game_entries: set[int] = set()
    if no_game_data:
        cut = without_game_data(config, emu_profiles, data_registry, target_cores)
        config, emu_profiles = cut.config, cut.profiles
    else:
        game_entries = platform_game_data(config, emu_profiles, data_registry)

    platform_display = config.get("platform", platform_name)
    base_dest = config.get("base_destination", "")
    case_insensitive = config.get("case_insensitive_fs", False)
    verification_mode = config.get("verification_mode", "existence")
    manifest_profiles = {
        name: emu_profiles[name]
        for name in _platform_cores(config, emu_profiles)
    }
    manifest_validation = _build_validation_index(manifest_profiles)
    manifest_owners = destination_owners(manifest_profiles)

    # Load registry for install metadata
    registry: dict = {}
    if os.path.exists(registry_path):
        with open(registry_path) as f:
            registry = yaml_load(f) or {}
    plat_registry = registry.get("platforms", {}).get(platform_name, {})
    install_section = plat_registry.get("install", {})
    detect = install_section.get("detect", [])
    standalone_copies = install_section.get("standalone_copies", [])

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    plat_cores = _platform_cores(config, emu_profiles) if target_cores else None
    pack_systems = filter_systems_by_target(
        config.get("systems", {}),
        emu_profiles,
        target_cores,
        platform_cores=plat_cores,
    )

    # A destination is game data when every declaration of it is: a firmware
    # declaration of the same path keeps it in a pack built without game data.
    declared_kinds: dict[str, set[bool]] = {}
    for system in pack_systems.values():
        for fe in system.get("files", []):
            bare = sanitize_pack_path(fe.get("destination", fe.get("name", "")))
            if bare:
                declared_kinds.setdefault(bare, set()).add(id(fe) in game_entries)
    game_destinations = {d for d, kinds in declared_kinds.items() if kinds == {True}}

    seen_destinations: set[str] = set()
    # Destination -> (entry, full destination, manifest destination) of each
    # platform file, for the core claims a target build would fall back on.
    platform_entries: dict[str, tuple[dict, str, str]] = {}
    # Full destination -> the platform systems declaring it. A file's
    # `systems` also names the systems whose cores read it there. A pack built
    # for a target keeps the file only while a declaring system stays.
    declared_by: dict[str, set[str]] = {}
    seen_lower: set[str] = set()
    seen_parents: set[str] = set()
    manifest_files: list[dict] = []
    omitted_by_destination: dict[str, dict] = {}
    total_size = 0
    # Sizes of the files the pack carries and the installer cannot fetch: the
    # collection does not index them, a data directory cache answered.
    pack_only_sizes: list[int] = []
    # Platform entries resolved into a data directory cache: destination ->
    # (cache file, size). Settled once the trees are walked.
    cache_held: dict[str, tuple[str, int]] = {}
    rename_notes: set[str] = set()
    # The full manifest records every core's answer at a contested slot, so a
    # target narrowed from it gets what that target's own pack serves.
    whole = target_cores is None and source != "platform" and bool(emu_profiles)
    slot_choices = (
        slots.slot_choices(config, emu_profiles, db, zip_contents, data_registry)
        if whole else {}
    )
    # Derived from the same choices: computed twice, it was 8% of a run.
    slot_overrides = slots.pack_overrides(
        config, emu_profiles, db, zip_contents, data_registry,
        target_cores=target_cores, source=source,
        choices=slot_choices if whole else None,
    )

    def manifest_destination(full_destination: str) -> str:
        if base_dest and full_destination.startswith(f"{base_dest}/"):
            return full_destination[len(base_dest) + 1:]
        return full_destination

    def record_omission(
        full_destination: str,
        file_entry: dict,
        system_id: str,
        reason: str,
        cores: list[str] | None,
    ) -> None:
        # A core extra (cores given) is keyed as the region pass keys it.
        bare = (
            sanitize_pack_path(file_entry.get("destination", file_entry.get("name", "")))
            if cores is None else extra_region_key(file_entry, declared_root(config))
        )
        save_root = file_entry.get("root") == "save"
        # Read in the emulator's own folder, outside the BIOS tree: dest is
        # the path the emulator reads, relative to that folder.
        outside = bool(file_entry.get("unplaced"))
        if outside:
            dest_fields: dict = {"dest": sanitize_pack_path(file_entry.get("path") or ""),
                                 "root": "emulator"}
        elif file_entry.get("root") in OUTER_ROOTS:
            dest_fields = {"dest": sanitize_pack_path(
                file_entry.get("destination") or file_entry.get("path") or ""
            ), "root": file_entry["root"]}
        elif save_root:
            dest_fields = {"dest": save_manifest_dest(file_entry), **save_entry_fields(file_entry)}
        else:
            dest_fields = {"dest": manifest_destination(full_destination)}
        omitted_by_destination[full_destination] = {
            **dest_fields,
            "name": str(file_entry.get("name") or ""),
            "system": system_id,
            "required": bool(file_entry.get("required", True)),
            "reason": reason,
            "cores": cores,
            # An omission keeps its region groups, as the builder groups it:
            # a requested file the collection lacks answers the request
            # without displacing a held fallback (resolve_region_drops,
            # held). One the builder holds and the installer cannot fetch
            # does displace it in the pack, so it says so, and the installer
            # drops the same fallback.
            **selection.fields(bare, str(file_entry.get("name") or "")),
            **({"held": True} if bare in builder_held else {}),
            **(
                {"category": GAME_DATA}
                if (bare in game_destinations if cores is None else is_game_data(file_entry))
                else {}
            ),
        }

    # Read by the region grouping and by phase 2 with the same arguments.
    undeclared = (
        undeclared_report(
            config, emulators_dir, db, emu_profiles, target_cores,
            include_all=(source == "truth"),
        )
        if source != "platform"
        else None
    )
    region_drops, selection, builder_held = _manifest_selection(
        config, pack_systems, emulators_dir, db, base_dest, emu_profiles,
        target_cores, source, required_only, regions, undeclared=undeclared,
        zip_contents=zip_contents, data_registry=data_registry,
        slot_overrides=slot_overrides,
    )

    # Phase 1: baseline files
    if source != "truth":
        # The same destination can be declared by more than one system, bare
        # in one and hash-constrained in another. The builder lets the
        # constrained sibling claim it. Without the same rule here the
        # manifest named whatever answered to the name, so the pack and the
        # installer disagreed about which file a destination means.
        # Decided among the declarations this manifest keeps, as the pack
        # does. A manifest carries no data directories.
        preferred_entries = _preferred_entries(
            pack_systems, db, bios_dir, base_dest, required_only,
            zip_contents, offline,
        )
        declarations: dict[str, dict[str, list[dict]]] = {}
        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                if required_only and file_entry.get("required") is False:
                    continue
                dest = sanitize_pack_path(file_entry.get("destination", file_entry["name"]))
                if dest and not (region_drops and dest in region_drops):
                    full_dest = f"{base_dest}/{dest}" if base_dest else dest
                    declarations.setdefault(full_dest, {}).setdefault(sys_id, []).append(
                        file_entry
                    )

        def declaration_order(full_dest: str) -> list[tuple[list[str], dict, str]]:
            """The declarations answering a destination as its systems drop.

            A pack built for a target loses the systems no available core
            reads, and the next declaration takes the destination by the
            same rule: RetroArch's bare nintendo-ds dsi_bios9.bin once the
            pinned nintendo-dsi one is gone.
            """
            remaining = dict(declarations.get(full_dest, {}))
            order: list[tuple[list[str], dict, str]] = []
            while remaining:
                winner = _preferred_entries(
                    {sid: {"files": fes} for sid, fes in remaining.items()},
                    db, bios_dir, base_dest, required_only, zip_contents, offline,
                ).get(full_dest)
                first_sys, first = next(
                    (sid, fe) for sid, fes in sorted(remaining.items()) for fe in fes
                    if winner is None or id(fe) == winner
                )
                systems = sorted(
                    sid for sid, fes in remaining.items()
                    if any(fe is first for fe in fes)
                )
                order.append((systems, first, first_sys))
                for sid in systems:
                    del remaining[sid]
            return order

        def settle(
            file_entry: dict, sys_id: str, dest: str, override: str | None
        ) -> tuple[str | None, str]:
            """The file served once the slot is settled, or None and why not."""
            local_path, status = resolve_declaration(
                file_entry,
                db,
                bios_dir,
                zip_contents,
                data_registry,
                override,
                offline=offline,
            )
            if status == "not_found" and not reads_file_contents(verification_mode):
                found = agnostic_substitute(file_entry, sys_id, db, manifest_profiles)
                if found:
                    local_path, status = found[0], "agnostic_fallback"
                    if os.path.basename(local_path) != file_entry.get("name", ""):
                        # The pack explains the rename in a note of its own.
                        rename_notes.add(file_entry.get("name", ""))
            # The builder's verdict: a hash platform omits what its frontend
            # would reject, a zipped_file archive included when the member is
            # missing whatever the outer resolution said. An existence
            # platform never reads the bytes.
            status, refusal = baseline_verdict(
                file_entry, local_path, status, verification_mode,
                config.get("hash_rule", ""),
            )
            if refusal or status in ("not_found", "external"):
                return None, "hash_mismatch" if refusal else status
            # The variant the pack ships when an emulator rejects the
            # resolved file: the installer must place the same bytes.
            local_path, _disagreement = validated_choice(
                file_entry, local_path, db, manifest_validation, bios_dir,
                digest_algorithm(verification_mode), dest, manifest_owners,
            )
            return local_path, status

        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                if required_only and file_entry.get("required") is False:
                    continue
                dest = sanitize_pack_path(file_entry.get("destination", file_entry["name"]))
                if not dest:
                    continue
                if region_drops and dest in region_drops:
                    continue
                full_dest = f"{base_dest}/{dest}" if base_dest else dest
                declared_by.setdefault(full_dest, set()).add(sys_id)

                preferred = preferred_entries.get(full_dest)
                if preferred is not None and id(file_entry) != preferred:
                    continue

                dedup_key = full_dest
                if dedup_key in seen_destinations:
                    continue
                if case_insensitive and dedup_key.lower() in seen_lower:
                    continue
                if _has_path_conflict(full_dest, seen_destinations, seen_parents):
                    continue

                storage = file_entry.get("storage", "embedded")
                if storage == "user_provided":
                    record_omission(
                        full_dest,
                        file_entry,
                        sys_id,
                        "user_provided",
                        None,
                    )
                    # The pack writes the instructions in the slot's place
                    # and holds it: one more member than the files listed.
                    instructions = file_entry.get(
                        "instructions", "Please provide this file manually."
                    )
                    pack_only_sizes.append(len(
                        f"File needed: {file_entry['name']}\n\n{instructions}\n".encode()
                    ))
                    seen_destinations.add(dedup_key)
                    _register_path(dedup_key, seen_destinations, seen_parents)
                    if case_insensitive:
                        seen_lower.add(dedup_key.lower())
                    continue

                local_path, status = settle(
                    file_entry, sys_id, dest, slot_overrides.get(full_dest)
                )
                if local_path is None:
                    record_omission(full_dest, file_entry, sys_id, status, None)
                    continue

                entry, file_size = _manifest_entry(
                    local_path, dest, None, db, repo_root,
                    selection.fields(dest, file_entry["name"]),
                )
                if entry is not None and dest in game_destinations:
                    entry["category"] = GAME_DATA
                if entry is not None and target_cores is None:
                    order = declaration_order(full_dest)
                    if full_dest in slot_choices or len(order) > 1:
                        _record_slot_choices(
                            entry, slot_choices.get(full_dest, []), order,
                            settle, dest, db, repo_root,
                        )
                if entry is None:
                    record_omission(full_dest, file_entry, sys_id, "not_found", None)
                    if file_size and full_dest not in seen_destinations:
                        if _in_data_cache(local_path, data_registry):
                            cache_held[full_dest] = (local_path, file_size)
                        else:
                            pack_only_sizes.append(file_size)
                        seen_destinations.add(dedup_key)
                        _register_path(dedup_key, seen_destinations, seen_parents)
                        if case_insensitive:
                            seen_lower.add(dedup_key.lower())
                    continue

                manifest_files.append(entry)
                platform_entries[dedup_key] = (entry, full_dest, dest)
                omitted_by_destination.pop(full_dest, None)
                total_size += file_size
                seen_destinations.add(dedup_key)
                _register_path(dedup_key, seen_destinations, seen_parents)
                if case_insensitive:
                    seen_lower.add(dedup_key.lower())

    # Phase 2: core complement (emulator extras)
    unplaceable: list[dict] = []
    baseline_claims: dict[str, dict] = {}
    absent: list[dict] = []
    if source != "platform":
        core_files = _collect_emulator_extras(
            config,
            emulators_dir,
            db,
            seen_destinations,
            base_dest,
            emu_profiles,
            target_cores=target_cores,
            include_all=(source == "truth"),
            unplaceable=unplaceable,
            baseline_claims=baseline_claims,
            absent=absent,
            undeclared=undeclared,
        )
    else:
        core_files = []
    _record_unplaceable(unplaceable, record_omission, config, emu_profiles)
    _record_absent(
        absent, config, base_dest, region_drops, required_only,
        seen_destinations, omitted_by_destination, record_omission,
    )
    total_size += _manifest_core_entries(
        core_files, config, db, bios_dir, base_dest, repo_root,
        zip_contents, offline, region_drops, case_insensitive,
        seen_destinations, seen_lower, seen_parents, manifest_files,
        omitted_by_destination, record_omission, pack_only_sizes, selection,
        required_only, manifest_validation, manifest_owners, data_registry,
        emu_profiles,
    )
    for key, (entry, full_dest, dest) in platform_entries.items():
        declared = declared_by.get(full_dest, set())
        if declared and declared != set(entry.get("systems") or []):
            entry["declared_in"] = sorted(declared)
        claims = baseline_claims.get(key, {}).get("other_claims")
        if claims and any(not is_game_data(claim) for claim in claims):
            # A core reads this path as firmware: a pack without game data
            # still fills it.
            entry.pop("category", None)
        if claims:
            _attach_claims(
                entry, claims, db, bios_dir, zip_contents, offline, required_only,
                manifest_validation, manifest_owners, dest, dest, repo_root,
                data_registry,
            )
    # A platform omission narrows like a platform file: by the systems
    # declaring it, which can be fewer than the ones whose cores read it.
    for full_dest, omission in omitted_by_destination.items():
        declared = declared_by.get(full_dest, set())
        if (
            omission.get("cores") is None
            and declared
            and declared != set(omission.get("systems") or [])
        ):
            omission["declared_in"] = sorted(declared)

    # Phase 3: data directories. They are not files of the collection: the
    # installer fetches each from its source archive and keeps the members
    # whose hash the list below records, the same tree the pack carries.
    data_refs: dict[str, tuple[str, tuple[str, ...], str, bool]] = {}
    reclaim = {full: path for full, (path, _size) in cache_held.items()}
    core_trees = ([] if source == "platform"
                  else core_data_trees(config, emu_profiles, platform_name, data_registry,
                                       target_cores))
    data_members = list(_data_directory_members(
        pack_systems, data_registry, platform_name, base_dest,
        case_insensitive, seen_destinations, seen_lower, seen_parents,
        data_refs, required_only=required_only,
        core_trees=core_trees,
        reclaim=reclaim,
    ))
    # A platform entry found in a tree the pack carries is that tree's member:
    # the installer rebuilds it from the tree's archive. One found in a tree
    # the pack does not carry stays omitted, held by the pack alone.
    for full_dest, (_path, size) in cache_held.items():
        if full_dest in reclaim:
            pack_only_sizes.append(size)
        else:
            omitted_by_destination.pop(full_dest, None)
    data_sizes = pack_only_sizes + [os.path.getsize(src) for src, _dest in data_members]
    data_directories = _manifest_data_directories(
        data_members, data_refs, data_registry or {}, base_dest,
        tree_readers(pack_systems, core_trees), pack_systems,
    )

    # The pack is unzipped into the BIOS folder: an entry the installer puts
    # in the roms, emulators or configs folder is in its list, not in the ZIP.
    outer = [e for e in manifest_files if e.get("root") in OUTER_ROOTS]
    now = _build_timestamp(db)
    core_names, system_cores = _manifest_core_index(
        config, emu_profiles, manifest_files, omitted_by_destination.values()
    )

    result: dict = {
        "manifest_version": 2,
        "source": source,
        "regions": list(regions or []),
        # A target-filtered manifest is only distinguishable from the full one
        # by its filename, so it records the filter the way regions does.
        # Absent on an unfiltered manifest rather than empty, to leave the
        # twelve default files byte-identical.
        **({"target": target_name} if target_name else {}),
        # Every game data file below says so: the installer's --no-game-data
        # relies on it, and refuses a list that does not record categories.
        "categorized": True,
        **({"no_game_data": True} if no_game_data else {}),
        "platform": platform_name,
        "display_name": platform_display,
        "version": platform_list_version(config, platform_name),
        "generated": now,
        "base_destination": base_dest,
        "detect": detect,
        "standalone_copies": _standalone_copies(
            standalone_copies, manifest_profiles, manifest_files,
        ),
        "total_files": len(manifest_files),
        "total_size": total_size,
        "pack_files": (
            len(manifest_files) - len(outer) + len(data_sizes) + len(PACK_DOCUMENTS)
            + len(rename_notes) + len(pack_markers(platform_name, target_name, platforms_dir))
        ),
        "pack_size": total_size - sum(int(e.get("size") or 0) for e in outer) + sum(data_sizes),
        "total_omitted": len(omitted_by_destination),
        "omitted_files": sorted(
            omitted_by_destination.values(), key=lambda entry: entry["dest"]
        ),
        "core_names": core_names,
        **({"downloaded_cores": downloaded} if (downloaded := _downloaded_cores(
            config, emu_profiles, core_names, platforms_dir,
        )) else {}),
        **({"offered_boards": offered} if (offered := _offered_boards(
            config, emu_profiles, core_names,
            [*manifest_files, *omitted_by_destination.values()],
        )) else {}),
        "system_cores": system_cores,
        # The names the platform itself gives its systems (Batocera's psx),
        # which --system accepts beside the ids.
        "system_names": platform_system_names(config, list(pack_systems)),
        "system_titles": system_titles(manifest_files, omitted_by_destination.values()),
        "files": manifest_files,
    }
    if data_directories:
        result["data_directories"] = data_directories
    for root in OUTER_ROOTS:
        layout = outer_layout(config, root) or {}
        if layout and any(entry.get("root") == root
                          for entry in [*manifest_files, *result["omitted_files"]]):
            # Where the installer finds the folder: relative to the folder
            # holding the BIOS folder, which the platform names bios_folder.
            result[f"{root}_directory"] = {
                key: layout[key] for key in MANIFEST_OUTER_FIELDS if key in layout
            }
    saved = [entry for entry in manifest_files if entry.get("root") == "save"]
    if saved:
        layout = save_layout(config)
        result["save_directory"] = {"folder": layout.folder, "by_core": layout.by_core}
        if layout.by_system:
            # The launcher writes the directory at each launch, one folder
            # per system: each dest starts with that folder.
            result["save_directory"]["by_system"] = True
    if case_insensitive and fold_case is None and any(
        d.get("os") not in CASE_FOLDING_OS for d in detect
    ):
        # RetroArch also runs where case is kept: there Mesen-CE opens
        # bios.col and np2kai np2kai/2608_bd.wav, which the folded list
        # serves only as BIOS.col and 2608_BD.WAV. The installer adds these
        # where the directory keeps case, while the pack, extracted on Windows
        # or macOS too, stays folded.
        kept = generate_manifest(
            platform_name, platforms_dir, db, bios_dir, registry_path,
            emulators_dir, zip_contents, full_profiles, target_cores, source,
            regions, target_name, offline, required_only, data_registry,
            fold_case=False, no_game_data=no_game_data,
        )
        folded = {entry["dest"] for entry in manifest_files}
        folded_lower = {dest.lower() for dest in folded}
        variants = [
            entry for entry in kept["files"]
            if entry["dest"] not in folded and entry["dest"].lower() in folded_lower
        ]
        if variants:
            result["case_variants"] = variants
    return result


def tree_readers(pack_systems: dict, core_trees: Iterable[dict]) -> dict[str, list[str]]:
    """The cores that read each tree, for a tree only cores read. A tree a
    platform system declares is the system's, whatever core runs it, and
    gets no entry. Every reference counts: two cores reading one tree yield
    its files once."""
    cores: dict[str, set[str]] = {}
    declared: set[str] = set()
    for _systems, dd in _tree_references(pack_systems, core_trees):
        ref = str(dd.get("ref") or "")
        if dd.get("core"):
            cores.setdefault(ref, set()).update(str(core) for core in dd.get("readers") or [dd["core"]])
        else:
            declared.add(ref)
    return {ref: sorted(names) for ref, names in cores.items() if ref not in declared}


def _manifest_data_directories(
    members: list[tuple[str, str]],
    refs: dict[str, tuple[str, tuple[str, ...], str, bool]],
    registry: dict,
    base_dest: str,
    readers: dict[str, list[str]] | None = None,
    platform_systems: Iterable[str] | None = None,
) -> list[dict]:
    """Each data directory the pack carries, as the installer rebuilds it.

    The source archive and the rule that maps its members onto the tree
    (strip_components for a ZIP, source_path for a tarball, exclude) come
    from _data_dirs.yml, the same refresh_data_dirs applies. Every file
    carries the sha1 and size the cache holds, so a member the source
    changed since is refused rather than installed. archive_size is the
    size of the archive refresh_data_dirs last downloaded, what fetching
    the tree costs: a tarball whose tree is 10 KB is a download of 21 MB.
    ``systems`` are the platform's ids (``platform_systems``) the tree's
    systems normalize to, as a core extra's are: a tree no platform system
    serves has none, and goes with the files of no system, as the pack
    built with --system puts it in the part of its own. FBNeo's cheats
    carried sega-megadrive where RetroArch's list says sega-mega-drive.
    ``optional`` marks a tree every core reading it runs without
    (``required: false``): install.py --required-only leaves it out, as the
    pack built with --required-only does. ``cores`` names the cores that
    read a tree no platform system declares (``readers``): an install for
    the games of a card keeps it only when its plan runs one of them.
    """
    grouped: dict[tuple[str, str], dict] = {}
    versions: dict[str, dict[str, dict]] = {}
    by_norm: dict[str, list[str]] = {}
    for sys_id in sorted(platform_systems or ()):
        by_norm.setdefault(_norm_system_id(sys_id), []).append(sys_id)
    for src, full in members:
        ref, systems, prefix, needed = refs[full]
        if platform_systems is not None:
            systems = tuple(own for sid in systems for own in by_norm.get(_norm_system_id(sid), ()))
        entry = registry.get(ref, {})
        key = (ref, prefix)
        group = grouped.get(key)
        if group is None:
            version = str(entry.get("version", "master"))
            dest = prefix
            if base_dest and (dest == base_dest or dest.startswith(base_dest + "/")):
                dest = dest[len(base_dest):].lstrip("/")
            group = grouped[key] = {
                "ref": ref,
                "dest": dest,
                "url": str(entry.get("source_url", "")).format(version=version),
                "type": "zip" if entry.get("source_type") == "zip" else "tarball",
                "systems": [],
                "files": {},
            }
            if group["type"] == "zip":
                group["strip_components"] = int(entry.get("strip_components", 0))
            else:
                group["source_path"] = str(entry.get("source_path", "")).format(version=version)
            if entry.get("exclude"):
                group["exclude"] = [str(e) for e in entry["exclude"]]
            cache = entry.get("local_cache")
            if cache:
                recorded = Path(cache).parent / ".versions.json"
                if str(recorded) not in versions:
                    try:
                        versions[str(recorded)] = json.loads(recorded.read_text())
                    except FileNotFoundError:
                        versions[str(recorded)] = {}
                size = versions[str(recorded)].get(ref, {}).get("archive_size")
                if isinstance(size, int) and size > 0:
                    group["archive_size"] = size
        if needed:
            group["needed"] = True
        group["systems"].extend(s for s in systems if s not in group["systems"])
        rel = full[len(prefix):].lstrip("/") if prefix else full
        hashes = compute_hashes(src, frozenset({"sha1"}))
        group["files"][rel] = {"sha1": hashes["sha1"], "size": os.path.getsize(src)}
    trees = []
    for key in sorted(grouped):
        group = grouped[key]
        if not group.pop("needed", False):
            group["optional"] = True
        if readers and group["ref"] in readers:
            group["cores"] = readers[group["ref"]]
        trees.append(group)
    return trees


def _offered_boards(
    config: dict,
    profiles: dict[str, dict],
    core_names: dict[str, list[str]],
    entries: list[dict],
) -> dict[str, list[dict]]:
    """The roms folders each profile is offered for on some boards only,
    each with those boards, aliases included, where the manifest places a
    file of that profile.

    ROCKNIX writes uae4arm for roms/amiga under the devices it builds it for
    (emulators/package.mk:188), and a board's core list names uae4arm when
    another folder offers it there. The pack builder reads the board from
    the config (TARGET_KEY) and `install.py --target` reads its answer here.
    A manifest built for one board needs none.
    """
    if config.get(TARGET_KEY):
        return {}
    pairs = content_folder_boards(config)
    if all(on is None for on in pairs.values()):
        return {}
    from launchers import _roms_place  # noqa: PLC0415

    by_key: dict[str, set[str]] = {}
    for name, claimants in upstream_profile_index(profiles).items():
        by_key.setdefault(_core_key(name), set()).update(claimants)
    free = {
        (profile, folder) for (core, folder), on in pairs.items() if on is None
        for profile in by_key.get(core, ())
    }
    found: dict[tuple[str, str, str], set[str]] = {}
    for (core, folder), on in pairs.items():
        where = _roms_place(config, folder) if on is not None else None
        if where is None:
            continue
        for profile in by_key.get(core, ()):
            if profile in core_names and (profile, folder) not in free:
                found.setdefault((profile, where[0], where[1]), set()).update(on)
    # An entry below the roms root names it, one in the install tree none.
    trees = {ROMS_ROOT: ROMS_ROOT, None: "install"}
    placed = {
        (profile, trees[entry.get("root")], str(entry.get("dest", "")).rpartition("/")[0])
        for entry in entries if entry.get("root") in trees
        for copy in [entry, *entry.get("alternatives", [])]
        for profile in copy.get("cores") or []
    }
    result: dict[str, list[dict]] = {}
    for (profile, tree, folder), boards in sorted(found.items()):
        if not any(
            p == profile and t == tree and (d == folder or d.startswith(f"{folder}/"))
            for p, t, d in placed
        ):
            continue
        result.setdefault(profile, []).append(
            {"root": tree, "folder": folder, "boards": sorted(boards)}
        )
    return result


def _downloaded_cores(
    config: dict,
    profiles: dict[str, dict],
    core_names: dict[str, list[str]],
    platforms_dir: str,
) -> dict[str, list[str]]:
    """The cores only the platform's RetroArch downloader brings, each with
    the boards, aliases included, whose downloader offers it.

    A target list names the board's standalone amiberry and the buildbot's
    amiberry core alike, so the installer cannot tell from the name whether
    the board reaches the core. `resolve_platform_cores` decides it, and
    `install.py --target` reads its answer here.
    """
    reached = {
        profile: names
        for profile, names in downloaded_only_profiles(config, profiles).items()
        if profile in core_names
    }
    if not reached:
        return {}
    platform = str(config.get("_key") or "")
    boards: dict[str, list[str]] = {profile: [] for profile in reached}
    for target in list_available_targets(platform, platforms_dir):
        cores = load_target_config(platform, target["name"], platforms_dir)
        if cores is None:
            continue
        for profile, names in reached.items():
            if downloadable_on(cores, names):
                boards[profile] += [target["name"], *target.get("aliases", [])]
    return {profile: sorted(names) for profile, names in sorted(boards.items())}


def _manifest_core_index(
    config: dict,
    profiles: dict[str, dict],
    files: list[dict],
    omitted: list[dict],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """What the installer needs to narrow by a list of core names.

    A target list, or the cores found installed, names cores the way the
    buildbot does, and a file names the profile that reads it: `core_names`
    gives each profile the other names it goes by, and names every core the
    platform runs, one that reads no file included: a core found installed
    that the list does not name is one it has no profile for. `system_cores`
    gives each platform system the cores whose presence keeps it, as
    `filter_systems_by_target` decides. A system absent from it is kept
    whatever is available.
    """
    runs = _platform_cores(config, profiles)
    reach = system_core_reach(config.get("systems", {}), profiles, runs)
    system_cores = {
        sys_id: sorted(cores) for sys_id, cores in sorted(reach.items())
        if cores is not None
    }
    named = {
        c for entry in [*files, *omitted]
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]
        for c in copy.get("cores") or []
    }
    named |= {c for cores in system_cores.values() for c in cores}
    named |= set(runs)
    aliases: dict[str, set[str]] = {profile: set() for profile in named & set(runs)}
    for name, claimants in upstream_profile_index(profiles, include_aliases=True).items():
        for profile in claimants & named:
            if name != profile:
                aliases.setdefault(profile, set()).add(name)
    core_names = {profile: sorted(names) for profile, names in sorted(aliases.items())}
    return core_names, system_cores


# Post-generation pack verification + manifest + SHA256SUMS



def pack_systems(install_manifest: dict, targets: dict | None = None) -> dict:
    """What a pack's manifest.json records of its systems, from the install
    list built with the same choices: each file's systems, by its path in
    the pack, and the names a person reads for them.

    A pack recorded none: the installer refused --system with a pack alone
    ("the file list comes from an older release") and offered no Choose
    systems, the route of a handheld without Wi-Fi.

    The install list itself and the platform's cores per board (targets, as
    install/targets/ publishes them) ride along: with the pack alone, a
    board was never applied and --target was refused, and a Batocera RPi4
    card took 8.9 GB where its board reads 5.8.
    """
    files = install_manifest.get("files", [])
    entries = [*files, *install_manifest.get("omitted_files", [])]
    # What the install list narrows by, the installer's recorded_axes: with
    # the pack alone it names that list as the way to --core and --region
    # only when the list records them. It named install/misterfpga.json for
    # --core, a list that records no core.
    records = {"systems"} if any("systems" in entry for entry in entries) else set()
    if any(copy.get("cores") for entry in files
           for copy in [entry, *entry.get("alternatives", []),
                        *entry.get("slot_choices", [])]):
        records.add("cores")
    if records or any("regions" in entry for entry in entries):
        records.add("regions")
    systems = {
        "files": {entry["dest"]: list(entry.get("systems") or [])
                  for entry in files if "systems" in entry},
        "system_titles": dict(install_manifest.get("system_titles") or {}),
        "system_names": dict(install_manifest.get("system_names") or {}),
        "list_records": sorted(records),
    }
    # The version of the platform's list, which the installer compares with
    # the one the machine runs when it has the pack alone.
    if install_manifest.get("version"):
        systems["list_version"] = install_manifest["version"]
    systems["install_list"] = install_manifest
    if targets is not None:
        systems["targets"] = targets
    return systems


def annotate_pack_systems(manifest: dict, systems: dict | None) -> None:
    """Write pack_systems into a pack's manifest: a systems list on each
    file the install list names, the titles and names beside."""
    if not systems:
        return
    for entry in manifest.get("files", []):
        held = systems["files"].get(entry["path"])
        if held is not None:
            entry["systems"] = held
    for key in ("system_titles", "system_names"):
        if systems.get(key):
            manifest[key] = systems[key]
    for key in ("list_records", "list_version", "install_list", "targets"):
        if key in systems:
            manifest[key] = systems[key]


def inject_manifest(zip_path: str, manifest: dict) -> None:
    """Inject manifest.json into an existing ZIP pack.

    The pack is rewritten beside its final name and swapped in, as
    _writing_pack builds it: appending in place rewrites the central
    directory last, so a process killed in between left an unreadable ZIP
    where a valid pack had been.
    """
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    with zipfile.ZipFile(zip_path, "r") as zf:
        has_manifest = "manifest.json" in zf.namelist()

    directory = os.path.dirname(zip_path) or "."
    fd, scratch = tempfile.mkstemp(
        prefix=f".{os.path.basename(zip_path)}.", suffix=".partial", dir=directory
    )
    os.close(fd)
    try:
        if not has_manifest:
            # Append to a copy. Append mode defaults to ZIP_STORED, which
            # would leave the manifest uncompressed and give the same pack
            # two different byte layouts depending on the path taken here.
            shutil.copyfile(zip_path, scratch)
            with zipfile.ZipFile(scratch, "a", zipfile.ZIP_DEFLATED) as zf:
                _write_generated_member(zf, "manifest.json", manifest_json)
        else:
            with zipfile.ZipFile(zip_path, "r") as src, \
                    zipfile.ZipFile(scratch, "w", zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    if item.filename == "manifest.json":
                        continue
                    dst.writestr(item, src.read(item.filename))
                _write_generated_member(dst, "manifest.json", manifest_json)
        set_plain_mode(scratch)
        os.replace(scratch, zip_path)
    except BaseException:
        Path(scratch).unlink(missing_ok=True)
        raise








def _target_cores_for(
    platform_name: str, target_name: str | None, platforms_dir: str
) -> set[str] | None:
    """Cores a target leaves available, or None when no target was asked for.

    Called on a platform the build already packed under the target, so the
    target is known to it: a platform without one is left out of the run.
    """
    if not target_name:
        return None
    return load_target_config(platform_name, target_name, platforms_dir)


def _expected_pack_names(
    platforms: list[str],
    platforms_dir: str,
    regions: list[str] | None,
    target_name: str | None,
    variants: tuple[tuple[str, bool], ...] = (("full", False),),
    no_game_data: bool = False,
) -> dict[str, set[str]]:
    """Exact pack file names --verify-packs may check, per platform.

    Rebuilt from the name builder, never matched by substring: a substring
    picks the full pack when a regional or targeted one was asked for, or a
    narrowed pack when the full one was. A platform answers to its own name
    and to the name of the group it shares a pack with. ``variants`` lists
    the (source, required_only) combinations the run built.
    """
    def narrow_tags(platform_name: str) -> list[str]:
        named = _platform_target(platform_name, target_name, platforms_dir)
        return [
            "".join(
                tag
                for tag, _label in _narrowings(
                    source, regions, named, False, required, no_game_data=no_game_data
                )
            )
            for source, required in variants
        ]

    names: dict[str, set[str]] = {
        p: {
            f"{_platform_pack_stem([p], p, platforms_dir)}{tags}_BIOS_Pack.zip"
            for tags in narrow_tags(p)
        }
        for p in platforms
    }
    # Groups depend on which platforms a run built: the release packs of
    # --all.
    pool = list_release_pack_platforms(platforms_dir)
    cache = None
    if target_name:
        try:
            cache, pool = build_target_cores_cache(
                pool, target_name, platforms_dir, is_all=True
            )
        except ValueError:
            # No platform has the target: no pack was built under it.
            return names
    for group, representative in group_identical_platforms(
        pool, platforms_dir, cache
    ):
        if len(group) < 2:
            continue
        stem = _platform_pack_stem(group, representative, platforms_dir)
        for tags in narrow_tags(representative):
            for p in group:
                if p in names:
                    names[p].add(f"{stem}{tags}_BIOS_Pack.zip")
    return names


def _content_narrowing_tags() -> tuple[str, ...]:
    """Tags naming a pack that holds fewer files than the platform declares.

    Read from the name builder rather than retyped, so the two cannot drift.
    Region and target are absent on purpose: both are handed to the check
    itself, which narrows its expectation instead of skipping it.
    """
    dimensions = (
        {"source": "platform"},
        {"source": "truth"},
        {"one_per_slot": True},
        {"required_only": True},
    )
    tags: list[str] = []
    for dimension in dimensions:
        tags.extend(
            tag
            for tag, _label in _narrowings(
                dimension.get("source", "full"),
                None,
                None,
                dimension.get("one_per_slot", False),
                dimension.get("required_only", False),
            )
        )
    return tuple(tags)


_CONTENT_NARROWING_TAGS = _content_narrowing_tags()


def _narrows_contents(pack_name: str) -> bool:
    """True when a pack holds fewer files than the platform declares.

    A source-restricted or required-only build is narrower by design, so the
    full platform expectation does not apply to it and conformance is skipped.
    Region is not listed: the region filter is passed to the check itself, and
    a hardware target is passed the same way.
    """
    return any(f"{tag}_" in pack_name for tag in _CONTENT_NARROWING_TAGS)


def _pack_variant(pack_name: str) -> tuple[str, bool] | None:
    """The (source, required_only) a pack was built as, read from its name.

    None for a one-per-slot pack, whose slot choice the check does not
    replay. The tags come from the name builder, as for _narrows_contents.
    """
    def tagged(**dimension: object) -> bool:
        tags = [
            tag for tag, _label in _narrowings(
                str(dimension.get("source", "full")), None, None,
                bool(dimension.get("one_per_slot", False)),
                bool(dimension.get("required_only", False)),
            )
        ]
        return all(f"{tag}_" in pack_name for tag in tags)

    if tagged(one_per_slot=True):
        return None
    source = next(
        (s for s in ("platform", "truth") if tagged(source=s)), "full"
    )
    return source, tagged(required_only=True)


def _pack_archives(output_dir: str) -> list[str]:
    """The ZIPs of a directory that are packs.

    A part of a split pack holds a share of a platform by design and was
    checked against the whole when it was cut: judged as a pack it would
    fail conformance, and injecting a manifest would change published bytes.
    Every name the builder gives holds `_BIOS_Pack`, then the system tag of
    a --system platform pack (`_BIOS_Pack_Playstation.zip`): build_port.py
    wrote its launcher archives (RetroBIOS.zip) to the same dist/, and
    taking every ZIP rewrote them with a manifest after build_port had
    printed their hashes.
    """
    return sorted(
        name
        for name in os.listdir(output_dir)
        if _PACK_NAME.search(name) and not split_pack.is_part(name)
    )


_PACK_NAME = re.compile(r"_BIOS_Pack(?:_[^/]+)?\.zip$")


def verify_and_finalize_packs(
    output_dir: str,
    db: dict,
    platforms_dir: str = "platforms",
    skip_conformance: bool = False,
    data_registry: dict | None = None,
    regions: list[str] | None = None,
    target_name: str | None = None,
    emulators_dir: str = "emulators",
    no_game_data: bool = False,
    pack_systems_by_name: dict[str, dict] | None = None,
    built: Iterable[str] | None = None,
) -> bool:
    """Verify all packs, inject manifests, generate SHA256SUMS.

    pack_systems_by_name gives, per pack file name, the systems its
    manifest.json records (pack_systems).

    ``built`` names the packs this run wrote, and only those are verified
    and get a manifest. A pack another run left in the directory was
    reopened, recompressed and given a manifest without its pack_systems,
    which made the installer refuse to narrow it. None takes every pack.

    Two-stage verification:
    1. Hash check against database.json (integrity)
    2. Extract + verify against platform config (conformance)

    Returns True if all packs pass verification.
    """
    all_ok = True

    # Map ZIP names to platform names
    # By the exact name this run's reduction gives a platform's pack, never by
    # substring: a _Custom or regional pack left by another run was judged
    # against this run's expectation and failed it.
    registered = list_registered_platforms(platforms_dir)
    expected = _expected_pack_names(
        registered, platforms_dir, regions, target_name, no_game_data=no_game_data
    )
    packs = _pack_archives(output_dir)
    if built is not None:
        packs = [name for name in packs if name in set(built)]
    pack_to_platform: dict[str, list[str]] = {}
    for name in packs:
        for pname in registered:
            if name in expected[pname]:
                pack_to_platform.setdefault(name, []).append(pname)

    failing: list[str] = []
    for name in packs:
        zip_path = os.path.join(output_dir, name)

        # Stage 1: database integrity
        ok, manifest = verify_pack(zip_path, db, data_registry=data_registry)
        summary = manifest["summary"]
        status = "OK" if ok else "ERRORS"
        print(
            f"  verify {name}: {summary['verified']}/{summary['total_files']} verified, "
            f"{summary['untracked']} untracked, {summary['errors']} errors [{status}]"
        )
        if not ok:
            for err in manifest["errors"]:
                print(f"    ERROR: {err}")
            all_ok = False
            failing.append(name)
        annotate_pack_systems(manifest, (pack_systems_by_name or {}).get(name))
        inject_manifest(zip_path, manifest)

        # Stage 2: platform conformance (extract + verify)
        # Skipped for filtered/split/custom packs (intentionally partial)
        if skip_conformance:
            continue
        if _narrows_contents(name):
            continue
        platforms = pack_to_platform.get(name, [])
        for pname in platforms:
            (
                p_ok,
                total,
                matched,
                p_errors,
                bl_checked,
                bl_present,
                core_checked,
                core_present,
                bl_excluded,
                bl_absent,
            ) = verify_pack_against_platform(
                zip_path,
                pname,
                platforms_dir,
                db=db,
                emulators_dir=emulators_dir,
                regions=regions,
                data_registry=data_registry,
                target_cores=_target_cores_for(pname, target_name, platforms_dir),
                no_game_data=no_game_data,
            )
            status = "OK" if p_ok else "FAILED"
            exclusion_note = "".join(
                f", {part}" for part in _baseline_shortfall(bl_excluded, bl_absent)
            )
            print(
                f"  platform {pname}: {bl_present}/{bl_checked} baseline present"
                f"{exclusion_note}, "
                f"{core_present}/{core_checked} cores present, {status}"
            )
            if not p_ok:
                for err in p_errors:
                    print(f"    {err}")
                all_ok = False
                failing.append(f"{name} ({pname})")

    generate_sha256sums(output_dir)
    if failing:
        # Named at the end, where a 4,000-line log is read, and on stderr.
        print(f"ERROR: packs failed verification: {', '.join(failing)}", file=sys.stderr)
    return all_ok

from packpaths import (  # noqa: E402,F401
    MEDIA_MARKER,
    lands_on_android,
    _archive_destination,
    _path_parents,
    _has_path_conflict,
    _register_path,
    _flat,
    _resolve_destination,
    placement_block,
    save_layout,
)
from packextras import (  # noqa: E402,F401
    ExtraResolver,
    extra_full_destination,
    extra_region_key,
    prefixed_destination,
    save_entry_fields,
    save_manifest_dest,
    _detect_extras_prefix,
    _detect_slug_structure,
    _map_emulator_to_slug,
    _collect_emulator_extras,
    _extra_system_ids,
    extras_for_systems as _extras_for_systems,
    platform_region_groups,
    emulator_region_drops,
    emulator_required_spares,
    _emulator_region_group,
    expand_agnostic_entries,
    undeclared_report,
)


from packreadme import (  # noqa: E402,F401
    _build_readme,
    _build_agnostic_rename_readme,
    save_place,
)
from packverify import (  # noqa: E402,F401
    _check_member_hash,
    _hash_matches,
    _repo_satisfies_declaration,
    _intentional_hash_exclusion,
    verify_pack_against_platform,
    verify_pack,
    generate_sha256sums,
)


# _OFFLINE is deliberately not re-exported: importing a value copies it, so a
# facade name would keep saying False after set_offline() changed the flag.
from packresolve import (  # noqa: E402,F401
    ACCEPTED_HASHES,
    _detect_hash_type,
    sha1_for_hash,
    preferred_entries as _preferred_entries,
    parse_hash_input,
    parse_hash_file,
    lookup_hashes,
    resolve_declaration,
    resolve_file,
    download_external,
)

if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
