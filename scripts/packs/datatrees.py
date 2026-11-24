"""The data directory trees a pack carries, and the cores that read them."""

from __future__ import annotations

import os
import re
import zipfile
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, TypedDict

from core.hashing import compute_hashes
from core.options import reject_unknown
from model.declarations import declared_root
from model.registry import load_versions, versions_file_for
from model.profiles import entry_system_ids, installed_data_refs_in
from model.systems import norm_system_id
from packs.archive import PackRecord, Placed, add_pack_member
from packs.datadirs import cache_lock, revisioned
from packs.extras import prefixed_destination
from packs.paths import MEDIA_MARKER, lands_on_android
from resolve.cores import resolve_platform_cores as _platform_cores
from resolve.layout import core_system_dirs
from resolve.standalone import platform_layouts, platform_launches
from resolve.entryscope import deliverable, read_from_system_dir

if TYPE_CHECKING:
    from typing_extensions import Unpack

_COMMIT = re.compile(r"[0-9a-f]{40}")


def pack_markers(
    platform_name: str, target_name: str | None, platforms_dir: str
) -> tuple[str, ...]:
    """The empty files a pack carries for the systems it is unzipped on,
    as named before flattening: the .nomedia of a pack for Android."""
    from model.targets import list_available_targets

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
    (``installed_data_refs_in``), one the build bundles or the platform never
    opens (``deliverable``), and one whose registry entry names the
    platforms it serves (``for_platforms``) without this one. A standalone build reads its data below its own folder, which a
    tree's destination does not describe, so its trees stay out, as does a
    tree read beside the content (``load_from``).

    Each reference carries the profile's systems (``source_systems``, as a
    core extra does), which --system and --split narrow on.
    """
    if not data_registry:
        return []
    installed = installed_data_refs_in(platform_name, profiles)
    launches = platform_launches(config, profiles)
    # Relative to base_destination, which the members are written under. A
    # platform with none writes its BIOS folder into every destination, and
    # the trees go there as the core extras do.
    root = declared_root(config)
    trees: list[dict] = []
    seen: dict[tuple[str, str], int] = {}
    for core in sorted(_platform_cores(config, profiles, target_cores)):
        profile = profiles[core]
        if all(standalone for _view, standalone in platform_layouts(core, profile, launches)):
            continue
        declared = [t for t in profile.get("data_directories") or [] if isinstance(t, dict)]
        directories = core_system_dirs(core, profile, launches)
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


def in_data_cache(path: str, data_registry: dict | None) -> bool:
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


class _TreeWalkOptions(TypedDict, total=False):
    """The keyword options of data_directory_members."""

    refs_out: dict | None
    uncached_out: list[tuple[str, str]] | None
    required_only: bool
    core_trees: Iterable[dict]
    reclaim: dict[str, str] | None
    installed: frozenset[str]


def _carried_tree(
    dd: dict, data_registry: dict | None, platform_name: str, installed: frozenset[str],
) -> str | None:
    """The cache folder of a tree reference the pack carries ("" when the
    cache does not hold it), or None for a tree the pack does not carry."""
    ref_key = dd.get("ref", "")
    if not ref_key or not data_registry or ref_key not in data_registry:
        return None
    if ref_key in installed:
        return None
    entry = data_registry[ref_key]
    allowed = entry.get("for_platforms")
    if allowed and platform_name not in allowed:
        return None
    return entry.get("local_cache", "")


def uncached_warning(ref_key: str, local_path: str) -> str:
    """The line a build prints for a tree it carries and the cache does not hold."""
    return f"  WARNING: data directory '{ref_key}' not cached at {local_path} (run refresh_data_dirs.py)"


def _tree_files(local_path: str, dd_prefix: str) -> Iterator[tuple[str, str]]:
    """(source, destination) of every file of a cached tree."""
    for root, _dirs, filenames in os.walk(local_path):
        for fname in filenames:
            src = os.path.join(root, fname)
            rel = os.path.relpath(src, local_path)
            yield src, f"{dd_prefix}/{rel}" if dd_prefix else rel


def data_directory_members(
    pack_systems: dict,
    data_registry: dict | None,
    platform_name: str,
    base_dest: str,
    placed: Placed,
    **options: Unpack[_TreeWalkOptions],
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

    ``uncached_out``, when given, receives (registry key, cache folder) for
    each tree the pack carries and the cache does not hold: the caller
    reports it and counts its run incomplete.

    ``installed`` names the trees the platform's packages install
    (installed_data_refs_in over the run's profiles): the walk leaves them
    out.

    These are not BIOS and carry no hash of their own: they are whole
    trees an emulator reads, refreshed from upstream, so what ships is
    whatever the cache holds. The pack and the install manifest both read
    this, the first to write the files and the second to count them.
    ``required_only`` leaves out a tree declared ``required: false``, one the
    core runs without, as it leaves out such a file.
    """
    reject_unknown("data_directory_members", options, _TreeWalkOptions.__optional_keys__)
    refs_out = options.get("refs_out")
    uncached_out = options.get("uncached_out")
    reclaim = options.get("reclaim")
    required_only = options.get("required_only", False)
    core_trees = options.get("core_trees", ())
    installed = options.get("installed", frozenset())
    # Data directories from _data_dirs.yml
    for systems, dd in _tree_references(pack_systems, core_trees):
        needed = dd.get("required") is not False
        if required_only and not needed:
            continue
        local_path = _carried_tree(dd, data_registry, platform_name, installed)
        if local_path is None:
            continue
        ref_key = dd.get("ref", "")
        if not local_path or not os.path.isdir(local_path):
            if uncached_out is not None:
                uncached_out.append((ref_key, local_path))
            continue
        dd_dest = dd.get("destination", "")
        dd_prefix = f"{base_dest}/{dd_dest}" if base_dest and dd_dest else base_dest or dd_dest
        # Held while the caller writes what is yielded: a refresh swapping
        # the tree waits until the walk is done.
        with cache_lock(local_path, shared=True):
            for src, full in _tree_files(local_path, dd_prefix):
                if reclaim and full in reclaim and (
                    os.path.normpath(reclaim[full]) == os.path.normpath(src)
                ):
                    del reclaim[full]
                elif placed.block(full):
                    continue
                else:
                    placed.take(full)
                if refs_out is not None:
                    refs_out[full] = (ref_key, systems, dd_prefix, needed)
                yield src, full


def carried_trees(
    profile: dict, standalone: bool, required_only: bool, data_registry: dict | None,
) -> Iterator[tuple[str, str | None, str]]:
    """(registry key, cache folder or None when not cached, destination) of
    each data tree an emulator pack carries for a profile.

    A tree only one build reads follows that build, like a file, and one
    declared ``required: false`` stays out of a required-only pack. The
    destination sits below the build's own folder (``pack_structure``).
    """
    structure = profile.get("pack_structure")
    prefix = structure.get("standalone" if standalone else "libretro", "") if structure else ""
    for dd in deliverable(profile.get("data_directories", []), standalone):
        if required_only and dd.get("required") is False:
            continue
        ref = dd.get("ref", "")
        if not ref:
            continue
        cache = (data_registry or {}).get(ref, {}).get("local_cache", "")
        dd_dest = dd.get("destination", "")
        if prefix:
            dd_dest = f"{prefix}/{dd_dest}" if dd_dest else prefix
        yield ref, cache if cache and os.path.isdir(cache) else None, dd_dest


def claimed_tree_files(
    local_cache: str, dd_dest: str, placed: Placed,
) -> Iterator[tuple[str, str]]:
    """(source, destination) of each tree file an emulator pack writes.

    A path another file already holds is skipped, the others are taken in
    `placed`. The cache's shared lock is held while the caller reads what
    is yielded: a refresh swaps the tree by rename, and a walk half done
    read the old tree and wrote files of the new one.
    """
    with cache_lock(local_cache, shared=True):
        for src, full in _tree_files(local_cache, dd_dest):
            if placed.block(full):
                continue
            placed.take(full)
            yield src, full


def pack_data_tree(
    zf: zipfile.ZipFile | PackRecord,
    local_cache: str,
    dd_dest: str,
    placed: Placed,
    packed_at: dict[str, str] | None = None,
) -> int:
    """Write one data directory into an emulator pack, under its shared lock.

    ``packed_at`` records each member, so a later profile asking for the
    same bytes there is served rather than reported missing.
    """
    added = 0
    for src, full in claimed_tree_files(local_cache, dd_dest, placed):
        # The installer writes a data tree member without the bit.
        add_pack_member(zf, src, full, executable=False)
        if packed_at is not None:
            packed_at[full.lower()] = src
        added += 1
    return added


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


def _tree_group(
    ref: str, prefix: str, entry: dict, base_dest: str, versions: dict[str, dict[str, dict]],
) -> dict:
    """The manifest record of one data directory, before its files.

    ``versions`` caches each .versions.json read, by path.
    """
    recorded = _recorded_version(ref, entry, versions)
    version = str(entry.get("version", "master"))
    revision = str(recorded.get("sha") or "")
    rolling = not revisioned(entry)
    if not rolling and recorded.get("version") == version and _COMMIT.fullmatch(revision):
        # The commit the cache was fetched at, not the branch's name.
        version = revision
    elif not _COMMIT.fullmatch(version):
        rolling = True
    dest = prefix
    if base_dest and (dest == base_dest or dest.startswith(base_dest + "/")):
        dest = dest[len(base_dest):].lstrip("/")
    group: dict = {
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
    size = recorded.get("archive_size")
    if isinstance(size, int) and size > 0:
        group["archive_size"] = size
    if rolling:
        group["rolling"] = True
    return group


def _recorded_version(ref: str, entry: dict, versions: dict[str, dict[str, dict]]) -> dict:
    """What refresh_data_dirs recorded of the tree's last fetch, read once
    per .versions.json."""
    if not entry.get("local_cache"):
        return {}
    recorded = versions_file_for(entry)
    if str(recorded) not in versions:
        versions[str(recorded)] = load_versions(recorded)
    found = versions[str(recorded)].get(ref)
    return found if isinstance(found, dict) else {}


def manifest_data_directories(
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
    carries the sha1 and size the cache holds. A source that names a
    revision is listed at the commit the cache was fetched at, so its
    members never change. One that names none (the buildbot's nightly
    assets) is ``rolling``: the installer writes what it serves, as
    RetroArch's downloader does, and the hashes describe the pack's copy.
    archive_size is the size of the archive refresh_data_dirs last
    downloaded, what fetching
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
        by_norm.setdefault(norm_system_id(sys_id), []).append(sys_id)
    for src, full in members:
        ref, systems, prefix, needed = refs[full]
        if platform_systems is not None:
            systems = tuple(own for sid in systems for own in by_norm.get(norm_system_id(sid), ()))
        key = (ref, prefix)
        group = grouped.get(key)
        if group is None:
            group = grouped[key] = _tree_group(
                ref, prefix, registry.get(ref, {}), base_dest, versions
            )
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
