"""Where a platform's launch code puts a file: roots, tag prefixes, standalone layout paths."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping

from model.declarations import declared_root


def runs_standalone(
    emu_name: str, profile: dict, standalone_cores: set[str]
) -> bool:
    """Whether a platform lays this emulator's files out for its standalone build.

    A platform names the emulators it launches standalone in
    ``standalone_cores``, by profile key or by any name in ``cores:``. The
    name alone is not enough: Recalbox and Batocera call their standalone
    ScummVM ``scummvm``, which is also the key of the libretro core's
    profile, and that profile documents no standalone build. Laid out
    "standalone" it would lose every ``path:`` and drop its files at the
    root, so a profile whose ``type`` has no standalone build keeps its
    libretro layout whatever the platform calls it.
    """
    if not standalone_cores:
        return False
    if "standalone" not in str(profile.get("type", "")):
        return False
    names = {emu_name, *(str(c) for c in profile.get("cores", []))}
    # A name a build the platform compiles itself answers to means that
    # build there: RetroBat's standalone amiberry is 8.3.0, and the 8.5.0
    # profile, run there as the buildbot core, keeps its libretro layout.
    owners: dict[str, set[str]] = {}
    for tag in standalone_cores:
        if tag.startswith(OWN_BUILD_PREFIX):
            name, owner, source = json.loads(tag[len(OWN_BUILD_PREFIX):])
            if source == profile.get("source"):
                owners.setdefault(name, set()).add(owner)
    if any(emu_name not in owners[n] for n in names & owners.keys()):
        return False
    return emu_name in standalone_cores or bool(standalone_cores & names)


# Marks, in a platform's standalone set, an emulator it also launches as a
# libretro core. No core name starts with it.
DUAL_MODE_PREFIX = "dual:"
# Marks, in the same set, a whole directory the platform's launcher hands a
# standalone emulator (launchers.handed_directories), as JSON.
HANDED_PREFIX = "handed:"
# Marks, in the same set, a libretro core and the system directory the
# platform hands it (``core_system_dirs``), as JSON.
CORE_DIR_PREFIX = "coredir:"
# Marks, in the same set, a file the platform's launcher executes
# (launchers.executed_files), as JSON.
EXECUTED_PREFIX = "exec:"
# Marks, in the same set, a standalone name a build the platform compiles
# itself (built_by) answers to, as JSON [name, profile, source].
OWN_BUILD_PREFIX = "ownbuild:"
# Marks, in the same set, a file name the platform declares under one of the
# systems a launcher record is written for, as JSON [system, name]: it says
# which launch reads a profile entry of that name.
SYSTEM_FILE_PREFIX = "sysfile:"
# The key, in that index, of a machine a launcher record offers.
MACHINE_KEY = "machine:"
# The platform is known: an entry read beside the content is placed in the
# roms folders a core is launched for, or named as read outside the BIOS
# folder. The tags below carry those folders.
CONTENT_SCOPE_TAG = "contentscope:"
# [core name, roms folder, (tree, path)]: a libretro core the platform
# launches for the games of that folder, which it reads beside.
CONTENT_FOLDER_PREFIX = "contentdir:"
# [emulator or core, (tree, path), system, machines, any machine,
# source_ref, build]: a standalone emulator, or a libretro core in the
# command line it is handed as content, given a roms folder as its ROM
# search path by a system's launch command.
ROM_SEARCH_PREFIX = "romsearch:"
# The frontend writes the BIOS it hands a core beside the content: the
# folder it gives the BIOS is the content's.
CONTENT_SYSTEM_TAG = "contentsystem:"
CONTENT_TAG_PREFIXES = (
    CONTENT_SCOPE_TAG, CONTENT_FOLDER_PREFIX, ROM_SEARCH_PREFIX, CONTENT_SYSTEM_TAG,
)


def core_system_dirs(
    emu_name: str, profile: dict, standalone_cores: Iterable[str]
) -> list[str] | None:
    """The system directories a platform hands this libretro core, or None.

    None when the platform declares no per-core directory: the core reads
    the one system directory every core shares. A platform that declares
    them (MinUI hands each launch tag its own Bios/<TAG>/) gives a core it
    lists no directory at all, so the list is then empty.
    """
    pairs = [
        json.loads(tag[len(CORE_DIR_PREFIX):])
        for tag in standalone_cores if tag.startswith(CORE_DIR_PREFIX)
    ]
    if not pairs:
        return None
    names = {emu_name, *(str(c) for c in profile.get("cores") or [])}
    return sorted({directory for core, directory in pairs if core in names})


def system_dir_view(profile: dict, directory: str) -> dict:
    """The profile as a core reads it from one handed system directory.

    Each file keeps its own path, relative to the system directory, and
    carries the directory: destinations put it in front, resolution takes
    it off again (resolve_local_file), so the collection is still searched
    by the core's own path. A core's archive subfolder moves with it.
    """
    view = {
        **profile,
        "files": [
            {**f, "system_dir": directory} if isinstance(f, dict) else f
            for f in profile.get("files") or []
        ],
    }
    if profile.get("archive_prefix"):
        view["archive_prefix"] = f"{directory}/{profile['archive_prefix']}"
    return view


def system_dir_path(entry: dict, path: str) -> str:
    """``path`` below the system directory the entry carries, if any."""
    directory = entry.get("system_dir")
    return f"{directory}/{path}" if directory else path


def _handed(standalone_cores: Iterable[str]) -> list:
    """The directories a standalone set carries, as launchers built them."""
    from resolve.launchers import HandedDirectory

    found = []
    for tag in standalone_cores:
        if not tag.startswith(HANDED_PREFIX):
            continue
        position, emulator, folder, directory, handles, ref, roms, systems, held = json.loads(
            tag[len(HANDED_PREFIX):]
        )
        found.append(((position, tag), HandedDirectory(
            emulator, folder, directory, frozenset(handles), ref,
            tuple(roms) if roms else None, frozenset(systems), held,
        )))
    return [h for _key, h in sorted(found, key=lambda pair: pair[0])]


def system_file_index(standalone_cores: Iterable[str]) -> dict[str, set[str]]:
    """File name, lower case -> the platform systems declaring it (SYSTEM_FILE_PREFIX)."""
    index: dict[str, set[str]] = {}
    for tag in standalone_cores:
        if tag.startswith(SYSTEM_FILE_PREFIX):
            slug, name = json.loads(tag[len(SYSTEM_FILE_PREFIX):])
            index.setdefault(name, set()).add(slug)
    return index


def entry_launch_systems(entry: dict, index: Mapping[str, set[str]]) -> frozenset[str]:
    """The platform systems, by our ids, that launch the emulator for an entry.

    The systems the entry names, and those under which the platform declares
    a file of one of its names (``index``, system_file_index): Recalbox lists
    XRoar's coco3.rom under trs80coco, which our coco is.
    """
    systems = {str(s) for s in entry.get("systems") or []}
    if entry.get("system"):
        systems.add(str(entry["system"]))
    for name in [entry.get("name"), *(entry.get("aliases") or [])]:
        if name:
            systems |= index.get(str(name).lower(), set())
    return frozenset(systems)


def _executed(standalone_cores: Iterable[str]) -> list:
    """The files a standalone set's launchers execute, as launchers read them."""
    from resolve.launchers import ExecutedFile

    found = []
    for tag in standalone_cores:
        if tag.startswith(EXECUTED_PREFIX):
            emulator, name, place, ref = json.loads(tag[len(EXECUTED_PREFIX):])
            found.append(ExecutedFile(emulator, name, tuple(place) if place else None, ref))
    return found


# Why a standalone entry has no destination on a platform that relocates its
# layout: the manifest's omission reason, named as the installer words it.
OUTSIDE_BIOS_FOLDER = "outside_bios_folder"
# The entry root of a file read below the platform's roms directory, and of
# one read in an emulator's folder outside the BIOS tree that the registry
# describes. Each is located by the registry entry <root>_directory.
ROMS_ROOT = "roms"
EMULATORS_ROOT = "emulators"
CONFIGS_ROOT = "configs"
OUTER_ROOTS = (ROMS_ROOT, EMULATORS_ROOT, CONFIGS_ROOT)


def outer_layout(config: dict, root: str) -> dict | None:
    """Where a platform keeps the folder an outer root names, or None.

    roms: the roms root its rom folders file records (``path``, the OS's
    spelling, and ``from_bios``, relative to the BIOS folder), with the
    BIOS folder's own name, base_destination, that a run's folder must
    carry before ``from_bios`` is followed from it. emulators: the
    registry's ``emulators_directory``, the folders a launcher searches
    for an emulator by key, which no rom folders file describes.
    """
    if root == ROMS_ROOT:
        found = config.get("_roms_root") or {}
        base = str(config.get("base_destination") or "")
        path, relation = found.get("path"), found.get("from_bios")
        if not (path and relation) or "<" in str(path):
            return None
        if base:
            return {"path": str(path), "from_bios": str(relation), "bios_folder": base}
        # A list whose dests start above the BIOS folder (AmberELEC's
        # bios/...) installs into the folder holding it: a roms root there
        # or below is part of the install tree, written as a plain dest.
        declared = declared_root(config)
        if not declared:
            return None
        inside = os.path.normpath(f"{declared}/{relation}")
        if inside == ".." or inside.startswith("../"):
            return None
        return {"path": str(path), "install_prefix": "" if inside == "." else inside}
    if root == EMULATORS_ROOT:
        return config.get("emulators_directory") or None
    if root == CONFIGS_ROOT:
        # The frontend's configs folder, as its path code builds it
        # (configs_root, Batocera's batoceraPaths CONFIGS).
        found = config.get("configs_root") or {}
        base = str(config.get("base_destination") or "")
        if not (found.get("path") and found.get("from_bios") and base):
            return None
        return {"path": str(found["path"]), "from_bios": str(found["from_bios"]),
                "bios_folder": base}
    return None


def standalone_layout_path(entry: dict, profile: dict) -> str | None:
    """The path of an entry relative to the directories its standalone build declares.

    ``standalone_path`` when the entry has one. A profile with no libretro
    build has one layout, so its ``path`` is that layout: UAE4All2 reads
    kickstarts/kick13.rom below its working directory. So does an entry only
    the standalone build reads (``mode: standalone``), whose destination is
    its ``path``: Dolphin's Load/Firmware/rtl_bt/ under its User directory.
    """
    own = entry.get("standalone_path")
    if own:
        return own
    if "libretro" in str(profile.get("type", "")) and entry.get("mode") != "standalone":
        return None
    return entry.get("path") or None


def standalone_destination(
    entry: dict, profile: dict, bindings: dict[str, tuple[str, str]]
) -> tuple[str, str] | None:
    """Where a platform puts a standalone entry: (tree, path).

    ``bindings`` are the places the platform's launchers give the layout
    (launchers.standalone_bindings): RetroPie and ROCKNIX give Flycast bios/dc,
    EmuDeck bios/flycast/bios, RetroPie gives UAE4All2's kickstarts/ bios/amiga,
    ROCKNIX runs PICO-8 from roms/pico-8. The tree is launchers.BIOS_TREE or
    launchers.ROMS_TREE. None when no binding covers the entry.
    """
    layout = standalone_layout_path(entry, profile)
    if layout is None or not bindings:
        return None
    from resolve.launchers import bound_path

    return bound_path(layout, bindings)


def standalone_bindings_for(
    emu_name: str, profile: dict, standalone_cores: Iterable[str],
    systems: Iterable[str] = (),
) -> dict[str, tuple[str, str]]:
    """The places a platform gives this emulator's standalone layout, by subfolder.

    ``systems`` are those the entry is launched for (entry_launch_systems).
    """
    from resolve.launchers import directory_handles, pool_folders, standalone_bindings

    declared = directory_handles(profile)
    pools = pool_folders(profile)
    if not declared and not pools:
        return {}

    names = {emu_name, *(str(c) for c in profile.get("cores") or [])}
    layout = [
        path for f in profile.get("files") or []
        if isinstance(f, dict) and (path := standalone_layout_path(f, profile))
    ]
    return standalone_bindings(
        names, declared, _handed(standalone_cores), _executed(standalone_cores), layout,
        pools, systems,
    )


def _placed_entry(entry: dict, profile: dict, placed: tuple[str, str]) -> dict:
    """A standalone entry moved to the (tree, path) a platform reads it from."""
    tree, path = placed
    moved = {**entry, "standalone_path": path,
             "layout_path": standalone_layout_path(entry, profile)}
    if entry.get("load_from"):
        # The build's own root no longer applies: RetroDECK hands
        # Cemu's MLC, read from its data directory, to bios/cemu.
        load_from = entry["load_from"]
        moved["load_from"] = {
            **(load_from if isinstance(load_from, dict) else {"libretro": load_from}),
            "standalone": "system_dir",
        }
    if tree == "install":
        # Below the roms root inside the install tree (AmberELEC's
        # /storage/roms): a plain dest the platform prefix skips.
        return {**moved, "unprefixed": True}
    # A file the launcher runs from the roms directory (ROCKNIX's
    # roms/pico-8) or an emulator folder (RetroBat's emulators/pico8)
    # is relative to it, and says so.
    return {**moved, "root": tree} if tree else moved
